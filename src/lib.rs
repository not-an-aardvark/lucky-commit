#[cfg(feature = "opencl")]
use ocl::{
    builders::DeviceSpecifier::TypeFlags,
    flags::{DeviceType, MemFlags},
    prm::Uint16,
    Buffer, Context, Kernel, Platform, Program, Queue,
};
use sha1::{
    compress,
    digest::{
        generic_array::{ArrayLength, GenericArray},
        BlockInput, Digest,
    },
    Sha1,
};
#[cfg(feature = "opencl")]
use std::convert::TryInto;
use std::{
    cmp::Ord,
    fmt::Debug,
    ops::Range,
    slice::from_raw_parts_mut,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::{spawn, JoinHandle},
};

/// A worker that, when invoked, will look in a predetermined search space to find a modification
/// to a specific commit that matches a specific hash prefix.
#[derive(Debug, PartialEq)]
pub struct HashSearchWorker {
    processed_commit: ProcessedCommit,
    desired_prefix: HashPrefix,
    search_space: Range<u64>,
}

/// Defines a desired target prefix for a commit hash.
///
/// For example, the hash prefix "deadbeef123" corresponds to the
/// following structure:
///   HashPrefix { data: [0xdeadbeef, 0x12300000, 0, 0, 0], mask: [0xffffffff, 0xfff00000, 0, 0, 0] }
#[derive(Debug, PartialEq, Clone)]
pub struct HashPrefix {
    /// The prefix, as split into big-endian four-byte chunks.
    /// All bits beyond the length of the prefix are set to 0.
    data: [u32; 5],
    /// Mask containing bits set to 1 if the bit at that position is specified
    /// in the prefix, and 0 otherwise.
    mask: [u32; 5],
}

// The fully padded data that gets hashed is the concatenation of all the following:
// |--- GIT COMMIT HEADER (part of git's raw commit format) ---
// | * The ASCII string "commit "
// | * The byte-length of the entire "git commit" section below, represented as base-10 ASCII digits
// | * A null byte (0x0)
// |--- GIT COMMIT ---
// | * The original git commit object that was provided as input, in git's normal commit encoding, up
// |   to the "padding insertion point". (For commits that are not GPG-signed, the padding insertion
// |   point is right near the end of the commit. For commits that are GPG-signed, the padding insertion
// |   point is at the end of the signature, which is right before the commit message.) This section
// |   contains metadata such as the author, timestamp, and parent commit.
// | * Some number of ASCII space characters, as "static padding", such that the point after the static
// |   padding is at a multiple-of-64-byte offset from the start of the data. Note that in very rare
// |   pathological cases, more than 63 space characters will be needed. This is because adding static
// |   padding also increases the length of the commit object, which is used in the git commit header
// |   above. As a result, adding one additional padding character could increase the alignment by 2,
// |   e.g. if the length increases from 999 to 1000.
// |
// | - NOTE: The length of all the data up to this point is a multiple of 64 bytes, and the length
// |         of the all the data after this point is also a multiple of 64 bytes. For reasons that will
// |         be explained in the declaration of `PartiallyHashedCommit`, the 64-byte blocks preceding
// |         this point are called "static blocks", and the 64-byte blocks following this point are called
// |         "dynamic blocks".
// |
// | * 48 bytes of "dynamic padding", consisting of some combination of ASCII space and tab characters.
// |   This is the only part of the commit data that actually varies across SHA1 invocations. The ultimate
// |   goal is to find a dynamic padding arrangement that produces the desired hash. A 48-byte length was
// |   chosen with the goal of only needing a single dynamic block for non-GPG-signed commits.
// | * The rest of the original commit object (from the "padding insertion point" onwards). For
// |   non-GPG-signed commits, this will typically just be a single newline. For GPG-signed commits, this
// |   will contain the commit message.
// |--- SHA1 FINALIZATION PADDING (specified as part of the SHA1 algorithm) ---
// | * The byte 0x80
// | * Some number of null bytes (0x0), such that the point after the null bytes is at an offset of
// |   56 (mod 64) bytes from the start of the data
// | * The bit-length of everything before the "finalization padding" section, represented as a big-endian
// |   64-bit integer
#[derive(Debug, PartialEq, Clone)]
struct ProcessedCommit {
    /// The data, as specified in the comment above. The length will always be a multiple of 64 bytes.
    data: Box<[u8]>,
    /// The location of the git commit, as an index range into `data`
    commit_range: Range<usize>,
    /// The number of 64-byte static blocks in the data
    num_static_blocks: usize,
}

/// A view of an underlying `ProcessedCommit`, with cached SHA1 state.
///
/// SHA1 works as follows:
///
/// * First, a 20-byte "state vector" is initialized to a constant.
/// * Next, each each 64-byte block in the input is processed in sequence. The state vector after
/// processing a block is a convoluted, deteriministic function of (a) the state vector before
/// processing the block, and (b) the contents of the block. Processing blocks is the main performance
/// bottleneck of lucky-commit.
/// * The "SHA1 hash" of some data is just the contents of the state vector after processing all of
/// the data (with SHA1 finalization padding added to the end of the data, as described in the comment
/// about the `ProcessedCommit` format).
///
/// So there's a big optimization we can do here -- we have to compute a bunch of SHA1 hashes, but the
/// only part of the data that we're changing between runs is the dynamic padding, which is very close
/// to the end of the data. The state vector after processing all of the blocks before the dynamic
/// padding (the "static blocks") doesn't depend at all on the contents of the dynamic padding -- it's
/// effectively a constant for any given `ProcessedCommit`. The purpose of `PartiallyHashedCommit` is
/// to cache that state vector, and only reprocess the "dynamic blocks" on each change to the dynamic
/// padding. This drastically reduces the number of blocks that need to be processed, resulting in a
/// ~5x end-to-end performance improvement for an average-sized commit.
#[derive(Debug)]
struct PartiallyHashedCommit<'a> {
    intermediate_sha1_state: [u32; 5],
    dynamic_blocks: &'a mut [GenericArray<u8, <Sha1 as BlockInput>::BlockSize>],
}

const SHA1_INITIAL_STATE: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

/// The result of a successful hash search
#[derive(Debug, PartialEq)]
pub struct HashedCommit {
    /// The git commit that has the desired hash
    pub commit: Vec<u8>,

    /// The hash of the commit, as a hex string
    pub hash: String,
}

impl HashSearchWorker {
    /// Creates a worker for a specific commit and prefix, with an initial
    /// workload of 1 ** 48 units. As a rough approximation depending on hardware,
    /// each worker can perform about 7 million units of work per second.
    pub fn new(current_commit: &[u8], desired_prefix: HashPrefix) -> Self {
        Self {
            processed_commit: ProcessedCommit::new(current_commit),
            desired_prefix,
            search_space: 0..(1 << 48),
        }
    }

    /// Caps a worker's search space to approximately the given size.
    pub fn with_capped_search_space(mut self, workload: u64) -> Self {
        self.search_space = self.search_space.start
            ..Ord::min(self.search_space.end, self.search_space.start + workload);
        self
    }

    /// Splits this worker into `divisor` new workers for the same commit and
    /// desired prefix, with the search space split roughly equally.
    /// A worker's search space is an approximation to help with effecient threading. There is
    /// no guarantee that the resulting workers have perfectly disjoint search spaces, so in theory
    /// multiple workers could both find the same hash match despite having "split" the space.
    fn split_search_space(self, divisor: u64) -> impl Iterator<Item = Self> {
        let amount_per_worker = (self.search_space.end - self.search_space.start) / divisor;
        (0..divisor).map(move |index| {
            let range_start = index * amount_per_worker + self.search_space.start;
            let range_end = if index < divisor - 1 {
                range_start + amount_per_worker
            } else {
                // In case the work can't be divided perfectly, just give all the slack to the last
                // worker. Typically, `amount_per_worker` will be many orders of magnitude larger
                // than `divisor`, so having a few extra units of work is immaterial.
                self.search_space.end
            };
            Self {
                processed_commit: self.processed_commit.clone(),
                desired_prefix: self.desired_prefix.clone(),
                search_space: range_start..range_end,
            }
        })
    }

    /// Invokes the worker. The worker will return early with a hash match if it finds one,
    /// otherwise it will search its entire search space and return `None`.
    pub fn search(self) -> Option<HashedCommit> {
        #[cfg(feature = "opencl")]
        if Self::gpus_available() {
            return self.search_with_gpu().unwrap();
        }

        self.search_with_cpus()
    }

    #[cfg(feature = "opencl")]
    fn gpus_available() -> bool {
        Platform::first().is_ok()
            && !TypeFlags(DeviceType::GPU)
                .to_device_list(None::<Platform>)
                .unwrap()
                .is_empty()
    }

    #[allow(clippy::needless_collect)]
    fn search_with_cpus(self) -> Option<HashedCommit> {
        let thread_count = num_cpus::get_physical();
        let lame_duck_cancel_signal = Arc::new(AtomicBool::new(false));
        let (shared_sender, receiver) = mpsc::channel();

        let _handles = self
            .split_search_space(thread_count as u64)
            .map(|worker| {
                let result_sender = shared_sender.clone();
                let worker_cancel_signal = Arc::clone(&lame_duck_cancel_signal);

                spawn(move || {
                    let _ = result_sender
                        .send(worker.search_with_cpu_single_threaded(worker_cancel_signal));
                })
            })
            .collect::<Vec<JoinHandle<()>>>();

        for _ in 0..thread_count {
            if let Some(result) = receiver.recv().unwrap() {
                lame_duck_cancel_signal.store(true, Ordering::Relaxed);

                // Lame-duck threads should halt shortly after any thread finds a match. However,
                // we don't want to actually wait for them to halt when running in production, especially
                // since the process will usually terminate shortly afterwards anyway. So the waiting
                // and panic detection is debug/test-only
                #[cfg(debug_assertions)]
                _handles
                    .into_iter()
                    .map(JoinHandle::join)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();

                return Some(result);
            }
        }

        None
    }

    #[inline(never)]
    fn search_with_cpu_single_threaded(
        self,
        lame_duck_cancel_signal: Arc<AtomicBool>,
    ) -> Option<HashedCommit> {
        let HashSearchWorker {
            search_space,
            desired_prefix,
            mut processed_commit,
        } = self;
        let mut partially_hashed_commit = processed_commit.as_partially_hashed_commit();

        let lame_duck_check_interval = Ord::min(search_space.end - search_space.start, 1 << 20);
        for base_padding_specifier in search_space.step_by(lame_duck_check_interval as usize) {
            for index_in_interval in 0..lame_duck_check_interval {
                partially_hashed_commit.scatter_padding(base_padding_specifier + index_in_interval);
                if desired_prefix.matches(&partially_hashed_commit.current_hash()) {
                    return Some(HashedCommit::new(processed_commit.commit()));
                }
            }

            if lame_duck_cancel_signal.load(Ordering::Relaxed) {
                break;
            }
        }

        None
    }

    #[cfg(feature = "opencl")]
    fn search_with_gpu(self) -> ocl::Result<Option<HashedCommit>> {
        let HashSearchWorker {
            search_space,
            desired_prefix,
            mut processed_commit,
        } = self;
        let mut partially_hashed_commit = processed_commit.as_partially_hashed_commit();

        let num_threads = *[
            desired_prefix.estimated_hashes_needed().saturating_mul(4),
            search_space.end - search_space.start,
            1 << 22,
        ]
        .iter()
        .min()
        .unwrap() as usize;

        assert!(num_threads < u32::MAX as usize);

        let devices = TypeFlags(DeviceType::GPU).to_device_list(Some(Platform::default()))?[0];
        let context = Context::builder().devices(devices).build()?;
        let queue = Queue::new(&context, devices, None)?;

        let mut successful_match_receiver_host_handle = [u32::MAX];
        let successful_match_receiver = Buffer::builder()
            .queue(queue.clone())
            .len(1)
            .flags(MemFlags::READ_WRITE)
            .copy_host_slice(&successful_match_receiver_host_handle)
            .build()?;
        let mut kernel = Kernel::builder()
            .name("scatter_padding_and_find_match")
            .program(
                &Program::builder()
                    .src(include_str!("sha1_prefix_matcher.cl"))
                    .cmplr_opt("-Werror")
                    .build(&context)?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(desired_prefix.data.len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(&desired_prefix.data[..])
                    .build()?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(desired_prefix.mask.len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(&desired_prefix.mask[..])
                    .build()?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(partially_hashed_commit.intermediate_sha1_state.len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(&partially_hashed_commit.intermediate_sha1_state)
                    .build()?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(partially_hashed_commit.dynamic_blocks.len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(
                        &partially_hashed_commit
                            .dynamic_blocks
                            .iter()
                            .map(|&block| encode_into_opencl_vector(block))
                            .collect::<Vec<_>>(),
                    )
                    .build()?,
            )
            .arg(partially_hashed_commit.dynamic_blocks.len() as u64)
            .arg(&successful_match_receiver)
            .queue(queue)
            .global_work_size(num_threads)
            .build()?;

        for base_padding_specifier in search_space.step_by(num_threads) {
            kernel.set_default_global_work_offset((base_padding_specifier,).into());

            // SAFETY: The OpenCL sha1 script is optimistically assumed to have no memory safety issues
            unsafe {
                kernel.enq()?;
            }

            successful_match_receiver
                .read(&mut successful_match_receiver_host_handle[..])
                .enq()?;

            if successful_match_receiver_host_handle[0] != u32::MAX {
                let successful_padding_specifier =
                    base_padding_specifier + (successful_match_receiver_host_handle[0] as u64);
                partially_hashed_commit.scatter_padding(successful_padding_specifier);

                assert!(
                    desired_prefix.matches(&partially_hashed_commit.current_hash()),
                    "\
                        A GPU search reported a commit with a successful match, but when that \
                        commit was hashed in postprocessing, it didn't match the desired prefix. \
                        This is a bug. The most likely explanation is that the two implementations of \
                        `scatter_padding` in Rust and OpenCL (or the implementations of SHA1) have diverged \
                        from each other.\n\npartial commit:\n\t{:?}\ndesired prefix:\n\t{:?}\ncommit hash \
                        produced during postprocessing:{:?}\n\tpadding specifier: {}",
                    partially_hashed_commit,
                    desired_prefix,
                    partially_hashed_commit.current_hash(),
                    successful_padding_specifier,
                );

                return Ok(Some(HashedCommit::new(processed_commit.commit())));
            }
        }

        Ok(None)
    }
}

impl ProcessedCommit {
    const DYNAMIC_PADDING_LENGTH: usize = 48;

    /// See the comment above the definition of `ProcessedCommit` for details on how
    /// the data layout.
    fn new(original_commit: &[u8]) -> Self {
        let padding_insertion_point = Self::get_padding_insertion_point(original_commit);

        // If the commit message already has spaces or tabs where we're putting padding, the most
        // likely explanation is that the user has run lucky-commit on this commit before. To prevent
        // commits from repeatedly growing after lucky-commit is run on them, omit the old padding
        // rather than piling onto it.
        let replaceable_padding_size = original_commit[padding_insertion_point..]
            .iter()
            .take_while(|&&byte| byte == b' ' || byte == b'\t')
            .count();

        // Use enough static padding to pad to a multiple of 64
        let static_padding_length = Self::compute_static_padding_length(
            padding_insertion_point,
            original_commit.len() - replaceable_padding_size + Self::DYNAMIC_PADDING_LENGTH,
        );

        let commit_length = original_commit.len() - replaceable_padding_size
            + static_padding_length
            + Self::DYNAMIC_PADDING_LENGTH;

        // Git commit header
        let mut data = format!("commit {}\0", commit_length).into_bytes();

        let commit_range = data.len()..(data.len() + commit_length);

        // First part of commit
        data.extend(&original_commit[..padding_insertion_point]);

        // Static padding
        data.resize(data.len() + static_padding_length, b' ');

        assert_eq!(data.len() % 64, 0);
        let num_static_blocks = data.len() / 64;

        // Dynamic padding, initialized to tabs for now
        data.resize(data.len() + Self::DYNAMIC_PADDING_LENGTH, b'\t');

        // Second part of commit
        data.extend(&original_commit[padding_insertion_point + replaceable_padding_size..]);

        assert_eq!(data.len(), commit_range.end);

        // SHA1 finalization padding
        data.push(0x80);
        data.resize(
            data.len() + (56 - data.len() as isize).rem_euclid(64) as usize,
            0,
        );
        data.extend(&(commit_range.end as u64 * 8).to_be_bytes());

        assert_eq!(data.len() % 64, 0);

        Self {
            data: data.into_boxed_slice(),
            commit_range,
            num_static_blocks,
        }
    }

    /// Finds the index at which static and dynamic padding should be inserted into a commit.
    ///
    /// If the commit has a GPG signature (detected by the presence of "-----END PGP SIGNATURE-----"
    /// after a line that starts with "gpgsig "), then add the padding whitespace immediately after
    /// the text "-----END PGP SIGNATURE-----".
    /// Otherwise, add the padding whitespace right before the end of the commit message.
    ///
    /// To save time hashing, we want the padding to be as close to the end of the commit
    /// as possible. However, if a signature is present, modifying the commit message would make
    /// the signature invalid.
    fn get_padding_insertion_point(commit: &[u8]) -> usize {
        let mut found_gpgsig_line = false;
        const SIGNATURE_MARKER: &[u8] = b"-----END PGP SIGNATURE-----";
        for index in 0..commit.len() {
            if commit[index..].starts_with(b"\ngpgsig ") {
                found_gpgsig_line = true;
            } else if !found_gpgsig_line && commit[index..].starts_with(b"\n\n") {
                // We've reached the commit message and no GPG signature has been found.
                // Add the padding to the end of the commit.
                break;
            } else if found_gpgsig_line && commit[index..].starts_with(SIGNATURE_MARKER) {
                return index + SIGNATURE_MARKER.len();
            }
        }

        // If there's no GPG signature, trim the end of the commit and take the length.
        // This ensures that the commit will still have a trailing newline after padding is added, and
        // that any existing padding appears after the padding insertion point.
        commit.len()
            - commit
                .iter()
                .rev()
                .take_while(|&&byte| byte == b' ' || byte == b'\t' || byte == b'\n')
                .count()
    }

    /// Returns the smallest nonnegative integer `static_padding_length` such that:
    ///   static_padding_length
    /// + commit_length_before_static_padding
    /// + 8
    /// + (number of digits in the base10 representation of
    ///       commit_length_excluding_static_padding + static_padding_length)
    /// is a multiple of 64.
    ///
    /// The 8 comes from the length of the word `commit`, plus a space and a null character, in
    /// git's commit hashing format.
    fn compute_static_padding_length(
        commit_length_before_static_padding: usize,
        commit_length_excluding_static_padding: usize,
    ) -> usize {
        let compute_alignment = |padding_len: usize| {
            (format!(
                "commit {}\0",
                commit_length_excluding_static_padding + padding_len
            )
            .len()
                + commit_length_before_static_padding
                + padding_len)
                % 64
        };
        let prefix_length_estimate = format!("commit {}\0", commit_length_excluding_static_padding)
            .len()
            + commit_length_before_static_padding;
        let initial_padding_length_guess = (64 - prefix_length_estimate % 64) % 64;

        let static_padding_length = if compute_alignment(initial_padding_length_guess) == 0 {
            initial_padding_length_guess
        } else if compute_alignment(initial_padding_length_guess - 1) == 0 {
            initial_padding_length_guess - 1
        } else {
            initial_padding_length_guess + 63
        };

        assert_eq!(compute_alignment(static_padding_length), 0);
        debug_assert!((0..static_padding_length).all(|len| compute_alignment(len) != 0));

        static_padding_length
    }

    fn commit(&self) -> &[u8] {
        &self.data[self.commit_range.clone()]
    }

    fn as_partially_hashed_commit(&mut self) -> PartiallyHashedCommit {
        let (static_blocks, dynamic_blocks) =
            as_chunks_mut::<u8, <Sha1 as BlockInput>::BlockSize>(&mut self.data[..])
                .0
                .split_at_mut(self.num_static_blocks);

        let mut intermediate_sha1_state = SHA1_INITIAL_STATE;
        compress(&mut intermediate_sha1_state, static_blocks);

        PartiallyHashedCommit {
            intermediate_sha1_state,
            dynamic_blocks,
        }
    }
}

impl<'a> PartiallyHashedCommit<'a> {
    #[inline(always)]
    fn dynamic_padding_mut(&mut self) -> &mut [u8] {
        &mut self.dynamic_blocks[0][..48]
    }

    // This should be kept in sync with the OpenCL `arrange_padding_block` implementation.
    #[inline(always)]
    fn scatter_padding(&mut self, padding_specifier: u64) {
        for (padding_chunk, &padding_specifier_byte) in self
            .dynamic_padding_mut()
            .chunks_exact_mut(8)
            .zip(padding_specifier.to_le_bytes().iter())
        {
            // An padding specifier is represented by an integer in the range [0, 2 ** 48).
            // The 48-byte dynamic padding string is mapped from the 48-bit specifier such that
            // each byte of padding is a [space/tab] if the corresponding little-endian bit of
            // the specifier is a [0/1], respectively.
            padding_chunk.copy_from_slice(&PADDING_CHUNKS[padding_specifier_byte as usize]);
        }
    }

    #[inline(always)]
    fn current_hash(&self) -> [u32; 5] {
        let mut sha1_hash = self.intermediate_sha1_state;
        compress(&mut sha1_hash, self.dynamic_blocks);
        sha1_hash
    }
}

impl HashPrefix {
    /// Creates a new hash prefix from a hex string, which is at most 40 characters.
    /// Returns `None` if the supplied prefix was invalid.
    pub fn new(prefix: &str) -> Option<Self> {
        if prefix.len() > 40 {
            return None;
        }

        let contains_only_valid_characters = prefix.chars().all(|c| {
            ('0'..='9').contains(&c) || ('a'..='f').contains(&c) || ('A'..='F').contains(&c)
        });

        if !contains_only_valid_characters {
            return None;
        }

        let mut data = [0u32; 5];
        let mut mask = [0u32; 5];

        for (i, chunk) in prefix.as_bytes().chunks(8).enumerate() {
            let value =
                u32::from_str_radix(&String::from_utf8(chunk.to_vec()).unwrap(), 16).unwrap();
            let num_unspecified_bits = 32 - 4 * chunk.len();
            data[i] = value << num_unspecified_bits;
            mask[i] = u32::MAX >> num_unspecified_bits << num_unspecified_bits;
        }

        Some(HashPrefix { data, mask })
    }

    #[inline(always)]
    fn matches(&self, hash: &[u32; 5]) -> bool {
        hash.iter()
            .zip(&self.mask)
            .map(|(&hash_word, &mask_word)| hash_word & mask_word)
            .zip(&self.data)
            .all(|(masked_hash_word, &desired_prefix_word)| masked_hash_word == desired_prefix_word)
    }

    #[cfg(feature = "opencl")]
    fn estimated_hashes_needed(&self) -> u64 {
        2u64.saturating_pow(self.mask.iter().map(|word| word.count_ones()).sum())
    }
}

impl Default for HashPrefix {
    fn default() -> Self {
        HashPrefix::new("0000000").unwrap()
    }
}

impl HashedCommit {
    fn new(commit: &[u8]) -> Self {
        Self {
            commit: commit.to_vec(),
            hash: hash_git_commit(commit),
        }
    }
}

#[cfg(feature = "opencl")]
/// Reinterpret a block with 64 8-bit integers as an OpenCL vector with 16 32-bit big-endian integers
fn encode_into_opencl_vector(data: GenericArray<u8, <Sha1 as BlockInput>::BlockSize>) -> Uint16 {
    let words: [u32; 16] = data
        .chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    words.into()
}

/// Hashes a commit object using git's object encoding, without adding padding or anything else
pub fn hash_git_commit(commit: &[u8]) -> String {
    Sha1::new()
        .chain(format!("commit {}\0", commit.len()).as_bytes())
        .chain(commit)
        .finalize()
        .iter()
        .map(|&byte| format!("{:02x}", byte))
        .collect::<String>()
}

// This is a modified implementation of std::slice::as_chunks_mut. It's copied because the
// standard library function is not yet stable (and neither are const generics).
fn as_chunks_mut<T, N: ArrayLength<T>>(slice: &mut [T]) -> (&mut [GenericArray<T, N>], &mut [T]) {
    let chunk_size = N::to_usize();
    assert_ne!(chunk_size, 0);
    let len = slice.len() / chunk_size;
    let (multiple_of_n, remainder) = slice.split_at_mut(len * chunk_size);
    let array_slice =

        // SAFETY: We cast a slice of `len * N` elements into
        // a slice of `len` many `N` elements chunks.
        unsafe { from_raw_parts_mut(multiple_of_n.as_mut_ptr().cast(), len) };
    (array_slice, remainder)
}

// The 256 unique strings of length 8 which contain only ' ' and '\t'.
// These are computed statically in advance to allow them to be copied quickly.
static PADDING_CHUNKS: [[u8; 8]; 256] = {
    let mut padding_chunks = [[0; 8]; 256];
    let mut i = 0;
    while i < 256 {
        let mut j = 0;
        while j < 8 {
            padding_chunks[i][j] = if i & (0x80 >> j) == 0 { b' ' } else { b'\t' };
            j += 1;
        }
        i += 1;
    }
    padding_chunks
};

#[cfg(test)]
mod tests;
