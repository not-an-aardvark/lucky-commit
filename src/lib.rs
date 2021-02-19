#[cfg(feature = "opencl")]
use ocl::{
    builders::DeviceSpecifier::TypeFlags,
    flags::{DeviceType, MemFlags},
    prm::{Uint16, Uint4},
    Platform, ProQue,
};
use sha1::{
    compress,
    digest::{generic_array::GenericArray, BlockInput},
    Sha1,
};
#[cfg(feature = "opencl")]
use std::convert::TryInto;
use std::{
    cmp::min,
    ops::Range,
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

/// Defines a target prefix for a commit hash.
#[derive(Debug, PartialEq, Clone)]
pub struct HashPrefix {
    /// The prefix, as split into big-endian four-byte chunks.
    /// All bits beyond the length of the prefix are set to 0.
    data: [u32; 5],
    /// Mask containing bits set to 1 if the bit at that position is specified
    /// in the prefix, and 0 otherwise.
    mask: [u32; 5],
}

/// The result of a successful hash search
#[derive(Debug, PartialEq)]
pub struct HashMatch {
    /// The git commit object that has the desired hash, in the format equivalent
    /// to the output of `git cat-file commit HEAD`.
    pub commit: Vec<u8>,

    /// The hash of the commit as a hex string, when hashed in git's object encoding
    pub hash: String,
}

#[derive(Debug, PartialEq, Clone)]
struct ProcessedCommit {
    header: Vec<u8>,
    commit: Vec<u8>,
    dynamic_padding_start_index: usize,
}

struct PartiallyHashedCommit {
    prehashed_commit_section: Vec<u8>,
    intermediate_sha1_state: [u32; 5],
    remaining_blocks: Vec<GenericArray<u8, <Sha1 as BlockInput>::BlockSize>>,
    total_commit_length: usize,
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
        self.search_space =
            self.search_space.start..min(self.search_space.end, self.search_space.start + workload);
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
    pub fn search(self) -> Option<HashMatch> {
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
    fn search_with_cpus(self) -> Option<HashMatch> {
        let thread_count = num_cpus::get_physical();
        let lame_duck_cancel_signal = Arc::new(AtomicBool::new(false));
        let (shared_sender, receiver) = mpsc::channel();

        let _handles = self
            .split_search_space(thread_count as u64)
            .map(|worker| {
                let result_sender = shared_sender.clone();
                let worker_cancel_signal = lame_duck_cancel_signal.clone();

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
    ) -> Option<HashMatch> {
        let HashSearchWorker {
            search_space,
            desired_prefix,
            processed_commit,
        } = self;
        let mut partially_hashed_commit = processed_commit.into_partially_hashed_commit();

        let lame_duck_check_interval = min(search_space.end - search_space.start, 1 << 20);
        for base_padding_specifier in search_space.step_by(lame_duck_check_interval as usize) {
            for index_in_interval in 0..lame_duck_check_interval {
                partially_hashed_commit.scatter_padding(base_padding_specifier + index_in_interval);
                if desired_prefix.matches(&partially_hashed_commit.current_hash()) {
                    return Some(partially_hashed_commit.into_hash_match());
                }
            }

            if lame_duck_cancel_signal.load(Ordering::Relaxed) {
                break;
            }
        }

        None
    }

    #[cfg(feature = "opencl")]
    fn search_with_gpu(self) -> ocl::Result<Option<HashMatch>> {
        let HashSearchWorker {
            search_space,
            desired_prefix,
            processed_commit,
        } = self;
        let mut partially_hashed_commit = processed_commit.into_partially_hashed_commit();

        const BASE_PADDING_SPECIFIER_ARG: &str = "base_padding_specifier";

        let num_threads = *[
            desired_prefix.estimated_hashes_needed().saturating_mul(4),
            search_space.end - search_space.start,
            // TODO: this value will get used a majority of the time, it should be calibrated more precisely
            1 << 22,
        ]
        .iter()
        .min()
        .unwrap() as usize;

        let pro_que = ProQue::builder()
            .src(include_str!("sha1_prefix_matcher.cl"))
            .dims(num_threads)
            .device(TypeFlags(DeviceType::GPU))
            .build()?;
        let desired_prefix_data_buffer = pro_que
            .buffer_builder::<u32>()
            .len(desired_prefix.data.len())
            .flags(MemFlags::READ_ONLY)
            .copy_host_slice(&desired_prefix.data[..])
            .build()?;
        let desired_prefix_mask_buffer = pro_que
            .buffer_builder::<u32>()
            .len(desired_prefix.mask.len())
            .flags(MemFlags::READ_ONLY)
            .copy_host_slice(&desired_prefix.mask[..])
            .build()?;
        let initial_state_buffer = pro_que
            .buffer_builder::<u32>()
            .len(partially_hashed_commit.intermediate_sha1_state.len())
            .flags(MemFlags::READ_ONLY)
            .copy_host_slice(&partially_hashed_commit.intermediate_sha1_state)
            .build()?;

        // This is a slight hack -- it seems like passing a zero-length buffer
        // (or null pointer) to an OpenCL kernel is not allowed. However, since we're
        // passing the length in separately anyway, we can just pass a buffer of length
        // 1 if there are no post-padding blocks, and it will never get used.
        let post_padding_blocks_buffer = if partially_hashed_commit.remaining_blocks.len() > 1 {
            pro_que
                .buffer_builder::<Uint16>()
                .len(partially_hashed_commit.remaining_blocks.len() - 1)
                .flags(MemFlags::READ_ONLY)
                .copy_host_slice(
                    partially_hashed_commit.remaining_blocks[1..]
                        .iter()
                        .map(|block| Uint16::from(encode_big_endian_words_64(block)))
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
                .build()?
        } else {
            pro_que
                .buffer_builder::<Uint16>()
                .len(1)
                .flags(MemFlags::READ_ONLY)
                .copy_host_slice(&[Uint16::zero()])
                .build()?
        };
        let mut successful_match_receiver_host_handle = [u64::MAX];
        let successful_match_receiver = pro_que
            .buffer_builder::<u64>()
            .len(1)
            .flags(MemFlags::WRITE_ONLY)
            .copy_host_slice(&successful_match_receiver_host_handle)
            .build()?;
        let kernel = pro_que
            .kernel_builder("scatter_padding_and_find_match")
            .arg(&desired_prefix_data_buffer)
            .arg(&desired_prefix_mask_buffer)
            .arg(&initial_state_buffer)
            .arg_named(BASE_PADDING_SPECIFIER_ARG, &0) // filled in later
            .arg(Uint4::from(encode_big_endian_words_16(
                &partially_hashed_commit.remaining_blocks[0][48..]
                    .try_into()
                    .unwrap(),
            )))
            .arg(partially_hashed_commit.remaining_blocks.len() - 1)
            .arg(&post_padding_blocks_buffer)
            .arg(&successful_match_receiver)
            .build()?;

        for base_padding_specifier in search_space.step_by(num_threads) {
            kernel.set_arg(BASE_PADDING_SPECIFIER_ARG, base_padding_specifier)?;

            // SAFETY: The OpenCL sha1 script is optimistically assumed to have no memory safety issues
            unsafe {
                kernel.enq()?;
            }

            successful_match_receiver
                .read(&mut successful_match_receiver_host_handle[..])
                .enq()?;

            if successful_match_receiver_host_handle[0] != u64::MAX {
                let successful_padding_specifier = successful_match_receiver_host_handle[0];
                partially_hashed_commit.scatter_padding(successful_padding_specifier);

                assert!(
                    desired_prefix.matches(&partially_hashed_commit.current_hash()),
                    "\
                        A GPU search reported a commit with a successful match, but when that \
                        commit was hashed in postprocessing, it didn't match the desired prefix. \
                        This is a bug. The most likely explanation is that the two implementations of \
                        `scatter_padding` in Rust and OpenCL (or the implementations of SHA1) have diverged \
                        from each other.\n\ndesired prefix:\n\t{:?}\ncommit hash produced during \
                        postprocessing:{:?}\n\tpadding specifier: {}\n\tcommit: {:?}",
                    desired_prefix,
                    partially_hashed_commit.current_hash(),
                    successful_padding_specifier,
                    String::from_utf8(partially_hashed_commit.into_hash_match().commit).unwrap_or_else(|_| "(invalid utf8)".to_owned())
                );

                return Ok(Some(partially_hashed_commit.into_hash_match()));
            }
        }

        Ok(None)
    }
}

impl ProcessedCommit {
    fn new(original_commit: &[u8]) -> Self {
        // The fully padded data that gets hashed is the concatenation of all the following:
        // * "commit " + length + "\x00", where `length` is the base-10 representation of the length
        //    of everything that follows the null character. This is part of git's raw commit format.
        // * The original commit object, containing everything up to the point where padding should be
        //   added.
        // * Up to 63 space characters, as static padding. This is inserted so that the dynamic padding
        //   that follows it will be at a multiple-of-64-byte offset. Since the performance-intensive
        //   search involves hashing all of the 64-byte blocks starting with the dynamic padding, this
        //   ensures that the dynamic padding is always in a single block. Note that in pathological cases,
        //   more than 63 space characters will be added to align the dynamic padding. This is because
        //   adding static padding also increases the length of the commit object used in the initial header,
        //   and this could bump the alignment twice if e.g. the length increases from 999 to 1000. In these
        //   cases, an additional 63 spaces will be added as static padding, to ensure that the start of the
        //   dynamic padding is always aligned.
        // * 48 bytes of dynamic padding, consisting of space and tab characters. The ultimate goal
        //   is to find some combination of spaces and tabs that produces the desired hash. A 48-byte
        //   length was chosen with the goal of having everything that follows the static padding
        //   fit into one block for non-GPG-signed commits. (This allows 8 bytes for SHA1's final
        //   length padding, as well as a couple bytes for the remainder of the commit object and
        //   any alignment issues, while still using a multiple of 8 bytes for easily copying padding.)
        // * The rest of the original commit object. For non-GPG-signed commits, this will just be
        //   a single newline. For GPG-signed commits, this will contain the commit message.
        let commit_split_index = Self::get_commit_split_index(original_commit);

        const DYNAMIC_PADDING_LENGTH: usize = 48;

        // If the commit message already has spaces or tabs where we're putting padding, the most
        // likely explanation is that the user has run lucky-commit on this commit before. To prevent
        // commits from repeatedly growing after lucky-commit is run on them, omit the old padding
        // rather than piling onto it.
        let replaceable_padding_size = original_commit[commit_split_index..]
            .iter()
            .take_while(|&&byte| byte == b' ' || byte == b'\t')
            .count();

        // Use enough static padding to pad to a multiple of 64
        let static_padding_length = Self::compute_static_padding_length(
            commit_split_index,
            original_commit.len() - replaceable_padding_size + DYNAMIC_PADDING_LENGTH,
        );

        let commit_length = original_commit.len() - replaceable_padding_size
            + static_padding_length
            + DYNAMIC_PADDING_LENGTH;
        let header = format!("commit {}\x00", commit_length).into_bytes();

        let mut commit = Vec::with_capacity(commit_length);
        commit.extend(&original_commit[..commit_split_index]);

        // Add static padding
        commit.resize(commit.len() + static_padding_length, b' ');

        let dynamic_padding_start_index = commit.len();

        // Add dynamic padding, initialized to tabs for now
        commit.resize(commit.len() + DYNAMIC_PADDING_LENGTH, b'\t');

        commit.extend(&original_commit[commit_split_index + replaceable_padding_size..]);

        assert!((header.len() + dynamic_padding_start_index) % 64 == 0);

        Self {
            header,
            commit,
            dynamic_padding_start_index,
        }
    }

    // Returns the smallest nonnegative integer `static_padding_length` such that:
    //   static_padding_length
    // + commit_length_before_static_padding
    // + 8
    // + (number of digits in the base10 representation of
    //       commit_length_excluding_static_padding + static_padding_length)
    // is a multiple of 64.
    //
    // The 8 comes from the length of the word `commit`, plus a space and a null character, in
    // git's commit hashing format.
    fn compute_static_padding_length(
        commit_length_before_static_padding: usize,
        commit_length_excluding_static_padding: usize,
    ) -> usize {
        let compute_alignment = |padding_len: usize| {
            (format!(
                "commit {}\x00",
                commit_length_excluding_static_padding + padding_len
            )
            .len()
                + commit_length_before_static_padding
                + padding_len)
                % 64
        };
        let prefix_length_estimate =
            format!("commit {}\x00", commit_length_excluding_static_padding).len()
                + commit_length_before_static_padding;
        let initial_padding_length_guess = (64 - prefix_length_estimate % 64) % 64;

        let static_padding_length = if compute_alignment(initial_padding_length_guess) == 0 {
            initial_padding_length_guess
        } else if compute_alignment(initial_padding_length_guess - 1) == 0 {
            initial_padding_length_guess - 1
        } else {
            initial_padding_length_guess + 63
        };

        assert_eq!(0, compute_alignment(static_padding_length));
        debug_assert!((0..static_padding_length).all(|len| compute_alignment(len) != 0));

        static_padding_length
    }

    fn get_commit_split_index(commit: &[u8]) -> usize {
        /*
         * If the commit has a GPG signature (detected by the presence of "-----END PGP SIGNATURE-----"
         * after a line that starts with "gpgsig "), then add the padding whitespace immediately after
         * the text "-----END PGP SIGNATURE-----".
         * Otherwise, add the padding whitespace right before the end of the commit message.
         *
         * To save time hashing, we want the padding to be as close to the end of the commit
         * as possible. However, if a signature is present, modifying the commit message would make
         * the signature invalid.
         */
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
        // that any existing padding appears after the split index.
        commit.len()
            - commit
                .iter()
                .rev()
                .take_while(|&&byte| byte == b' ' || byte == b'\t' || byte == b'\n')
                .count()
    }

    fn into_partially_hashed_commit(mut self) -> PartiallyHashedCommit {
        const SHA1_INITIAL_STATE: [u32; 5] =
            [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];

        let prehashed_commit_section = self.commit[..self.dynamic_padding_start_index].to_vec();

        // SHA1 works by splitting the input data into 64-byte blocks. Each 64-byte block
        // can be processed in sequence. Since we're adding whitespace near the end of a
        // commit object, the first few 64-byte blocks of the commit will always be the same.
        // Instead of reprocessing those blocks every time, we can just cache the SHA1 state
        // after processing those blocks, and only process the new padding each time.
        let mut intermediate_sha1_state = SHA1_INITIAL_STATE;
        compress(
            &mut intermediate_sha1_state,
            self.header
                .iter()
                .chain(prehashed_commit_section.iter())
                .copied()
                .collect::<Vec<_>>()
                .chunks_exact(64)
                .map(GenericArray::clone_from_slice)
                .collect::<Vec<_>>()
                .as_slice(),
        );

        let total_commit_length = self.commit.len();
        self.commit.push(0x80);
        while self.commit[self.dynamic_padding_start_index..].len() % 64 != 56 {
            self.commit.push(0);
        }
        self.commit.extend_from_slice(
            &((self.header.len() + total_commit_length) as u64 * 8).to_be_bytes(),
        );

        PartiallyHashedCommit {
            prehashed_commit_section,
            intermediate_sha1_state,
            total_commit_length,
            remaining_blocks: self.commit[self.dynamic_padding_start_index..]
                .chunks_exact(64)
                .map(GenericArray::clone_from_slice)
                .collect(),
        }
    }
}

impl PartiallyHashedCommit {
    // This should be kept in sync with the OpenCL `arrange_padding_block` implementation.
    #[inline(always)]
    fn scatter_padding(&mut self, padding_specifier: u64) {
        for (padding_chunk, padding_specifier_byte) in self.remaining_blocks[0][..48]
            .chunks_exact_mut(8)
            .zip(padding_specifier.to_le_bytes().iter())
        {
            // An padding specifier is represented by an integer in the range [0, 2 ** 48).
            // The 48-byte dynamic padding string is mapped from the 48-bit specifier such that
            // each byte of padding is a [space/tab] if the corresponding little-endian bit of
            // the specifier is a [0/1], respectively.
            padding_chunk.copy_from_slice(&Self::PADDING_CHUNKS[*padding_specifier_byte as usize]);
        }
    }

    // The 256 unique strings of length 8 which contain only ' ' and '\t'.
    // These are computed statically in advance to allow them to be copied quickly.
    const PADDING_CHUNKS: [[u8; 8]; 256] = {
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

    #[inline(always)]
    fn current_hash(&self) -> [u32; 5] {
        let mut sha1_hash = self.intermediate_sha1_state;
        compress(&mut sha1_hash, &self.remaining_blocks[..]);
        sha1_hash
    }

    fn into_hash_match(self) -> HashMatch {
        HashMatch {
            commit: self
                .prehashed_commit_section
                .iter()
                .chain(self.remaining_blocks.iter().flat_map(|block| block.iter()))
                .take(self.total_commit_length)
                .copied()
                .collect(),
            hash: self
                .current_hash()
                .iter()
                .map(|&byte| format!("{:08x}", byte))
                .collect::<String>(),
        }
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
            let num_unset_bits = 32 - 4 * chunk.len();
            data[i] = value << num_unset_bits;
            mask[i] = u32::MAX >> num_unset_bits << num_unset_bits;
        }

        Some(HashPrefix { data, mask })
    }

    #[inline(always)]
    fn matches(&self, hash: &[u32; 5]) -> bool {
        hash.iter()
            .zip(&self.mask)
            .map(|(hash_word, &mask_word)| hash_word & mask_word)
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

// Maybe soon const generics will finally reach stable, and this function
// won't need to be implemented twice.
#[cfg(feature = "opencl")]
fn encode_big_endian_words_16(data: &[u8; 16]) -> [u32; 4] {
    data.chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .as_slice()
        .try_into()
        .unwrap()
}
#[cfg(feature = "opencl")]
fn encode_big_endian_words_64(
    data: &GenericArray<u8, <Sha1 as BlockInput>::BlockSize>,
) -> [u32; 16] {
    data.chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .as_slice()
        .try_into()
        .unwrap()
}

#[cfg(test)]
mod tests;
