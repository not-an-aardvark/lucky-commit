//! The underlying API of lucky_commit is also exposed as a Rust library, in case anyone
//! wants to use it programmatically. However, note that the library API is considered
//! unstable, and might have backwards-incompatible changes even in minor or patch
//! releases of the crate. If you use the library interface, pinning to an exact version
//! is recommended.

#![deny(missing_docs)]

use std::{
    cmp::Ord,
    error::Error,
    fmt::{Debug, Display, Formatter},
    iter, mem,
    ops::Range,
    str::FromStr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread::{self, JoinHandle},
};

#[cfg(feature = "opencl")]
use ocl::{
    builders::DeviceSpecifier::TypeFlags,
    flags::{DeviceType, MemFlags},
    prm::Uint16,
    Buffer, Context, Kernel, Platform, Program, Queue,
};
#[cfg(feature = "opencl")]
use std::convert::TryInto;

/// A worker that, when invoked, will look in a predetermined search space to find a modification
/// to a specific commit that matches a specific hash spec.
#[derive(Debug, PartialEq)]
pub struct HashSearchWorker<H: GitHashFn> {
    processed_commit: ProcessedCommit,
    hash_spec: HashSpec<H>,
    search_space: Range<u64>,
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
// |   This is the only part of the commit data that actually varies across hash invocations. The ultimate
// |   goal is to find a dynamic padding arrangement that produces the desired hash. A 48-byte length was
// |   chosen with the goal of only needing a single dynamic block for non-GPG-signed commits.
// | * The rest of the original commit object (from the "padding insertion point" onwards). For
// |   non-GPG-signed commits, this will typically just be a single newline. For GPG-signed commits, this
// |   will contain the commit message.
// |--- SHA1/SHA256 FINALIZATION PADDING (specified as part of the SHA1/SHA256 algorithm) ---
// | * The byte 0x80
// | * Up to 63 null bytes (0x0), such that the point after the null bytes is at an offset of 56 (mod 64) bytes
// |   from the start of the data
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

/// A view of an underlying `ProcessedCommit`, with cached hash state.
///
/// SHA1 and SHA256 work as follows:
///
/// * First, a 20-byte or 32-byte "state vector" is initialized to a constant.
/// * Next, each each 64-byte block in the input is processed in sequence. The state vector after
/// processing a block is a convoluted, deteriministic function of (a) the state vector before
/// processing the block, and (b) the contents of the block. Processing blocks is the main performance
/// bottleneck of lucky-commit.
/// * The "hash" of some data is just the contents of the state vector after processing all of
/// the data (with finalization padding added to the end of the data, as described in the comment
/// about the `ProcessedCommit` format).
///
/// So there's a big optimization we can do here -- we have to compute a bunch of hashes, but the
/// only part of the data that we're changing between runs is the dynamic padding, which is very close
/// to the end of the data. The state vector after processing all of the blocks before the dynamic
/// padding (the "static blocks") doesn't depend at all on the contents of the dynamic padding -- it's
/// effectively a constant for any given `ProcessedCommit`. The purpose of `PartiallyHashedCommit` is
/// to cache that state vector, and only reprocess the "dynamic blocks" on each change to the dynamic
/// padding. This drastically reduces the number of blocks that need to be processed, resulting in a
/// ~5x end-to-end performance improvement for an average-sized commit.
#[derive(Debug)]
struct PartiallyHashedCommit<'a, H: GitHashFn> {
    intermediate_state: H::State,
    dynamic_blocks: &'a mut [H::Block],
}

/// Defines a spec for a desired commit hash.
#[derive(Debug, PartialEq, Clone)]
pub struct HashSpec<H: GitHashFn> {
    /// The data in the desired hash, as split into big-endian four-byte chunks.
    /// All bits that are unspecified (e.g. bits corresponding to the end of the hash, when only a prefix is being matched)
    /// are set to zero.
    data: H::State,
    /// Mask containing bits set to 1 if the bit at that position is specified, and 0 otherwise.
    mask: H::State,
    // For example, the sha1 hash prefix "deadbeef123" corresponds to the
    // following spec:
    //   HashSpec { data: [0xdeadbeef, 0x12300000, 0, 0, 0], mask: [0xffffffff, 0xfff00000, 0, 0, 0] }
}

/// An error that results from parsing an invalid HashSpec
#[non_exhaustive]
#[derive(PartialEq, Eq)]
pub enum ParseHashSpecErr {
    /// The input string is longer than a hash with the specified algorithm
    TooLong,
    /// The input string contains characters which are neither hex characters nor '_'.
    InvalidCharacter(char),
}

/// A git commit
#[derive(PartialEq, Eq)]
pub struct GitCommit<H: GitHashFn> {
    /// The commit data, represented in git's object format
    object: Vec<u8>,

    /// The hash of the commit
    hash: H::State,
}

/// A hash function used by git. This is a sealed trait implemented by `Sha1` and `Sha256`.
/// The fields and methods on this trait are subject to change. Consumers should pretend that
/// the types implementing the trait are opaque.
pub trait GitHashFn: private::Sealed + Debug + Send + Clone + Eq + 'static {
    /// The type of the output and intermediate state of this hash function.
    /// For sha1 and sha256, this is [u32; N] for some N. Ideally this trait would just
    /// have an associated const for the length of the state vector, and then
    /// `State` would be defined as `[u32; N]`, but this isn't possible due
    /// to <https://github.com/rust-lang/rust/issues/60551>.
    type State: AsRef<[u32]> + AsMut<[u32]> + Clone + Copy + Debug + Default + Eq + Send;

    /// The initial value of the state vector for the given algorithm
    const INITIAL_STATE: Self::State;

    /// The datatype representing a block for this algorithm. This must be layout-equivalent
    /// to [u8; 64], although the nominal type that gets used might be different on a
    /// per-library basis due to const generic limitations.
    type Block: AsRef<[u8]> + AsMut<[u8]> + Copy + Debug;

    /// Processes a set of blocks using the given algorithm
    fn compress(state: &mut Self::State, blocks: &[Self::Block]);

    #[cfg(feature = "opencl")]
    /// Source code of an OpenCL shader kernel finding hash matches for the given
    /// algorithm. The kernel should have a function `scatter_padding_and_find_match`, which
    /// accepts the following parameters:
    /// 1. A pointer to the `data` in the desired hash spec (pointing to the appropriate
    ///    number of bytes for the given hash algorithm)
    /// 1. A pointer to the `mask` of the desired hash spec
    /// 1. The "base padding specifier" for the current run, which determines which padding will
    ///    be attempted. The padding specifier used by any given thread is equal to the base
    ///    specifier plus that thread's ID.
    /// 1. A pointer to the intermediate state after all static blocks have been hashed
    /// 1. A pointer to the dynamic blocks, encoded as big-endian 32-bit integers
    /// 1. The number of dynamic blocks that are present
    /// 1. A writeable pointer where the shader should write a thread ID if it finds an appropriate
    ///    match.
    const KERNEL: &'static str;
}

/// The hash type used for Sha1 git repositories (the default at the time of writing)
/// This type is uninhabited, and is only intended to be used as a type parameter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Sha1 {}
impl GitHashFn for Sha1 {
    type State = [u32; 5];

    const INITIAL_STATE: Self::State = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    type Block = sha1::digest::core_api::Block<sha1::Sha1Core>;

    fn compress(state: &mut Self::State, blocks: &[Self::Block]) {
        sha1::compress(state, blocks)
    }

    #[cfg(feature = "opencl")]
    const KERNEL: &'static str = include_str!("sha1_matcher.cl");
}

/// The hash type used for Sha256 git repositories.
/// This type is uninhabited, and is only intended to be used as a type parameter.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Sha256 {}
impl GitHashFn for Sha256 {
    type State = [u32; 8];

    const INITIAL_STATE: Self::State = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    type Block = sha2::digest::core_api::Block<sha2::Sha256>;

    fn compress(state: &mut Self::State, blocks: &[Self::Block]) {
        sha2::compress256(state, blocks)
    }

    #[cfg(feature = "opencl")]
    const KERNEL: &'static str = include_str!("sha256_matcher.cl");
}

mod private {
    pub trait Sealed {}
    impl Sealed for super::Sha1 {}
    impl Sealed for super::Sha256 {}
}

impl<H: GitHashFn> HashSearchWorker<H> {
    /// Creates a worker for a specific commit and hash spec, with an initial
    /// search space of 2**48.
    pub fn new(current_commit: &[u8], hash_spec: HashSpec<H>) -> Self {
        Self {
            processed_commit: ProcessedCommit::new(current_commit),
            hash_spec,
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
    /// desired hash, with the search space split roughly equally.
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
                hash_spec: self.hash_spec.clone(),
                search_space: range_start..range_end,
            }
        })
    }

    /// Invokes the worker. The worker will return a git commit matching the hash,
    /// if it finds one. Otherwise, it will return None after exhausing its entire search space.
    pub fn search(self) -> Option<GitCommit<H>> {
        #[cfg(feature = "opencl")]
        if Self::gpus_available() {
            return self.search_with_gpu().unwrap();
        }

        self.search_with_cpus()
    }

    #[cfg(feature = "opencl")]
    fn gpus_available() -> bool {
        Platform::list().iter().any(|platform| {
            platform.name().map_or_else(
                |_| {
                    eprintln!("Platform {:?} is not okay.", platform);
                    false
                },
                |_| {
                    TypeFlags(DeviceType::GPU)
                        .to_device_list(Some(*platform))
                        .map_or_else(
                            |e| {
                                eprintln!(
                                    "Failed to get GPU devices for platform {:?}: {}",
                                    platform, e
                                );
                                false
                            },
                            |devices| !devices.is_empty(),
                        )
                },
            )
        })
    }

    #[allow(clippy::needless_collect)]
    fn search_with_cpus(self) -> Option<GitCommit<H>> {
        let thread_count = num_cpus::get_physical();
        let lame_duck_cancel_signal = Arc::new(AtomicBool::new(false));
        let (shared_sender, receiver) = mpsc::channel();

        let _handles = self
            .split_search_space(thread_count as u64)
            .map(|worker| {
                let result_sender = shared_sender.clone();
                let worker_cancel_signal = Arc::clone(&lame_duck_cancel_signal);

                thread::spawn(move || {
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
    ) -> Option<GitCommit<H>> {
        let HashSearchWorker {
            search_space,
            hash_spec,
            mut processed_commit,
            ..
        } = self;
        let mut partially_hashed_commit = processed_commit.as_partially_hashed_commit::<H>();

        let lame_duck_check_interval = Ord::min(search_space.end - search_space.start, 1 << 20);
        for base_padding_specifier in search_space.step_by(lame_duck_check_interval as usize) {
            for index_in_interval in 0..lame_duck_check_interval {
                partially_hashed_commit.scatter_padding(base_padding_specifier + index_in_interval);
                if hash_spec.matches(&partially_hashed_commit.current_hash()) {
                    return Some(GitCommit::new(processed_commit.commit()));
                }
            }

            if lame_duck_cancel_signal.load(Ordering::Relaxed) {
                break;
            }
        }

        None
    }

    #[cfg(feature = "opencl")]
    fn search_with_gpu(self) -> ocl::Result<Option<GitCommit<H>>> {
        let HashSearchWorker {
            search_space,
            hash_spec,
            mut processed_commit,
            ..
        } = self;
        let mut partially_hashed_commit = processed_commit.as_partially_hashed_commit::<H>();

        let num_threads = *[
            hash_spec.estimated_attempts_needed().saturating_mul(4),
            search_space.end - search_space.start,
            1 << 22,
        ]
        .iter()
        .min()
        .unwrap() as usize;

        assert!(num_threads < u32::MAX as usize);

        let devices = Platform::list()
            .iter()
            .find_map(|platform| {
                platform.name().ok().and_then(|_| {
                    TypeFlags(DeviceType::GPU)
                        .to_device_list(Some(*platform))
                        .ok()
                        .and_then(|devices| devices.get(0).cloned())
                })
            })
            .ok_or_else(|| ocl::Error::from("No GPU devices found."))?;
        let context = Context::builder().devices(devices).build()?;
        let queue = Queue::new(&context, devices, None)?;

        let mut successful_match_receiver_host_handle = [u32::MAX];
        let successful_match_receiver = Buffer::builder()
            .queue(queue.clone())
            .len(1)
            .flags(MemFlags::READ_WRITE)
            .copy_host_slice(&successful_match_receiver_host_handle)
            .build()?;

        const BASE_PADDING_SPECIFIER_ARG: &str = "base_padding_specifier";
        let kernel = Kernel::builder()
            .name("scatter_padding_and_find_match")
            .program(
                &Program::builder()
                    .src(H::KERNEL)
                    .cmplr_opt("-Werror")
                    .build(&context)?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(hash_spec.data.as_ref().len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(hash_spec.data.as_ref())
                    .build()?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(hash_spec.mask.as_ref().len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(hash_spec.mask.as_ref())
                    .build()?,
            )
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(partially_hashed_commit.intermediate_state.as_ref().len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(partially_hashed_commit.intermediate_state.as_ref())
                    .build()?,
            )
            .arg_named(BASE_PADDING_SPECIFIER_ARG, 0u64) // filled in later
            .arg(
                &Buffer::builder()
                    .queue(queue.clone())
                    .len(partially_hashed_commit.dynamic_blocks.len())
                    .flags(MemFlags::READ_ONLY)
                    .copy_host_slice(
                        &partially_hashed_commit
                            .dynamic_blocks
                            .iter()
                            .map(|&block| encode_into_opencl_vector::<H>(block))
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
            kernel.set_arg(BASE_PADDING_SPECIFIER_ARG, base_padding_specifier)?;

            // SAFETY: The OpenCL scripts are optimistically assumed to have no memory safety issues
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
                    hash_spec.matches(&partially_hashed_commit.current_hash()),
                    "\
                        A GPU search reported a commit with a successful match, but when that \
                        commit was hashed in postprocessing, it didn't match the desired spec. \
                        This is a bug. The most likely explanation is that the two implementations of \
                        `scatter_padding` in Rust and OpenCL (or the implementations of SHA1/SHA256) have diverged \
                        from each other.\n\npartial commit:\n\t{:?}\ndesired hash spec:\n\t{:?}\ncommit hash \
                        produced during postprocessing:{:?}\n\tpadding specifier: {}",
                    partially_hashed_commit,
                    hash_spec,
                    partially_hashed_commit.current_hash(),
                    successful_padding_specifier,
                );

                return Ok(Some(GitCommit::new(processed_commit.commit())));
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

        // SHA finalization padding
        data.extend(sha_finalization_padding(data.len()));
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
        // Check if the commit has a signature header before the start of the commit message
        let insertion_point_plus_preexisting_padding = (0..commit.len())
            .take_while(|&i| !commit[i..].starts_with(b"\n\n"))
            .find(|&i| {
                commit[i..].starts_with(b"\ngpgsig ")
                    || commit[i..].starts_with(b"\ngpgsig-sha256 ")
            })
            .map(|i| i + 1)
            // If so, put the padding right at the end of that header
            .and_then(|signature_header_start_index| {
                (signature_header_start_index..commit.len())
                    .find(|&i| commit[i..].starts_with(b"\n") && !commit[i..].starts_with(b"\n "))
            })
            .unwrap_or(commit.len());

        return insertion_point_plus_preexisting_padding
            - commit[..insertion_point_plus_preexisting_padding]
                .iter()
                .rev()
                .take_while(|&&byte| byte == b' ' || byte == b'\t' || byte == b'\n')
                .count();
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

    fn as_partially_hashed_commit<H: GitHashFn>(&mut self) -> PartiallyHashedCommit<H> {
        let (static_blocks, dynamic_blocks) =
            as_chunks_mut::<H>(&mut self.data[..]).split_at_mut(self.num_static_blocks);

        let mut intermediate_state = H::INITIAL_STATE;
        H::compress(&mut intermediate_state, static_blocks);

        PartiallyHashedCommit {
            intermediate_state,
            dynamic_blocks,
        }
    }
}

impl<'a, H: GitHashFn> PartiallyHashedCommit<'a, H> {
    #[inline(always)]
    fn dynamic_padding_mut(&mut self) -> &mut [u8] {
        &mut self.dynamic_blocks[0].as_mut()[..48]
    }

    // This should be kept in sync with the OpenCL `arrange_padding_block` implementation.
    #[inline(always)]
    fn scatter_padding(&mut self, padding_specifier: u64) {
        // The 256 unique strings of length 8 which contain only ' ' and '\t'.
        // These are computed at compile-time to allow them to be copied quickly.
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

        self.dynamic_padding_mut()
            .chunks_exact_mut(8)
            .zip(padding_specifier.to_le_bytes().iter())
            .for_each(|(padding_chunk, &padding_specifier_byte)| {
                // An padding specifier is represented by an integer in the range [0, 2 ** 48).
                // The 48-byte dynamic padding string is mapped from the 48-bit specifier such that
                // each byte of padding is a [space/tab] if the corresponding little-endian bit of
                // the specifier is a [0/1], respectively.
                padding_chunk.copy_from_slice(&PADDING_CHUNKS[padding_specifier_byte as usize]);
            })
    }

    #[inline(always)]
    fn current_hash(&self) -> H::State {
        let mut hash = self.intermediate_state;
        H::compress(&mut hash, self.dynamic_blocks);
        hash
    }
}

impl<H: GitHashFn> HashSpec<H> {
    #[inline(always)]
    fn matches(&self, hash: &H::State) -> bool {
        hash.as_ref()
            .iter()
            .zip(self.mask.as_ref().iter())
            .map(|(&hash_word, &mask_word)| hash_word & mask_word)
            .zip(self.data.as_ref().iter())
            .all(|(masked_hash_word, &hash_spec_word)| masked_hash_word == hash_spec_word)
    }

    #[cfg(feature = "opencl")]
    fn estimated_attempts_needed(&self) -> u64 {
        2u64.saturating_pow(
            self.mask
                .as_ref()
                .iter()
                .map(|word| word.count_ones())
                .sum(),
        )
    }
}

impl<H: GitHashFn> FromStr for HashSpec<H> {
    type Err = ParseHashSpecErr;
    /// Parses a HashSpec from a string. The string must only contain hex characters (0-9, a-f, A-F), indicating the hex
    /// value that the hash should have at a given position, or `_`, indicating that the hash can have any value at the given
    /// position. All positions in the hash beyond the length of the string are treated as unspecified (equivalent to if the
    /// string was right-padded with `_`).
    fn from_str(prefix_string: &str) -> Result<Self, Self::Err> {
        let max_hex_character_length = mem::size_of::<H::State>() * 2;
        if prefix_string.chars().count() > max_hex_character_length {
            return Err(ParseHashSpecErr::TooLong);
        }

        let mut parsed_hash_spec = HashSpec::<H> {
            // Zero-initialize the data and mask
            data: H::State::default(),
            mask: H::State::default(),
        };
        prefix_string
            .chars()
            // Pad the input string out to the length of a hash
            .chain(iter::repeat('_'))
            .take(max_hex_character_length)
            // Split it into 8-hex-character chunks
            .collect::<Vec<_>>()
            .chunks(8)
            // Associate each 8-hex-character chunk with corresponding 32-bit word of the hash spec
            .zip(parsed_hash_spec.data.as_mut())
            .zip(parsed_hash_spec.mask.as_mut())
            .try_for_each(|((hash_spec_chunk, data_word), mask_word)| {
                hash_spec_chunk
                    .iter()
                    .zip((0..32).step_by(4).rev())
                    .try_for_each(|(&hash_spec_character, slot_bit_offset)| {
                        // Parse each hex character of the input string and write it to the appropriate slots of the hash spec.
                        if let Some(hex_character_value) = hash_spec_character.to_digit(16) {
                            *data_word |= hex_character_value << slot_bit_offset;
                            *mask_word |= 0xf << slot_bit_offset;
                        } else if hash_spec_character != '_' {
                            // The '_' character in a hash spec is allowed as an "any value is allowed here" placeholder
                            // (corresponds to a 0 in both the data slot and the mask slot). All other non-hex characters are
                            // disallowed.
                            return Err(ParseHashSpecErr::InvalidCharacter(hash_spec_character));
                        }
                        Ok(())
                    })
            })?;

        Ok(parsed_hash_spec)
    }
}

impl<H: GitHashFn> Default for HashSpec<H> {
    fn default() -> Self {
        "0000000".parse().unwrap()
    }
}

impl Error for ParseHashSpecErr {}
impl Display for ParseHashSpecErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::TooLong => write!(f, "hash spec can't be longer than an actual hash"),
            Self::InvalidCharacter(c) => write!(f, "hash spec contains invalid character '{}' (only hex characters and underscores are allowed)", c),
        }
    }
}
impl Debug for ParseHashSpecErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <Self as Display>::fmt(self, f)
    }
}

impl<H: GitHashFn> GitCommit<H> {
    /// Constructs a GitCommit from the given commit data. The data is assumed to be in
    /// git's object format, but this is not technically required.
    pub fn new(commit: &[u8]) -> Self {
        Self {
            object: commit.to_vec(),
            hash: {
                let mut state = H::INITIAL_STATE;
                let commit_header = format!("commit {}\0", commit.len()).into_bytes();
                let commit_data_length = commit_header.len() + commit.len();

                H::compress(
                    &mut state,
                    as_chunks_mut::<H>(
                        commit_header
                            .into_iter()
                            .chain(commit.iter().cloned())
                            .chain(sha_finalization_padding(commit_data_length))
                            .collect::<Vec<_>>()
                            .as_mut(),
                    ),
                );
                state
            },
        }
    }

    /// The git object data for this commit
    pub fn object(&self) -> &[u8] {
        &self.object
    }

    /// The hash of this commit, as a hex string
    pub fn hex_hash(&self) -> String {
        self.hash
            .as_ref()
            .iter()
            .map(|word| format!("{:08x}", word))
            .collect()
    }
}

impl<H: GitHashFn> Debug for GitCommit<H> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GitCommit {{ object: {:?}, hash: {:?} }}",
            String::from_utf8_lossy(&self.object),
            self.hex_hash()
        )
    }
}

#[cfg(feature = "opencl")]
/// Reinterpret a block with 64 8-bit integers as an OpenCL vector with 16 32-bit big-endian integers
fn encode_into_opencl_vector<H: GitHashFn>(data: H::Block) -> Uint16 {
    let words: [u32; 16] = data
        .as_ref()
        .chunks(4)
        .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    words.into()
}

// This is a modified implementation of std::slice::as_chunks_mut. It's copied because the
// standard library function is not yet stable. As a local safety invariant, `Block` is expected
// to be layout-identical to `[u8; 64]`. (It's a generic parameter because the `GenericArray` subdependency
// could technically end up being at different versions between the sha1 and sha2 crates, which would cause
// compile errors if the sha1 version of `GenericArray` gets passed to sha2 methods.
fn as_chunks_mut<H: GitHashFn>(slice: &mut [u8]) -> &mut [H::Block] {
    assert_eq!(mem::size_of::<H::Block>(), 64);
    assert_eq!(mem::align_of::<H::Block>(), mem::align_of::<u8>());
    assert_eq!(slice.len() % mem::size_of::<H::Block>(), 0);
    // SAFETY:
    // * All of the bytes in the slice are initialized, and the alignment of u8 and [u8; 64]
    //   are the same.
    // * The slice length is a multiple of 64, and so the slice's pointer points to
    //   the same number of elements as the resulting pointer.
    // * Since `slice` is mutable, its values aren't accessible anywhere else during its lifetime.
    // * Since the length of the new slice is smaller, it can't overflow beyond isize::MAX.
    unsafe {
        std::slice::from_raw_parts_mut(
            slice.as_mut_ptr().cast(),
            slice.len() / mem::size_of::<H::Block>(),
        )
    }
}

// Finalization padding that gets added to the end of data being hashed with sha1 or sha256
// (the padding happens to be the same for both)
fn sha_finalization_padding(data_length: usize) -> impl IntoIterator<Item = u8> {
    iter::once(0x80)
        .chain(iter::repeat(0).take((55 - data_length as isize).rem_euclid(64) as usize))
        .chain(<[u8; 8]>::into_iter((data_length as u64 * 8).to_be_bytes()))
}

#[cfg(test)]
mod tests;
