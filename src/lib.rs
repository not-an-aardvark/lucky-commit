use ocl::{
    builders::DeviceSpecifier::TypeFlags,
    flags::{DeviceType, MemFlags},
    Platform, ProQue,
};
use sha1::{compress, digest::FixedOutputDirty, Digest, Sha1};
use std::{cmp::min, convert::TryInto, ops::Range};

const SHA1_BYTE_LENGTH: usize = 20;

// See the comment in `process_commit` for the commit and padding layout.
const DYNAMIC_PADDING_LENGTH: usize = 48;

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

/// A worker that, when invoked, will look in a predetermined search space on a single
/// thread, to find a modification to a specific commit that matches a specific hash prefix.
#[derive(Debug, PartialEq)]
pub struct HashSearchWorker {
    processed_commit: ProcessedCommit,
    desired_prefix: HashPrefix,
    search_space: Range<u64>,
}

/// The result of a successful hash search
#[derive(Debug, PartialEq)]
pub struct HashMatch {
    /// The git commit object that has the desired hash, in the format equivalent
    /// to the output of `git cat-file commit HEAD`.
    pub commit: Vec<u8>,

    /// The hash of the commit, when hashed in git's object encoding
    pub hash: [u8; SHA1_BYTE_LENGTH],
}

#[derive(Debug, PartialEq, Clone)]
struct ProcessedCommit {
    header: Vec<u8>,
    commit: Vec<u8>,
    dynamic_padding_start_index: usize,
}

impl HashSearchWorker {
    /// Creates a worker for a specific commit and prefix, with an initial
    /// workload of 1 ** 48 units. As a rough approximation depending on hardware,
    /// each worker can perform about 7 million units of work per second.
    pub fn new(current_commit: &[u8], desired_prefix: HashPrefix) -> Self {
        HashSearchWorker {
            processed_commit: process_commit(current_commit),
            desired_prefix,
            search_space: 0..(1 << (DYNAMIC_PADDING_LENGTH as u64)),
        }
    }

    /// Splits this worker into `divisor` new workers for the same commit and
    /// desired prefix, with the search space split roughly equally.
    /// A worker's search space is an approximation to help with effecient threading. There is
    /// no guarantee that the resulting workers have perfectly disjoint search spaces, so in theory
    /// multiple workers could both find the same hash match despite having "split" the space.
    pub fn split_search_space(self, divisor: u64) -> impl Iterator<Item = Self> {
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
            HashSearchWorker {
                processed_commit: self.processed_commit.clone(),
                desired_prefix: self.desired_prefix.clone(),
                search_space: range_start..range_end,
            }
        })
    }

    /// Caps a worker's search space to approximately the given size.
    pub fn with_capped_search_space(mut self, workload: u64) -> Self {
        self.search_space =
            self.search_space.start..min(self.search_space.end, self.search_space.start + workload);
        self
    }

    /// Invokes the worker. The worker will return early with a hash match if it finds one,
    /// otherwise it will search its entire search space and return `None`.
    pub fn search(self) -> Option<HashMatch> {
        if self.is_eligible_for_gpu_searching() {
            self.search_with_gpu().unwrap()
        } else {
            self.search_with_cpu()
        }
    }

    fn opencl_available() -> bool {
        Platform::first().is_ok()
    }

    /// Determines whether any GPUs are present and available to use for searching
    pub fn gpus_available() -> bool {
        Self::opencl_available()
            && !TypeFlags(DeviceType::GPU)
                .to_device_list(None::<Platform>)
                .unwrap()
                .is_empty()
    }

    /// Determines the worker will attempt to use a GPU for these search parameters
    pub fn is_eligible_for_gpu_searching(&self) -> bool {
        // If there aren't any GPUs available, using GPUs to search for hashes isn't going to work very well
        if !Self::gpus_available() {
            return false;
        }

        // Commits that are GPG-signed, or have an unusually large number of trailing newlines, are ineligible
        // for GPU searching at the moment because the padding is not in the final block.
        if self.processed_commit.commit.len() - self.processed_commit.dynamic_padding_start_index
            > 55
        {
            return false;
        }

        // In the rare case where the start of the dynamic padding is not block-aligned (see `process_commit`
        // for details), GPU searching won't work because it assumes that the dynamic padding is at the start
        // of a block. This case can probably be eliminated in the future by adding more padding.
        if (self.processed_commit.header.len() + self.processed_commit.dynamic_padding_start_index)
            % 64
            != 0
        {
            return false;
        }

        true
    }

    #[inline(never)]
    fn search_with_cpu(self) -> Option<HashMatch> {
        // SHA1 works by splitting the input data into 64-byte blocks. Each 64-byte block
        // can be processed in sequence. Since we're adding whitespace near the end of a
        // commit object, the first few 64-byte blocks of the commit will always be the same.
        // Instead of reprocessing those blocks every time, we can just cache the SHA1 state
        // after processing those blocks, and only process the new padding each time.
        let HashSearchWorker {
            search_space,
            desired_prefix,
            processed_commit:
                ProcessedCommit {
                    header,
                    mut commit,
                    dynamic_padding_start_index,
                },
        } = self;

        let cached_sha1_state = Sha1::new()
            .chain(&header)
            .chain(&commit[0..dynamic_padding_start_index]);

        let remaining_commit_data = &mut commit[dynamic_padding_start_index..];
        let mut hash_result = Default::default();

        for padding_specifier in search_space {
            // An padding specifier is represented by an integer in the range [0, 2 ** 48).
            // The 48-byte dynamic padding string is mapped from the 48-bit specifier such that
            // each byte of padding is a [space/tab] if the corresponding little-endian bit of
            // the specifier is a [0/1], respectively.
            scatter_padding(
                padding_specifier,
                &mut remaining_commit_data[0..DYNAMIC_PADDING_LENGTH],
            );

            let mut sha1_hash = cached_sha1_state.clone();
            sha1_hash.update(&remaining_commit_data);
            sha1_hash.finalize_into_dirty(&mut hash_result);

            if desired_prefix.matches(hash_result.as_ref()) {
                return Some(HashMatch {
                    commit,
                    hash: hash_result.into(),
                });
            }
        }

        None
    }

    fn search_with_gpu(self) -> ocl::Result<Option<HashMatch>> {
        let HashSearchWorker {
            search_space,
            desired_prefix,
            processed_commit,
        } = self;
        let block_ending = processed_commit.finalized_dynamic_padding_suffix();
        let sha1_state_vector = processed_commit.partially_hash();
        let ProcessedCommit {
            header,
            mut commit,
            dynamic_padding_start_index,
        } = processed_commit;

        const BASE_PADDING_SPECIFIER_ARG: &str = "base_padding_specifier";

        let num_threads = *[
            desired_prefix.estimated_hashes_needed() * 4,
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
            .len(sha1_state_vector.len())
            .flags(MemFlags::READ_ONLY)
            .copy_host_slice(&sha1_state_vector)
            .build()?;
        let block_ending_buffer = pro_que
            .buffer_builder::<u8>()
            .len(block_ending.len())
            .flags(MemFlags::READ_ONLY)
            .copy_host_slice(&block_ending)
            .build()?;
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
            .arg(&block_ending_buffer)
            .arg_named(BASE_PADDING_SPECIFIER_ARG, &0) // filled in later
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
                scatter_padding(
                    successful_padding_specifier,
                    &mut commit[dynamic_padding_start_index..dynamic_padding_start_index + 48],
                );
                let hash = Sha1::new().chain(&header).chain(&commit).finalize().into();

                assert!(
                    desired_prefix.matches(&hash),
                    "\
                        A GPU search reported a commit with a successful match, but when that \
                        commit was hashed in postprocessing, it didn't match the desired prefix. \
                        This is a bug. The most likely explanation is that the two implementations of \
                        `scatter_padding` in Rust and OpenCL (or the implementations of SHA1) have diverged \
                        from each other.\n\ndesired prefix:\n\t{:?}\ncommit object produced during \
                        postprocessing:\n\thash: {}\n\tpadding specifier: {}\n\tcommit: {:?}",
                    desired_prefix,
                    hash.iter().map(|byte| format!("{:02x}", *byte)).collect::<String>(),
                    successful_padding_specifier,
                    String::from_utf8(commit).unwrap_or_else(|_| "(invalid utf8)".to_owned())
                );

                return Ok(Some(HashMatch { hash, commit }));
            }
        }

        Ok(None)
    }
}

impl ProcessedCommit {
    fn partially_hash(&self) -> [u32; 5] {
        assert!((self.header.len() + self.dynamic_padding_start_index) % 64 == 0);

        let mut sha1_state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
        for chunk in self
            .header
            .iter()
            .chain(self.commit[0..self.dynamic_padding_start_index].iter())
            .copied()
            .collect::<Vec<u8>>()
            .chunks_exact(64)
        {
            compress(&mut sha1_state, &[Clone::clone(chunk.into())]);
        }

        sha1_state
    }

    fn finalized_dynamic_padding_suffix(&self) -> [u8; 16] {
        let commit_end_index_in_block =
            self.commit.len() - self.dynamic_padding_start_index - DYNAMIC_PADDING_LENGTH;
        assert!(commit_end_index_in_block <= 7);
        let mut finalized_dynamic_padding_suffix = [0; 16];
        finalized_dynamic_padding_suffix[0..commit_end_index_in_block].copy_from_slice(
            &self.commit[self.dynamic_padding_start_index + DYNAMIC_PADDING_LENGTH..],
        );
        finalized_dynamic_padding_suffix[commit_end_index_in_block] = 0x80;
        finalized_dynamic_padding_suffix[8..16]
            .copy_from_slice(&((self.header.len() + self.commit.len()) as u64 * 8).to_be_bytes());
        finalized_dynamic_padding_suffix
    }
}

impl HashPrefix {
    /// Creates a new hash prefix from a hex string, which is at most 40 characters.
    /// Returns `None` if the supplied prefix was invalid.
    pub fn new(prefix: &str) -> Option<Self> {
        if prefix.len() > SHA1_BYTE_LENGTH * 2 {
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
    fn matches(&self, hash: &[u8; SHA1_BYTE_LENGTH]) -> bool {
        hash.chunks(4)
            .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
            .zip(&self.mask)
            .map(|(hash_word, mask_word)| hash_word & *mask_word)
            .zip(&self.data)
            .all(|(masked_hash_word, desired_prefix_word)| masked_hash_word == *desired_prefix_word)
    }

    fn estimated_hashes_needed(&self) -> u64 {
        2u64.saturating_pow(self.mask.iter().map(|word| word.count_ones()).sum())
    }
}

impl Default for HashPrefix {
    fn default() -> Self {
        HashPrefix::new("0000000").unwrap()
    }
}

// This should be kept in sync with the OpenCL `scatter_padding` implementation.
#[inline(always)]
fn scatter_padding(padding_specifier: u64, padding_container: &mut [u8]) {
    debug_assert!(padding_container.len() == DYNAMIC_PADDING_LENGTH);
    for (padding_chunk, padding_specifier_byte) in padding_container
        .chunks_exact_mut(8)
        .zip(padding_specifier.to_le_bytes().iter())
    {
        padding_chunk.copy_from_slice(&PADDING_CHUNKS[*padding_specifier_byte as usize]);
    }
}

fn process_commit(original_commit: &[u8]) -> ProcessedCommit {
    // The fully padded data that gets hashed is the concatenation of all the following:
    // * "commit " + length + "\x00", where `length` is the base-10 representation of the length
    //    of everything that follows the null character. This is part of git's raw commit format.
    // * The original commit object, containing everything up to the point where padding should be
    //   added.
    // * Up to 63 space characters, as static padding. This is inserted so that the dynamic padding
    //   that follows it will be at a multiple-of-64-byte offset. Since the performance-intensive
    //   search involves hashing all of the 64-byte blocks starting with the dynamic padding, this
    //   ensures that the dynamic padding is always in a single block. Note that it sometimes won't
    //   be possible to align the dynamic padding perfectly, because adding static padding also
    //   increases the length of the commit object used in the initial header, and this could
    //   bump the alignment twice if e.g. the length increases from 999 to 1000. As a result, in
    //   rare cases the dynamic padding will actually be at a multiple-of-64-byte + 1 offset,
    //   which isn't the end of the world because everything that follows the static padding
    //   will usually fit in one block anyway.
    // * 48 bytes of dynamic padding, consisting of space and tab characters. The ultimate goal
    //   is to find some combination of spaces and tabs that produces the desired hash. A 48-byte
    //   length was chosen with the goal of having everything that follows the static padding
    //   fit into one block for non-GPG-signed commits. (This allows 8 bytes for SHA1's final
    //   length padding, as well as a couple bytes for the remainder of the commit object and
    //   any alignment issues, while still using a multiple of 8 bytes for easily copying padding.)
    // * The rest of the original commit object. For non-GPG-signed commits, this will just be
    //   a single newline. For GPG-signed commits, this will contain the commit message.

    const DYNAMIC_PADDING_ALIGNMENT: usize = 64;
    let commit_split_index = get_commit_split_index(original_commit);

    // If the commit message already has spaces or tabs where we're putting padding, the most
    // likely explanation is that the user has run lucky-commit on this commit before. To prevent
    // commits from repeatedly growing after lucky-commit is run on them, omit the old padding
    // rather than piling onto it.
    let replaceable_padding_size = original_commit[commit_split_index..]
        .iter()
        .take_while(|byte| **byte == b' ' || **byte == b'\t')
        .count();
    let approximate_length_before_static_padding =
        format!("commit {}\x00", original_commit.len()).len() + commit_split_index;

    // Use enough static padding to pad to a multiple of 64
    let static_padding_length = (DYNAMIC_PADDING_ALIGNMENT
        - (approximate_length_before_static_padding % DYNAMIC_PADDING_ALIGNMENT))
        % DYNAMIC_PADDING_ALIGNMENT;

    let commit_length = original_commit.len() - replaceable_padding_size
        + static_padding_length
        + DYNAMIC_PADDING_LENGTH;
    let header = format!("commit {}\x00", commit_length).into_bytes();

    let mut commit = Vec::with_capacity(commit_length);
    commit.extend(&original_commit[..commit_split_index]);

    // Add static padding
    commit.resize(commit.len() + static_padding_length, b' ');

    let dynamic_padding_start_index = commit.len();
    assert!((dynamic_padding_start_index + header.len()) % DYNAMIC_PADDING_ALIGNMENT <= 1);

    // Add dynamic padding, initialized to tabs for now
    commit.resize(commit.len() + DYNAMIC_PADDING_LENGTH, b'\t');

    commit.extend(&original_commit[commit_split_index + replaceable_padding_size..]);

    ProcessedCommit {
        header,
        commit,
        dynamic_padding_start_index,
    }
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
            .take_while(|byte| **byte == b' ' || **byte == b'\t' || **byte == b'\n')
            .count()
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
