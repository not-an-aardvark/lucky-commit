use sha1::{digest::FixedOutputDirty, Digest, Sha1};
use std::cmp::min;
use std::ops::Range;

const SHA1_BYTE_LENGTH: usize = 20;

// See the comment in `process_commit` for the commit and padding layout.
const DYNAMIC_PADDING_LENGTH: usize = 48;

/// Defines a target prefix for a commit hash.
#[derive(Debug, PartialEq, Clone)]
pub struct HashPrefix {
    // The full bytes of the prefix.
    data: Vec<u8>,

    // If the desired prefix has an odd number of characters when represented
    // as a hex string, the last character should be specified in `half_byte`.
    // Only the most significant four bits of `half_byte` are used.
    half_byte: Option<u8>,
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

    /// Caps a worker's search space to the given size
    pub fn with_capped_search_space(mut self, workload: u64) -> Self {
        self.search_space =
            self.search_space.start..min(self.search_space.end, self.search_space.start + workload);
        self
    }

    /// Invokes the worker. The worker will return early with a hash match if it finds one,
    /// otherwise it will search its entire search space and return `None`.
    #[inline(never)]
    pub fn search(self) -> Option<HashMatch> {
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

        // SHA1 works by splitting the input data into 64-byte blocks. Each 64-byte block
        // can be processed in sequence. Since we're adding whitespace near the end of a
        // commit object, the first few 64-byte blocks of the commit will always be the same.
        // Instead of reprocessing those blocks every time, we can just cache the SHA1 state
        // after processing those blocks, and only process the new padding each time.
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
            let dynamic_padding_data = &mut remaining_commit_data[0..DYNAMIC_PADDING_LENGTH];
            for (padding_chunk, padding_specifier_byte) in dynamic_padding_data
                .chunks_exact_mut(8)
                .zip(padding_specifier.to_le_bytes().iter())
            {
                padding_chunk.copy_from_slice(&PADDING_CHUNKS[*padding_specifier_byte as usize]);
            }

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
}

impl HashPrefix {
    /// Creates a new hash prefix from a hex string, which is at most 40 characters.
    /// Returns `None` if the supplied prefix was invalid.
    pub fn new(prefix: &str) -> Option<Self> {
        if prefix.len() > SHA1_BYTE_LENGTH * 2 {
            return None;
        }

        let mut data = Vec::new();
        for index in 0..(prefix.len() / 2) {
            match u8::from_str_radix(&prefix[2 * index..2 * index + 2], 16) {
                Ok(value) => data.push(value),
                Err(_) => return None,
            }
        }

        Some(HashPrefix {
            data,
            half_byte: if prefix.len() % 2 == 1 {
                match u8::from_str_radix(&prefix[prefix.len() - 1..], 16) {
                    Ok(value) => Some(value << 4),
                    Err(_) => return None,
                }
            } else {
                None
            },
        })
    }

    fn matches(&self, hash: &[u8; SHA1_BYTE_LENGTH]) -> bool {
        self.data == hash[..self.data.len()]
            && match self.half_byte {
                Some(half_byte) => (hash[self.data.len()] & 0xf0) == half_byte,
                None => true,
            }
    }
}

impl Default for HashPrefix {
    fn default() -> Self {
        HashPrefix::new("0000000").unwrap()
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
