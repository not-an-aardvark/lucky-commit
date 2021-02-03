use sha1::{digest::FixedOutputDirty, Digest, Sha1};
use std::ops;

const SHA1_BYTE_LENGTH: usize = 20;

// See the comment in `process_commit` for the commit and padding layout.
const DYNAMIC_PADDING_LENGTH: usize = 48;

/// Defines a target prefix for a commit hash.
#[derive(Debug, PartialEq, Clone)]
pub struct HashPrefix {
    // The full bytes of the prefix.
    pub data: Vec<u8>,

    // If the desired prefix has an odd number of characters when represented
    // as a hex string, the last character should be specified in `half_byte`.
    // Only the most significant four bits of `half_byte` are used.
    pub half_byte: Option<u8>,
}

pub struct SearchParams {
    pub current_commit: Vec<u8>,
    pub desired_prefix: HashPrefix,
    pub counter_range: ops::Range<u64>,
}

#[derive(Debug, PartialEq)]
pub struct HashMatch {
    pub commit: Vec<u8>,
    pub hash: [u8; SHA1_BYTE_LENGTH],
}

#[derive(Debug, PartialEq)]
struct ProcessedCommit {
    header: Vec<u8>,
    commit: Vec<u8>,
    dynamic_padding_start_index: usize,
}

// The 256 unique strings of length 8 which contain only ' ' and '\t'.
// These are computed statically in advance to allow them to be copied quickly.
static PADDINGS: [[u8; 8]; 256] = {
    let mut paddings = [[0; 8]; 256];
    let mut i = 0;
    while i < 256 {
        let mut j = 0;
        while j < 8 {
            paddings[i][j] = if i & (0x80 >> j) == 0 { b' ' } else { b'\t' };
            j += 1;
        }
        i += 1;
    }
    paddings
};

pub fn iterate_for_match(params: &SearchParams) -> Option<HashMatch> {
    let ProcessedCommit {
        header,
        mut commit,
        dynamic_padding_start_index,
    } = process_commit(&params.current_commit);

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

    for counter in params.counter_range.clone() {
        let dynamic_padding_data = &mut remaining_commit_data[0..DYNAMIC_PADDING_LENGTH];
        for (padding_chunk, counter_byte) in dynamic_padding_data
            .chunks_exact_mut(8)
            .zip(counter.to_le_bytes().iter())
        {
            padding_chunk.copy_from_slice(&PADDINGS[*counter_byte as usize]);
        }

        let mut sha1_hash = cached_sha1_state.clone();
        sha1_hash.update(&remaining_commit_data);
        sha1_hash.finalize_into_dirty(&mut hash_result);

        if matches_desired_prefix(hash_result.as_ref(), &params.desired_prefix) {
            return Some(HashMatch {
                commit,
                hash: hash_result.into(),
            });
        }
    }

    None
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

fn matches_desired_prefix(hash: &[u8; SHA1_BYTE_LENGTH], prefix: &HashPrefix) -> bool {
    prefix.data == hash[..prefix.data.len()]
        && match prefix.half_byte {
            Some(half_byte) => (hash[prefix.data.len()] & 0xf0) == half_byte,
            None => true,
        }
}

pub fn parse_prefix(prefix: &str) -> Option<HashPrefix> {
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

#[cfg(test)]
mod tests;
