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
    pub raw_object: Vec<u8>,
    pub hash: [u8; SHA1_BYTE_LENGTH],
}

#[derive(Debug, PartialEq)]
struct ProcessedCommit {
    raw_object: Vec<u8>,
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
    let desired_prefix = &params.desired_prefix;
    let mut processed_commit = process_commit(&params.current_commit);

    // SHA1 works by splitting the input data into 64-byte blocks. Each 64-byte block
    // can be processed in sequence. Since we're adding whitespace near the end of a
    // commit object, the first few 64-byte blocks of the commit will always be the same.
    // Instead of reprocessing those blocks every time, we can just cache the SHA1 state
    // after processing those blocks, and only process the new padding each time.
    let cached_sha1_state = Sha1::new()
        .chain(&processed_commit.raw_object[0..processed_commit.dynamic_padding_start_index]);

    let remaining_commit_data =
        &mut processed_commit.raw_object[processed_commit.dynamic_padding_start_index..];
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

        if matches_desired_prefix(hash_result.as_ref(), desired_prefix) {
            return Some(HashMatch {
                raw_object: processed_commit.raw_object,
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

    let mut raw_object: Vec<u8> = format!(
        "commit {}\x00",
        original_commit.len() - replaceable_padding_size
            + static_padding_length
            + DYNAMIC_PADDING_LENGTH
    )
    .into_bytes();

    raw_object.extend(&original_commit[..commit_split_index]);

    // Add static padding
    raw_object.resize(raw_object.len() + static_padding_length, b' ');

    let dynamic_padding_start_index = raw_object.len();
    assert!(dynamic_padding_start_index % DYNAMIC_PADDING_ALIGNMENT <= 2);

    // Add dynamic padding, initialized to tabs for now
    raw_object.resize(raw_object.len() + DYNAMIC_PADDING_LENGTH, b'\t');

    raw_object.extend(&original_commit[commit_split_index + replaceable_padding_size..]);

    ProcessedCommit {
        raw_object,
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
mod tests {
    use std::iter;

    use super::*;

    const TEST_COMMIT_WITHOUT_SIGNATURE: &[u8] = b"\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        author Foo B\xc3\xa1r <foo@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        \n\
        Do a thing\n\
        \n\
        Makes some changes to the foo feature\n";

    const TEST_COMMIT_WITH_SIGNATURE: &[u8] = b"\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        author Foo B\xc3\xa1r <foo@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        gpgsig -----BEGIN PGP SIGNATURE-----\n\
        \n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        =AAAA\n\
        -----END PGP SIGNATURE-----\n\
        \n\
        Do a thing\n\
        \n\
        Makes some changes to the foo feature\n";

    const TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS: &[u8] = b"\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        parent 2468246824682468246824682468246824682468\n\
        author Foo B\xc3\xa1r <foo@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        gpgsig -----BEGIN PGP SIGNATURE-----\n\
        \n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        =AAAA\n\
        -----END PGP SIGNATURE-----\n\
        \n\
        Do a thing\n\
        \n\
        Makes some changes to the foo feature\n";

    const TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE: &[u8] = b"\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        author Foo B\xc3\xa1r <foo@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        \n\
        For no particular reason, this commit message looks like a GPG signature.\n\
        gpgsig -----END PGP SIGNATURE-----\n\
        \n\
        So anyway, that's fun.\n";

    const TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL: &[u8] = b"\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        author Foo B\xc3\xa1r <-----END PGP SIGNATURE-----@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        \n\
        For no particular reason, the commit author's email has a GPG signature marker.\n";

    #[test]
    fn iterate_for_match_failure() {
        let search_params = SearchParams {
            current_commit: TEST_COMMIT_WITH_SIGNATURE.to_owned(),
            desired_prefix: HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x40),
            },
            counter_range: 1..100,
        };

        assert_eq!(None, iterate_for_match(&search_params))
    }

    #[test]
    fn search_for_match_success() {
        let search_params = SearchParams {
            current_commit: TEST_COMMIT_WITH_SIGNATURE.to_owned(),
            desired_prefix: HashPrefix {
                data: vec![73, 174],
                half_byte: Some(0x80),
            },
            counter_range: 1..100,
        };

        assert_eq!(
            Some(HashMatch {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        author Foo Bár <foo@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        gpgsig -----BEGIN PGP SIGNATURE-----\n\
                        \n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        =AAAA\n\
                        -----END PGP SIGNATURE-----{}{}\n\
                        \n\
                        Do a thing\n\
                        \n\
                        Makes some changes to the foo feature\n",
                    TEST_COMMIT_WITH_SIGNATURE.len() + 40 + 48,
                    iter::repeat(" ").take(40).collect::<String>(),
                    "    \t \t                                         "
                )
                .into_bytes(),
                hash: [
                    73, 174, 143, 115, 152, 190, 169, 211, 5, 49, 116, 178, 8, 186, 106, 125, 3,
                    169, 65, 184
                ]
            }),
            iterate_for_match(&search_params)
        )
    }

    #[test]
    fn process_commit_without_gpg_signature() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        author Foo Bár <foo@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        \n\
                        Do a thing\n\
                        \n\
                        Makes some changes to the foo feature\
                        {}{}\n",
                    TEST_COMMIT_WITHOUT_SIGNATURE.len() + 61 + 48,
                    iter::repeat(" ").take(61).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 320
            },
            process_commit(TEST_COMMIT_WITHOUT_SIGNATURE)
        )
    }

    #[test]
    fn process_commit_with_gpg_signature() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        author Foo Bár <foo@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        gpgsig -----BEGIN PGP SIGNATURE-----\n\
                        \n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        =AAAA\n\
                        -----END PGP SIGNATURE-----{}{}\n\
                        \n\
                        Do a thing\n\
                        \n\
                        Makes some changes to the foo feature\n",
                    TEST_COMMIT_WITH_SIGNATURE.len() + 40 + 48,
                    iter::repeat(" ").take(40).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 704
            },
            process_commit(TEST_COMMIT_WITH_SIGNATURE)
        );
    }

    #[test]
    fn process_commit_already_padded() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        author Foo Bár <foo@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        gpgsig {}-----BEGIN PGP SIGNATURE-----\n\
                        \n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        =AAAA\n\
                        -----END PGP SIGNATURE-----{}{}\n\
                        \n\
                        Do a thing\n\
                        \n\
                        Makes some changes to the foo feature\n",
                    TEST_COMMIT_WITH_SIGNATURE.len() + 32 + 8 + 48,
                    iter::repeat("\t").take(32).collect::<String>(),
                    iter::repeat(" ").take(8).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 704
            },
            process_commit(
                &format!(
                    "\
                    tree 0123456701234567012345670123456701234567\n\
                    parent 7654321076543210765432107654321076543210\n\
                    author Foo Bár <foo@example.com> 1513980859 -0500\n\
                    committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                    gpgsig {}-----BEGIN PGP SIGNATURE-----\n\
                    \n\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                    =AAAA\n\
                    -----END PGP SIGNATURE-----{}\n\
                    \n\
                    Do a thing\n\
                    \n\
                    Makes some changes to the foo feature\n",
                    iter::repeat("\t").take(32).collect::<String>(),
                    iter::repeat(" ").take(100).collect::<String>()
                )
                .into_bytes()
            )
        )
    }

    #[test]
    fn process_merge_commit_with_signature() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        parent 2468246824682468246824682468246824682468\n\
                        author Foo Bár <foo@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        gpgsig -----BEGIN PGP SIGNATURE-----\n\
                        \n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                        =AAAA\n\
                        -----END PGP SIGNATURE-----{}{}\n\
                        \n\
                        Do a thing\n\
                        \n\
                        Makes some changes to the foo feature\n",
                    TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS.len() + 56 + 48,
                    iter::repeat(" ").take(56).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 768
            },
            process_commit(TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS)
        );
    }

    #[test]
    fn process_commit_with_gpg_stuff_in_message() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        author Foo Bár <foo@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        \n\
                        For no particular reason, this commit message looks like a GPG signature.\n\
                        gpgsig -----END PGP SIGNATURE-----\n\
                        \n\
                        So anyway, that's fun.{}{}\n",
                    TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE.len() + 42 + 48,
                    iter::repeat(" ").take(42).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 384
            },
            process_commit(TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE)
        )
    }

    #[test]
    fn process_commit_with_gpg_stuff_in_email() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                        commit {}\x00\
                        tree 0123456701234567012345670123456701234567\n\
                        parent 7654321076543210765432107654321076543210\n\
                        author Foo Bár <-----END PGP SIGNATURE-----@example.com> 1513980859 -0500\n\
                        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                        \n\
                        For no particular reason, the commit author's email has a GPG signature marker.{}{}\n",
                    TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL.len() + 7 + 48,
                    iter::repeat(" ").take(7).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 320
            },
            process_commit(TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL)
        )
    }

    #[test]
    fn matches_desired_prefix_empty() {
        assert!(matches_desired_prefix(
            &[0; SHA1_BYTE_LENGTH],
            &HashPrefix {
                data: Vec::new(),
                half_byte: None
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_single_half() {
        assert!(matches_desired_prefix(
            &[0x1e; SHA1_BYTE_LENGTH],
            &HashPrefix {
                data: Vec::new(),
                half_byte: Some(0x10)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_single_half_mismatch() {
        assert!(!matches_desired_prefix(
            &[0x21; SHA1_BYTE_LENGTH],
            &HashPrefix {
                data: Vec::new(),
                half_byte: Some(0x10)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_data_without_half() {
        assert!(matches_desired_prefix(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 2, 3],
                half_byte: None
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_matching_data_and_half() {
        assert!(matches_desired_prefix(
            &[1, 2, 3, 0x4f, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x40)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_matching_data_mismatching_half() {
        assert!(!matches_desired_prefix(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x50)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_mismatching_data_matching_half() {
        assert!(!matches_desired_prefix(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 5, 3],
                half_byte: Some(0x40)
            }
        ))
    }

    #[test]
    fn parse_prefix_empty() {
        assert_eq!(
            Some(HashPrefix {
                data: Vec::new(),
                half_byte: None
            }),
            parse_prefix("")
        )
    }

    #[test]
    fn parse_prefix_single_char() {
        assert_eq!(
            Some(HashPrefix {
                data: Vec::new(),
                half_byte: Some(0xa0)
            }),
            parse_prefix("a")
        )
    }

    #[test]
    fn parse_prefix_even_chars() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![0xab, 0xcd, 0xef],
                half_byte: None
            }),
            parse_prefix("abcdef")
        )
    }

    #[test]
    fn parse_prefix_odd_chars() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![0xab, 0xcd, 0xef],
                half_byte: Some(0x50)
            }),
            parse_prefix("abcdef5")
        )
    }

    #[test]
    fn parse_prefix_capital_letters() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![0xab, 0xcd, 0xef],
                half_byte: Some(0xb0)
            }),
            parse_prefix("ABCDEFB")
        )
    }

    #[test]
    fn parse_prefix_invalid_even_chars() {
        assert_eq!(None, parse_prefix("abcdgeb"))
    }

    #[test]
    fn parse_prefix_invalid_odd_char() {
        assert_eq!(None, parse_prefix("abcdefg"))
    }

    #[test]
    fn parse_prefix_exact_length_match() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![
                    0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12,
                    0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78
                ],
                half_byte: None
            }),
            parse_prefix("1234567812345678123456781234567812345678")
        )
    }

    #[test]
    fn parse_prefix_too_long_with_half_byte() {
        assert_eq!(
            None,
            parse_prefix("12345678123456781234567812345678123456781")
        )
    }

    #[test]
    fn parse_prefix_too_many_full_bytes() {
        assert_eq!(
            None,
            parse_prefix("123456781234567812345678123456781234567812")
        )
    }
}
