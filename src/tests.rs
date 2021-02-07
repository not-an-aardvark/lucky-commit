use std::iter::repeat;

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
fn search_failure() {
    assert_eq!(
        None,
        HashSearchWorker::new(
            TEST_COMMIT_WITH_SIGNATURE,
            HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x40),
            }
        )
        .with_capped_search_space(100)
        .search()
    );
}

#[test]
fn search_success() {
    assert_eq!(
        Some(HashMatch {
            commit: format!(
                "\
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
                repeat(" ").take(40).collect::<String>(),
                "    \t \t                                         "
            )
            .into_bytes(),
            hash: [
                73, 174, 143, 115, 152, 190, 169, 211, 5, 49, 116, 178, 8, 186, 106, 125, 3, 169,
                65, 184
            ]
        }),
        HashSearchWorker::new(
            TEST_COMMIT_WITH_SIGNATURE,
            HashPrefix {
                data: vec![73, 174],
                half_byte: Some(0x80),
            },
        )
        .with_capped_search_space(100)
        .search()
    );
}

#[test]
fn split_search_space_uneven() {
    assert_eq!(
        vec![
            HashSearchWorker {
                processed_commit: process_commit(TEST_COMMIT_WITH_SIGNATURE),
                desired_prefix: Default::default(),
                search_space: 0..33,
            },
            HashSearchWorker {
                processed_commit: process_commit(TEST_COMMIT_WITH_SIGNATURE),
                desired_prefix: Default::default(),
                search_space: 33..66,
            },
            HashSearchWorker {
                processed_commit: process_commit(TEST_COMMIT_WITH_SIGNATURE),
                desired_prefix: Default::default(),
                search_space: 66..100,
            }
        ],
        HashSearchWorker {
            processed_commit: process_commit(TEST_COMMIT_WITH_SIGNATURE),
            desired_prefix: Default::default(),
            search_space: 0..100,
        }
        .split_search_space(3)
        .collect::<Vec<_>>()
    )
}

#[test]
fn process_commit_without_gpg_signature() {
    assert_eq!(
        ProcessedCommit {
            header: format!(
                "commit {}\x00",
                TEST_COMMIT_WITHOUT_SIGNATURE.len() + 61 + 48
            )
            .into_bytes(),
            commit: format!(
                "\
                    tree 0123456701234567012345670123456701234567\n\
                    parent 7654321076543210765432107654321076543210\n\
                    author Foo Bár <foo@example.com> 1513980859 -0500\n\
                    committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                    \n\
                    Do a thing\n\
                    \n\
                    Makes some changes to the foo feature\
                    {}{}\n",
                repeat(" ").take(61).collect::<String>(),
                repeat("\t").take(48).collect::<String>()
            )
            .into_bytes(),
            dynamic_padding_start_index: 309
        },
        process_commit(TEST_COMMIT_WITHOUT_SIGNATURE)
    )
}

#[test]
fn process_commit_with_gpg_signature() {
    assert_eq!(
        ProcessedCommit {
            header: format!("commit {}\x00", TEST_COMMIT_WITH_SIGNATURE.len() + 40 + 48)
                .into_bytes(),
            commit: format!(
                "\
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
                repeat(" ").take(40).collect::<String>(),
                repeat("\t").take(48).collect::<String>()
            )
            .into_bytes(),
            dynamic_padding_start_index: 693
        },
        process_commit(TEST_COMMIT_WITH_SIGNATURE)
    );
}

#[test]
fn process_commit_already_padded() {
    assert_eq!(
        ProcessedCommit {
            header: format!(
                "commit {}\x00",
                TEST_COMMIT_WITH_SIGNATURE.len() + 32 + 8 + 48
            )
            .into_bytes(),
            commit: format!(
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
                    -----END PGP SIGNATURE-----{}{}\n\
                    \n\
                    Do a thing\n\
                    \n\
                    Makes some changes to the foo feature\n",
                repeat("\t").take(32).collect::<String>(),
                repeat(" ").take(8).collect::<String>(),
                repeat("\t").take(48).collect::<String>()
            )
            .into_bytes(),
            dynamic_padding_start_index: 693
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
                repeat("\t").take(32).collect::<String>(),
                repeat(" ").take(100).collect::<String>()
            )
            .into_bytes()
        )
    )
}

#[test]
fn process_merge_commit_with_signature() {
    assert_eq!(
        ProcessedCommit {
            header: format!(
                "commit {}\x00",
                TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS.len() + 56 + 48
            )
            .into_bytes(),
            commit: format!(
                "\
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
                repeat(" ").take(56).collect::<String>(),
                repeat("\t").take(48).collect::<String>()
            )
            .into_bytes(),
            dynamic_padding_start_index: 757
        },
        process_commit(TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS)
    );
}

#[test]
fn process_commit_with_gpg_stuff_in_message() {
    assert_eq!(
        ProcessedCommit {
            header: format!(
                "commit {}\x00",
                TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE.len() + 42 + 48
            )
            .into_bytes(),
            commit: format!(
                "\
                    tree 0123456701234567012345670123456701234567\n\
                    parent 7654321076543210765432107654321076543210\n\
                    author Foo Bár <foo@example.com> 1513980859 -0500\n\
                    committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                    \n\
                    For no particular reason, this commit message looks like a GPG signature.\n\
                    gpgsig -----END PGP SIGNATURE-----\n\
                    \n\
                    So anyway, that's fun.{}{}\n",
                repeat(" ").take(42).collect::<String>(),
                repeat("\t").take(48).collect::<String>()
            )
            .into_bytes(),
            dynamic_padding_start_index: 373
        },
        process_commit(TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE)
    )
}

#[test]
fn process_commit_with_gpg_stuff_in_email() {
    assert_eq!(
        ProcessedCommit {
            header: format!("commit {}\x00", TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL.len() + 7 + 48).into_bytes(),
            commit: format!(
                "\
                    tree 0123456701234567012345670123456701234567\n\
                    parent 7654321076543210765432107654321076543210\n\
                    author Foo Bár <-----END PGP SIGNATURE-----@example.com> 1513980859 -0500\n\
                    committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                    \n\
                    For no particular reason, the commit author's email has a GPG signature marker.{}{}\n",
                repeat(" ").take(7).collect::<String>(),
                repeat("\t").take(48).collect::<String>()
            )
            .into_bytes(),
            dynamic_padding_start_index: 309
        },
        process_commit(TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL)
    )
}

#[test]
fn matches_desired_prefix_empty() {
    assert!(HashPrefix {
        data: Vec::new(),
        half_byte: None
    }
    .matches(&[0; SHA1_BYTE_LENGTH]))
}

#[test]
fn matches_desired_prefix_single_half() {
    assert!(HashPrefix {
        data: Vec::new(),
        half_byte: Some(0x10)
    }
    .matches(&[0x1e; SHA1_BYTE_LENGTH]))
}

#[test]
fn matches_desired_prefix_single_half_mismatch() {
    assert!(!HashPrefix {
        data: Vec::new(),
        half_byte: Some(0x10)
    }
    .matches(&[0x21; SHA1_BYTE_LENGTH]))
}

#[test]
fn matches_desired_prefix_data_without_half() {
    assert!(HashPrefix {
        data: vec![1, 2, 3],
        half_byte: None
    }
    .matches(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn matches_desired_prefix_matching_data_and_half() {
    assert!(HashPrefix {
        data: vec![1, 2, 3],
        half_byte: Some(0x40)
    }
    .matches(&[1, 2, 3, 0x4f, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn matches_desired_prefix_matching_data_mismatching_half() {
    assert!(!HashPrefix {
        data: vec![1, 2, 3],
        half_byte: Some(0x50)
    }
    .matches(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn matches_desired_prefix_mismatching_data_matching_half() {
    assert!(!HashPrefix {
        data: vec![1, 5, 3],
        half_byte: Some(0x40)
    }
    .matches(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn parse_prefix_empty() {
    assert_eq!(
        Some(HashPrefix {
            data: Vec::new(),
            half_byte: None
        }),
        HashPrefix::new("")
    )
}

#[test]
fn parse_prefix_single_char() {
    assert_eq!(
        Some(HashPrefix {
            data: Vec::new(),
            half_byte: Some(0xa0)
        }),
        HashPrefix::new("a")
    )
}

#[test]
fn parse_prefix_even_chars() {
    assert_eq!(
        Some(HashPrefix {
            data: vec![0xab, 0xcd, 0xef],
            half_byte: None
        }),
        HashPrefix::new("abcdef")
    )
}

#[test]
fn parse_prefix_odd_chars() {
    assert_eq!(
        Some(HashPrefix {
            data: vec![0xab, 0xcd, 0xef],
            half_byte: Some(0x50)
        }),
        HashPrefix::new("abcdef5")
    )
}

#[test]
fn parse_prefix_capital_letters() {
    assert_eq!(
        Some(HashPrefix {
            data: vec![0xab, 0xcd, 0xef],
            half_byte: Some(0xb0)
        }),
        HashPrefix::new("ABCDEFB")
    )
}

#[test]
fn parse_prefix_invalid_even_chars() {
    assert_eq!(None, HashPrefix::new("abcdgeb"))
}

#[test]
fn parse_prefix_invalid_odd_char() {
    assert_eq!(None, HashPrefix::new("abcdefg"))
}

#[test]
fn parse_prefix_exact_length_match() {
    assert_eq!(
        Some(HashPrefix {
            data: vec![
                0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34,
                0x56, 0x78, 0x12, 0x34, 0x56, 0x78
            ],
            half_byte: None
        }),
        HashPrefix::new("1234567812345678123456781234567812345678")
    )
}

#[test]
fn parse_prefix_too_long_with_half_byte() {
    assert_eq!(
        None,
        HashPrefix::new("12345678123456781234567812345678123456781")
    )
}

#[test]
fn parse_prefix_too_many_full_bytes() {
    assert_eq!(
        None,
        HashPrefix::new("123456781234567812345678123456781234567812")
    )
}
