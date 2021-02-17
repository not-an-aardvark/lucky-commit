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
            HashPrefix::new("0102034").unwrap(),
        )
        .with_capped_search_space(100)
        .search()
    );
}

#[test]
fn search_success_without_gpg_signature() {
    assert_eq!(
        Some(HashMatch {
            commit: format!(
                "\
                    tree 0123456701234567012345670123456701234567\n\
                    parent 7654321076543210765432107654321076543210\n\
                    author Foo Bár <foo@example.com> 1513980859 -0500\n\
                    committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                    \n\
                    Do a thing\n\
                    \n\
                    Makes some changes to the foo feature{}{}\n",
                repeat(" ").take(61).collect::<String>(),
                "  \t                                             "
            )
            .into_bytes(),
            hash: [
                143, 30, 66, 142, 194, 91, 30, 168, 131, 137, 22, 94, 235, 63, 189, 255, 191, 124,
                50, 103
            ]
        }),
        HashSearchWorker::new(
            TEST_COMMIT_WITHOUT_SIGNATURE,
            HashPrefix::new("8f1e428").unwrap(),
        )
        .with_capped_search_space(100)
        .search()
    );
}

#[test]
fn search_success_without_gpg_signature_gpu_cpu_parity() {
    if !HashSearchWorker::gpus_available() {
        return;
    }
    assert_eq!(
        HashSearchWorker::new(
            TEST_COMMIT_WITHOUT_SIGNATURE,
            HashPrefix::new("8f1e428").unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpu(),
        HashSearchWorker::new(
            TEST_COMMIT_WITHOUT_SIGNATURE,
            HashPrefix::new("8f1e428").unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_gpu()
        .unwrap()
    )
}

#[test]
fn search_success_with_multi_word_prefix() {
    assert_eq!(
        Some(HashMatch {
            commit: format!(
                "\
                    tree 0123456701234567012345670123456701234567\n\
                    parent 7654321076543210765432107654321076543210\n\
                    author Foo Bár <foo@example.com> 1513980859 -0500\n\
                    committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                    \n\
                    Do a thing\n\
                    \n\
                    Makes some changes to the foo feature{}{}\n",
                repeat(" ").take(61).collect::<String>(),
                "  \t                                             "
            )
            .into_bytes(),
            hash: [
                143, 30, 66, 142, 194, 91, 30, 168, 131, 137, 22, 94, 235, 63, 189, 255, 191, 124,
                50, 103
            ]
        }),
        HashSearchWorker::new(
            TEST_COMMIT_WITHOUT_SIGNATURE,
            HashPrefix::new("8f1e428ec").unwrap(),
        )
        .with_capped_search_space(100)
        .search()
    );
}

#[test]
fn search_success_with_multi_word_prefix_gpu_cpu_parity() {
    if !HashSearchWorker::gpus_available() {
        return;
    }
    assert_eq!(
        HashSearchWorker::new(
            TEST_COMMIT_WITHOUT_SIGNATURE,
            HashPrefix::new("8f1e428ec").unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpu(),
        HashSearchWorker::new(
            TEST_COMMIT_WITHOUT_SIGNATURE,
            HashPrefix::new("8f1e428ec").unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_gpu()
        .unwrap()
    )
}

#[test]
fn search_success_with_gpg_signature() {
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
            HashPrefix::new("49ae8").unwrap(),
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
fn matches_desired_prefix_single_half() {
    assert!(HashPrefix::new("1")
        .unwrap()
        .matches(&[0x1e; SHA1_BYTE_LENGTH]))
}

#[test]
fn matches_desired_prefix_single_half_mismatch() {
    assert!(!HashPrefix::new("1")
        .unwrap()
        .matches(&[0x21; SHA1_BYTE_LENGTH]))
}

#[test]
fn matches_desired_prefix_data_without_half() {
    assert!(HashPrefix::new("010203")
        .unwrap()
        .matches(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn matches_desired_prefix_matching_data_and_half() {
    assert!(HashPrefix::new("0102034")
        .unwrap()
        .matches(&[1, 2, 3, 0x4f, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn matches_desired_prefix_matching_data_mismatching_half() {
    assert!(!HashPrefix::new("0102035")
        .unwrap()
        .matches(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn matches_desired_prefix_mismatching_data_matching_half() {
    assert!(!HashPrefix::new("0105034")
        .unwrap()
        .matches(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]))
}

#[test]
fn hash_prefix_three_and_a_half_bytes() {
    assert_eq!(
        Some(HashPrefix {
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
            data: [0x8f_1e_42_80, 0, 0, 0, 0],
        }),
        HashPrefix::new("8f1e428"),
    )
}

#[test]
fn hash_prefix_two_bytes() {
    assert_eq!(
        Some(HashPrefix {
            mask: [0xff_ff_00_00, 0, 0, 0, 0],
            data: [0x8f_1e_00_00, 0, 0, 0, 0],
        }),
        HashPrefix::new("8f1e"),
    )
}

#[test]
fn hash_prefix_four_bytes() {
    assert_eq!(
        Some(HashPrefix {
            mask: [0xff_ff_ff_ff, 0, 0, 0, 0],
            data: [0x8f_1e_42_8e, 0, 0, 0, 0],
        }),
        HashPrefix::new("8f1e428e")
    )
}

#[test]
fn hash_prefix_only_half_byte() {
    assert_eq!(
        Some(HashPrefix {
            mask: [0xf0_00_00_00, 0, 0, 0, 0],
            data: [0x80_00_00_00, 0, 0, 0, 0],
        }),
        HashPrefix::new("8")
    )
}

#[test]
fn hash_prefix_multi_word_inexact() {
    assert_eq!(
        Some(HashPrefix {
            data: [0xab_cd_ef_00, 0x12_34_00_00, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_00_00, 0, 0, 0],
        }),
        HashPrefix::new("abcdef001234")
    )
}

#[test]
fn hash_prefix_multi_word_exact() {
    assert_eq!(
        Some(HashPrefix {
            data: [0xab_cd_ef_00, 0x12_34_56_78, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_ff_ff, 0, 0, 0],
        }),
        HashPrefix::new("abcdef0012345678")
    )
}

#[test]
fn hash_prefix_empty() {
    assert_eq!(
        Some(HashPrefix {
            data: [0; 5],
            mask: [0; 5],
        }),
        HashPrefix::new("")
    )
}

#[test]
fn hash_prefix_odd_chars() {
    assert_eq!(
        Some(HashPrefix {
            data: [0xab_cd_ef_50, 0, 0, 0, 0],
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
        }),
        HashPrefix::new("abcdef5")
    )
}

#[test]
fn hash_prefix_capital_letters() {
    assert_eq!(
        Some(HashPrefix {
            data: [0xab_cd_ef_b0, 0, 0, 0, 0],
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
        }),
        HashPrefix::new("ABCDEFB")
    )
}

#[test]
fn hash_prefix_invalid_even_chars() {
    assert_eq!(None, HashPrefix::new("abcdgeb"))
}

#[test]
fn hash_prefix_invalid_odd_char() {
    assert_eq!(None, HashPrefix::new("abcdefg"))
}

#[test]
fn hash_prefix_exact_length_match() {
    assert_eq!(
        Some(HashPrefix {
            data: [
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78
            ],
            mask: [0xff_ff_ff_ff; 5]
        }),
        HashPrefix::new("1234567812345678123456781234567812345678")
    )
}

#[test]
fn hash_prefix_too_long_with_half_byte() {
    assert_eq!(
        None,
        HashPrefix::new("12345678123456781234567812345678123456781")
    )
}

#[test]
fn hash_prefix_too_many_full_bytes() {
    assert_eq!(
        None,
        HashPrefix::new("123456781234567812345678123456781234567812")
    )
}
