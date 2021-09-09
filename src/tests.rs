use std::iter::repeat;

use super::*;

macro_rules! test_commit_without_signature {
    () => {
        "\
            tree 0123456701234567012345670123456701234567\n\
            parent 7654321076543210765432107654321076543210\n\
            author Foo Bár <foo@example.com> 1513980859 -0500\n\
            committer Baz Qux <baz@example.com> 1513980898 -0500\n\
            \n\
            Do a thing\n\
            \n\
            Makes some changes to the foo feature{static_padding}{dynamic_padding}\n"
    };
}

macro_rules! test_commit_with_signature {
    () => {
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
            -----END PGP SIGNATURE-----{static_padding}{dynamic_padding}\n\
            \n\
            Do a thing\n\
            \n\
            Makes some changes to the foo feature\n"
    };
}

macro_rules! test_commit_with_signature_and_multiple_parents {
    () => {
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
            -----END PGP SIGNATURE-----{static_padding}{dynamic_padding}\n\
            \n\
            Do a thing\n\
            \n\
            Makes some changes to the foo feature\n"
    };
}

macro_rules! test_commit_with_gpg_stuff_in_message {
    () => {
        "\
            tree 0123456701234567012345670123456701234567\n\
            parent 7654321076543210765432107654321076543210\n\
            author Foo Bár <foo@example.com> 1513980859 -0500\n\
            committer Baz Qux <baz@example.com> 1513980898 -0500\n\
            \n\
            For no particular reason, this commit message looks like a GPG signature.\n\
            gpgsig -----END PGP SIGNATURE-----\n\
            \n\
            So anyway, that's fun.{static_padding}{dynamic_padding}\n"
    };
}

macro_rules! test_commit_with_gpg_stuff_in_email {
    () => {
        "\
            tree 0123456701234567012345670123456701234567\n\
            parent 7654321076543210765432107654321076543210\n\
            author Foo Bár <-----END PGP SIGNATURE-----@example.com> 1513980859 -0500\n\
            committer Baz Qux <baz@example.com> 1513980898 -0500\n\
            \n\
            For no particular reason, the commit author's email has a GPG signature marker.\
            {static_padding}{dynamic_padding}\n"
    };
}

macro_rules! pathological_commit {
    () => {
        "\
            tree 0123456701234567012345670123456701234567\n\
            parent 7654321076543210765432107654321076543210\n\
            author Foo Bár <foo@example.com> 1513980859 -0500\n\
            committer Baz Qux <baz@example.com> 1513980898 -0500\n\
            \n\
            This commit is a pathological case for `ProcessedCommit`\n\
            \n\
            If it adds 41 bytes of static padding, then the total length of the \n\
            commit will be 999 bytes, and the dynamic padding that follows it \n\
            will start one byte too soon to be 64-byte aligned. If it adds 42 bytes \n\
            of static padding, then the total length of the commit will be 1000 bytes. \n\
            Since this is now a four-digit number, it will add an additional byte to the \n\
            header, so the dynamic padding will start one byte too late to be 64-byte \n\
            aligned. We should detect this case and add 105 bytes of static padding, \n\
            to ensure that the dynamic padding is aligned. This is the only case where \n\
            ProcessedCommit will add more than 63 bytes of static padding.{static_padding}{dynamic_padding}\n\n\n"
    };
}

#[test]
fn search_failure() {
    assert_eq!(
        HashSearchWorker::new(
            format!(
                test_commit_with_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("0102034").unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        None
    );
}

#[test]
fn search_success_without_gpg_signature() {
    assert_eq!(
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("8f1e428").unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(HashedCommit {
            commit: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "  \t                                             "
            )
            .into_bytes(),
            hash: "8f1e428ec25b1ea88389165eeb3fbdffbf7c3267".to_owned()
        })
    );
}

#[test]
fn search_success_after_many_iterations() {
    assert_eq!(
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("000000").unwrap(),
        )
        .with_capped_search_space(1 << 24)
        .search(),
        Some(HashedCommit {
            commit: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding =
                    "\t\t\t\t\t\t \t \t\t\t    \t \t \t\t\t\t                        "
            )
            .into_bytes(),
            hash: "000000a256d137b6cf22aa10f59b0c5fecb860b6".to_owned()
        })
    );
}

#[test]
fn search_success_with_large_padding_specifier() {
    assert_eq!(
        HashSearchWorker {
            processed_commit: ProcessedCommit::new(
                format!(
                    test_commit_without_signature!(),
                    static_padding = "",
                    dynamic_padding = ""
                )
                .as_bytes()
            ),
            desired_prefix: HashPrefix::new("00").unwrap(),
            search_space: (1 << 40)..((1 << 40) + 256)
        }
        .search(),
        Some(HashedCommit {
            commit: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "\t  \t \t                                         \t"
            )
            .into_bytes(),
            hash: "008429bb1623671620cd203e57d622174ba2b8c3".to_owned()
        })
    );
}

#[test]
fn search_success_with_full_prefix_and_no_capped_space() {
    // If this test keeps running and never finishes, it might indicate a bug in the lame-duck thread
    // signalling (where a single thread finds a match, but the other threads don't realize that they
    // were supposed to stop searching)
    assert_eq!(
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("8f1e428ec25b1ea88389165eeb3fbdffbf7c3267").unwrap(),
        )
        .search(),
        Some(HashedCommit {
            commit: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "  \t                                             "
            )
            .into_bytes(),
            hash: "8f1e428ec25b1ea88389165eeb3fbdffbf7c3267".to_owned()
        })
    );
}

#[cfg(feature = "opencl")]
#[test]
fn search_success_without_gpg_signature_gpu_cpu_parity() {
    assert!(
        HashSearchWorker::gpus_available(),
        "\
            Cannot run test because no GPUs are available. Consider using \
            `cargo test --no-default-features` to ignore tests that require GPUs."
    );
    assert_eq!(
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("8f1e428").unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpus(),
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
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
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("8f1e428ec").unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(HashedCommit {
            commit: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "  \t                                             "
            )
            .into_bytes(),
            hash: "8f1e428ec25b1ea88389165eeb3fbdffbf7c3267".to_owned()
        })
    );
}

#[cfg(feature = "opencl")]
#[test]
fn search_success_with_multi_word_prefix_gpu_cpu_parity() {
    assert!(
        HashSearchWorker::gpus_available(),
        "\
            Cannot run test because no GPUs are available. Consider using \
            `cargo test --no-default-features` to ignore tests that require GPUs."
    );
    assert_eq!(
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("8f1e428ec").unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpus(),
        HashSearchWorker::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
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
        HashSearchWorker::new(
            format!(
                test_commit_with_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            HashPrefix::new("49ae8").unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(HashedCommit {
            commit: format!(
                test_commit_with_signature!(),
                static_padding = repeat(" ").take(40).collect::<String>(),
                dynamic_padding = "    \t \t                                         "
            )
            .into_bytes(),
            hash: "49ae8f7398bea9d3053174b208ba6a7d03a941b8".to_owned()
        })
    );
}

#[test]
fn split_search_space_uneven() {
    assert_eq!(
        HashSearchWorker {
            processed_commit: ProcessedCommit::new(
                format!(
                    test_commit_with_signature!(),
                    static_padding = "",
                    dynamic_padding = ""
                )
                .as_bytes()
            ),
            desired_prefix: Default::default(),
            search_space: 0..100,
        }
        .split_search_space(3)
        .collect::<Vec<_>>(),
        vec![
            HashSearchWorker {
                processed_commit: ProcessedCommit::new(
                    format!(
                        test_commit_with_signature!(),
                        static_padding = "",
                        dynamic_padding = ""
                    )
                    .as_bytes()
                ),
                desired_prefix: Default::default(),
                search_space: 0..33,
            },
            HashSearchWorker {
                processed_commit: ProcessedCommit::new(
                    format!(
                        test_commit_with_signature!(),
                        static_padding = "",
                        dynamic_padding = ""
                    )
                    .as_bytes()
                ),
                desired_prefix: Default::default(),
                search_space: 33..66,
            },
            HashSearchWorker {
                processed_commit: ProcessedCommit::new(
                    format!(
                        test_commit_with_signature!(),
                        static_padding = "",
                        dynamic_padding = ""
                    )
                    .as_bytes()
                ),
                desired_prefix: Default::default(),
                search_space: 66..100,
            }
        ]
    )
}

#[test]
fn processed_commit_without_gpg_signature() {
    assert_eq!(
        ProcessedCommit::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
        )
        .commit(),
        format!(
            test_commit_without_signature!(),
            static_padding = repeat(" ").take(61).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>()
        )
        .into_bytes()
    )
}

#[test]
fn processed_commit_with_gpg_signature() {
    assert_eq!(
        ProcessedCommit::new(
            format!(
                test_commit_with_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes()
        )
        .commit(),
        format!(
            test_commit_with_signature!(),
            static_padding = repeat(" ").take(40).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>(),
        )
        .into_bytes()
    );
}

#[test]
fn processed_commit_already_padded() {
    assert_eq!(
        ProcessedCommit::new(
            format!(
                test_commit_with_signature!(),
                static_padding = repeat(" ").take(4).collect::<String>(),
                dynamic_padding = repeat("\t").take(100).collect::<String>()
            )
            .as_bytes()
        )
        .commit(),
        format!(
            test_commit_with_signature!(),
            static_padding = repeat(" ").take(40).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>(),
        )
        .into_bytes()
    )
}

#[test]
fn process_merge_commit_with_signature() {
    assert_eq!(
        ProcessedCommit::new(
            format!(
                test_commit_with_signature_and_multiple_parents!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes()
        )
        .commit(),
        format!(
            test_commit_with_signature_and_multiple_parents!(),
            static_padding = repeat(" ").take(56).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>()
        )
        .into_bytes()
    );
}

#[test]
fn processed_commit_with_gpg_stuff_in_message() {
    assert_eq!(
        ProcessedCommit::new(
            format!(
                test_commit_with_gpg_stuff_in_message!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes()
        )
        .commit(),
        format!(
            test_commit_with_gpg_stuff_in_message!(),
            static_padding = repeat(" ").take(42).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>()
        )
        .into_bytes(),
    )
}

#[test]
fn processed_commit_with_gpg_stuff_in_email() {
    assert_eq!(
        ProcessedCommit::new(
            format!(
                test_commit_with_gpg_stuff_in_email!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes()
        )
        .commit(),
        format!(
            test_commit_with_gpg_stuff_in_email!(),
            static_padding = repeat(" ").take(7).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>()
        )
        .into_bytes()
    )
}

#[test]
fn processed_commit_pathological_padding_alignment() {
    assert_eq!(
        ProcessedCommit::new(
            &format!(
                pathological_commit!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .into_bytes()
        )
        .commit(),
        format!(
            pathological_commit!(),
            static_padding = repeat(" ").take(105).collect::<String>(),
            dynamic_padding = repeat("\t").take(48).collect::<String>(),
        )
        .into_bytes()
    )
}

#[test]
fn compute_static_padding_length_simple() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(226, 300), 19)
}

#[test]
fn compute_static_padding_length_zero() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(245, 300), 0)
}

#[test]
fn compute_static_padding_length_max() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(246, 300), 63)
}

#[test]
fn compute_static_padding_length_increasing_digit_count() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(920, 980), 28)
}

#[test]
fn compute_static_padding_length_increasing_digit_count_to_power_of_ten_minus_one() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(941, 991), 8)
}

#[test]
fn compute_static_padding_length_increasing_digit_count_to_power_of_ten() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(940, 992), 8)
}

#[test]
fn compute_static_padding_length_solution_overlaps_digit_count_boundary() {
    assert_eq!(ProcessedCommit::compute_static_padding_length(940, 991), 72)
}

#[test]
fn matches_desired_prefix_single_half() {
    assert!(HashPrefix::new("1").unwrap().matches(&[0x1e1e1e1e; 5]))
}

#[test]
fn matches_desired_prefix_single_half_mismatch() {
    assert!(!HashPrefix::new("1").unwrap().matches(&[0x21212121; 5]))
}

#[test]
fn matches_desired_prefix_data_without_half() {
    assert!(HashPrefix::new("010203")
        .unwrap()
        .matches(&[0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn matches_desired_prefix_matching_data_and_half() {
    assert!(HashPrefix::new("0102034")
        .unwrap()
        .matches(&[0x0102034f, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn matches_desired_prefix_matching_data_mismatching_half() {
    assert!(!HashPrefix::new("0102035")
        .unwrap()
        .matches(&[0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn matches_desired_prefix_mismatching_data_matching_half() {
    assert!(!HashPrefix::new("0105034")
        .unwrap()
        .matches(&[0x0102034f, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn hash_prefix_three_and_a_half_bytes() {
    assert_eq!(
        HashPrefix::new("8f1e428"),
        Some(HashPrefix {
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
            data: [0x8f_1e_42_80, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_two_bytes() {
    assert_eq!(
        HashPrefix::new("8f1e"),
        Some(HashPrefix {
            mask: [0xff_ff_00_00, 0, 0, 0, 0],
            data: [0x8f_1e_00_00, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_four_bytes() {
    assert_eq!(
        HashPrefix::new("8f1e428e"),
        Some(HashPrefix {
            mask: [0xff_ff_ff_ff, 0, 0, 0, 0],
            data: [0x8f_1e_42_8e, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_only_half_byte() {
    assert_eq!(
        HashPrefix::new("8"),
        Some(HashPrefix {
            mask: [0xf0_00_00_00, 0, 0, 0, 0],
            data: [0x80_00_00_00, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_multi_word_inexact() {
    assert_eq!(
        HashPrefix::new("abcdef001234"),
        Some(HashPrefix {
            data: [0xab_cd_ef_00, 0x12_34_00_00, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_00_00, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_multi_word_exact() {
    assert_eq!(
        HashPrefix::new("abcdef0012345678"),
        Some(HashPrefix {
            data: [0xab_cd_ef_00, 0x12_34_56_78, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_ff_ff, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_empty() {
    assert_eq!(
        HashPrefix::new(""),
        Some(HashPrefix {
            data: [0; 5],
            mask: [0; 5],
        })
    )
}

#[test]
fn hash_prefix_odd_chars() {
    assert_eq!(
        HashPrefix::new("abcdef5"),
        Some(HashPrefix {
            data: [0xab_cd_ef_50, 0, 0, 0, 0],
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_capital_letters() {
    assert_eq!(
        HashPrefix::new("ABCDEFB"),
        Some(HashPrefix {
            data: [0xab_cd_ef_b0, 0, 0, 0, 0],
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_invalid_even_chars() {
    assert_eq!(HashPrefix::new("abcdgeb"), None)
}

#[test]
fn hash_prefix_invalid_odd_char() {
    assert_eq!(HashPrefix::new("abcdefg"), None)
}

#[test]
fn hash_prefix_exact_length_match() {
    assert_eq!(
        HashPrefix::new("1234567812345678123456781234567812345678"),
        Some(HashPrefix {
            data: [
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78
            ],
            mask: [0xff_ff_ff_ff; 5]
        })
    )
}

#[test]
fn hash_prefix_too_long_with_half_byte() {
    assert_eq!(
        HashPrefix::new("12345678123456781234567812345678123456781"),
        None
    )
}

#[test]
fn hash_prefix_too_many_full_bytes() {
    assert_eq!(
        HashPrefix::new("123456781234567812345678123456781234567812"),
        None
    )
}
