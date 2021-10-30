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
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_with_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "0102034".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        None
    );
}

#[test]
fn search_success_without_gpg_signature() {
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "  \t                                             "
            )
            .into_bytes(),
            hash: [0x8f1e428e, 0xc25b1ea8, 0x8389165e, 0xeb3fbdff, 0xbf7c3267]
        })
    );
}

#[test]
fn search_success_sha256_without_gpg_signature() {
    assert_eq!(
        HashSearchWorker::<Sha256>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8d84635".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "      \t                                         "
            )
            .into_bytes(),
            hash: [
                0x8d84635e, 0x3c969997, 0x8993a0b2, 0x7b144cd1, 0x97abdfdc, 0x88223259, 0x116651b4,
                0x0076f9f6
            ]
        })
    );
}

#[test]
fn search_success_after_many_iterations() {
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "000000".parse().unwrap(),
        )
        .with_capped_search_space(1 << 24)
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding =
                    "\t\t\t\t\t\t \t \t\t\t    \t \t \t\t\t\t                        "
            )
            .into_bytes(),
            hash: [0x000000a2, 0x56d137b6, 0xcf22aa10, 0xf59b0c5f, 0xecb860b6]
        })
    );
}

#[test]
fn search_success_with_large_padding_specifier() {
    assert_eq!(
        HashSearchWorker::<Sha1> {
            processed_commit: ProcessedCommit::new(
                format!(
                    test_commit_without_signature!(),
                    static_padding = "",
                    dynamic_padding = ""
                )
                .as_bytes()
            ),
            desired_prefix: "00".parse().unwrap(),
            search_space: (1 << 40)..((1 << 40) + 256)
        }
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "\t  \t \t                                         \t"
            )
            .into_bytes(),
            hash: [0x008429bb, 0x16236716, 0x20cd203e, 0x57d62217, 0x4ba2b8c3]
        })
    );
}

#[test]
fn search_success_with_full_prefix_and_no_capped_space() {
    // If this test keeps running and never finishes, it might indicate a bug in the lame-duck thread
    // signalling (where a single thread finds a match, but the other threads don't realize that they
    // were supposed to stop searching)
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428ec25b1ea88389165eeb3fbdffbf7c3267".parse().unwrap(),
        )
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "  \t                                             "
            )
            .into_bytes(),
            hash: [0x8f1e428e, 0xc25b1ea8, 0x8389165e, 0xeb3fbdff, 0xbf7c3267]
        })
    );
}

#[cfg(feature = "opencl")]
#[test]
fn search_success_without_gpg_signature_gpu_cpu_parity() {
    assert!(
        HashSearchWorker::<Sha1>::gpus_available(),
        "\
            Cannot run test because no GPUs are available. Consider using \
            `cargo test --no-default-features` to ignore tests that require GPUs."
    );
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpus(),
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_gpu()
        .unwrap()
    )
}

#[cfg(feature = "opencl")]
#[test]
fn search_success_without_gpg_signature_gpu_cpu_parity_sha256() {
    assert!(
        HashSearchWorker::<Sha1>::gpus_available(),
        "\
            Cannot run test because no GPUs are available. Consider using \
            `cargo test --no-default-features` to ignore tests that require GPUs."
    );
    assert_eq!(
        HashSearchWorker::<Sha256>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8d84635".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpus(),
        HashSearchWorker::<Sha256>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8d84635".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_gpu()
        .unwrap()
    )
}

#[test]
fn search_success_with_multi_word_prefix() {
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428ec".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "  \t                                             "
            )
            .into_bytes(),
            hash: [0x8f1e428e, 0xc25b1ea8, 0x8389165e, 0xeb3fbdff, 0xbf7c3267]
        })
    );
}

#[test]
fn search_success_with_multi_word_prefix_sha256() {
    assert_eq!(
        HashSearchWorker::<Sha256>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8d84635e3c969".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_without_signature!(),
                static_padding = repeat(" ").take(61).collect::<String>(),
                dynamic_padding = "      \t                                         "
            )
            .into_bytes(),
            hash: [
                0x8d84635e, 0x3c969997, 0x8993a0b2, 0x7b144cd1, 0x97abdfdc, 0x88223259, 0x116651b4,
                0x0076f9f6
            ]
        })
    );
}

#[cfg(feature = "opencl")]
#[test]
fn search_success_with_multi_word_prefix_gpu_cpu_parity() {
    assert!(
        HashSearchWorker::<Sha1>::gpus_available(),
        "\
            Cannot run test because no GPUs are available. Consider using \
            `cargo test --no-default-features` to ignore tests that require GPUs."
    );
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428ec".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpus(),
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8f1e428ec".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_gpu()
        .unwrap()
    )
}

#[cfg(feature = "opencl")]
#[test]
fn search_success_with_multi_word_prefix_gpu_cpu_parity_sha256() {
    assert!(
        HashSearchWorker::<Sha1>::gpus_available(),
        "\
            Cannot run test because no GPUs are available. Consider using \
            `cargo test --no-default-features` to ignore tests that require GPUs."
    );
    assert_eq!(
        HashSearchWorker::<Sha256>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8d84635e3c969".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_cpus(),
        HashSearchWorker::<Sha256>::new(
            format!(
                test_commit_without_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "8d84635e3c969".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search_with_gpu()
        .unwrap()
    )
}

#[test]
fn search_success_with_gpg_signature() {
    assert_eq!(
        HashSearchWorker::<Sha1>::new(
            format!(
                test_commit_with_signature!(),
                static_padding = "",
                dynamic_padding = ""
            )
            .as_bytes(),
            "49ae8".parse().unwrap(),
        )
        .with_capped_search_space(100)
        .search(),
        Some(GitCommit {
            object: format!(
                test_commit_with_signature!(),
                static_padding = repeat(" ").take(40).collect::<String>(),
                dynamic_padding = "    \t \t                                         "
            )
            .into_bytes(),
            hash: [0x49ae8f73, 0x98bea9d3, 0x053174b2, 0x08ba6a7d, 0x03a941b8]
        })
    );
}

#[test]
fn split_search_space_uneven() {
    assert_eq!(
        HashSearchWorker::<Sha1> {
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
    assert!("1"
        .parse::<HashPrefix<Sha1>>()
        .unwrap()
        .matches(&[0x1e1e1e1e; 5]))
}

#[test]
fn matches_desired_prefix_single_half_mismatch() {
    assert!(!"1"
        .parse::<HashPrefix<Sha1>>()
        .unwrap()
        .matches(&[0x21212121; 5]))
}

#[test]
fn matches_desired_prefix_data_without_half() {
    assert!("010203"
        .parse::<HashPrefix<Sha1>>()
        .unwrap()
        .matches(&[0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn matches_desired_prefix_matching_data_and_half() {
    assert!("0102034"
        .parse::<HashPrefix<Sha1>>()
        .unwrap()
        .matches(&[0x0102034f, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn matches_desired_prefix_matching_data_mismatching_half() {
    assert!(!"0102035"
        .parse::<HashPrefix<Sha1>>()
        .unwrap()
        .matches(&[0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn matches_desired_prefix_mismatching_data_matching_half() {
    assert!(!"0105034"
        .parse::<HashPrefix<Sha1>>()
        .unwrap()
        .matches(&[0x0102034f, 0x05060708, 0x090a0b0c, 0x0d0e0f10, 0x11121314]))
}

#[test]
fn hash_prefix_three_and_a_half_bytes() {
    assert_eq!(
        "8f1e428".parse(),
        Ok(HashPrefix::<Sha1> {
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
            data: [0x8f_1e_42_80, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_two_bytes() {
    assert_eq!(
        "8f1e".parse(),
        Ok(HashPrefix::<Sha1> {
            mask: [0xff_ff_00_00, 0, 0, 0, 0],
            data: [0x8f_1e_00_00, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_four_bytes() {
    assert_eq!(
        "8f1e428e".parse(),
        Ok(HashPrefix::<Sha1> {
            mask: [0xff_ff_ff_ff, 0, 0, 0, 0],
            data: [0x8f_1e_42_8e, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_only_half_byte() {
    assert_eq!(
        "8".parse(),
        Ok(HashPrefix::<Sha1> {
            mask: [0xf0_00_00_00, 0, 0, 0, 0],
            data: [0x80_00_00_00, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_multi_word_inexact() {
    assert_eq!(
        "abcdef001234".parse(),
        Ok(HashPrefix::<Sha1> {
            data: [0xab_cd_ef_00, 0x12_34_00_00, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_00_00, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_multi_word_inexact_sha256() {
    assert_eq!(
        "abcdef001234".parse(),
        Ok(HashPrefix::<Sha256> {
            data: [0xab_cd_ef_00, 0x12_34_00_00, 0, 0, 0, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_00_00, 0, 0, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_multi_word_exact() {
    assert_eq!(
        "abcdef0012345678".parse(),
        Ok(HashPrefix::<Sha1> {
            data: [0xab_cd_ef_00, 0x12_34_56_78, 0, 0, 0],
            mask: [0xff_ff_ff_ff, 0xff_ff_ff_ff, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_empty() {
    assert_eq!(
        "".parse(),
        Ok(HashPrefix::<Sha1> {
            data: [0; 5],
            mask: [0; 5],
        })
    )
}

#[test]
fn hash_prefix_odd_chars() {
    assert_eq!(
        "abcdef5".parse(),
        Ok(HashPrefix::<Sha1> {
            data: [0xab_cd_ef_50, 0, 0, 0, 0],
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_capital_letters() {
    assert_eq!(
        "ABCDEFB".parse(),
        Ok(HashPrefix::<Sha1> {
            data: [0xab_cd_ef_b0, 0, 0, 0, 0],
            mask: [0xff_ff_ff_f0, 0, 0, 0, 0],
        })
    )
}

#[test]
fn hash_prefix_invalid_even_chars() {
    assert_eq!(
        "abcdgeb".parse::<HashPrefix<Sha1>>(),
        Err(ParseHashPrefixErr::OnlyHexCharactersAllowed)
    )
}

#[test]
fn hash_prefix_invalid_odd_char() {
    assert_eq!(
        "abcdefg".parse::<HashPrefix<Sha1>>(),
        Err(ParseHashPrefixErr::OnlyHexCharactersAllowed)
    )
}

#[test]
fn hash_prefix_exact_length_match() {
    assert_eq!(
        "1234567812345678123456781234567812345678".parse(),
        Ok(HashPrefix::<Sha1> {
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
        "12345678123456781234567812345678123456781".parse::<HashPrefix<Sha1>>(),
        Err(ParseHashPrefixErr::TooLong)
    )
}

#[test]
fn hash_prefix_too_long_for_sha1_but_ok_for_sha256() {
    assert_eq!(
        "12345678123456781234567812345678123456781".parse(),
        Ok(HashPrefix::<Sha256> {
            data: [
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x12_34_56_78,
                0x10_00_00_00,
                0,
                0
            ],
            mask: [
                0xff_ff_ff_ff,
                0xff_ff_ff_ff,
                0xff_ff_ff_ff,
                0xff_ff_ff_ff,
                0xff_ff_ff_ff,
                0xf0_00_00_00,
                0,
                0
            ]
        })
    )
}

#[test]
fn hash_prefix_too_long_with_half_byte_sha256() {
    assert_eq!(
        "12345678123456781234567812345678123456781234567812345678123456781"
            .parse::<HashPrefix<Sha256>>(),
        Err(ParseHashPrefixErr::TooLong)
    )
}

#[test]
fn hash_prefix_too_many_full_bytes() {
    assert_eq!(
        "123456781234567812345678123456781234567812".parse::<HashPrefix<Sha1>>(),
        Err(ParseHashPrefixErr::TooLong)
    )
}
