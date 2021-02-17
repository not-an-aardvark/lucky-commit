use lucky_commit_lib::{HashPrefix, HashSearchWorker};

pub fn run_single_core_benchmark() {
    // Runs a benchmark for performance testing. Using a single core, this does a constant
    // hash search. This benchmark should take roughly the same amount of time as running
    // `lucky_commit` with no arguments, but the performance should be much more consistent.
    // Caveats:
    // * The benchmark doesn't spawn any git commands or interact with the filesystem, whereas
    //   a real run does a ~single-digit number of filesystem operations.
    //
    // To use: run `time target/release/lucky_commit --benchmark`.
    assert_eq!(
        None,
        HashSearchWorker::new(
            b"\
                tree 6f4e79123e206448f80ec73b9a53e07eb0784fef\n\
                author Foo Bar <foo@example.com> 1611912738 -0500\n\
                committer Foo Bar <foo@example.com> 1611912738 -0500\n\
                \n\
                Test commit for benchmarking performance changes\n",
            HashPrefix::new("000000000000000000000000000000000000000").unwrap(),
        )
        .with_capped_search_space(
            (1 << 28)
                / if HashSearchWorker::gpus_available() {
                    1
                } else {
                    num_cpus::get_physical() as u64
                }
        )
        .search()
    );
}
