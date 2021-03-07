use lucky_commit::{HashPrefix, HashSearchWorker};

pub fn run_benchmark() {
    // Runs a benchmark for performance testing. This does a constant hash search. This benchmark
    // should take roughly the same amount of time as running `lucky_commit` with no arguments, but
    // the performance should be much more consistent.
    // Caveats:
    // * The benchmark doesn't spawn any git commands or interact with the filesystem, whereas
    //   a real run does a ~single-digit number of filesystem operations.
    // * When built without OpenCL support, this might slightly underestimate performance if threads
    //   end sharing CPU load unequally, because this benchmark will wait until every thread finishes,
    //   and during that time threads that have already finished will be idle. In a more realistic
    //   scenario, each thread would almost always still be doing work at any given time.
    //
    // To use: run `time target/release/lucky_commit --benchmark`.
    assert_eq!(
        HashSearchWorker::new(
            b"\
                tree 6f4e79123e206448f80ec73b9a53e07eb0784fef\n\
                author Foo Bar <foo@example.com> 1611912738 -0500\n\
                committer Foo Bar <foo@example.com> 1611912738 -0500\n\
                \n\
                Test commit for benchmarking performance changes\n",
            HashPrefix::new("000000000000000000000000000000000000000").unwrap(),
        )
        .with_capped_search_space(1 << 28)
        .search(),
        None
    );
}
