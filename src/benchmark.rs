use lucky_commit_lib::{HashPrefix, HashSearchWorker};

pub fn run_single_core_benchmark() {
    // Runs a benchmark for performance testing. Using a single core, this does a constant
    // hash search. This benchmark should take roughly the same amount of time as running
    // `lucky_commit` with no arguments, but the performance should be much more consistent.
    // Caveats:
    // * Assumes perfect parallelization by scaling the workload down when there are multiple
    //   CPUs. While hash searching is perfectly parallelizable in theory, this benchmark might
    //   fail to catch performance bugs resulting from contention.
    // * Assumes that CPU utilization would remain the same when adding threads (this might
    //   not be the case if the other CPUs are being used for something else)
    // * Might overestimate the available cache space, since in reality multiple threads would
    //   be sharing the cache.
    // * The benchmark uses an unusually long desired prefix to make it implausible that it ends
    //   early. While this shouldn't result in substantially more instructions executed, in theory
    //   it could have an effect on things like alignment and the cache.
    // * The benchmark doesn't spawn any git commands or interact with the filesystem, whereas
    // * a real run does a ~single-digit number of filesystem operations.
    //
    // To use: run `time target/release/lucky_commit --benchmark` and look at the user time.
    // The observed standard deviation for this benchmark is somewhere around 0.05 seconds.
    //
    // For a more end-to-end benchmark without the above caveats and with more noise, see the
    // `benchmark-branch` branch. The observed standard deviation for that benchmark is somewhere
    // around 0.5 seconds.
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
        .with_capped_search_space(1 << 28)
        .split_search_space(num_cpus::get_physical() as u64)
        .next()
        .unwrap()
        .search()
    );
}
