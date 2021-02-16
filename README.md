## This branch is obsolete in favor of the `--benchmark` flag.

The following is preserved as an archive, but it may be out of date, particularly because it assumes that hashes are performed on parallel CPUs rather than GPUs.

# Benchmarking

This branch is used for benchmarking the average performance of lucky-commit. The performance is typically hard to measure because it has high variance. (On average 2<sup>28</sup> hashes need to be attempted for a 7-character commit prefix, but it's effectively a [repeated Bernoulli trial](https://en.wikipedia.org/wiki/Bernoulli_trial).) The one commit on this branch has been precomputed so that it requires 2<sup>28</sup> hashes to regenerate.

## How to use

 To run a benchmark:

 1. Make some changes, build with `cargo build --release`, and temporarily commit the changes to your working branch.
 1. Switch to the `benchmark-branch` branch
 1. Run `time target/release/lucky_commit $(git rev-parse HEAD)`. This will compute exactly 2<sup>28</sup> hashes to generate a "new" commit with a hash that already matches the existing hash.

## Caveats

The commit will be found after the first CPU core computes its 2<sup>27</sup>th hash. The claim that this is an "average" run assumes that the computer has two physical CPUs, and that work is distributed evenly between them. When using a different number of cores, the run won't be "average", but the time can be multiplied by `2 / (# physical CPUs)` to get a more accurate number.

This benchmark will stop working if the tool changes how it inserts padding into commits, or if it changes the order in which it chooses padding.
