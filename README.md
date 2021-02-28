# lucky-commit

Make your git commits lucky!

## What?

With this simple tool, you can change the start of your git commit hashes to whatever you want.

```bash
$ git log
1f6383a Some commit
$ lucky_commit
$ git log
0000000 Some commit
```

As a demonstration, see the latest commit in this repository.

## How?

`lucky-commit` amends your commit messages by adding a few characters of various types of whitespace, and keeps trying new messages until it finds a good hash. By default, it will keep searching until it finds a hash starting with "0000000", but this can be changed by simply passing the desired hash as an argument.

```bash
$ lucky_commit 1010101
$ git log
1010101 Some commit
```

## Why?

¯\\\_(ツ)_/¯

## Installation

* Make sure you have `rustc` and `cargo` installed. Installation instructions can be found [here](https://doc.rust-lang.org/book/ch01-01-installation.html).
* Run `cargo install lucky_commit --locked`

Depending on your `cargo` setup, this will usually add the binary to your `$PATH`. You can then use it by running `lucky_commit`.

Alternatively, you can build from source:

```
$ git clone https://github.com/not-an-aardvark/lucky-commit
$ cd lucky-commit/
$ cargo build --release
```

This will create the `lucky_commit` binary (`lucky_commit.exe` on Windows) in the `target/release` directory. You can move this to wherever you want, or set up an alias for it.

### Optional: Disable OpenCL

By default, `lucky-commit` links with your system's OpenCL headers and runs on your GPUs. This makes it significantly faster. However, if you don't have any GPUs, or you encounter linker errors that you don't feel like dealing with, you can compile `lucky-commit` without OpenCL to make it fall back to a multithreaded CPU implementation. (This is about 10x slower on my laptop, although the degree of slowdown will vary significantly depending on your machine specs.)

To compile `lucky-commit` without OpenCL, add the flag `--no-default-features` to your install or build command (i.e. `cargo install lucky_commit --locked --no-default-features` or `cargo build --release --no-default-features`).

### Installing an older version

I've rewritten the `lucky-commit` project several times as a method to learn new programming languages. As a result, there are several older implementations of `lucky-commit` in different languages. To install an older version ([Node.js](https://github.com/not-an-aardvark/lucky-commit/tree/nodejs), [C](https://github.com/not-an-aardvark/lucky-commit/tree/C), or [pure Rust without OpenCL](https://github.com/not-an-aardvark/lucky-commit/tree/pure-rust-without-opencl)), see the instructions in the `README.md` file on the corresponding branch.

## Performance

`lucky-commit`'s performance is determined by how powerful your computer is, and whether you GPG-sign your commits.

The main bottleneck is SHA1 throughput. The default hash prefix of `0000000` has length 7, so on average, `lucky-commit` needs to compute 16<sup>7</sup> SHA1 hashes.

For non-GPG-signed commits, `lucky-commit` adds its whitespace to a 64-byte-aligned block at the very end of the commit message. Since everything that precedes the whitespace is constant for any particular commit, this allows `lucky-commit` to cache the SHA1 buffer state and only hash a single 64-byte block on each attempt.

Hash searching is extremely parallelizable, and `lucky-commit` takes advantage of this by running on a GPU when available. (The intuitive idea is that if you pretend that your commits are actually graphical image data, where SHA1 is a "shading" that gets applied to the whole image at once, and the resulting commit shorthashes are, say, RGBA pixel color values, then you can hash a large number of commits at once by just "rendering the image".) The GPU on my 2015 MacBook Pro can compute about 164 million single-block hashes per second.

As a result, the theoretical average time to find a `0000000` commit hash on my 2015 MacBook Pro is (16<sup>7</sup> hashes) / (164000000 hashes/s) = **1.6 seconds**.

Outside of hashing, the tool also has to do a constant amount of I/O (e.g. spawning `git` a few times), resulting in an observed average time of about 2 seconds. You can estimate the average time for your computer by running `time lucky_commit --benchmark`.

For GPG-signed commits, the commit message is part of the signed payload, so `lucky-commit` can't edit the commit message without making the signature invalid. Instead, it adds its whitespace to the end of the signature itself. Since the signature precedes the commit message in git's commit encoding, this requires `lucky-commit` to do more work on each attempt (it can't cache the SHA1 buffer state as effectively, and it needs to rehash the commit message every time). As a result, the performance for GPG-signed commits depends on the length of the commit message. This adds a multiplier of roughly `1 + ceiling(commit message length / 64 bytes)` to the average search time.
