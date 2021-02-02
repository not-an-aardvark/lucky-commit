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
* Run `cargo install lucky_commit`

Depending on your `cargo` setup, this will usually add the binary to your `$PATH`. You can then use it by running `lucky_commit`.

Alternatively, you can build from source:

```
$ git clone https://github.com/not-an-aardvark/lucky-commit
$ cd lucky-commit/
$ cargo build --release
```

This will create the `lucky_commit` binary (`lucky_commit.exe` on Windows) in the `target/release` directory. You can move this to wherever you want, or set up an alias for it.

I've rewritten the `lucky-commit` project several times as a method to learn new programming languages. As a result, there are several older implementations of `lucky-commit` in different languages. To install an older version ([C](https://github.com/not-an-aardvark/lucky-commit/tree/C) or [Node.js](https://github.com/not-an-aardvark/lucky-commit/tree/nodejs)), see the instructions in the `README.md` file on the corresponding branch.


## Performance

`lucky-commit`'s performance is determined by how powerful your computer is,<sup name="a1">[1](#f1)</sup> and whether you GPG-sign your commits.

The main bottleneck is SHA1 throughput. The default hash prefix of `0000000` has length 7, so on average, `lucky-commit` needs to compute  16<sup>7</sup> SHA1 hashes.

For non-GPG-signed commits, `lucky-commit` adds its whitespace to a 64-byte-aligned block at the very end of the commit message. Since everything that precedes the whitespace is constant for any particular commit, this allows `lucky-commit` to cache the SHA1 buffer state and only hash a single 64-byte block on each attempt. A single core of my 2015 MacBook Pro can compute 6.99 million single-block hashes per second while checking for prefix matches. (Note that [hyper-threading](https://en.wikipedia.org/wiki/Hyper-threading) does not seem to improve `lucky-commit`'s performance.) As a result, the theoretical average time to find a `0000000` commit hash on my 2015 MacBook Pro is:

```
(16^7 hashes) / (6990000 hashes/s/core) / (2 physical cores) = 19.2 seconds
```

Outside of hashing, the tool's other tasks (spawning `git` a few times, writing to the filesystem, thread synchronization, etc.) collectively add about 1 second of overhead, bringing the measured average time to about 20.2 seconds. You can estimate the average time for your computer by running `time lucky_commit --benchmark` (hashing-only), or by following the instructions in the [benchmarking test branch](https://github.com/not-an-aardvark/lucky-commit/tree/benchmark-branch) (hashing + various overhead).

For GPG-signed commits, the commit message is part of the signed payload, so `lucky-commit` can't edit the commit message without making the signature invalid. Instead, it adds its whitespace to the end of the signature itself. Since the signature precedes the commit message in git's commit encoding, this requires `lucky-commit` to do more work on each attempt (it can't cache the SHA1 buffer state as effectively, and it needs to rehash the commit message every time). As a result, the performance for GPG-signed commits depends on the length of the commit message. As a rule of thumb, multiply the theoretical wait time above for non-GPG-signed commits by `1 + ceiling(commit message length / 64 bytes)` to get a theoretical average wait time for GPG-signed commits.

---

<sup name="f1">1</sup> Aside from raw processing power, you might also get better performance if your CPU supports hardware-accelerated SHA1, which is available on certain [x86 chips manufactured in 2016 or later](https://en.wikipedia.org/wiki/Intel_SHA_extensions) and [ARM chips manufactured in 2013 or later](https://en.wikipedia.org/wiki/AArch64#ARMv8-A). [↩](#a1)
