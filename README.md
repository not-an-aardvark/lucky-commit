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

`lucky-commit` amends your commit messages by adding a few characters of various types of whitespace, and keeps trying new messages until it finds a good hash. By default, it will look for a commit hash starting with "0000000".

To find a hash starting with something other than "0000000", pass the desired prefix as a command-line argument:

```bash
$ lucky_commit 1010101
$ git log
1010101 Some commit
```

The command-line argument can also contain `_` placeholders (e.g. `lucky_commit 00_111`), indicating that the hash is allowed to have any hex character in the given slot.

## Why?

¯\\\_(ツ)\_/¯

## Installation

* Make sure you have `rustc` and `cargo` installed. Installation instructions can be found [here](https://doc.rust-lang.org/book/ch01-01-installation.html).
* Run `cargo install lucky_commit --locked`

Depending on your `cargo` setup, this will usually add the binary to your `$PATH`. You can then use it by running `lucky_commit`.

Alternatively, you can build from source:

```
git clone https://github.com/not-an-aardvark/lucky-commit
cd lucky-commit/
cargo build --release
```

This will create the `lucky_commit` binary (`lucky_commit.exe` on Windows) in the `target/release` directory. You can move this to wherever you want, or set up an alias for it.

### Troubleshooting linker errors

By default, `lucky-commit` links with your system's OpenCL headers and runs on a GPU. This makes it significantly faster.

However, if you encounter a linker error along the lines of `/usr/bin/ld: cannot find -lOpenCL`, there are a few workarounds:

* Compile `lucky-commit` without OpenCL by adding the flag `--no-default-features` to your install or build command (i.e. `cargo install lucky_commit --locked --no-default-features` or `cargo build --release --no-default-features`). This will make `lucky-commit` fall back to a multithreaded CPU implementation. The CPU implementation is about 20x slower on my laptop, but depending on what you're planning to use the tool for, there's a good chance it's fast enough anyway.

    This is the recommended approach if you just want a stable build, and you don't need the extra performance from GPUs.
* You can try installing the OpenCL libraries for your system. The instructions for this will vary by OS (see e.g. [here](https://software.intel.com/content/www/us/en/develop/articles/opencl-drivers.html)). Note that this will only be useful if your machine has a GPU.
* You can try installing an older version of the library written in a different language (see the branches for [Node.js](https://github.com/not-an-aardvark/lucky-commit/tree/nodejs), [C](https://github.com/not-an-aardvark/lucky-commit/tree/C), and [pure Rust without OpenCL](https://github.com/not-an-aardvark/lucky-commit/tree/pure-rust-without-opencl)). Note that these older versions are drastically slower than the current version, and are also unmaintained.

### Distro packages

#### Arch Linux

`lucky-commit` can be installed from the [community repository](https://archlinux.org/packages/community/x86_64/lucky-commit/) using [pacman](https://wiki.archlinux.org/title/Pacman):

```
pacman -S lucky-commit
```

#### Funtoo Linux

`lucky-commit` can be installed from [dev-kit](https://github.com/funtoo/dev-kit/tree/1.4-release/dev-util/lucky-commit):

```
emerge dev-util/lucky-commit
```

#### Homebrew

`lucky-commit` is available from the default Homebrew tap:

```
brew install lucky-commit
```

## Performance

`lucky-commit`'s performance is determined by how powerful your computer is, whether you GPG-sign your commits, and whether you use experimental git features.

### Hash rate

`lucky-commit`'s main bottleneck is SHA1 throughput. The default hash prefix of `0000000` has length 7, so on average, `lucky-commit` needs to compute 16<sup>7</sup> SHA1 hashes.

For non-GPG-signed commits, `lucky-commit` adds its whitespace to a 64-byte-aligned block at the very end of the commit message. Since everything that precedes the whitespace is constant for any particular commit, this allows `lucky-commit` to cache the SHA1 buffer state and only hash a single 64-byte block on each attempt. For an average-sized commit, this speeds up the search by a factor of ~5 over the naive approach of hashing the entire commit on each attempt.

Hash searching is extremely parallelizable, and `lucky-commit` takes advantage of this by running on a GPU. When no GPU is available, it falls back to a multithreaded CPU implementation.

The GPU on my 2021 MacBook Pro can compute about 1.5 billion single-block hashes per second. As a result, the theoretical average time to find a `0000000` commit hash on my laptop is (16<sup>7</sup> hashes) / (1500000000 hashes/s) = **0.18 seconds**. You can estimate the average time for your computer by running `time lucky_commit --benchmark`.

Outside of hashing, the tool also has to do a constant amount of I/O (e.g. spawning `git` a few times), resulting in an observed average time on my laptop of about 0.24 seconds.

### GPG signatures

For GPG-signed commits, the commit message is part of the signed payload, so `lucky-commit` can't edit the commit message without making the signature invalid. Instead, it adds its whitespace to the end of the signature itself. Since the signature precedes the commit message in git's commit encoding, this requires `lucky-commit` to do more work on each attempt (it can't cache the SHA1 buffer state as effectively, and it needs to rehash the commit message every time). As a result, the performance for GPG-signed commits depends on the length of the commit message. This multiplies the average search time by roughly `1 + ceiling(commit message length / 64 bytes)`.

### SHA256 repositories

Finally, `lucky-commit` also supports git repositories using the [experimental sha256 object format](https://git-scm.com/docs/hash-function-transition/). If `lucky-commit` detects that it's being run in a repository with sha256 objects, it will automatically customize the sha256 shorthash of the commit at `HEAD`, rather than the sha1 shorthash. The hash rate for sha256 is a bit slower than the hash rate for sha1.

If you're wondering whether your repository uses sha256, then it probably doesn't. At the time of writing, this is a highly experimental feature and is very rarely used.

## Related projects

* [`every-git-commit-shorthash`](https://github.com/not-an-aardvark/every-git-commit-shorthash)
