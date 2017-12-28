# lucky-commit

Make your git commits lucky!

## What?

With this simple command, you can change the start of your git commit hashes to whatever you want.

```bash
$ git log
1f6383a Some commit
$ lucky-commit
$ git log
0000000 Some commit
```

As a demonstration, see the latest commit in this repository.

## How?

lucky-commit amends your commits by adding a few characters of various types of whitespace, and keeps hashing new messages until it gets the right value. By default, it will keep searching until it finds a hash starting with "0000000", but this can be changed by simply passing the desired hash as an argument.

```bash
$ lucky-commit 1010101
$ git log
1010101 Some commit
```

## Why?

¯\\\_(ツ)_/¯

## Installation

I've rewritten the `lucky-commit` project several times as a method to learn new programming languages. As a result, there are multiple different implementations of `lucky-commit` in different languages.

The latest version is written in **Rust**. To install it:

* Make sure you have `rustc` and `cargo` installed. Installation instructions can be found [here](https://doc.rust-lang.org/book/second-edition/ch01-01-installation.html#installation).

    ```
    $ git clone https://github.com/not-an-aardvark/lucky-commit
    $ cd lucky-commit/
    $ cargo build --release
    ```

    This will create the `lucky_commit` binary (`lucky_commit.exe` on Windows) in the `target/release` directory. You can move this to wherever you want, or set up an alias for it.

To install an older version, see the instructions in the `README.md` file on the corresponding branch:

* **C** (see the [`C` branch](https://github.com/not-an-aardvark/lucky-commit/tree/C) of this repository)
* **Node.js** (see the [`nodejs` branch](https://github.com/not-an-aardvark/lucky-commit/tree/nodejs) of this repository)

## Performance

* `lucky-commit`'s main performance bottleneck is SHA1 throughput. On a single core of a 2015 MacBook Pro, `rust-crypto`'s SHA1 implementation has a throughput of 350-550 MB/s.<sup>1</sup>
* Long hash prefixes require more hash computations. The default hash prefix of `0000000` has length 7, so an average of 16<sup>7</sup> hashes are needed.
* Large git commit objects increase the amount of data that needs to be hashed on each iteration.
    * A git commit object with a short commit message is typically about 250 bytes.
    * Adding a GPG signature to a commit increases the size by about 350-850 bytes, depending on the PGP key size.<sup>2</sup>

* Machines with more CPUs can compute more hashes. Hash searching is very parallelizable, so performance scales linearly with the number of physical CPUs. ([Hyper-threading](https://en.wikipedia.org/wiki/Hyper-threading) does not improve `lucky-commit`'s performance.)

This means that on a 2015 MacBook Pro with 2 physical cores, searching for a `0000000` prefix on a commit with no GPG signature will take an average of

```
(16^7 hashes) * (250 bytes/hash) / (380 MB/s/core) / (2 cores) = 88 seconds
```

<sup>1</sup> The performance is roughly linear in the total amount of data to hash, but it's affected by a variety of factors. (For example, there is a per-hash overhead which disproportionately affects small input sizes, and very large input sizes can cause L1 cache misses.) I found that the throughput for 250-byte inputs was 1.52 MH/s (equivalent to 380 MB/s), and the throughput for 1100-byte inputs was 451 kH/s (equivalent to 500 MB/s).

<sup>2</sup> More precisely, a signature increases the commit size by roughly `175 bytes + 4/3 * PGP key size`. For example, a signature with a 2048-bit public key increases the commit size by about `175 bytes + 4/3 * 2048 bits = 516 bytes`. This is because an RSA signature has the same length as its public key, and signature packets for git commits are encoded in base64. The OpenPGP protocol adds some additional overhead with a signature packet header and `-----{BEGIN|END} PGP SIGNATURE-----` markers.
