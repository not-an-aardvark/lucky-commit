# lucky-commit

Make your git commits lucky!

## What?

With this simple command, you can change the start of your git commit hashes to whatever you want.

```bash
$ git log
1f6383a (HEAD -> master) Some commit
$ ./lucky-commit
$ git log
0000000 (HEAD -> master) Some commit
```

As a demonstration, see the latest commit in this repository.

## How?

lucky-commit amends your commits by adding a few characters of various types of whitespace, and keeps hashing new messages until it gets the right value. By default, it will keep searching until it finds a hash starting with "0000000", but this can be changed by simply passing the desired hash as a parameter.

```bash
$ ./lucky-commit 1010101
$ git log
1010101 (HEAD -> master) Some commit
```

On average, this requires the computation of 16<sup>7</sup> sha1 hashes, which takes about 4 minutes on my laptop.

## Why?

¯\\\_(ツ)_/¯
