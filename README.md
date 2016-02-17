# lucky-commit

Make your git commits lucky!

## What?

With this simple command, you can change the start of your git commit hashes to whatever you want.

```bash
$ git log
1f6383a (HEAD -> master) Some commit (take note of the hash on the left)
$ npm install -g lucky-commit
$ lucky-commit
$ git log
0000000 (HEAD -> master) Some commit (take note of the hash on the left)
```

As a demonstration, see the latest commit in this repository.

## How?

lucky-commit amends your commit messages by adding a few characters of gibberish to the end, and keeps hashing new commits until it gets the right value. By default, it will keep searching until it finds a hash starting with "0000000", but this can be changed by simply passing the desired hash as a parameter.

```bash
$ lucky-commit 1010101
$ git log
1010101 (HEAD -> master) Some commit (take note of the hash on the left)
```

On average, this requires the computation of 16^7 sha1 hashes, which takes about 20 minutes on my laptop.

## Why?

¯\\\_(ツ)_/¯
