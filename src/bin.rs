mod benchmark;

use lucky_commit::{
    hash_git_commit, GitHash, HashPrefix, HashSearchWorker, HashedCommit, Sha1, Sha256,
};
use std::{
    env,
    io::Write,
    process::{exit, Command, Stdio},
};

fn main() {
    let args = env::args().collect::<Vec<String>>();

    if args.len() == 2 && args[1] == "--benchmark" {
        benchmark::run_benchmark();
        return;
    }

    let existing_commit = spawn_git(&["cat-file", "commit", "HEAD"], None);
    if looks_like_sha256_repository(&existing_commit) {
        run_lucky_commit(
            &existing_commit,
            &match args.len() {
                1 => HashPrefix::<Sha256>::default(),
                2 => parse_hash_prefix_or_exit::<Sha256>(&args[1]),
                _ => print_usage_and_exit(),
            },
        )
    } else {
        run_lucky_commit(
            &existing_commit,
            &match args.len() {
                1 => HashPrefix::<Sha1>::default(),
                2 => parse_hash_prefix_or_exit::<Sha1>(&args[1]),
                _ => print_usage_and_exit(),
            },
        )
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!("Usage: lucky_commit [commit-hash-prefix]");
    exit(1)
}

fn run_lucky_commit<H: GitHash>(existing_commit: &[u8], desired_prefix: &HashPrefix<H>) {
    if let Some(HashedCommit { commit, hash }) =
        HashSearchWorker::new(existing_commit, desired_prefix.clone()).search()
    {
        let new_hash_hex = hash.to_string();
        let new_git_oid = spawn_git(
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            Some(&commit),
        );

        assert_eq!(
            new_hash_hex.as_bytes(),
            &new_git_oid[0..new_hash_hex.len()],
            "Found a matching commit, but git unexpectedly computed a different hash for it",
        );

        // Do an atomic ref update to ensure that no work gets lost, e.g. if someone forgot the tool was running
        // and made new commits in the meantime.
        spawn_git(
            &[
                "update-ref",
                "-m",
                "amend with lucky_commit",
                "HEAD",
                &new_hash_hex,
                &hash_git_commit::<H>(existing_commit).to_string(),
            ],
            None,
        );
    } else {
        eprintln!(
            "Sorry, failed to find a commit matching the given prefix despite searching hundreds \
            of trillions of possible commits. Hopefully you haven't just been sitting here \
            waiting the whole time."
        );
        exit(1)
    }
}

fn spawn_git(args: &[&str], stdin: Option<&[u8]>) -> Vec<u8> {
    let mut child = Command::new("git")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    if let Some(input) = stdin {
        child.stdin.as_mut().unwrap().write_all(input).unwrap();
    }

    let output = child.wait_with_output().unwrap();

    if !output.status.success() {
        panic!("git finished with non-zero exit code: {:?}", args);
    }

    output.stdout
}

fn parse_hash_prefix_or_exit<H: GitHash>(specifier: &str) -> HashPrefix<H> {
    match HashPrefix::new(specifier) {
        Some(hash_prefix) => hash_prefix,
        None => print_usage_and_exit(),
    }
}

fn looks_like_sha256_repository(commit: &[u8]) -> bool {
    // Try to determine whether the repository uses the SHA1 or SHA256 object format, based on
    // the commit data.
    // SHA256 repositories are still very experimental, and the way that this gets detected
    // might need to change in the future when repositories can contain both SHA1 and SHA256
    // objects. For now, it should be sufficient to parse the `tree` hash from the first line
    // of the commit.
    commit.iter().position(|&char| char == b'\n') == Some("tree ".len() + 64)
}
