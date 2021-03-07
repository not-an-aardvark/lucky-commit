mod benchmark;

use lucky_commit::{hash_git_commit, HashPrefix, HashSearchWorker, HashedCommit};
use std::env;
use std::io::Write;
use std::process::{exit, Command, Stdio};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && args[1] == "--benchmark" {
        benchmark::run_benchmark();
        return;
    }

    match args.len() {
        1 => run_lucky_commit(&HashPrefix::default()),
        2 => match HashPrefix::new(&args[1]) {
            Some(prefix) => run_lucky_commit(&prefix),
            None => print_usage_and_exit(),
        },
        _ => print_usage_and_exit(),
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!("Usage: lucky_commit [commit-hash-prefix]");
    exit(1)
}

fn run_lucky_commit(desired_prefix: &HashPrefix) {
    let old_commit = spawn_git(&["cat-file", "commit", "HEAD"], None);

    if let Some(HashedCommit { commit, hash }) =
        HashSearchWorker::new(&old_commit, desired_prefix.clone()).search()
    {
        let new_git_oid = spawn_git(
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            Some(&commit),
        );

        assert_eq!(
            hash.as_bytes(),
            &new_git_oid[0..40],
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
                &hash,
                &hash_git_commit(&old_commit),
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
