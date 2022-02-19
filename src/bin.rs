mod benchmark;

use lucky_commit::{
    GitCommit, GitHashFn, HashPrefix, HashSearchWorker, ParseHashPrefixErr, Sha1, Sha256,
};
use std::{
    env,
    io::Write,
    process::{self, Command, Stdio},
};

fn main() -> Result<(), ParseHashPrefixErr> {
    let args = env::args().collect::<Vec<String>>();
    let prefix_spec = match args.as_slice() {
        [_, arg] if arg == "--benchmark" => {
            benchmark::run_benchmark();
            process::exit(0)
        }
        [_, prefix] => Some(prefix.as_str()),
        [_] => None,
        _ => {
            eprintln!("Usage: lucky_commit [commit-hash-prefix]");
            process::exit(1)
        }
    };

    let existing_commit = spawn_git(&["cat-file", "commit", "HEAD"], None);
    if looks_like_sha256_repository(&existing_commit) {
        run_lucky_commit::<Sha256>(&existing_commit, prefix_spec)
    } else {
        run_lucky_commit::<Sha1>(&existing_commit, prefix_spec)
    }
}

fn run_lucky_commit<H: GitHashFn>(
    existing_commit: &[u8],
    prefix_spec: Option<&str>,
) -> Result<(), ParseHashPrefixErr> {
    let desired_prefix = prefix_spec
        .map(str::parse::<HashPrefix<H>>)
        .transpose()?
        .unwrap_or_default();

    if let Some(found_commit) = HashSearchWorker::new(existing_commit, desired_prefix).search() {
        let new_hash = found_commit.hex_hash();
        let new_git_oid = spawn_git(
            &["hash-object", "-t", "commit", "-w", "--stdin"],
            Some(found_commit.object()),
        );

        assert_eq!(
            new_hash.as_bytes(),
            &new_git_oid[0..new_hash.len()],
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
                &new_hash,
                &GitCommit::<H>::new(existing_commit).hex_hash(),
            ],
            None,
        );

        Ok(())
    } else {
        eprintln!(
            "Sorry, failed to find a commit matching the given prefix despite searching hundreds \
            of trillions of possible commits. Hopefully you haven't just been sitting here \
            waiting the whole time."
        );
        process::exit(1)
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

fn looks_like_sha256_repository(commit: &[u8]) -> bool {
    // Try to determine whether the repository uses the SHA1 or SHA256 object format, based on
    // the commit data.
    // SHA256 repositories are still very experimental, and the way that this gets detected
    // might need to change in the future when repositories can contain both SHA1 and SHA256
    // objects. For now, it should be sufficient to parse the `tree` hash from the first line
    // of the commit.
    commit.iter().position(|&char| char == b'\n') == Some("tree ".len() + 64)
}
