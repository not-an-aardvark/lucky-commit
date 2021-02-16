mod benchmark;

use lucky_commit_lib::{HashMatch, HashPrefix, HashSearchWorker};
use std::env;
use std::io;
use std::io::Write;
use std::process::{exit, Command, Stdio};
use std::sync::mpsc;
use std::thread;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && args[1] == "--benchmark" {
        benchmark::run_single_core_benchmark();
        return;
    }

    match args.len() {
        1 => run_lucky_commit(&Default::default()),
        2 => match HashPrefix::new(&args[1]) {
            Some(prefix) => run_lucky_commit(&prefix),
            None => print_usage_and_exit(),
        },
        _ => print_usage_and_exit(),
    }
}

fn print_usage_and_exit() -> ! {
    fail_with_message("Usage: lucky_commit [commit-hash-prefix]")
}

fn fail_with_message(message: &str) -> ! {
    eprintln!("{}", message);
    exit(1)
}

fn run_lucky_commit(desired_prefix: &HashPrefix) {
    let current_commit = run_command("git", &["cat-file", "commit", "HEAD"]);

    match find_match(&current_commit, desired_prefix) {
        Some(hash_match) => {
            create_git_commit(&hash_match)
                .expect("Found a commit, but failed to write it to the git object database.");
            run_command("git", &["reset", &to_hex_string(&hash_match.hash)]);
        }
        None => fail_with_message(
            "Sorry, failed to find a commit matching the given prefix despite searching hundreds \
             of trillions of possible commits. Hopefully you haven't just been sitting here \
             waiting the whole time.",
        ),
    }
}

fn run_command(command: &str, args: &[&str]) -> Vec<u8> {
    let output = Command::new(command)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|_| {
            panic!(
                "Failed to spawn command `{}` with args `{:?}`",
                command, args
            )
        });

    if !output.status.success() {
        panic!(
            "Command finished with non-zero exit code: {} {:?}",
            command, args
        );
    }

    output.stdout
}

fn find_match(current_commit: &[u8], desired_prefix: &HashPrefix) -> Option<HashMatch> {
    let full_worker = HashSearchWorker::new(current_commit, desired_prefix.clone());

    if full_worker.is_eligible_for_gpu_searching() {
        return full_worker.search();
    }

    let (shared_sender, receiver) = mpsc::channel();
    let num_threads = num_cpus::get_physical() as u64;
    for worker in full_worker.split_search_space(num_threads) {
        let result_sender = shared_sender.clone();
        thread::spawn(move || {
            /*
             * If an error occurs when sending, then the receiver has already received
             * a match from another thread, so ignore the error.
             */
            let _ = result_sender.send(worker.search());
        });
    }

    for _ in 0..num_threads {
        let result = receiver.recv().unwrap();
        if result.is_some() {
            return result;
        }
    }

    None
}

fn create_git_commit(search_result: &HashMatch) -> io::Result<()> {
    let mut git_hash_object_child = Command::new("git")
        .args(&["hash-object", "-t", "commit", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;

    git_hash_object_child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&search_result.commit)?;
    let output = git_hash_object_child.wait_with_output()?;

    if !output.status.success() {
        panic!("Found a commit, but failed to write it to the git object database.");
    }
    let git_hash_output =
        String::from_utf8(output.stdout).expect("Git produced a hash containing invalid utf8?");
    assert!(
        git_hash_output.trim_end() == to_hex_string(&search_result.hash),
        "Found a commit ({}), but git unexpectedly computed a different hash for it ({})",
        to_hex_string(&search_result.hash),
        git_hash_output.trim_end(),
    );
    Ok(())
}

fn to_hex_string(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", *byte))
        .collect::<String>()
}
