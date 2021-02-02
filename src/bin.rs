use lucky_commit_lib::{iterate_for_match, HashMatch, HashPrefix, SearchParams, SHA1_BYTE_LENGTH};
use std::cmp::min;
use std::env;
use std::io;
use std::io::Write;
use std::process::{exit, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::u8;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 && args[1] == "--benchmark" {
        run_single_core_benchmark();
        return;
    }

    match args.len() {
        1 => run_lucky_commit(&parse_prefix("0000000").unwrap()),
        2 => match parse_prefix(&args[1]) {
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

fn parse_prefix(prefix: &str) -> Option<HashPrefix> {
    if prefix.len() > SHA1_BYTE_LENGTH * 2 {
        return None;
    }

    let mut data = Vec::new();
    for index in 0..(prefix.len() / 2) {
        match u8::from_str_radix(&prefix[2 * index..2 * index + 2], 16) {
            Ok(value) => data.push(value),
            Err(_) => return None,
        }
    }

    Some(HashPrefix {
        data,
        half_byte: if prefix.len() % 2 == 1 {
            match u8::from_str_radix(&prefix[prefix.len() - 1..], 16) {
                Ok(value) => Some(value << 4),
                Err(_) => return None,
            }
        } else {
            None
        },
    })
}

fn run_lucky_commit(desired_prefix: &HashPrefix) {
    let current_commit = run_command("git", &["cat-file", "commit", "HEAD"]);

    match find_match(&current_commit, desired_prefix) {
        Some(hash_match) => {
            create_git_commit(&hash_match)
                .expect("Found a commit, but failed to write it to the git object database.");
            git_reset_to_hash(&hash_match.hash);
        }
        None => fail_with_message(
            "Sorry, failed to find a commit matching the given prefix despite searching hundreds\
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
    let (shared_sender, receiver) = mpsc::channel();
    let num_threads = min(num_cpus::get_physical(), 65535) as u64;
    let workload_per_thread = 1 << 48;

    for thread_index in 0..num_threads {
        let search_params = SearchParams {
            current_commit: current_commit.to_vec(),
            desired_prefix: desired_prefix.clone(),
            counter_range: (thread_index * workload_per_thread)
                ..((thread_index + 1) * workload_per_thread),
        };
        let result_sender = shared_sender.clone();
        thread::spawn(move || {
            /*
             * If an error occurs when sending, then the receiver has already received
             * a match from another thread, so ignore the error.
             */
            let _ = result_sender.send(iterate_for_match(&search_params));
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
    assert!(&search_result.raw_object[0..7] == b"commit ");
    let commit_start_index = search_result
        .raw_object
        .iter()
        .position(|byte| *byte == 0)
        .expect("No null character found in constructed raw git object?")
        + 1;

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
        .write_all(&search_result.raw_object[commit_start_index..])?;
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

fn git_reset_to_hash(hash: &[u8; SHA1_BYTE_LENGTH]) {
    run_command("git", &["reset", &to_hex_string(hash)]);
}

fn to_hex_string(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", *byte))
        .collect::<String>()
}

fn run_single_core_benchmark() {
    // Runs a benchmark for performance testing. Using a single core, this does a constant
    // hash search. This benchmark should take roughly the same amount of time as running
    // `lucky_commit` with no arguments, but the performance should be much more consistent.
    // Caveats:
    // * Assumes perfect parallelization by scaling the workload down when there are multiple
    //   CPUs. While hash searching is perfectly parallelizable in theory, this benchmark might
    //   fail to catch performance bugs resulting from contention.
    // * Assumes that CPU utilization would remain the same when adding threads (this might
    //   not be the case if the other CPUs are being used for something else)
    // * Might overestimate the available cache space, since in reality multiple threads would
    //   be sharing the cache.
    // * The benchmark uses an unusually long desired prefix to make it implausible that it ends
    //   early. While this shouldn't result in substantially more instructions executed, in theory
    //   it could have an effect on things like alignment and the cache.
    // * The benchmark doesn't spawn any git commands or interact with the filesystem, whereas
    // * a real run does a ~single-digit number of filesystem operations.
    //
    // To use: run `time target/release/lucky_commit --benchmark` and look at the user time.
    // The observed standard deviation for this benchmark is somewhere around 0.05 seconds.
    //
    // For a more end-to-end benchmark without the above caveats and with more noise, see the
    // `benchmark-branch` branch. The observed standard deviation for that benchmark is somewhere
    // around 0.5 seconds.
    assert_eq!(
        None,
        iterate_for_match(&SearchParams {
            current_commit: b"\
                    tree 6f4e79123e206448f80ec73b9a53e07eb0784fef\n\
                    author Foo Bar <foo@example.com> 1611912738 -0500\n\
                    committer Foo Bar <foo@example.com> 1611912738 -0500\n\
                    \n\
                    Test commit for benchmarking performance changes\n"
                .to_vec(),
            desired_prefix: HashPrefix {
                data: vec![0; 19],
                half_byte: Some(0x0)
            },
            counter_range: 1..((1 << 28) / num_cpus::get_physical() as u64)
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_prefix_empty() {
        assert_eq!(
            Some(HashPrefix {
                data: Vec::new(),
                half_byte: None
            }),
            parse_prefix("")
        )
    }

    #[test]
    fn parse_prefix_single_char() {
        assert_eq!(
            Some(HashPrefix {
                data: Vec::new(),
                half_byte: Some(0xa0)
            }),
            parse_prefix("a")
        )
    }

    #[test]
    fn parse_prefix_even_chars() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![0xab, 0xcd, 0xef],
                half_byte: None
            }),
            parse_prefix("abcdef")
        )
    }

    #[test]
    fn parse_prefix_odd_chars() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![0xab, 0xcd, 0xef],
                half_byte: Some(0x50)
            }),
            parse_prefix("abcdef5")
        )
    }

    #[test]
    fn parse_prefix_capital_letters() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![0xab, 0xcd, 0xef],
                half_byte: Some(0xb0)
            }),
            parse_prefix("ABCDEFB")
        )
    }

    #[test]
    fn parse_prefix_invalid_even_chars() {
        assert_eq!(None, parse_prefix("abcdgeb"))
    }

    #[test]
    fn parse_prefix_invalid_odd_char() {
        assert_eq!(None, parse_prefix("abcdefg"))
    }

    #[test]
    fn parse_prefix_exact_length_match() {
        assert_eq!(
            Some(HashPrefix {
                data: vec![
                    0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12,
                    0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78
                ],
                half_byte: None
            }),
            parse_prefix("1234567812345678123456781234567812345678")
        )
    }

    #[test]
    fn parse_prefix_too_long_with_half_byte() {
        assert_eq!(
            None,
            parse_prefix("12345678123456781234567812345678123456781")
        )
    }

    #[test]
    fn parse_prefix_too_many_full_bytes() {
        assert_eq!(
            None,
            parse_prefix("123456781234567812345678123456781234567812")
        )
    }

    #[test]
    fn to_hex_string_basic() {
        assert_eq!("00", to_hex_string(&[0]));
    }

    #[test]
    fn to_hex_string_multichar() {
        assert_eq!("00ff14", to_hex_string(&[0, 255, 20]));
    }
}
