use sha1::{digest::FixedOutput, Digest, Sha1};

use std::env;
use std::io;
use std::io::Write;
use std::ops;
use std::process::{exit, Command, Stdio};
use std::str;
use std::sync::mpsc;
use std::thread;
use std::u64;
use std::u8;

const SHA1_BYTE_LENGTH: usize = 20;

// See the comment in `process_commit` for the commit and padding layout.
const DYNAMIC_PADDING_LENGTH: usize = 48;

#[derive(Debug, PartialEq, Clone)]
struct HashPrefix {
    data: Vec<u8>,
    half_byte: Option<u8>,
}

struct SearchParams {
    current_commit: String,
    desired_prefix: HashPrefix,
    counter_range: ops::Range<u64>,
}

#[derive(Debug, PartialEq)]
struct HashMatch {
    raw_object: Vec<u8>,
    hash: [u8; SHA1_BYTE_LENGTH],
}

#[derive(Debug, PartialEq)]
struct ProcessedCommit {
    raw_object: Vec<u8>,
    dynamic_padding_start_index: usize,
}

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
    let mut data = Vec::new();
    for index in 0..(prefix.len() / 2) {
        match u8::from_str_radix(&prefix[2 * index..2 * index + 2], 16) {
            Ok(value) => data.push(value),
            Err(_) => return None,
        }
    }

    let parsed_prefix = HashPrefix {
        data,
        half_byte: if prefix.len() % 2 == 1 {
            match u8::from_str_radix(&prefix[prefix.len() - 1..], 16) {
                Ok(value) => Some(value << 4),
                Err(_) => return None,
            }
        } else {
            None
        },
    };

    Some(parsed_prefix)
}

fn run_lucky_commit(desired_prefix: &HashPrefix) {
    let current_commit_bytes = run_command("git", &["cat-file", "commit", "HEAD"]);
    let current_commit =
        &String::from_utf8(current_commit_bytes).expect("Git commit contains invalid utf8");

    match find_match(current_commit, desired_prefix) {
        Some(hash_match) => {
            create_git_commit(&hash_match).expect("Failed to create git commit");
            git_reset_to_hash(&hash_match.hash);
        }
        None => fail_with_message("Failed to find a match"),
    }
}

fn run_command(command: &str, args: &[&str]) -> Vec<u8> {
    let output = Command::new(command)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .expect("Failed to run command");

    if !output.status.success() {
        exit(1);
    }

    output.stdout
}

fn find_match(current_commit: &str, desired_prefix: &HashPrefix) -> Option<HashMatch> {
    let num_threads = num_cpus::get_physical();
    let (shared_sender, receiver) = mpsc::channel();
    let counter_ranges = split_range(0, 1u64 << 48, num_threads);

    for counter_range in counter_ranges {
        spawn_hash_searcher(
            shared_sender.clone(),
            SearchParams {
                current_commit: current_commit.to_owned(),
                desired_prefix: desired_prefix.clone(),
                counter_range: counter_range.clone(),
            },
        );
    }

    for _ in 0..num_threads {
        let result = receiver.recv().unwrap();
        if result.is_some() {
            return result;
        }
    }

    None
}

fn spawn_hash_searcher(result_sender: mpsc::Sender<Option<HashMatch>>, params: SearchParams) {
    thread::spawn(move || {
        /*
         * If an error occurs when sending, then the receiver has already received
         * a match from another thread, so ignore the error.
         */
        let _ = result_sender.send(iterate_for_match(&params));
    });
}

fn split_range(min: u64, max: u64, num_segments: usize) -> Vec<ops::Range<u64>> {
    let segment_size = (max - min) / (num_segments as u64);

    let mut segments = Vec::new();
    let mut last_range_end = 0;
    for _ in 0..num_segments {
        segments.push(last_range_end..last_range_end + segment_size);
        last_range_end += segment_size;
    }

    segments
}

fn iterate_for_match(params: &SearchParams) -> Option<HashMatch> {
    let desired_prefix = &params.desired_prefix;
    let mut processed_commit = process_commit(&params.current_commit);

    // SHA1 works by splitting the input data into 64-byte blocks. Each 64-byte block
    // can be processed in sequence. Since we're adding whitespace near the end of a
    // commit object, the first few 64-byte blocks of the commit will always be the same.
    // Instead of reprocessing those blocks every time, we can just cache the SHA1 state
    // after processing those blocks, and only process the new padding each time.
    let cached_sha1_state = Sha1::new()
        .chain(&processed_commit.raw_object[0..processed_commit.dynamic_padding_start_index]);

    let remaining_commit_data =
        &mut processed_commit.raw_object[processed_commit.dynamic_padding_start_index..];
    let mut hash_result = Default::default();

    for counter in params.counter_range.clone() {
        let dynamic_padding_data = &mut remaining_commit_data[0..DYNAMIC_PADDING_LENGTH];
        for (padding_chunk, counter_byte) in dynamic_padding_data
            .chunks_exact_mut(8)
            .zip(counter.to_le_bytes().iter())
        {
            padding_chunk.copy_from_slice(&PADDINGS[*counter_byte as usize]);
        }

        let mut sha1_hash = cached_sha1_state.clone();
        sha1_hash.update(&remaining_commit_data);
        sha1_hash.finalize_into_reset(&mut hash_result);

        if matches_desired_prefix(hash_result.as_ref(), desired_prefix) {
            return Some(HashMatch {
                raw_object: processed_commit.raw_object,
                hash: hash_result.into(),
            });
        }
    }

    None
}

fn process_commit(original_commit: &str) -> ProcessedCommit {
    // The fully padded data that gets hashed is the concatenation of all the following:
    // * "commit " + length + "\x00", where `length` is the base-10 representation of the length
    //    of everything that follows the null character.
    // * The original commit object, containing everything up to the point where padding should be
    //   added.
    // * Up to 63 space characters, as static padding. This is inserted so that the dynamic padding
    //   that follows it will be at a multiple-of-64-byte offset. Since the performance-intensive
    //   search involves hashing all of the 64-byte blocks starting with the dynamic padding, this
    //   ensures that the dynamic padding is always in a single block. Note that it sometimes won't
    //   be possible to align the dynamic padding perfectly, because adding static padding also
    //   increases the length of the commit object used in the initial header, and this could
    //   bump the alignment twice if e.g. the length increases from 999 to 1000. As a result, in
    //   rare cases the dynamic padding will actually be at a multiple-of-64-byte + 1 offset,
    //   which isn't the end of the world because everything that follows the static padding
    //   will usually fit in one block anyway.
    // * 48 bytes of dynamic padding, consisting of space and tab characters. The ultimate goal
    //   is to find some combination of spaces and tabs that produces the desired hash. A 48-byte
    //   length was chosen with the goal of having everything that follows the static padding
    //   fit into one block for non-GPG-signed commits. (This allows 8 bytes for SHA1's final
    //   length padding, as well as a couple bytes for the remainder of the commit object and
    //   any alignment issues, while still using a multiple of 8 bytes for easily copying padding.)
    // * The rest of the original commit object. For non-GPG-signed commits, this will just be
    //   a single newline. For GPG-signed commits, this will contain the commit message.

    const DYNAMIC_PADDING_ALIGNMENT: usize = 64;
    let commit_split_index = get_commit_split_index(original_commit);
    let trimmable_paddings: &[_] = &[' ', '\t'];
    let trimmed_end_half =
        original_commit[commit_split_index..].trim_start_matches(trimmable_paddings);
    let length_before_static_padding =
        format!("commit {}\x00", commit_split_index).len() + commit_split_index;
    let static_padding_length = (DYNAMIC_PADDING_ALIGNMENT
        - (length_before_static_padding % DYNAMIC_PADDING_ALIGNMENT))
        % DYNAMIC_PADDING_ALIGNMENT;

    let mut raw_object: Vec<u8> = format!(
        "commit {}\x00",
        commit_split_index
            + static_padding_length
            + DYNAMIC_PADDING_LENGTH
            + trimmed_end_half.len()
    )
    .into_bytes();

    let dynamic_padding_start_index = raw_object.len() + commit_split_index + static_padding_length;
    assert!(dynamic_padding_start_index % DYNAMIC_PADDING_ALIGNMENT <= 2);

    for character in original_commit[..commit_split_index].as_bytes() {
        // Add the first half of the original commit
        raw_object.push(*character);
    }

    // Add static padding
    raw_object.resize(raw_object.len() + static_padding_length, b' ');
    // Add dynamic padding, initialized to tabs for now
    raw_object.resize(raw_object.len() + DYNAMIC_PADDING_LENGTH, b'\t');

    for character in trimmed_end_half.as_bytes() {
        // Add the rest of the commit
        raw_object.push(*character);
    }

    ProcessedCommit {
        raw_object,
        dynamic_padding_start_index,
    }
}

fn get_commit_split_index(commit: &str) -> usize {
    /*
     * If the commit has a GPG signature (detected by the presence of "-----END PGP SIGNATURE-----"
     * after a line that starts with "gpgsig "), then add the padding whitespace immediately after
     * the text "-----END PGP SIGNATURE-----".
     * Otherwise, add the padding whitespace right before the end of the commit message.
     *
     * To save time hashing, we want the padding to be as close to the end of the commit
     * as possible. However, if a signature is present, modifying the commit message would make
     * the signature invalid.
     */
    let mut found_gpgsig_line = false;
    const SIGNATURE_MARKER: &str = "-----END PGP SIGNATURE-----";
    for (index, _character) in commit.char_indices() {
        if commit[index..].starts_with("\ngpgsig ") {
            found_gpgsig_line = true;
        } else if !found_gpgsig_line && commit[index..].starts_with("\n\n") {
            // We've reached the commit message and no GPG signature has been found.
            // Add the padding to the end of the commit.
            break;
        } else if found_gpgsig_line && commit[index..].starts_with(SIGNATURE_MARKER) {
            return index + SIGNATURE_MARKER.len();
        }
    }

    commit.trim_end().len()
}

fn matches_desired_prefix(hash: &[u8; SHA1_BYTE_LENGTH], prefix: &HashPrefix) -> bool {
    prefix.data == hash[..prefix.data.len()]
        && match prefix.half_byte {
            Some(half_byte) => (hash[prefix.data.len()] & 0xf0) == half_byte,
            None => true,
        }
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
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "git hash-object failed",
        ));
    }
    assert!(
        String::from_utf8(output.stdout).unwrap().trim_end() == to_hex_string(&search_result.hash),
        "Found a commit, but git unexpectedly computed a different hash for it"
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

// The 256 unique strings of length 8 which contain only ' ' and '\t'.
// These are computed statically in advance to allow them to be copied quickly.
static PADDINGS: [[u8; 8]; 256] = {
    let mut paddings = [[0; 8]; 256];
    let mut i = 0;
    while i < 256 {
        let mut j = 0;
        while j < 8 {
            paddings[i][j] = if i & (0x80 >> j) == 0 { b' ' } else { b'\t' };
            j += 1;
        }
        i += 1;
    }
    paddings
};

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
            current_commit: "tree 6f4e79123e206448f80ec73b9a53e07eb0784fef\n\
                                     author Foo Bar <foo@example.com> 1611912738 -0500\n\
                                     committer Foo Bar <foo@example.com> 1611912738 -0500\n\
                                     \n\
                                     Test commit for benchmarking performance changes\n"
                .to_owned(),
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
    use std::iter;

    use super::*;

    const TEST_COMMIT_WITHOUT_SIGNATURE: &str = "\
         tree 0123456701234567012345670123456701234567\n\
         parent 7654321076543210765432107654321076543210\n\
         author Foo Bár <foo@example.com> 1513980859 -0500\n\
         committer Baz Qux <baz@example.com> 1513980898 -0500\n\
         \n\
         Do a thing\n\
         \n\
         Makes some changes to the foo feature\n\
         ";

    const TEST_COMMIT_WITH_SIGNATURE: &str = "\
         tree 0123456701234567012345670123456701234567\n\
         parent 7654321076543210765432107654321076543210\n\
         author Foo Bár <foo@example.com> 1513980859 -0500\n\
         committer Baz Qux <baz@example.com> 1513980898 -0500\n\
         gpgsig -----BEGIN PGP SIGNATURE-----\n\
         \n\
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
         =AAAA\n\
         -----END PGP SIGNATURE-----\n\
         \n\
         Do a thing\n\
         \n\
         Makes some changes to the foo feature\n\
         ";

    const TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS: &str = "\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        parent 2468246824682468246824682468246824682468\n\
        author Foo Bár <foo@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        gpgsig -----BEGIN PGP SIGNATURE-----\n\
        \n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        =AAAA\n\
        -----END PGP SIGNATURE-----\n\
        \n\
        Do a thing\n\
        \n\
        Makes some changes to the foo feature\n\
        ";

    const TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE: &str = "\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        author Foo Bár <foo@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        \n\
        For no particular reason, this commit message looks like a GPG signature.\n\
        gpgsig -----END PGP SIGNATURE-----\n\
        \n\
        So anyway, that's fun.\n\
        ";

    const TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL: &str = "\
        tree 0123456701234567012345670123456701234567\n\
        parent 7654321076543210765432107654321076543210\n\
        author Foo Bár <-----END PGP SIGNATURE-----@example.com> 1513980859 -0500\n\
        committer Baz Qux <baz@example.com> 1513980898 -0500\n\
        \n\
        For no particular reason, the commit author's email has a GPG signature marker.\n\
        ";

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
    fn iterate_for_match_failure() {
        let search_params = SearchParams {
            current_commit: TEST_COMMIT_WITH_SIGNATURE.to_owned(),
            desired_prefix: HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x40),
            },
            counter_range: 1..100,
        };

        assert_eq!(None, iterate_for_match(&search_params))
    }

    #[test]
    fn search_for_match_success() {
        let search_params = SearchParams {
            current_commit: TEST_COMMIT_WITH_SIGNATURE.to_owned(),
            desired_prefix: HashPrefix {
                data: vec![73, 174],
                half_byte: Some(0x80),
            },
            counter_range: 1..100,
        };

        assert_eq!(
            Some(HashMatch {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig -----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     =AAAA\n\
                     -----END PGP SIGNATURE-----{}{}\n\
                     \n\
                     Do a thing\n\
                     \n\
                     Makes some changes to the foo feature\n\
                     ",
                    TEST_COMMIT_WITH_SIGNATURE.len() + 40 + 48,
                    iter::repeat(" ").take(40).collect::<String>(),
                    "    \t \t                                         "
                )
                .into_bytes(),
                hash: [
                    73, 174, 143, 115, 152, 190, 169, 211, 5, 49, 116, 178, 8, 186, 106, 125, 3,
                    169, 65, 184
                ]
            }),
            iterate_for_match(&search_params)
        )
    }

    #[test]
    fn process_commit_without_gpg_signature() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     \n\
                     Do a thing\n\
                     \n\
                     Makes some changes to the foo feature\
                     {}{}\n\
                     ",
                    TEST_COMMIT_WITHOUT_SIGNATURE.len() + 61 + 48,
                    iter::repeat(" ").take(61).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 320
            },
            process_commit(TEST_COMMIT_WITHOUT_SIGNATURE)
        )
    }

    #[test]
    fn process_commit_with_gpg_signature() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig -----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     =AAAA\n\
                     -----END PGP SIGNATURE-----{}{}\n\
                     \n\
                     Do a thing\n\
                     \n\
                     Makes some changes to the foo feature\n\
                     ",
                    TEST_COMMIT_WITH_SIGNATURE.len() + 40 + 48,
                    iter::repeat(" ").take(40).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 704
            },
            process_commit(TEST_COMMIT_WITH_SIGNATURE)
        );
    }

    #[test]
    fn process_commit_already_padded() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig {}-----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     =AAAA\n\
                     -----END PGP SIGNATURE-----{}{}\n\
                     \n\
                     Do a thing\n\
                     \n\
                     Makes some changes to the foo feature\n\
                     ",
                    TEST_COMMIT_WITH_SIGNATURE.len() + 32 + 8 + 48,
                    iter::repeat("\t").take(32).collect::<String>(),
                    iter::repeat(" ").take(8).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 704
            },
            process_commit(&format!(
                "\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig {}-----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     =AAAA\n\
                     -----END PGP SIGNATURE-----{}\n\
                     \n\
                     Do a thing\n\
                     \n\
                     Makes some changes to the foo feature\n\
                     ",
                iter::repeat("\t").take(32).collect::<String>(),
                iter::repeat(" ").take(100).collect::<String>()
            ))
        )
    }

    #[test]
    fn process_merge_commit_with_signature() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     parent 2468246824682468246824682468246824682468\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig -----BEGIN PGP SIGNATURE-----\n\
                     \n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
                     =AAAA\n\
                     -----END PGP SIGNATURE-----{}{}\n\
                     \n\
                     Do a thing\n\
                     \n\
                     Makes some changes to the foo feature\n\
                     ",
                    TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS.len() + 56 + 48,
                    iter::repeat(" ").take(56).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 768
            },
            process_commit(TEST_COMMIT_WITH_SIGNATURE_AND_MULTIPLE_PARENTS)
        );
    }

    #[test]
    fn process_commit_with_gpg_stuff_in_message() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     \n\
                     For no particular reason, this commit message looks like a GPG signature.\n\
                     gpgsig -----END PGP SIGNATURE-----\n\
                     \n\
                     So anyway, that's fun.{}{}\n\
                     ",
                    TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE.len() + 42 + 48,
                    iter::repeat(" ").take(42).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 384
            },
            process_commit(TEST_COMMIT_WITH_GPG_STUFF_IN_MESSAGE)
        )
    }

    #[test]
    fn process_commit_with_gpg_stuff_in_email() {
        assert_eq!(
            ProcessedCommit {
                raw_object: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <-----END PGP SIGNATURE-----@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     \n\
                     For no particular reason, the commit author's email has a GPG signature marker.{}{}\n\
                     ",
                    TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL.len() + 7 + 48,
                    iter::repeat(" ").take(7).collect::<String>(),
                    iter::repeat("\t").take(48).collect::<String>()
                )
                .into_bytes(),
                dynamic_padding_start_index: 320
            },
            process_commit(TEST_COMMIT_WITH_GPG_STUFF_IN_EMAIL)
        )
    }

    #[test]
    fn split_range_u32_one_segment() {
        assert_eq!(vec![0..1u64 << 32], split_range(0, 1u64 << 32, 1));
    }

    #[test]
    fn split_range_u32_multiple_segments() {
        let range_max = 1u64 << 32;
        assert_eq!(
            vec![
                0..range_max / 5,
                range_max / 5..2 * range_max / 5,
                2 * range_max / 5..3 * range_max / 5,
                3 * range_max / 5..4 * range_max / 5,
                4 * range_max / 5..range_max - 1
            ],
            split_range(0, range_max, 5)
        );
    }

    #[test]
    fn split_range_u64_one_segment() {
        assert_eq!(vec![0..u64::MAX], split_range(0, u64::MAX, 1));
    }

    #[test]
    fn split_range_u64_multiple_segments() {
        let range_max = u64::MAX;
        assert_eq!(
            vec![
                0..range_max / 5,
                range_max / 5..range_max / 5 * 2,
                range_max / 5 * 2..range_max / 5 * 3,
                range_max / 5 * 3..range_max / 5 * 4,
                range_max / 5 * 4..range_max
            ],
            split_range(0, range_max, 5)
        );
    }

    #[test]
    fn matches_desired_prefix_empty() {
        assert!(matches_desired_prefix(
            &[0; SHA1_BYTE_LENGTH],
            &HashPrefix {
                data: Vec::new(),
                half_byte: None
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_single_half() {
        assert!(matches_desired_prefix(
            &[0x1e; SHA1_BYTE_LENGTH],
            &HashPrefix {
                data: Vec::new(),
                half_byte: Some(0x10)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_single_half_mismatch() {
        assert!(!matches_desired_prefix(
            &[0x21; SHA1_BYTE_LENGTH],
            &HashPrefix {
                data: Vec::new(),
                half_byte: Some(0x10)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_data_without_half() {
        assert!(matches_desired_prefix(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 2, 3],
                half_byte: None
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_matching_data_and_half() {
        assert!(matches_desired_prefix(
            &[1, 2, 3, 0x4f, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x40)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_matching_data_mismatching_half() {
        assert!(!matches_desired_prefix(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x50)
            }
        ))
    }

    #[test]
    fn matches_desired_prefix_mismatching_data_matching_half() {
        assert!(!matches_desired_prefix(
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
            &HashPrefix {
                data: vec![1, 5, 3],
                half_byte: Some(0x40)
            }
        ))
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
