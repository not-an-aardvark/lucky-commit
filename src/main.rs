extern crate crypto;
extern crate flate2;
extern crate num_cpus;

mod padding;

use crypto::digest::Digest;
use crypto::sha1;

use flate2::write::ZlibEncoder;
use flate2::Compression;

use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::ops;
use std::process;
use std::str;
use std::sync::mpsc;
use std::thread;
use std::u64;
use std::u8;

const SHA1_BYTE_LENGTH: usize = 20;

#[derive(Debug, PartialEq)]
struct HashPrefix {
    data: Vec<u8>,
    half_byte: Option<u8>,
}

impl Clone for HashPrefix {
    fn clone(&self) -> Self {
        HashPrefix {
            data: self.data.to_owned(),
            half_byte: self.half_byte.to_owned(),
        }
    }
}

struct SearchParams {
    current_message: String,
    desired_prefix: HashPrefix,
    counter_range: ops::Range<u64>,
    extension_word_length: usize,
}

#[derive(Debug, PartialEq)]
struct HashMatch {
    data: Vec<u8>,
    hash: [u8; SHA1_BYTE_LENGTH],
}

#[derive(Debug, PartialEq)]
struct ProcessedCommitMessage {
    full_message: Vec<u8>,
    whitespace_index: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();

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
    fail_with_message("Usage: lucky-commit [commit-hash-prefix]")
}

fn fail_with_message(message: &str) -> ! {
    eprintln!("{}", message);
    process::exit(1)
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
    let current_message_bytes = run_command("git", &["cat-file", "commit", "HEAD"]);
    let current_message =
        &String::from_utf8(current_message_bytes).expect("Git commit contains invalid utf8");

    match find_match(current_message, desired_prefix) {
        Some(hash_match) => {
            create_git_object_file(&hash_match).expect("Failed to create git object file");
            git_reset_to_hash(&hash_match.hash);
        }
        None => fail_with_message("Failed to find a match"),
    }
}

fn run_command(command: &str, args: &[&str]) -> Vec<u8> {
    let output = process::Command::new(command)
        .args(args)
        .stderr(process::Stdio::inherit())
        .output()
        .expect("Failed to run command");

    if !output.status.success() {
        process::exit(1);
    }

    output.stdout
}

fn find_match(current_message: &str, desired_prefix: &HashPrefix) -> Option<HashMatch> {
    let num_threads = num_cpus::get_physical();
    let (shared_sender, receiver) = mpsc::channel();
    let u32_ranges = split_range(0, 1u64 << 32, num_threads);
    let u64_ranges = split_range(0, u64::MAX, num_threads);

    for thread_index in 0..num_threads {
        spawn_hash_searcher(
            shared_sender.clone(),
            SearchParams {
                current_message: current_message.to_owned(),
                desired_prefix: desired_prefix.clone(),
                counter_range: u32_ranges[thread_index].clone(),
                extension_word_length: 4,
            },
        );
    }

    for thread_index in 0..num_threads * 2 {
        let result = receiver.recv().unwrap();
        if result.is_some() {
            return result;
        }

        if thread_index < num_threads {
            spawn_hash_searcher(
                shared_sender.clone(),
                SearchParams {
                    current_message: current_message.to_owned(),
                    desired_prefix: desired_prefix.clone(),
                    counter_range: u64_ranges[thread_index].clone(),
                    extension_word_length: 8,
                },
            );
        }
    }

    None
}

fn spawn_hash_searcher(result_sender: mpsc::Sender<Option<HashMatch>>, params: SearchParams) {
    thread::spawn(move || {
        match result_sender.send(iterate_for_match(&params)) {
            /*
             * If an error occurs when sending, then the receiver has already received
             * a match from another thread, so ignore the error.
             */
            Ok(_) => (),
            Err(_) => (),
        }
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
    let extension_length = params.extension_word_length * 8;
    let processed_message = process_commit_message(&params.current_message, extension_length);

    let mut hash_data = processed_message.full_message;
    let whitespace_index = processed_message.whitespace_index;

    let mut sha1_hash = sha1::Sha1::new();
    let mut hash_result: [u8; SHA1_BYTE_LENGTH] = [0; SHA1_BYTE_LENGTH];

    for counter in params.counter_range.clone() {
        let mut whitespace_word_index = 0;
        while whitespace_word_index < extension_length {
            let start_index = whitespace_index + whitespace_word_index;
            let padding_index = (counter >> whitespace_word_index) as u8 as usize;
            &mut hash_data[start_index..start_index + 8]
                .copy_from_slice(&padding::PADDING_LIST[padding_index]);
            whitespace_word_index += 8;
        }

        sha1_hash.input(&hash_data);
        sha1_hash.result(&mut hash_result);

        if matches_desired_prefix(&hash_result, desired_prefix) {
            return Some(HashMatch {
                data: hash_data,
                hash: hash_result,
            });
        }

        sha1_hash.reset();
    }

    None
}

fn process_commit_message(
    original_message: &str,
    extension_length: usize,
) -> ProcessedCommitMessage {
    let commit_split_index = get_commit_message_split_index(original_message);
    let trimmable_paddings: &[_] = &[' ', '\t'];
    let trimmed_end_half =
        original_message[commit_split_index..].trim_start_matches(trimmable_paddings);

    let mut message_object: Vec<u8> = format!(
        "commit {}\x00",
        original_message[..commit_split_index].len() + extension_length + trimmed_end_half.len()
    )
    .into_bytes();

    let whitespace_index = commit_split_index + message_object.len();

    for character in original_message[..commit_split_index].as_bytes() {
        message_object.push(*character);
    }

    for _ in 0..extension_length {
        message_object.push(padding::SPACE);
    }

    for character in trimmed_end_half.as_bytes() {
        message_object.push(*character);
    }

    ProcessedCommitMessage {
        full_message: message_object,
        whitespace_index,
    }
}

fn get_commit_message_split_index(message: &str) -> usize {
    /*
     * If the commit has a GPG signature (detected by the presence of "-----BEGIN PGP SIGNATURE-----" on
     * the fifth line), then add the padding whitespace immediately after the text "-----BEGIN PGP SIGNATURE-----".
     * Otherwise, add the padding whitespace right before the end of the commit message.
     *
     * If a signature is present, modifying the commit message would make the signature invalid.
     */
    let mut current_line_index = 0;
    const SIGNATURE_MARKER: &str = "-----BEGIN PGP SIGNATURE-----";
    for (index, character) in message.char_indices() {
        if current_line_index == 4 {
            if message[index..].starts_with(SIGNATURE_MARKER) {
                return index + SIGNATURE_MARKER.len();
            }
        }
        if character == '\n' {
            current_line_index += 1;
        }
    }

    message.trim_end().len()
}

fn matches_desired_prefix(hash: &[u8; SHA1_BYTE_LENGTH], prefix: &HashPrefix) -> bool {
    prefix.data == &hash[..prefix.data.len()]
        && match prefix.half_byte {
            Some(half_byte) => (hash[prefix.data.len()] & 0xf0) == half_byte,
            None => true,
        }
}

fn create_git_object_file(search_result: &HashMatch) -> io::Result<()> {
    let compressed_object = zlib_compress(&search_result.data)?;
    let git_dir_bytes = run_command("git", &["rev-parse", "--git-dir"]);
    let mut git_dir =
        String::from_utf8(git_dir_bytes).expect("git rev-parse --git-dir returned invalid utf8");
    let len = git_dir.len();
    git_dir.truncate(len - 1);
    let dir_path = format!("{}/objects/{:02x}", git_dir, search_result.hash[0]);
    let file_path = format!("{}/{}", dir_path, to_hex_string(&search_result.hash[1..]));

    fs::DirBuilder::new().recursive(true).create(dir_path)?;

    fs::File::create(file_path)?.write_all(&compressed_object)
}

fn zlib_compress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write(data)?;
    encoder.finish()
}

fn git_reset_to_hash(hash: &[u8; SHA1_BYTE_LENGTH]) {
    run_command("git", &["reset", &to_hex_string(hash)]);
}

fn to_hex_string(hash: &[u8]) -> String {
    hash.iter()
        .map(|byte| format!("{:02x}", *byte))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    const TEST_COMMIT_MESSAGE_WITHOUT_SIGNATURE: &str =
        "\
         tree 0123456701234567012345670123456701234567\n\
         parent 7654321076543210765432107654321076543210\n\
         author Foo Bár <foo@example.com> 1513980859 -0500\n\
         committer Baz Qux <baz@example.com> 1513980898 -0500\n\
         \n\
         Do a thing\n\
         \n\
         Makes some changes to the foo feature\n\
         ";

    const TEST_COMMIT_MESSAGE_WITH_SIGNATURE: &str =
        "\
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
            current_message: TEST_COMMIT_MESSAGE_WITH_SIGNATURE.to_owned(),
            desired_prefix: HashPrefix {
                data: vec![1, 2, 3],
                half_byte: Some(0x40),
            },
            counter_range: 1..100,
            extension_word_length: 4,
        };

        assert_eq!(None, iterate_for_match(&search_params))
    }

    #[test]
    fn search_for_match_success() {
        let search_params = SearchParams {
            current_message: TEST_COMMIT_MESSAGE_WITH_SIGNATURE.to_owned(),
            desired_prefix: HashPrefix {
                data: vec![60, 14, 227],
                half_byte: Some(0xa0),
            },
            counter_range: 1..100,
            extension_word_length: 4,
        };

        assert_eq!(
            Some(HashMatch {
                data: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig -----BEGIN PGP SIGNATURE-----{}\n\
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
                     ",
                    TEST_COMMIT_MESSAGE_WITH_SIGNATURE.len() + 32,
                    "  \t\t\t\t\t                         "
                )
                .into_bytes(),
                hash: [
                    60, 14, 227, 164, 209, 218, 169, 30, 57, 111, 16, 239, 90, 26, 77, 144, 229,
                    220, 205, 46
                ]
            }),
            iterate_for_match(&search_params)
        )
    }

    #[test]
    fn process_commit_message_without_gpg_signature() {
        assert_eq!(
            ProcessedCommitMessage {
                full_message: format!(
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
                     {}\n\
                     ",
                    TEST_COMMIT_MESSAGE_WITHOUT_SIGNATURE.len() + 32,
                    iter::repeat(" ").take(32).collect::<String>()
                )
                .into_bytes(),
                whitespace_index: 259
            },
            process_commit_message(TEST_COMMIT_MESSAGE_WITHOUT_SIGNATURE, 32)
        )
    }

    #[test]
    fn process_commit_message_with_gpg_signature() {
        assert_eq!(
            ProcessedCommitMessage {
                full_message: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig -----BEGIN PGP SIGNATURE-----{}\n\
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
                     ",
                    TEST_COMMIT_MESSAGE_WITH_SIGNATURE.len() + 64,
                    iter::repeat(" ").take(64).collect::<String>()
                )
                .into_bytes(),
                whitespace_index: 245
            },
            process_commit_message(TEST_COMMIT_MESSAGE_WITH_SIGNATURE, 64)
        );
    }

    #[test]
    fn process_commit_message_already_padded() {
        assert_eq!(
            ProcessedCommitMessage {
                full_message: format!(
                    "\
                     commit {}\x00\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig {}-----BEGIN PGP SIGNATURE-----{}\n\
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
                     ",
                    TEST_COMMIT_MESSAGE_WITH_SIGNATURE.len() + 64,
                    iter::repeat("\t").take(32).collect::<String>(),
                    iter::repeat(" ").take(32).collect::<String>()
                )
                .into_bytes(),
                whitespace_index: 277
            },
            process_commit_message(
                &format!(
                    "\
                     tree 0123456701234567012345670123456701234567\n\
                     parent 7654321076543210765432107654321076543210\n\
                     author Foo Bár <foo@example.com> 1513980859 -0500\n\
                     committer Baz Qux <baz@example.com> 1513980898 -0500\n\
                     gpgsig {}-----BEGIN PGP SIGNATURE-----{}\n\
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
                     ",
                    iter::repeat("\t").take(32).collect::<String>(),
                    iter::repeat("\t").take(64).collect::<String>()
                ),
                32
            )
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
