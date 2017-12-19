extern crate crypto;
extern crate flate2;

mod padding;

use flate2::Compression;
use flate2::write::ZlibEncoder;

use std::env;
use std::fs;
use std::io::Write;
use std::ops;
use std::process;
use std::str;
use std::u8;
use crypto::digest::Digest;
use crypto::sha1;

const SHA1_BYTE_LENGTH: usize = 20;

struct HashPrefix {
    data: Vec<u8>,
    half_byte: Option<u8>,
}

struct SearchParams<'a> {
    current_message: &'a str,
    desired_prefix: HashPrefix,
    counter_range: ops::Range<u64>,
    extension_word_length: usize
}

struct HashMatch {
    data: Vec<u8>,
    hash: [u8; SHA1_BYTE_LENGTH],
}

struct ProcessedCommitMessage {
    full_message: Vec<u8>,
    whitespace_index: usize,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match args.len() {
        1 => run_lucky_commit(parse_prefix("0000000").unwrap()),
        2 => match parse_prefix(&args[1]) {
            Some(prefix) => run_lucky_commit(prefix),
            None => print_usage_and_exit()
        },
        _ => print_usage_and_exit()
    }
}

fn print_usage_and_exit() {
    fail_with_message("Usage: lucky-commit [commit-hash-prefix]");
}

fn fail_with_message(message: &str) {
    eprintln!("{}", message);
    process::exit(1);
}

fn parse_prefix(prefix: &str) -> Option<HashPrefix> {
    let mut data = Vec::new();
    for index in 0..(prefix.len() / 2) {
        match u8::from_str_radix(&prefix[2 * index..2 * index + 2], 16) {
            Ok(value) => data.push(value),
            Err(_) => return None
        }
    }

    let parsed_prefix = HashPrefix {
        data,
        half_byte: if prefix.len() % 2 == 1 {
            match u8::from_str_radix(&prefix[prefix.len() - 1..], 16) {
                Ok(value) => Some(value << 4),
                Err(_) => return None
            }
        } else {
            None
        }
    };

    Some(parsed_prefix)
}

fn run_lucky_commit(desired_prefix: HashPrefix) {
    let current_message_bytes = run_command("git", &["cat-file", "commit", "HEAD"]);
    let current_message = &String::from_utf8(current_message_bytes)
        .expect("Git commit contains invalid utf8");

    let search_params = SearchParams {
        current_message,
        desired_prefix,
        counter_range: ops::Range { start: 0, end: std::u64::MAX },
        extension_word_length: 8
    };

    match search_for_match(&search_params) {
        Some(hash_match) => {
            create_git_object_file(&hash_match);
            git_reset_to_hash(&hash_match.hash);
        },
        None => fail_with_message("Failed to find a match")
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

fn search_for_match(params: &SearchParams) -> Option<HashMatch> {
    let desired_prefix = &params.desired_prefix;
    let extension_length = params.extension_word_length * 8;
    let processed_message = process_commit_message(
        params.current_message,
        extension_length
    );

    let mut hash_data = processed_message.full_message;
    let whitespace_index = processed_message.whitespace_index;

    let mut sha1_hash = sha1::Sha1::new();
    let mut hash_result: [u8; SHA1_BYTE_LENGTH] = [0; SHA1_BYTE_LENGTH];

    for counter in params.counter_range.clone() {
        let mut whitespace_word_index = 0;
        while whitespace_word_index < extension_length {
            let start_index = whitespace_index + whitespace_word_index;
            let padding_index = (counter >> whitespace_word_index) as u8 as usize;
            &mut hash_data[start_index..start_index + 8].copy_from_slice(&padding::PADDING_LIST[padding_index]);
            whitespace_word_index += 8;
        }

        sha1_hash.input(&hash_data);
        sha1_hash.result(&mut hash_result);

        if matches_desired_prefix(&hash_result, desired_prefix) {
            return Some(HashMatch {
                data: hash_data,
                hash: hash_result,
            })
        }

        sha1_hash.reset();
    }

    None
}

fn process_commit_message(original_message: &str, extension_length: usize) -> ProcessedCommitMessage {
    let mut message_object: Vec<u8> = format!("commit {}\x00", original_message.len() + extension_length)
        .into_bytes();

    let commit_split_index = get_commit_message_split_index(original_message);
    let whitespace_index = commit_split_index + message_object.len();

    for character in original_message[..commit_split_index].as_bytes() {
        message_object.push(*character);
    }

    for _ in 0..extension_length {
        message_object.push(padding::SPACE);
    }

    for character in original_message[commit_split_index..].as_bytes() {
        message_object.push(*character);
    }

    ProcessedCommitMessage {
        full_message: message_object,
        whitespace_index,
    }
}

fn get_commit_message_split_index(message: &str) -> usize {
    /*
     * If the commit has a GPG signature (detected by the presence of "gpgsig " at the start
     * of the fifth line), then add the padding whitespace immediately after the text "gpgsig ".
     * Otherwise, add the padding whitespace right before the end of the commit message.
     *
     * If a signature is present, modifying the commit message would make the signature invalid.
     */
    let mut current_line_index = 0;
    const SIGNATURE_MARKER: &str = "gpgsig ";
    for (index, character) in message.chars().enumerate() {
        if current_line_index == 4 {
            if message[index..].starts_with(SIGNATURE_MARKER) {
                return index + SIGNATURE_MARKER.len();
            } else {
                return message.len() - 1;
            }
        }
        if character == '\n' {
            current_line_index += 1;
        }
    }

    message.len() - 1
}

fn matches_desired_prefix(hash: &[u8; SHA1_BYTE_LENGTH], prefix: &HashPrefix) -> bool {
    prefix.data == &hash[..prefix.data.len()] && match prefix.half_byte {
        Some(half_byte) => (hash[prefix.data.len()] & 0xf0) == half_byte,
        None => true,
    }
}

fn create_git_object_file(search_result: &HashMatch) {
    let compressed_object = zlib_compress(&search_result.data);
    let dir_path = format!(".git/objects/{:02x}", search_result.hash[0]);
    let file_path = format!(
        "{}/{}",
        dir_path,
        to_hex_string(&search_result.hash[1..])
    );

    fs::DirBuilder::new()
        .recursive(true)
        .create(dir_path)
        .expect("Failed to create git object directory");

    fs::File::create(file_path)
        .expect("Failed to open git object file")
        .write_all(&compressed_object)
        .expect("Failed to write git object file");
}

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write(data).expect("zlib compression failed");
    encoder.finish().expect("zlib compression failed")
}

fn git_reset_to_hash(hash: &[u8; SHA1_BYTE_LENGTH]) {
    run_command("git", &["reset", &to_hex_string(hash)]);
}

fn to_hex_string(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{:02x}", *byte)).collect::<String>()
}
