// sshkeyv: read OpenSSH keys and certificates, and answer the questions an
// SSH certificate authority deployment raises.
//
// Exit status is part of the contract and the suite asserts on it:
//   0  every requested check passed
//   1  the input is malformed or unreadable
//   2  usage error
//   3  a signature did not verify
//   4  parsed, but not valid now or not authorising the principal asked about

mod b64;

use std::io::{Read, Write};

const USAGE: &str = "\
usage: sshkeyv COMMAND [OPTIONS] [FILE...]

  b64 -d | -e     base64 between stdin and stdout, strictly
";

fn fail(code: i32, msg: &str) -> ! {
    eprintln!("sshkeyv: {}", msg);
    std::process::exit(code);
}

fn read_stdin() -> Vec<u8> {
    let mut v = Vec::new();
    match std::io::stdin().read_to_end(&mut v) {
        Ok(_) => v,
        Err(e) => fail(1, &format!("cannot read stdin: {}", e)),
    }
}

// The b64 command exists for the suite. The decoder is the first thing in
// the chain and every later comparison runs through it, so it needs an
// oracle of its own rather than being tested only by what it feeds.
fn cmd_b64(args: &[String]) -> i32 {
    let mut out = std::io::stdout();
    match args.first().map(|s| s.as_str()) {
        Some("-d") => {
            let mut input = read_stdin();
            while input.last() == Some(&b'\n') || input.last() == Some(&b'\r') {
                input.pop();
            }
            match b64::decode(&input) {
                Ok(b) => {
                    out.write_all(&b).ok();
                    0
                }
                Err(e) => {
                    eprintln!("sshkeyv: {}", e);
                    1
                }
            }
        }
        Some("-e") => {
            let input = read_stdin();
            out.write_all(b64::encode(&input).as_bytes()).ok();
            out.write_all(b"\n").ok();
            0
        }
        _ => {
            eprint!("{}", USAGE);
            2
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", USAGE);
        std::process::exit(2);
    }
    let code = match args[0].as_str() {
        "b64" => cmd_b64(&args[1..]),
        other => {
            eprintln!("sshkeyv: unknown command {}", other);
            2
        }
    };
    std::process::exit(code);
}
