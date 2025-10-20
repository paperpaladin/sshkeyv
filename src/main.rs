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
mod wire;

use std::io::{Read, Write};

const USAGE: &str = "\
usage: sshkeyv COMMAND [OPTIONS] [FILE...]

  blob [FILE...]  the top-level SSH strings of a blob: index, offset,
                  length, and the bytes as text or hex
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

/// Read a file and pull the base64 blob out of it. A public key line is
/// "algorithm blob [comment]"; a bare blob on its own line is also
/// accepted, because that is what a pasted key usually is.
fn blob_of_file(path: &str) -> Result<Vec<u8>, String> {
    let raw = match std::fs::read(path) {
        Ok(v) => v,
        Err(e) => return Err(format!("{}: {}", path, e)),
    };
    let text = match std::str::from_utf8(&raw) {
        Ok(s) => s,
        Err(_) => return Err(format!("{}: not text", path)),
    };
    let line = match text.lines().find(|l| !l.trim().is_empty()) {
        Some(l) => l.trim(),
        None => return Err(format!("{}: empty", path)),
    };
    let mut parts = line.split_whitespace();
    let first = parts.next().unwrap_or("");
    let field = if first.contains('-') || first.contains('@') {
        match parts.next() {
            Some(f) => f,
            None => return Err(format!("{}: no blob after {}", path, first)),
        }
    } else {
        first
    };
    b64::decode(field.as_bytes()).map_err(|e| format!("{}: {}", path, e))
}

fn cmd_blob(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in args {
        let b = match blob_of_file(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sshkeyv: {}", e);
                code = 1;
                continue;
            }
        };
        println!("{}: {} bytes", path, b.len());
        let mut r = wire::Reader::new(&b, "blob");
        let mut i = 0;
        loop {
            if r.at_end() {
                break;
            }
            let at = r.offset();
            match r.string() {
                Ok(s) => {
                    println!("{}\t{}\t{}\t{}", i, at, s.len(), render(s));
                    i += 1;
                }
                Err(e) => {
                    eprintln!("sshkeyv: {}: {}", path, e);
                    code = 1;
                    break;
                }
            }
        }
    }
    code
}

/// Printable ASCII goes out as text, anything else as hex. The suite's
/// third parser applies the same rule, so the two outputs are comparable
/// line for line without either of them having to know about key types.
fn render(s: &[u8]) -> String {
    if !s.is_empty() && s.iter().all(|&c| (0x20..0x7f).contains(&c)) {
        format!("text:{}", String::from_utf8_lossy(s))
    } else {
        let mut h = String::with_capacity(s.len() * 2 + 4);
        h.push_str("hex:");
        for &c in s {
            h.push_str(&format!("{:02x}", c));
        }
        h
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", USAGE);
        std::process::exit(2);
    }
    let code = match args[0].as_str() {
        "blob" => cmd_blob(&args[1..]),
        "b64" => cmd_b64(&args[1..]),
        other => {
            eprintln!("sshkeyv: unknown command {}", other);
            2
        }
    };
    std::process::exit(code);
}
