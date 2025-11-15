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
mod fields;
mod fp;
mod hash;
mod key;
mod wire;

use std::io::{Read, Write};

const USAGE: &str = "\
usage: sshkeyv COMMAND [OPTIONS] [FILE...]

  fp [-E HASH] [FILE...]
                  fingerprints, the line ssh-keygen -l prints
  fields [FILE...]  one \"path name value\" line per field, tab separated
  blob [FILE...]  the top-level SSH strings of a blob: index, offset,
                  length, and the bytes as text or hex
  hash ALG        hex digest of stdin: sha256 or sha512
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

/// The first non-blank line of a file. Every public key format this
/// program reads is one line, and a file with several is a file where the
/// first one is the subject.
fn first_line(path: &str) -> Result<String, String> {
    let raw = match std::fs::read(path) {
        Ok(v) => v,
        Err(e) => return Err(format!("{}: {}", path, e)),
    };
    let text = match String::from_utf8(raw) {
        Ok(s) => s,
        Err(_) => return Err(format!("{}: not valid UTF-8", path)),
    };
    match text.lines().find(|l| !l.trim().is_empty()) {
        Some(l) => Ok(l.to_string()),
        None => Err(format!("{}: empty", path)),
    }
}

fn cmd_fp(args: &[String]) -> i32 {
    let mut kind = fp::Kind::Sha256;
    let mut paths: Vec<&String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-E" {
            match it.next().and_then(|n| fp::Kind::from_name(n)) {
                Some(k) => kind = k,
                None => {
                    eprintln!("sshkeyv: -E wants a hash name");
                    return 2;
                }
            }
        } else {
            paths.push(a);
        }
    }
    if paths.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in paths {
        let r = first_line(path)
            .and_then(|l| key::PublicKey::parse_line(&l))
            .and_then(|k| fp::line(kind, &k));
        match r {
            Ok(l) => println!("{}", l),
            Err(e) => {
                eprintln!("sshkeyv: {}", e);
                code = 1;
            }
        }
    }
    code
}

fn cmd_fields(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in args {
        let r = first_line(path)
            .and_then(|l| key::PublicKey::parse_line(&l))
            .and_then(|k| fields::print(path, &k));
        if let Err(e) = r {
            eprintln!("sshkeyv: {}", e);
            code = 1;
        }
    }
    code
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

// The hash command exists for the suite: sha256sum and sha512sum are the
// oracle for the digests, and a digest that is wrong only for inputs of a
// particular length is exactly the defect a key-sized test cannot see.
fn cmd_hash(args: &[String]) -> i32 {
    let data = read_stdin();
    let d = match args.first().map(|s| s.as_str()) {
        Some("sha256") => fields::hex(&hash::sha256(&data)),
        Some("sha512") => fields::hex(&hash::sha512(&data)),
        _ => {
            eprint!("{}", USAGE);
            return 2;
        }
    };
    println!("{}", d);
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprint!("{}", USAGE);
        std::process::exit(2);
    }
    let code = match args[0].as_str() {
        "fp" => cmd_fp(&args[1..]),
        "fields" => cmd_fields(&args[1..]),
        "blob" => cmd_blob(&args[1..]),
        "hash" => cmd_hash(&args[1..]),
        "b64" => cmd_b64(&args[1..]),
        other => {
            eprintln!("sshkeyv: unknown command {}", other);
            2
        }
    };
    std::process::exit(code);
}
