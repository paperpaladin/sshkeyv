// sshkeyv: read OpenSSH keys and certificates, and answer the questions an
// SSH certificate authority deployment raises.
//
// Exit status is part of the contract and the suite asserts on it:
//   0  every requested check passed
//   1  the input is malformed or unreadable
//   2  usage error
//   3  a signature did not verify
//   4  parsed, but not valid now or not authorising the principal asked about

mod ask;
mod b64;
mod bignum;
mod cert;
mod ed25519;
mod fields;
mod fp;
mod hash;
mod show;
mod time;
mod key;
mod pem;
mod privkey;
mod privshow;
mod rsa;
mod sig;
mod wire;

use std::io::{Read, Write};

const USAGE: &str = "\
usage: sshkeyv COMMAND [OPTIONS] [FILE...]

  valid [--at TIME] [FILE...]
                  is each certificate in its window, and for how long
  authorises NAME [FILE...]
                  does each certificate authorise NAME
  verify [FILE...]  check the CA signature over each certificate
  priv [FILE...]  the private key container header, without decrypting
  show [FILE...]  certificate fields, the block ssh-keygen -L prints
  fp [-E HASH] [FILE...]
                  fingerprints, the line ssh-keygen -l prints
  fields [FILE...]  one \"path name value\" line per field, tab separated
  blob [FILE...]  the top-level SSH strings of a blob: index, offset,
                  length, and the bytes as text or hex
  big OP A B [M]  bignum arithmetic on hex arguments, for the suite
  hash ALG        hex digest of stdin: sha256, sha512, sha1 or md5
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

/// Read one file as a certificate. The subject blob is returned with it
/// because show needs it and the borrow of the blob cannot outlive it.
fn read_cert(path: &str) -> Result<(key::PublicKey, Vec<u8>), String> {
    let k = key::PublicKey::parse_line(&first_line(path)?)?;
    if !k.algo.cert {
        return Err(format!("{} is not a certificate", path));
    }
    let subject = k.subject_blob()?;
    Ok((k, subject))
}

fn cmd_valid(args: &[String]) -> i32 {
    let mut at = time::now();
    let mut paths: Vec<&String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--at" {
            match it.next().map(|v| time::parse(v)) {
                Some(Ok(t)) => at = t,
                Some(Err(e)) => {
                    eprintln!("sshkeyv: {}", e);
                    return 2;
                }
                None => {
                    eprintln!("sshkeyv: --at wants a time");
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
        match read_cert(path).and_then(|(k, _)| {
            let c = cert::Cert::parse(&k.blob, k.algo)?;
            Ok(ask::valid(path, &c, at))
        }) {
            Ok((line, ok)) => {
                println!("{}", line);
                if !ok && code == 0 {
                    code = 4;
                }
            }
            Err(e) => {
                eprintln!("sshkeyv: {}", e);
                code = 1;
            }
        }
    }
    code
}

fn cmd_authorises(args: &[String]) -> i32 {
    if args.len() < 2 {
        eprint!("{}", USAGE);
        return 2;
    }
    let name = &args[0];
    let mut code = 0;
    for path in &args[1..] {
        match read_cert(path).and_then(|(k, _)| {
            let c = cert::Cert::parse(&k.blob, k.algo)?;
            Ok(ask::authorises(path, &c, name))
        }) {
            Ok((line, ok)) => {
                println!("{}", line);
                if !ok && code == 0 {
                    code = 4;
                }
            }
            Err(e) => {
                eprintln!("sshkeyv: {}", e);
                code = 1;
            }
        }
    }
    code
}

fn cmd_verify(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    // The worst outcome wins and the order is deliberate: a file that will
    // not parse is a louder fact than a bad signature in another file, and
    // a missing verifier is louder than both, because it means the
    // question was never asked.
    let mut code = 0;
    for path in args {
        let (k, _subject) = match read_cert(path) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sshkeyv: {}", e);
                code = code.max(1);
                continue;
            }
        };
        let c = match cert::Cert::parse(&k.blob, k.algo) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("sshkeyv: {}: {}", path, e);
                code = code.max(1);
                continue;
            }
        };
        let (sa, ca) = match (c.signature_algo(), c.ca_algo()) {
            (Ok(a), Ok(b)) => (a, b),
            _ => {
                eprintln!("sshkeyv: {}: the signature or CA key blob is \
                           malformed", path);
                code = code.max(1);
                continue;
            }
        };
        match sig::verify(c.signature_key, c.signature, c.tbs) {
            sig::Outcome::Good => println!(
                "{}: signature good, {} over {} bytes by the {} CA key",
                path,
                sa,
                c.tbs.len(),
                ca
            ),
            sig::Outcome::Bad(why) => {
                println!("{}: SIGNATURE BAD: {}", path, why);
                code = code.max(3);
            }
            sig::Outcome::NoVerifier(why) => {
                println!("{}: NO VERIFIER: {}", path, why);
                code = code.max(5);
            }
        }
    }
    code
}

fn cmd_priv(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in args {
        let r = std::fs::read_to_string(path)
            .map_err(|e| format!("{}: {}", path, e))
            .and_then(|t| pem::parse(&t).map_err(|e| format!("{}: {}", path, e)))
            .and_then(|p| {
                if p.label != "OPENSSH PRIVATE KEY" {
                    return Err(format!(
                        "{}: the PEM label is {:?}, not OPENSSH PRIVATE KEY",
                        path, p.label
                    ));
                }
                privshow::print(path, &p.body)
            });
        if let Err(e) = r {
            eprintln!("sshkeyv: {}", e);
            code = 1;
        }
    }
    code
}

fn cmd_show(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in args {
        let r = first_line(path)
            .and_then(|l| key::PublicKey::parse_line(&l))
            .and_then(|k| {
                if !k.algo.cert {
                    return Err(format!("{} is not a certificate", path));
                }
                let subject = k.subject_blob()?;
                let c = cert::Cert::parse(&k.blob, k.algo)?;
                show::show(path, &c, &subject)
            });
        if let Err(e) = r {
            eprintln!("sshkeyv: {}", e);
            code = 1;
        }
    }
    code
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
// The big command exists for the suite. RSA verification is one
// exponentiation and the curve code is a few thousand multiplications, so
// a defect in the bignum shows up as "every signature is invalid", which
// is indistinguishable from strictness. python's own integers are the
// oracle.
fn cmd_big(args: &[String]) -> i32 {
    let hex = |s: &String| -> Option<bignum::Nat> {
        let mut b = Vec::with_capacity((s.len() + 1) / 2);
        let s = if s.len() % 2 == 1 {
            format!("0{}", s)
        } else {
            s.clone()
        };
        for i in (0..s.len()).step_by(2) {
            b.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
        }
        Some(bignum::Nat::from_be(&b))
    };
    if args.len() < 3 {
        eprint!("{}", USAGE);
        return 2;
    }
    let (a, b) = match (hex(&args[1]), hex(&args[2])) {
        (Some(a), Some(b)) => (a, b),
        _ => {
            eprintln!("sshkeyv: big wants hex arguments");
            return 2;
        }
    };
    let m = args.get(3).and_then(hex);
    let out = |n: &bignum::Nat| {
        let w = (n.bits() + 7) / 8;
        println!("{}", fields::hex(&n.to_be(w.max(1)).unwrap()));
    };
    match args[0].as_str() {
        "add" => out(&a.add(&b)),
        "sub" => {
            if a.cmp(&b) == std::cmp::Ordering::Less {
                eprintln!("sshkeyv: sub would be negative");
                return 1;
            }
            out(&a.sub(&b))
        }
        "mul" => out(&a.mul(&b)),
        "div" => out(&a.divrem(&b).0),
        "rem" => out(&a.divrem(&b).1),
        "bits" => println!("{}", a.bits()),
        "modexp" => match m {
            Some(m) if !m.is_zero() => out(&a.modexp(&b, &m)),
            _ => {
                eprintln!("sshkeyv: modexp wants a non-zero modulus");
                return 2;
            }
        },
        "invmod" => match m {
            Some(m) if !m.is_zero() => out(&a.invmod_prime(&m)),
            _ => {
                eprintln!("sshkeyv: invmod wants a non-zero prime modulus");
                return 2;
            }
        },
        other => {
            eprintln!("sshkeyv: unknown big operation {}", other);
            return 2;
        }
    }
    0
}

fn cmd_hash(args: &[String]) -> i32 {
    let data = read_stdin();
    let d = match args.first().map(|s| s.as_str()) {
        Some("sha256") => fields::hex(&hash::sha256(&data)),
        Some("sha512") => fields::hex(&hash::sha512(&data)),
        Some("md5") => fields::hex(&hash::md5(&data)),
        Some("sha1") => fields::hex(&hash::sha1(&data)),
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
        "valid" => cmd_valid(&args[1..]),
        "authorises" => cmd_authorises(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "priv" => cmd_priv(&args[1..]),
        "show" => cmd_show(&args[1..]),
        "fp" => cmd_fp(&args[1..]),
        "fields" => cmd_fields(&args[1..]),
        "blob" => cmd_blob(&args[1..]),
        "big" => cmd_big(&args[1..]),
        "hash" => cmd_hash(&args[1..]),
        "b64" => cmd_b64(&args[1..]),
        other => {
            eprintln!("sshkeyv: unknown command {}", other);
            2
        }
    };
    std::process::exit(code);
}
