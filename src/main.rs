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
mod convert;
mod counts;
mod der;
mod ecdsa;
mod ed25519;
mod fields;
mod fp;
mod hash;
mod show;
mod sshsig;
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
  verify [--ca FILE]... [FILE...]
                  check the CA signature over each certificate, and with
                  --ca that the signer is one of the keys given
  sigverify -s SIGFILE -n NAMESPACE [--key FILE] [MSGFILE]
                  check a detached SSHSIG signature; the message comes
                  from MSGFILE or from stdin
  priv [FILE...]  the private key container header, without decrypting
  show [FILE...]  certificate fields, the block ssh-keygen -L prints
  fp [-E HASH] [FILE...]
                  fingerprints, the line ssh-keygen -l prints
  convert -m FORMAT FILE
                  re-encode a public key as rfc4716, pkcs8 or openssh
  unknown [FILE...]  options and extensions the local OpenSSH does not
                  recognise; exits 4 when a CRITICAL one is unrecognised
  check [FILE...]   parse each file fully; print ok or the refusal
  counts [FILE...]  how many of each construct the files hold
  fields [FILE...]  one \"path name value\" line per field, tab separated
  blob [FILE...]  the top-level SSH strings of a blob: index, offset,
                  length, and the bytes as text or hex
  curve NAME      the curve parameters sshkeyv holds, as hex
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

fn cmd_sigverify(args: &[String]) -> i32 {
    let mut sigfile: Option<&String> = None;
    let mut namespace: Option<&String> = None;
    let mut keyfile: Option<&String> = None;
    let mut msgfile: Option<&String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-s" => sigfile = it.next(),
            "-n" => namespace = it.next(),
            "--key" => keyfile = it.next(),
            other if other.starts_with('-') => {
                eprintln!("sshkeyv: unknown option {}", other);
                return 2;
            }
            _ => msgfile = Some(a),
        }
    }
    let (sigfile, namespace) = match (sigfile, namespace) {
        (Some(s), Some(n)) => (s, n),
        _ => {
            eprintln!("sshkeyv: sigverify wants -s SIGFILE and -n NAMESPACE");
            return 2;
        }
    };
    let text = match std::fs::read_to_string(sigfile) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("sshkeyv: {}: {}", sigfile, e);
            return 1;
        }
    };
    let pem = match pem::parse(&text) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sshkeyv: {}: {}", sigfile, e);
            return 1;
        }
    };
    if pem.label != "SSH SIGNATURE" {
        eprintln!(
            "sshkeyv: {}: the PEM label is {:?}, not SSH SIGNATURE",
            sigfile, pem.label
        );
        return 1;
    }
    let s = match sshsig::Sshsig::parse(&pem.body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sshkeyv: {}: {}", sigfile, e);
            return 1;
        }
    };
    let msg = match msgfile {
        Some(p) => match std::fs::read(p) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("sshkeyv: {}: {}", p, e);
                return 1;
            }
        },
        None => read_stdin(),
    };

    println!("{}: version {}", sigfile, s.version);
    println!("{}: namespace in the file {}", sigfile, s.namespace);
    println!("{}: hash algorithm {}", sigfile, s.hash_algorithm);
    println!(
        "{}: signer {}",
        sigfile,
        fp::digest(fp::Kind::Sha256, s.public_key)
    );

    // The namespace must be the one asked for. It is inside the signed
    // blob, so a verifier that takes it from the file and signs over what
    // it took accepts a signature made for any purpose.
    if s.namespace != namespace.as_str() {
        println!(
            "{}: NAMESPACE MISMATCH: the file says {} and {} was asked for",
            sigfile, s.namespace, namespace
        );
        return 3;
    }
    // An explicitly named key must be the signer. Without --key the
    // signature is only checked against the key it names, which proves the
    // file is self-consistent and nothing about who wrote it. That is what
    // ssh-keygen -Y check-novalidate does and it says so too.
    if let Some(kf) = keyfile {
        let line = match first_line(kf) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sshkeyv: {}", e);
                return 1;
            }
        };
        let k = match key::PublicKey::parse_line(&line) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("sshkeyv: {}: {}", kf, e);
                return 1;
            }
        };
        let want = match k.subject_blob() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("sshkeyv: {}: {}", kf, e);
                return 1;
            }
        };
        if want != s.public_key {
            println!(
                "{}: SIGNER MISMATCH: the file was signed by {} and {} holds {}",
                sigfile,
                fp::digest(fp::Kind::Sha256, s.public_key),
                kf,
                fp::digest(fp::Kind::Sha256, &want)
            );
            return 3;
        }
    } else {
        println!(
            "{}: no --key given, so this checks the file against the key it \
             names and says nothing about who signed it",
            sigfile
        );
    }

    let blob = match s.signed_blob(&msg) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sshkeyv: {}: {}", sigfile, e);
            return 1;
        }
    };
    match sig::verify(s.public_key, s.signature, &blob) {
        sig::Outcome::Good => {
            println!("{}: signature good over {} bytes of message",
                     sigfile, msg.len());
            0
        }
        sig::Outcome::Bad(why) => {
            println!("{}: SIGNATURE BAD: {}", sigfile, why);
            3
        }
        sig::Outcome::NoVerifier(why) => {
            println!("{}: NO VERIFIER: {}", sigfile, why);
            5
        }
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    // --ca is the difference between "this certificate is internally
    // consistent" and "this certificate was issued by my CA". Without it,
    // verify proves the signature matches the CA key the certificate
    // names, and a certificate names its own CA, so anybody can mint one
    // that verifies. That is the single most important thing about this
    // command and it prints a line saying so when no --ca is given.
    let mut trusted: Vec<Vec<u8>> = Vec::new();
    let mut paths: Vec<&String> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--ca" {
            let cafile = match it.next() {
                Some(f) => f,
                None => {
                    eprintln!("sshkeyv: --ca wants a file");
                    return 2;
                }
            };
            // A CA file may hold several keys, one per line, which is how
            // TrustedUserCAKeys is written.
            let text = match std::fs::read_to_string(cafile) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("sshkeyv: {}: {}", cafile, e);
                    return 1;
                }
            };
            let mut found = 0;
            for line in text.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') {
                    continue;
                }
                match key::PublicKey::parse_line(l) {
                    Ok(k) => {
                        if k.algo.cert {
                            eprintln!(
                                "sshkeyv: {}: a CA key must be a plain key, \
                                 not a certificate",
                                cafile
                            );
                            return 1;
                        }
                        trusted.push(k.blob);
                        found += 1;
                    }
                    Err(e) => {
                        eprintln!("sshkeyv: {}: {}", cafile, e);
                        return 1;
                    }
                }
            }
            if found == 0 {
                eprintln!("sshkeyv: {}: no keys in it", cafile);
                return 1;
            }
        } else {
            paths.push(a);
        }
    }
    let args: Vec<&String> = paths;
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    if trusted.is_empty() {
        println!(
            "note: no --ca given, so this checks each certificate against \
             the CA key it names itself and says nothing about who issued it"
        );
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
            sig::Outcome::Good => {
                println!(
                    "{}: signature good, {} over {} bytes by the {} CA key \
                     {}",
                    path,
                    sa,
                    c.tbs.len(),
                    ca,
                    fp::digest(fp::Kind::Sha256, c.signature_key)
                );
                // Trust is a separate answer from validity, so it gets a
                // separate exit status: 4, the same one an expired
                // certificate gets, because in both cases the file parsed
                // and verified and the answer to the question is no.
                if !trusted.is_empty()
                    && !trusted.iter().any(|t| t == c.signature_key)
                {
                    println!(
                        "{}: UNTRUSTED CA: the signer is not one of the {} \
                         keys given with --ca",
                        path,
                        trusted.len()
                    );
                    code = code.max(4);
                }
            }
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

/// Read a public key from any of the three containers, detected from the
/// bytes rather than from the name.
fn read_any_pubkey(path: &str) -> Result<key::PublicKey, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {}", path, e))?;
    let trimmed = text.trim_start();
    if trimmed.starts_with("---- BEGIN SSH2 PUBLIC KEY ----") {
        let (blob, comment) = convert::from_rfc4716(&text)
            .map_err(|e| format!("{}: {}", path, e))?;
        let line = format!(
            "{} {}{}",
            {
                let mut r = wire::Reader::new(&blob, "rfc4716 blob");
                r.text().map_err(|e| format!("{}: {}", path, e))?.to_string()
            },
            b64::encode(&blob),
            match &comment {
                Some(c) => format!(" {}", c),
                None => String::new(),
            }
        );
        return key::PublicKey::parse_line(&line)
            .map_err(|e| format!("{}: {}", path, e));
    }
    if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        let p = pem::parse(&text).map_err(|e| format!("{}: {}", path, e))?;
        if p.label != "PUBLIC KEY" {
            return Err(format!("{}: the PEM label is {:?}", path, p.label));
        }
        let blob = convert::from_spki(&p.body)
            .map_err(|e| format!("{}: {}", path, e))?;
        let name = {
            let mut r = wire::Reader::new(&blob, "spki blob");
            r.text().map_err(|e| format!("{}: {}", path, e))?.to_string()
        };
        let line = format!("{} {}", name, b64::encode(&blob));
        return key::PublicKey::parse_line(&line)
            .map_err(|e| format!("{}: {}", path, e));
    }
    key::PublicKey::parse_line(&first_line(path)?)
        .map_err(|e| format!("{}: {}", path, e))
}

/// Parse a file as far as its container allows and return a one-line
/// description, or the reason it will not parse. Everything that can be
/// read is read: a certificate's options lists, a private container's
/// section when it is not encrypted, an SSHSIG's fields. Reading only the
/// outer layer and reporting ok is how a check command comes to pass on a
/// file nothing else can use.
fn check_one(path: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {}", path, e))?;
    let trimmed = text.trim_start();
    if trimmed.starts_with(concat!("-----BEGIN OPENSSH ", "PRIVATE KEY-----")) {
        let p = pem::parse(&text).map_err(|e| format!("{}: {}", path, e))?;
        let c = privkey::Container::parse(&p.body)
            .map_err(|e| format!("{}: {}", path, e))?;
        if c.encrypted() {
            return Ok(format!(
                "{}: ok, OpenSSH private key, {} with {} at {} rounds, the \
                 private section not parsed because it is encrypted",
                path,
                c.cipher,
                c.kdf,
                c.rounds.unwrap_or(0)
            ));
        }
        let block = privkey::cipher_block(c.cipher).unwrap_or(8);
        let pv = privkey::Private::parse(c.private, block)
            .map_err(|e| format!("{}: {}", path, e))?;
        if pv.public != c.public[0] {
            return Err(format!(
                "{}: the two copies of the public key disagree",
                path
            ));
        }
        return Ok(format!(
            "{}: ok, OpenSSH private key, {}, unencrypted",
            path, pv.keytype
        ));
    }
    if trimmed.starts_with("-----BEGIN SSH SIGNATURE-----") {
        let p = pem::parse(&text).map_err(|e| format!("{}: {}", path, e))?;
        let s = sshsig::Sshsig::parse(&p.body)
            .map_err(|e| format!("{}: {}", path, e))?;
        // The signed blob construction is part of the parse: it is where
        // an unknown hash algorithm shows up.
        s.signed_blob(b"")
            .map_err(|e| format!("{}: {}", path, e))?;
        return Ok(format!(
            "{}: ok, SSHSIG version {}, namespace {}, hash {}",
            path, s.version, s.namespace, s.hash_algorithm
        ));
    }
    let k = read_any_pubkey(path)?;
    let m = k.material().map_err(|e| format!("{}: {}", path, e))?;
    if !k.algo.cert {
        return Ok(format!(
            "{}: ok, {} public key, {} bits",
            path,
            m.label(),
            m.bits()
        ));
    }
    let c = cert::Cert::parse(&k.blob, k.algo)
        .map_err(|e| format!("{}: {}", path, e))?;
    // Every option's data is read here even though nothing below uses it,
    // because an option whose data is not a single string is a defect this
    // command is the right place to find.
    for (which, list) in [("critical option", &c.critical),
                          ("extension", &c.extensions)] {
        for o in list.iter() {
            if let Some(Err(e)) = o.as_string() {
                return Err(format!(
                    "{}: the {} {} has data that is not a single string: {}",
                    path, which, o.name, e
                ));
            }
        }
    }
    Ok(format!(
        "{}: ok, {} certificate for {}, {} principals, {} critical \
         options, {} extensions, signed with {}",
        path,
        c.type_name(),
        c.key_id,
        c.principals.len(),
        c.critical.len(),
        c.extensions.len(),
        c.signature_algo().map_err(|e| format!("{}: {}", path, e))?
    ))
}

// `unknown` answers the question behind a certificate that fails closed:
// which names in it does the software at the other end not know.
//
// The set sshkeyv compares against is the set the LOCAL OpenSSH's
// ssh-keygen prints bare rather than as UNKNOWN, which is measurable:
// t/unknowncmp.py probes the installed ssh-keygen with a synthetic
// certificate per name and reads back which ones it recognises.
//
// That set is not sshd's accept list. They are separate code paths in
// OpenSSH and there is no sshd on this machine to measure the other one,
// so the README says which question is answered and which is not. The
// original plan was a --version N flag carrying a per-release table; it is
// marked BLOCKED in PLAN.md, because the only source for such a table here
// would be memory.
fn cmd_unknown(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in args {
        let (k, _) = match read_cert(path) {
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
        let mut said = false;
        for o in &c.critical {
            if !show::STRING_CRITICAL.contains(&o.name)
                && !show::FLAG_CRITICAL.contains(&o.name)
            {
                println!(
                    "{}: critical option {} is not recognised; a server \
                     that does not understand a critical option REFUSES \
                     the certificate",
                    path, o.name
                );
                said = true;
                code = code.max(4);
            }
        }
        for o in &c.extensions {
            if !show::FLAG_EXTENSIONS.contains(&o.name) {
                println!(
                    "{}: extension {} is not recognised; a server ignores \
                     an extension it does not understand, so the \
                     permission it was meant to grant is simply absent",
                    path, o.name
                );
                said = true;
            }
        }
        if !said {
            println!(
                "{}: every critical option and extension is recognised",
                path
            );
        }
    }
    code
}

fn cmd_check(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let mut code = 0;
    for path in args {
        match check_one(path) {
            Ok(line) => println!("{}", line),
            Err(e) => {
                println!("{}: REFUSED: {}", path, e);
                code = 1;
            }
        }
    }
    code
}

fn cmd_counts(args: &[String]) -> i32 {
    if args.is_empty() {
        eprint!("{}", USAGE);
        return 2;
    }
    let now = time::now();
    let mut c = counts::Counts::default();
    for path in args {
        c.add_file(path, now);
    }
    for (k, v) in &c.n {
        println!("{}\t{}", k, v);
    }
    0
}

fn cmd_convert(args: &[String]) -> i32 {
    let mut format: Option<&String> = None;
    let mut path: Option<&String> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "-m" {
            format = it.next();
        } else {
            path = Some(a);
        }
    }
    let (format, path) = match (format, path) {
        (Some(f), Some(p)) => (f, p),
        _ => {
            eprintln!("sshkeyv: convert wants -m FORMAT and a file");
            return 2;
        }
    };
    let k = match read_any_pubkey(path) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("sshkeyv: {}", e);
            return 1;
        }
    };
    match format.as_str() {
        "rfc4716" => print!("{}", convert::rfc4716(&k)),
        "pkcs8" => {
            let m = match k.material() {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("sshkeyv: {}: {}", path, e);
                    return 1;
                }
            };
            print!("{}", convert::pkcs8_pem(&convert::spki(&m)));
        }
        "openssh" => {
            println!(
                "{} {}{}",
                k.algo.name,
                b64::encode(&k.blob),
                match &k.comment {
                    Some(c) => format!(" {}", c),
                    None => String::new(),
                }
            );
        }
        other => {
            eprintln!(
                "sshkeyv: unknown format {}; want rfc4716, pkcs8 or openssh",
                other
            );
            return 2;
        }
    }
    0
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
// The curve command exists for the suite. A mistyped curve constant does
// not crash and does not produce a wrong answer: it produces a refusal
// with a plausible message, which is the hardest kind of defect to see
// from the outside. Writing the P-521 group order with one hex digit
// missing divided it by sixteen and every P-521 signature was then
// reported as having an r or s above the group order.
fn cmd_curve(args: &[String]) -> i32 {
    let name = match args.first() {
        Some(n) => n.as_str(),
        None => {
            eprint!("{}", USAGE);
            return 2;
        }
    };
    let c = match key::Curve::from_name(name) {
        Some(c) => c,
        None => {
            eprintln!("sshkeyv: unknown curve {}", name);
            return 2;
        }
    };
    let pr = ecdsa::params(c);
    let w = pr.bytes;
    let put = |label: &str, n: &bignum::Nat| {
        println!("{}\t{}\t{}", name, label, fields::hex(&n.to_be(w).unwrap()))
    };
    println!("{}\tbytes\t{}", name, w);
    println!("{}\tfield-bits\t{}", name, pr.p.bits());
    println!("{}\torder-bits\t{}", name, pr.n.bits());
    put("p", &pr.p);
    put("n", &pr.n);
    put("b", &pr.b);
    put("gx", &pr.gx);
    put("gy", &pr.gy);
    0
}

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
        "sigverify" => cmd_sigverify(&args[1..]),
        "priv" => cmd_priv(&args[1..]),
        "show" => cmd_show(&args[1..]),
        "fp" => cmd_fp(&args[1..]),
        "unknown" => cmd_unknown(&args[1..]),
        "check" => cmd_check(&args[1..]),
        "counts" => cmd_counts(&args[1..]),
        "convert" => cmd_convert(&args[1..]),
        "fields" => cmd_fields(&args[1..]),
        "blob" => cmd_blob(&args[1..]),
        "curve" => cmd_curve(&args[1..]),
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
