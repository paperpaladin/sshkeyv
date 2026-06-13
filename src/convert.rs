// Re-encoding a public key: the RFC 4716 container and the PKCS8
// SubjectPublicKeyInfo, in both directions.
//
// A second encoding of the same key is worth having because it gives the
// two formats something to disagree about. ssh-keygen -e and -i are the
// oracle in both directions and the PKCS8 bytes are compared byte for
// byte, which is the strongest comparison in this project: there is
// exactly one right answer and ssh-keygen prints it.

use crate::b64;
use crate::der;
use crate::key::{algo, Curve, Material, PublicKey};
use crate::wire::{Reader, Writer};

/// The OID of each key type's algorithm, and for EC the curve OID that
/// follows it.
fn rsa_oid() -> Vec<u8> {
    der::oid(&[1, 2, 840, 113549, 1, 1, 1])
}
fn ec_oid() -> Vec<u8> {
    der::oid(&[1, 2, 840, 10045, 2, 1])
}
fn curve_oid(c: Curve) -> Vec<u8> {
    match c {
        Curve::P256 => der::oid(&[1, 2, 840, 10045, 3, 1, 7]),
        Curve::P384 => der::oid(&[1, 3, 132, 0, 34]),
        Curve::P521 => der::oid(&[1, 3, 132, 0, 35]),
    }
}
fn ed25519_oid() -> Vec<u8> {
    der::oid(&[1, 3, 101, 112])
}

/// The DER SubjectPublicKeyInfo for a key.
pub fn spki(m: &Material) -> Vec<u8> {
    match m {
        Material::Rsa { e, n, .. } => {
            let mut alg = rsa_oid();
            alg.extend_from_slice(&der::null());
            let mut key = der::integer(n);
            key.extend_from_slice(&der::integer(e));
            let mut body = der::sequence(&alg);
            body.extend_from_slice(&der::bitstring(&der::sequence(&key)));
            der::sequence(&body)
        }
        Material::Ecdsa { curve, point } => {
            let mut alg = ec_oid();
            alg.extend_from_slice(&curve_oid(*curve));
            let mut body = der::sequence(&alg);
            body.extend_from_slice(&der::bitstring(point));
            der::sequence(&body)
        }
        // ssh-keygen refuses to write this one: do_convert_to_pkcs8 says
        // "unsupported key type ED25519". It is a perfectly ordinary
        // SubjectPublicKeyInfo under RFC 8410 and openssl reads it, so
        // sshkeyv writes it and openssl is the oracle instead.
        Material::Ed25519 { pk } => {
            let body = {
                let mut b = der::sequence(&ed25519_oid());
                b.extend_from_slice(&der::bitstring(pk));
                b
            };
            der::sequence(&body)
        }
    }
}

/// PEM-wrap a DER SubjectPublicKeyInfo, 64 base64 characters per line,
/// which is what openssl and ssh-keygen both write.
pub fn pkcs8_pem(der_bytes: &[u8]) -> String {
    let b = b64::encode(der_bytes);
    let mut s = String::from("-----BEGIN PUBLIC KEY-----\n");
    for i in (0..b.len()).step_by(64) {
        s.push_str(&b[i..(i + 64).min(b.len())]);
        s.push('\n');
    }
    s.push_str("-----END PUBLIC KEY-----\n");
    s
}

/// Read a SubjectPublicKeyInfo back into an SSH public key blob.
pub fn from_spki(d: &[u8]) -> Result<Vec<u8>, String> {
    let outer = der::expect(d, 0x30, "SubjectPublicKeyInfo")?;
    let alg = der::read(outer.body)?;
    if alg.tag != 0x30 {
        return Err("the algorithm field is not a SEQUENCE".to_string());
    }
    let rest = &outer.body[alg.total..];
    let bits = der::read(rest)?;
    if bits.tag != 0x03 {
        return Err("the key field is not a BIT STRING".to_string());
    }
    if bits.total != rest.len() {
        return Err("trailing bytes after the BIT STRING".to_string());
    }
    if bits.body.is_empty() || bits.body[0] != 0 {
        return Err(
            "the BIT STRING has unused bits, which a key never does"
                .to_string(),
        );
    }
    let key = &bits.body[1..];

    let oid = der::read(alg.body)?;
    if oid.tag != 0x06 {
        return Err("the algorithm identifier is not an OID".to_string());
    }
    let params = &alg.body[oid.total..];
    let mut w = Writer::new();
    if oid.body == &der::oid(&[1, 2, 840, 113549, 1, 1, 1])[2..] {
        if params != der::null().as_slice() {
            return Err(
                "an RSA algorithm identifier must have NULL parameters"
                    .to_string(),
            );
        }
        let seq = der::expect(key, 0x30, "RSAPublicKey")?;
        let n = der::read(seq.body)?;
        if n.tag != 0x02 {
            return Err("the modulus is not an INTEGER".to_string());
        }
        let e = der::read(&seq.body[n.total..])?;
        if e.tag != 0x02 {
            return Err("the exponent is not an INTEGER".to_string());
        }
        if n.total + e.total != seq.body.len() {
            return Err("trailing bytes in RSAPublicKey".to_string());
        }
        w.string(b"ssh-rsa");
        w.mpint(e.body);
        w.mpint(n.body);
        return Ok(w.b);
    }
    if oid.body == &der::oid(&[1, 2, 840, 10045, 2, 1])[2..] {
        let cp = der::read(params)?;
        if cp.tag != 0x06 || cp.total != params.len() {
            return Err(
                "an EC algorithm identifier wants exactly one curve OID"
                    .to_string(),
            );
        }
        let curve = [Curve::P256, Curve::P384, Curve::P521]
            .into_iter()
            .find(|c| curve_oid(*c)[2..] == *cp.body);
        let curve = match curve {
            Some(c) => c,
            None => {
                return Err(
                    "the curve OID is not one of the three NIST prime \
                     curves SSH uses"
                        .to_string(),
                )
            }
        };
        let want = 1 + 2 * ((curve.bits() as usize + 7) / 8);
        if key.len() != want || key[0] != 4 {
            return Err(format!(
                "the EC point is {} bytes starting 0x{:02x}; want {} bytes \
                 starting 0x04",
                key.len(),
                key.first().copied().unwrap_or(0),
                want
            ));
        }
        w.string(format!("ecdsa-sha2-{}", curve.name()).as_bytes());
        w.string(curve.name().as_bytes());
        w.string(key);
        return Ok(w.b);
    }
    if oid.body == &der::oid(&[1, 3, 101, 112])[2..] {
        if !params.is_empty() {
            return Err(
                "an Ed25519 algorithm identifier has no parameters"
                    .to_string(),
            );
        }
        if key.len() != 32 {
            return Err(format!(
                "an Ed25519 key is 32 bytes, this is {}",
                key.len()
            ));
        }
        w.string(b"ssh-ed25519");
        w.string(key);
        return Ok(w.b);
    }
    Err("unknown public key algorithm OID".to_string())
}

/// The RFC 4716 block. The Comment header is the key's own comment; the
/// one ssh-keygen writes names the local user and host, so the two cannot
/// be compared as text and the suite compares the base64 payload and the
/// header structure instead.
pub fn rfc4716(k: &PublicKey) -> String {
    let mut s = String::from("---- BEGIN SSH2 PUBLIC KEY ----\n");
    if let Some(c) = &k.comment {
        // RFC 4716 says a header value is quoted when it holds anything
        // other than a printable run, and ssh-keygen always quotes the
        // comment. A line longer than 72 characters is continued with a
        // trailing backslash, which is the rule a hand-written reader
        // forgets.
        let header = format!("Comment: \"{}\"", c.replace('\\', "\\\\"));
        for chunk in wrap_header(&header) {
            s.push_str(&chunk);
            s.push('\n');
        }
    }
    let b = b64::encode(&k.blob);
    for i in (0..b.len()).step_by(70) {
        s.push_str(&b[i..(i + 70).min(b.len())]);
        s.push('\n');
    }
    s.push_str("---- END SSH2 PUBLIC KEY ----\n");
    s
}

/// Split a header line so that no line exceeds 72 characters including
/// the continuation backslash.
fn wrap_header(h: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest: &str = h;
    while rest.len() > 72 {
        out.push(format!("{}\\", &rest[..71]));
        rest = &rest[71..];
    }
    out.push(rest.to_string());
    out
}

// shortcut: of the RFC 4716 headers only Comment is interpreted. The
// ceiling is a block carrying Subject or an x- header, whose value is
// parsed for the continuation rule and then dropped. Nothing OpenSSH
// writes has one.
/// Read an RFC 4716 block into a key blob and its Comment header.
pub fn from_rfc4716(text: &str) -> Result<(Vec<u8>, Option<String>), String> {
    let mut lines = text.lines();
    let mut started = false;
    for l in lines.by_ref() {
        if l.trim() == "---- BEGIN SSH2 PUBLIC KEY ----" {
            started = true;
            break;
        }
        if !l.trim().is_empty() {
            return Err(format!("expected the BEGIN line, got {:?}", l));
        }
    }
    if !started {
        return Err("no ---- BEGIN SSH2 PUBLIC KEY ---- line".to_string());
    }
    let mut headers: Vec<String> = Vec::new();
    let mut b64text = String::new();
    let mut pending: Option<String> = None;
    let mut closed = false;
    let mut in_body = false;
    for l in lines {
        let t = l.trim_end_matches(['\r', '\n']);
        if t.trim() == "---- END SSH2 PUBLIC KEY ----" {
            closed = true;
            break;
        }
        if let Some(p) = pending.take() {
            // A continued header line. The continuation is joined with no
            // separator, which is what RFC 4716 section 3.3 says.
            let (frag, more) = split_continuation(t);
            let joined = format!("{}{}", p, frag);
            if more {
                pending = Some(joined);
            } else {
                headers.push(joined);
            }
            continue;
        }
        if !in_body && t.contains(": ") {
            let (frag, more) = split_continuation(t);
            if more {
                pending = Some(frag.to_string());
            } else {
                headers.push(frag.to_string());
            }
            continue;
        }
        in_body = true;
        b64text.push_str(t.trim());
    }
    if pending.is_some() {
        return Err(
            "the block ends inside a continued header line".to_string()
        );
    }
    if !closed {
        return Err("no ---- END SSH2 PUBLIC KEY ---- line".to_string());
    }
    let blob = b64::decode(b64text.as_bytes())?;
    // The blob must name a key algorithm sshkeyv knows, or the container
    // read cleanly and produced something that is not a key.
    let mut r = Reader::new(&blob, "rfc4716 blob");
    let name = r.text()?;
    if algo(name).is_none() {
        return Err(format!("unknown key algorithm {:?} in the block", name));
    }
    let comment = headers
        .iter()
        .find(|h| h.starts_with("Comment: "))
        .map(|h| {
            let v = &h["Comment: ".len()..];
            v.trim_matches('"').to_string()
        });
    Ok((blob, comment))
}

fn split_continuation(l: &str) -> (&str, bool) {
    match l.strip_suffix('\\') {
        Some(s) => (s, true),
        None => (l, false),
    }
}
