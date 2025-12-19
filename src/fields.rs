// `sshkeyv fields`: one "name<TAB>value" line per field, so a comparison
// can be made field by field.
//
// Field by field and not file by file. ssh-keygen -L and sshkeyv do not
// agree about indentation, blank lines or the order of anything, and a
// whole-output diff of two programs that format differently can only say
// "different". The suite reads these lines into a dictionary and asks
// about one name at a time.

use crate::cert::Cert;
use crate::key::{Material, PublicKey};

pub fn print(path: &str, k: &PublicKey) -> Result<(), String> {
    let f = |n: &str, v: &str| println!("{}\t{}\t{}", path, n, v);
    f("algorithm", k.algo.name);
    f("is-cert", if k.algo.cert { "yes" } else { "no" });
    f("plain-algorithm", k.algo.plain);
    f("blob-bytes", &k.blob.len().to_string());
    match &k.comment {
        Some(c) => f("comment", c),
        None => f("comment-absent", "yes"),
    }
    let m = k.material()?;
    // ssh-keygen prints the kind with -CERT appended for a certificate, in
    // the brackets at the end of its fingerprint line. It is the oracle, so
    // this is its spelling and not a tidier one.
    let kind = if k.algo.cert {
        format!("{}-CERT", m.label())
    } else {
        m.label().to_string()
    };
    f("kind", &kind);
    f("bits", &m.bits().to_string());
    match m {
        Material::Ed25519 { pk } => f("ed25519-pk", &hex(pk)),
        Material::Ecdsa { curve, point } => {
            f("ecdsa-curve", curve.name());
            f("ecdsa-point", &hex(point));
        }
        Material::Rsa { e, n, noncanonical } => {
            f("rsa-e", &hex(e));
            f("rsa-n", &hex(n));
            f("rsa-n-bits", &crate::key::bitlen(n).to_string());
            if noncanonical {
                f("rsa-mpint-noncanonical", "yes");
            }
        }
    }
    if k.algo.cert {
        cert_fields(path, &Cert::parse(&k.blob, k.algo)?)?;
    }
    Ok(())
}

fn cert_fields(path: &str, c: &Cert) -> Result<(), String> {
    let f = |n: &str, v: &str| println!("{}\t{}\t{}", path, n, v);
    f("cert-algorithm", c.algo.name);
    f("cert-subject-kind", c.subject.label());
    f("cert-subject-bits", &c.subject.bits().to_string());
    f("cert-nonce", &hex(c.nonce));
    f("cert-nonce-bytes", &c.nonce.len().to_string());
    f("cert-serial", &c.serial.to_string());
    f("cert-type", &c.cert_type.to_string());
    f("cert-type-name", c.type_name());
    f("cert-key-id", c.key_id);
    f("cert-principal-count", &c.principals.len().to_string());
    for (i, p) in c.principals.iter().enumerate() {
        f(&format!("cert-principal-{}", i), p);
    }
    f("cert-valid-after", &c.valid_after.to_string());
    f("cert-valid-before", &c.valid_before.to_string());
    f("cert-critical-count", &c.critical.len().to_string());
    for (i, o) in c.critical.iter().enumerate() {
        f(&format!("cert-critical-{}-name", i), o.name);
        f(&format!("cert-critical-{}-data", i), &hex(o.data));
        // An option whose data holds exactly one SSH string gets the
        // string too: that is how force-command and source-address are
        // specified, and it is what ssh-keygen -L prints beside the name.
        match o.as_string() {
            Some(Ok(s)) => f(
                &format!("cert-critical-{}-string", i),
                &String::from_utf8_lossy(s),
            ),
            Some(Err(_)) => f(&format!("cert-critical-{}-string", i), "<not a string>"),
            None => {}
        }
    }
    f("cert-extension-count", &c.extensions.len().to_string());
    for (i, o) in c.extensions.iter().enumerate() {
        f(&format!("cert-extension-{}-name", i), o.name);
        f(&format!("cert-extension-{}-data", i), &hex(o.data));
        match o.as_string() {
            Some(Ok(s)) => f(
                &format!("cert-extension-{}-string", i),
                &String::from_utf8_lossy(s),
            ),
            Some(Err(_)) => f(&format!("cert-extension-{}-string", i), "<not a string>"),
            None => {}
        }
    }
    f("cert-reserved-bytes", &c.reserved.len().to_string());
    f("cert-ca-algorithm", c.ca_algo()?);
    f("cert-ca-blob-bytes", &c.signature_key.len().to_string());
    f("cert-signature-algorithm", c.signature_algo()?);
    f("cert-signature-blob-bytes", &c.signature.len().to_string());
    f("cert-tbs-bytes", &c.tbs.len().to_string());
    Ok(())
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &c in b {
        s.push_str(&format!("{:02x}", c));
    }
    s
}
