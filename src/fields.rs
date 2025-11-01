// `sshkeyv fields`: one "name<TAB>value" line per field, so a comparison
// can be made field by field.
//
// Field by field and not file by file. ssh-keygen -L and sshkeyv do not
// agree about indentation, blank lines or the order of anything, and a
// whole-output diff of two programs that format differently can only say
// "different". The suite reads these lines into a dictionary and asks
// about one name at a time.

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
    Ok(())
}

pub fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &c in b {
        s.push_str(&format!("{:02x}", c));
    }
    s
}
