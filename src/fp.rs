// Fingerprints, in the forms ssh-keygen prints them.
//
// The whole line is reproduced, not just the digest, because the line is
// what people read and compare by eye and because reproducing it exactly
// gives the suite a string comparison against ssh-keygen -l with nothing
// to interpret. Its shape is:
//
//     BITS HASH:DIGEST COMMENT (KIND)
//
// with the literal words "no comment" where the key line had no comment
// field. That spelling is ssh-keygen's and is ambiguous: a key whose
// comment is the words "no comment" prints identically. sshkeyv copies the
// ambiguity rather than improving on it, because the point of this command
// is to be diffable against the oracle.

use crate::hash;
use crate::key::PublicKey;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Sha256,
}

impl Kind {
    pub fn from_name(s: &str) -> Option<Kind> {
        match s {
            "sha256" | "SHA256" => Some(Kind::Sha256),
            _ => None,
        }
    }
}

/// The digest part, with its prefix: "SHA256:xxxx".
pub fn digest(kind: Kind, blob: &[u8]) -> String {
    match kind {
        Kind::Sha256 => {
            format!("SHA256:{}", crate::b64::encode_nopad(&hash::sha256(blob)))
        }
    }
}

/// The whole line ssh-keygen -l prints.
pub fn line(kind: Kind, k: &PublicKey) -> Result<String, String> {
    let m = k.material()?;
    let subject = k.subject_blob()?;
    let label = if k.algo.cert {
        format!("{}-CERT", m.label())
    } else {
        m.label().to_string()
    };
    Ok(format!(
        "{} {} {} ({})",
        m.bits(),
        digest(kind, &subject),
        k.comment.as_deref().unwrap_or("no comment"),
        label
    ))
}
