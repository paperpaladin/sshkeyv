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
    Md5,
    Sha1,
    /// The Bubble Babble encoding of a SHA-1 digest, which ssh-keygen
    /// prints with -B rather than with -E.
    BubbleBabble,
}

impl Kind {
    pub fn from_name(s: &str) -> Option<Kind> {
        match s {
            "sha256" | "SHA256" => Some(Kind::Sha256),
            "md5" | "MD5" => Some(Kind::Md5),
            "sha1" | "SHA1" => Some(Kind::Sha1),
            "bubblebabble" => Some(Kind::BubbleBabble),
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
        Kind::Md5 => {
            // Colon-separated lower-case hex, which is the form a
            // pre-6.8 OpenSSH printed and the form old runbooks hold.
            let d = hash::md5(blob);
            let mut s = String::from("MD5:");
            for (i, b) in d.iter().enumerate() {
                if i > 0 {
                    s.push(':');
                }
                s.push_str(&format!("{:02x}", b));
            }
            s
        }
        Kind::Sha1 => {
            format!("SHA1:{}", crate::b64::encode_nopad(&hash::sha1(blob)))
        }
        // ssh-keygen -B prints this one bare, with no hash name in front
        // of it, so there is no prefix here either.
        Kind::BubbleBabble => bubblebabble(&hash::sha1(blob)),
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

/// The Bubble Babble encoding, from Antti Huima's 2000 specification and
/// as OpenSSH implements it in sshkey.c. Five characters per two input
/// bytes, with a rolling checksum in `seed` that makes a transposition of
/// two words visible.
///
/// The output is exactly as long as the input determines, and the Vec says
/// so: 1 + 6 * (rounds - 1) + 3 + 1 for an even-length digest. Writing it
/// with a rounds * 6 buffer, which is what OpenSSH does, would hold three
/// spare bytes for a SHA-1 digest and move the bounds check off the end of
/// the data.
fn bubblebabble(d: &[u8]) -> String {
    const VOWELS: &[u8; 6] = b"aeiouy";
    const CONSONANTS: &[u8; 17] = b"bcdfghklmnprstvzx";
    let rounds = d.len() / 2 + 1;
    let len = 1 + 6 * (rounds - 1) + 3 + 1;
    let mut out: Vec<u8> = Vec::with_capacity(len);
    let mut seed: usize = 1;
    out.push(b'x');
    for i in 0..rounds {
        if i + 1 < rounds || d.len() % 2 != 0 {
            let b0 = d[2 * i] as usize;
            out.push(VOWELS[((b0 >> 6 & 3) + seed) % 6]);
            out.push(CONSONANTS[b0 >> 2 & 15]);
            out.push(VOWELS[((b0 & 3) + seed / 6) % 6]);
            if i + 1 < rounds {
                let b1 = d[2 * i + 1] as usize;
                out.push(CONSONANTS[b1 >> 4 & 15]);
                out.push(b'-');
                out.push(CONSONANTS[b1 & 15]);
                seed = (seed * 5 + b0 * 7 + b1) % 36;
            }
        } else {
            out.push(VOWELS[seed % 6]);
            out.push(CONSONANTS[16]);
            out.push(VOWELS[seed / 6]);
        }
    }
    out.push(b'x');
    debug_assert_eq!(out.len(), len);
    debug_assert_eq!(out.capacity(), len);
    String::from_utf8(out).expect("bubblebabble emits ASCII only")
}
