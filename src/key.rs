// Public key algorithm names, and the key material behind each one.
//
// The algorithm name appears twice in every file: once in clear text at
// the start of the line and once as the first string inside the base64
// blob. They have to agree. A hand-edited key line where they do not is
// read differently by different programs, which is the whole reason the
// check is here and not an afterthought.

use crate::wire::{Reader, Res};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Curve {
    P256,
    P384,
    P521,
}

impl Curve {
    pub fn name(&self) -> &'static str {
        match self {
            Curve::P256 => "nistp256",
            Curve::P384 => "nistp384",
            Curve::P521 => "nistp521",
        }
    }
    pub fn bits(&self) -> u32 {
        match self {
            Curve::P256 => 256,
            Curve::P384 => 384,
            Curve::P521 => 521,
        }
    }
    pub fn from_name(s: &str) -> Option<Curve> {
        match s {
            "nistp256" => Some(Curve::P256),
            "nistp384" => Some(Curve::P384),
            "nistp521" => Some(Curve::P521),
            _ => None,
        }
    }
}

/// The key material, as it comes off the wire. The byte slices borrow the
/// blob, so nothing is copied and nothing is rounded up.
#[derive(Clone, Debug)]
pub enum Material<'a> {
    Ed25519 {
        pk: &'a [u8],
    },
    Ecdsa {
        curve: Curve,
        /// The uncompressed point, 0x04 followed by X and Y.
        point: &'a [u8],
    },
    Rsa {
        e: &'a [u8],
        n: &'a [u8],
        /// True when either mpint carried a redundant leading zero octet.
        /// ssh-keygen reads such a key, so sshkeyv does too and says so.
        noncanonical: bool,
    },
}

impl<'a> Material<'a> {
    /// What ssh-keygen prints in its fingerprint line and after the
    /// fingerprint in a certificate dump.
    pub fn label(&self) -> &'static str {
        match self {
            Material::Ed25519 { .. } => "ED25519",
            Material::Ecdsa { .. } => "ECDSA",
            Material::Rsa { .. } => "RSA",
        }
    }

    /// The bit count ssh-keygen prints first on a fingerprint line. For RSA
    /// it is the bit length of the modulus, so a 2048-bit key whose modulus
    /// happens to have a short top byte would print fewer; that does not
    /// happen for a generated key but the rule is the modulus and not the
    /// requested size.
    pub fn bits(&self) -> u32 {
        match self {
            Material::Ed25519 { .. } => 256,
            Material::Ecdsa { curve, .. } => curve.bits(),
            Material::Rsa { n, .. } => bitlen(n),
        }
    }
}

/// Bit length of a big-endian unsigned integer with no leading zero octets.
pub fn bitlen(n: &[u8]) -> u32 {
    let mut i = 0;
    while i < n.len() && n[i] == 0 {
        i += 1;
    }
    if i == n.len() {
        return 0;
    }
    (n.len() - i) as u32 * 8 - n[i].leading_zeros()
}

/// A key algorithm name, split into what it says about the key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Algo {
    pub name: &'static str,
    /// True for the -cert-v01@openssh.com names.
    pub cert: bool,
    /// The name of the plain key algorithm this certificate wraps, or the
    /// name itself for a plain key.
    pub plain: &'static str,
}

const ALGOS: &[Algo] = &[
    Algo { name: "ssh-ed25519", cert: false, plain: "ssh-ed25519" },
    Algo { name: "ssh-rsa", cert: false, plain: "ssh-rsa" },
    Algo { name: "ecdsa-sha2-nistp256", cert: false, plain: "ecdsa-sha2-nistp256" },
    Algo { name: "ecdsa-sha2-nistp384", cert: false, plain: "ecdsa-sha2-nistp384" },
    Algo { name: "ecdsa-sha2-nistp521", cert: false, plain: "ecdsa-sha2-nistp521" },
    Algo {
        name: "ssh-ed25519-cert-v01@openssh.com",
        cert: true,
        plain: "ssh-ed25519",
    },
    Algo {
        name: "ssh-rsa-cert-v01@openssh.com",
        cert: true,
        plain: "ssh-rsa",
    },
    Algo {
        name: "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        cert: true,
        plain: "ecdsa-sha2-nistp256",
    },
    Algo {
        name: "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        cert: true,
        plain: "ecdsa-sha2-nistp384",
    },
    Algo {
        name: "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        cert: true,
        plain: "ecdsa-sha2-nistp521",
    },
];

pub fn algo(name: &str) -> Option<Algo> {
    ALGOS.iter().find(|a| a.name == name).copied()
}

/// Read the key material that follows an algorithm name inside a blob. The
/// reader is positioned after the name. Certificates call this too, after
/// the nonce, because a certificate carries its subject key inline rather
/// than as a nested blob.
pub fn material<'a>(r: &mut Reader<'a>, plain: &str) -> Res<Material<'a>> {
    match plain {
        "ssh-ed25519" => {
            let pk = r.string()?;
            if pk.len() != 32 {
                return Err(format!(
                    "ed25519 public key is {} bytes, not 32",
                    pk.len()
                ));
            }
            Ok(Material::Ed25519 { pk })
        }
        "ssh-rsa" => {
            let (e, ce) = r.mpint_nc()?;
            let (n, cn) = r.mpint_nc()?;
            let noncanonical = !ce || !cn;
            if n.is_empty() {
                return Err("rsa modulus is empty".to_string());
            }
            if e.is_empty() {
                return Err("rsa exponent is empty".to_string());
            }
            Ok(Material::Rsa { e, n, noncanonical })
        }
        _ => {
            let curve = match Curve::from_name(
                plain.strip_prefix("ecdsa-sha2-").unwrap_or(""),
            ) {
                Some(c) => c,
                None => return Err(format!("unknown key algorithm {}", plain)),
            };
            let named = r.text()?;
            if named != curve.name() {
                return Err(format!(
                    "ecdsa curve name {} inside the blob does not match {} \
                     in the algorithm name",
                    named,
                    curve.name()
                ));
            }
            let point = r.string()?;
            let want = 1 + 2 * ((curve.bits() as usize + 7) / 8);
            if point.len() != want {
                return Err(format!(
                    "{} point is {} bytes, not {}",
                    curve.name(),
                    point.len(),
                    want
                ));
            }
            if point[0] != 4 {
                return Err(format!(
                    "{} point starts with 0x{:02x}; only the uncompressed \
                     form 0x04 is defined for SSH",
                    curve.name(),
                    point[0]
                ));
            }
            Ok(Material::Ecdsa { curve, point })
        }
    }
}

/// A public key as a file holds it: the clear-text algorithm name, the
/// blob, and whatever followed the blob on the line.
pub struct PublicKey {
    pub algo: Algo,
    pub blob: Vec<u8>,
    pub comment: Option<String>,
}

impl PublicKey {
    /// Parse one public key line. The comment is everything after the
    /// blob, spaces included, and an absent comment is not an empty one:
    /// ssh-keygen prints no comment field at all for a key written with
    /// -C '' and the suite compares that.
    pub fn parse_line(line: &str) -> Result<PublicKey, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        let mut it = line.splitn(3, ' ');
        let name = it.next().unwrap_or("");
        let algo = match algo(name) {
            Some(a) => a,
            None => return Err(format!("unknown key algorithm {:?}", name)),
        };
        let b64field = match it.next() {
            Some(f) if !f.is_empty() => f,
            _ => return Err(format!("no key blob after {}", name)),
        };
        let blob = crate::b64::decode(b64field.as_bytes())?;
        let comment = it.next().map(|c| c.to_string()).filter(|c| !c.is_empty());
        // The name inside the blob has to match the name outside it.
        let mut r = Reader::new(&blob, "key blob");
        let inner = r.text()?.to_string();
        if inner != name {
            return Err(format!(
                "the blob says {:?} and the line says {:?}",
                inner, name
            ));
        }
        Ok(PublicKey { algo, blob, comment })
    }

    /// The key material. Re-read from the blob each time rather than stored,
    /// because the slices borrow the blob and the blob is owned here.
    pub fn material(&self) -> Res<Material<'_>> {
        let mut r = Reader::new(&self.blob, "key blob");
        r.text()?;
        if self.algo.cert {
            // nonce
            r.string()?;
        }
        let m = material(&mut r, self.algo.plain)?;
        if !self.algo.cert {
            r.end()?;
        }
        Ok(m)
    }
}
