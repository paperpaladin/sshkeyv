// The SSHSIG detached signature format, from OpenSSH's PROTOCOL.sshsig.
//
// It is here for two reasons. It gives the verifier a second kind of
// signature over data this suite chooses, rather than only over
// certificates ssh-keygen wrote, and it has a namespace field inside the
// signed blob, which is the one structural idea in the format: a
// signature made for "git" must not verify as a signature for "file".
// A verifier that reads the namespace out of the signature and then
// signs over what it read would accept any namespace at all, which is
// why the namespace to check against is an argument here and the one in
// the file is only ever compared.
//
// Armour:        -----BEGIN SSH SIGNATURE-----
// Blob:          "SSHSIG", uint32 version, string publickey,
//                string namespace, string reserved,
//                string hash_algorithm, string signature
// Signed bytes:  "SSHSIG", string namespace, string reserved,
//                string hash_algorithm, string H(message)

use crate::hash;
use crate::wire::{Reader, Res, Writer};

pub const MAGIC: &[u8; 6] = b"SSHSIG";

pub struct Sshsig<'a> {
    pub version: u32,
    pub public_key: &'a [u8],
    pub namespace: &'a str,
    pub reserved: &'a [u8],
    pub hash_algorithm: &'a str,
    pub signature: &'a [u8],
}

impl<'a> Sshsig<'a> {
    pub fn parse(b: &'a [u8]) -> Res<Sshsig<'a>> {
        if b.len() < 6 || &b[..6] != MAGIC {
            return Err(
                "not an SSHSIG signature: the magic preamble is wrong"
                    .to_string(),
            );
        }
        let mut r = Reader::new(&b[6..], "sshsig");
        let version = r.u32()?;
        // OpenSSH refuses anything but 1 and so does this. A version it
        // does not know is a format it does not know, and reading the
        // fields anyway is how a parser invents a meaning.
        if version != 1 {
            return Err(format!(
                "SSHSIG version is {}; only version 1 is defined",
                version
            ));
        }
        let public_key = r.string()?;
        let namespace = r.text()?;
        if namespace.is_empty() {
            return Err("the SSHSIG namespace is empty".to_string());
        }
        let reserved = r.string()?;
        let hash_algorithm = r.text()?;
        let signature = r.string()?;
        r.end()?;
        Ok(Sshsig {
            version,
            public_key,
            namespace,
            reserved,
            hash_algorithm,
            signature,
        })
    }

    /// The bytes the signature covers, for a given message.
    pub fn signed_blob(&self, msg: &[u8]) -> Res<Vec<u8>> {
        let h: Vec<u8> = match self.hash_algorithm {
            "sha256" => hash::sha256(msg).to_vec(),
            "sha512" => hash::sha512(msg).to_vec(),
            other => {
                return Err(format!(
                    "SSHSIG hash algorithm {:?} is not sha256 or sha512",
                    other
                ))
            }
        };
        let mut w = Writer::new();
        w.b.extend_from_slice(MAGIC);
        w.string(self.namespace.as_bytes());
        w.string(self.reserved);
        w.string(self.hash_algorithm.as_bytes());
        w.string(&h);
        Ok(w.b)
    }
}
