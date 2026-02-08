// The OpenSSH private key container, from PROTOCOL.key.
//
// Nothing here decrypts anything. The header is parsed and reported,
// including the bcrypt-pbkdf parameters, and the encrypted bytes are left
// alone. "How many KDF rounds is this key protected with, and with which
// cipher" is a question with no tool to answer it, and the answer is
// twenty-four bytes into the file.
//
// Layout:
//   "openssh-key-v1\0"
//   string  ciphername
//   string  kdfname
//   string  kdfoptions        (for bcrypt: string salt, uint32 rounds)
//   uint32  number of keys
//   string  publickey         (repeated, number of keys times)
//   string  encrypted         (the private section, ciphertext when
//                              ciphername is not "none")
//
// and the private section, once decrypted or when it never was:
//   uint32  checkint
//   uint32  checkint          (the same value again)
//   per key: string keytype, key material, string comment
//   padding 1, 2, 3, ... to the cipher's block size

use crate::wire::{Reader, Res};

pub const MAGIC: &[u8] = b"openssh-key-v1\0";

pub struct Container<'a> {
    pub cipher: &'a str,
    pub kdf: &'a str,
    pub kdf_options: &'a [u8],
    /// The bcrypt-pbkdf salt and rounds, when the KDF is bcrypt.
    pub salt: Option<&'a [u8]>,
    pub rounds: Option<u32>,
    pub nkeys: u32,
    pub public: Vec<&'a [u8]>,
    pub private: &'a [u8],
}

/// The block size each cipher pads the private section to. OpenSSH pads to
/// the cipher's block size even when the key is not encrypted, in which
/// case the cipher is "none" and the block size is 8.
pub fn cipher_block(name: &str) -> Option<usize> {
    match name {
        "none" => Some(8),
        "aes128-cbc" | "aes192-cbc" | "aes256-cbc" => Some(16),
        "aes128-ctr" | "aes192-ctr" | "aes256-ctr" => Some(16),
        "aes128-gcm@openssh.com" | "aes256-gcm@openssh.com" => Some(16),
        "chacha20-poly1305@openssh.com" => Some(8),
        "3des-cbc" => Some(8),
        _ => None,
    }
}

/// Bytes of authentication tag the cipher appends to the private section.
/// The AEAD ciphers add 16; the others add none.
pub fn cipher_tag(name: &str) -> usize {
    match name {
        "aes128-gcm@openssh.com"
        | "aes256-gcm@openssh.com"
        | "chacha20-poly1305@openssh.com" => 16,
        _ => 0,
    }
}

impl<'a> Container<'a> {
    pub fn parse(b: &'a [u8]) -> Res<Container<'a>> {
        if b.len() < MAGIC.len() || &b[..MAGIC.len()] != MAGIC {
            return Err(
                "not an OpenSSH private key: the magic is wrong".to_string()
            );
        }
        let mut r = Reader::new(&b[MAGIC.len()..], "private key container");
        let cipher = r.text()?;
        let kdf = r.text()?;
        let kdf_options = r.string()?;
        let nkeys = r.u32()?;
        // OpenSSH has never written anything but 1 and its own reader
        // refuses anything else, so a file saying 4 is a file to refuse
        // rather than to loop over.
        if nkeys != 1 {
            return Err(format!(
                "the container holds {} keys; OpenSSH writes and reads \
                 exactly 1",
                nkeys
            ));
        }
        let mut public = Vec::with_capacity(nkeys as usize);
        for _ in 0..nkeys {
            public.push(r.string()?);
        }
        let private = r.string()?;
        r.end()?;

        // The cipher and the KDF have to agree about whether there is a
        // passphrase. A file with cipher "none" and kdf "bcrypt" has no
        // key to derive and a file with a real cipher and kdf "none" has
        // no way to derive one, and both are refused by OpenSSH.
        let encrypted = cipher != "none";
        if encrypted && kdf == "none" {
            return Err(format!(
                "cipher is {} but the KDF is none, so there is no key",
                cipher
            ));
        }
        if !encrypted && kdf != "none" {
            return Err(format!(
                "cipher is none but the KDF is {}, so the derived key \
                 would be unused",
                kdf
            ));
        }

        let (salt, rounds) = if kdf == "bcrypt" {
            let mut k = Reader::new(kdf_options, "bcrypt kdf options");
            let salt = k.string()?;
            let rounds = k.u32()?;
            k.end()?;
            if rounds == 0 {
                return Err("bcrypt rounds is 0".to_string());
            }
            (Some(salt), Some(rounds))
        } else if kdf == "none" {
            if !kdf_options.is_empty() {
                return Err(format!(
                    "the KDF is none but it carries {} bytes of options",
                    kdf_options.len()
                ));
            }
            (None, None)
        } else {
            return Err(format!(
                "unknown KDF {:?}; OpenSSH has only ever written bcrypt",
                kdf
            ));
        };

        let block = match cipher_block(cipher) {
            Some(b) => b,
            None => return Err(format!("unknown cipher {:?}", cipher)),
        };
        let tag = cipher_tag(cipher);
        if private.len() < tag {
            return Err(format!(
                "the private section is {} bytes, shorter than {}'s {}-byte \
                 tag",
                private.len(),
                cipher,
                tag
            ));
        }
        if (private.len() - tag) % block != 0 {
            return Err(format!(
                "the private section is {} bytes, which is not a multiple \
                 of {}'s block size {} after its {}-byte tag",
                private.len(),
                cipher,
                block,
                tag
            ));
        }

        Ok(Container {
            cipher,
            kdf,
            kdf_options,
            salt,
            rounds,
            nkeys,
            public,
            private,
        })
    }

    pub fn encrypted(&self) -> bool {
        self.cipher != "none"
    }
}

/// The private section once it is in clear: what a container with cipher
/// "none" holds directly, and what a passphrase would reveal.
pub struct Private<'a> {
    pub checkint: u32,
    pub keytype: &'a str,
    /// The public half, as it appears inside the private section. It must
    /// equal the container's own copy of the public key.
    pub public: Vec<u8>,
    pub comment: &'a str,
    pub padding: &'a [u8],
}

impl<'a> Private<'a> {
    /// Parse the clear private section. The private scalars are skipped
    /// rather than stored: this program never needs them and a struct that
    /// holds a private key is a struct that can print one by accident.
    pub fn parse(b: &'a [u8], block: usize) -> Res<Private<'a>> {
        let mut r = Reader::new(b, "private key section");
        let c1 = r.u32()?;
        let c2 = r.u32()?;
        if c1 != c2 {
            // This is the only integrity signal the format has, and it is
            // what a wrong passphrase trips: the two words are written
            // equal and decryption with the wrong key makes them differ.
            return Err(format!(
                "the two check words differ ({} and {}), which is what a \
                 wrong passphrase looks like",
                c1, c2
            ));
        }
        let keytype = r.text()?;
        let algo = match crate::key::algo(keytype) {
            Some(a) => a,
            None => return Err(format!("unknown key type {:?}", keytype)),
        };
        if algo.cert {
            return Err(format!(
                "{} is a certificate algorithm; a private key section \
                 names a plain key type",
                keytype
            ));
        }
        // The public half comes first in every key type's private
        // encoding, so it can be read out without touching the secret.
        //
        // RSA is the trap. The public blob is e then n; the private
        // section is n then e. Reading the private section with the public
        // reader produces a key whose exponent is the modulus, and the
        // only reason that was noticed here is that the two copies of the
        // public key are compared: the swapped version parsed cleanly, the
        // comment and the padding were in the right place, and every other
        // field was right.
        let public = {
            let mut w = crate::wire::Writer::new();
            w.string(keytype.as_bytes());
            if algo.plain == "ssh-rsa" {
                let n = r.mpint_nc()?.0;
                let e = r.mpint_nc()?.0;
                w.mpint(e);
                w.mpint(n);
            } else {
                let m = crate::key::material(&mut r, algo.plain)?;
                m.write(&mut w);
            }
            w.b
        };
        skip_private_scalars(&mut r, algo.plain)?;
        let comment = r.text()?;
        let padding = r.bytes(r.remaining())?;
        // 1, 2, 3, ... up to the block size. OpenSSH's own reader checks
        // this, and a container whose padding is zeros was written by
        // something else.
        if padding.len() >= block {
            return Err(format!(
                "{} bytes of padding, which is not less than the block \
                 size {}",
                padding.len(),
                block
            ));
        }
        for (i, &p) in padding.iter().enumerate() {
            if p as usize != i + 1 {
                return Err(format!(
                    "padding byte {} is {}, expected {}",
                    i,
                    p,
                    i + 1
                ));
            }
        }
        Ok(Private {
            checkint: c1,
            keytype,
            public,
            comment,
            padding,
        })
    }
}

/// Step over the secret scalars of each key type. Read and discarded: the
/// lengths have to be right for the comment and the padding to be in the
/// right place, so they cannot be skipped by arithmetic.
fn skip_private_scalars(r: &mut Reader, plain: &str) -> Res<()> {
    match plain {
        // ed25519's private string holds the 64-byte expanded key, whose
        // second half is the public key again.
        "ssh-ed25519" => {
            r.string()?;
        }
        // d, iqmp, p, q. n and e were already read as the public half.
        "ssh-rsa" => {
            for _ in 0..4 {
                r.string()?;
            }
        }
        // the scalar
        _ => {
            r.string()?;
        }
    }
    Ok(())
}
