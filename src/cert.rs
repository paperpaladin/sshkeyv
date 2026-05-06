// The OpenSSH certificate format, as PROTOCOL.certkeys describes it.
//
// The field order is fixed and there is no version number other than the
// v01 in the algorithm name, so a parser either reads all of it or is lost.
// Two fields are nested: valid_principals is a string holding a sequence
// of strings, and critical_options and extensions are strings each holding
// a sequence of name and data pairs where the data is itself a string.
// That nesting is where the length arithmetic has to be right.

use crate::key::{material, Algo, Material};
use crate::wire::{Reader, Res};

/// A name and its data, from the critical options or the extensions list.
/// The data is the raw inner string: for force-command it holds another
/// SSH string with the command in it, and for a flag option like
/// permit-pty it is empty.
pub struct Opt<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
}

impl<'a> Opt<'a> {
    /// The single string an option's data holds, for the options whose
    /// data is specified that way. None when the data is empty, which is
    /// how a flag option is spelled, and Err when it is neither.
    pub fn as_string(&self) -> Option<Res<&'a [u8]>> {
        if self.data.is_empty() {
            return None;
        }
        let mut r = Reader::new(self.data, "option data");
        Some(r.string().and_then(|s| {
            r.end()?;
            Ok(s)
        }))
    }
}

/// The most principals OpenSSH will load. Measured against ssh-keygen,
/// not copied from a header.
pub const MAX_PRINCIPALS: usize = 256;

pub const TYPE_USER: u32 = 1;
pub const TYPE_HOST: u32 = 2;

pub struct Cert<'a> {
    pub algo: Algo,
    pub nonce: &'a [u8],
    pub subject: Material<'a>,
    pub serial: u64,
    pub cert_type: u32,
    pub key_id: &'a str,
    pub principals: Vec<&'a str>,
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical: Vec<Opt<'a>>,
    pub extensions: Vec<Opt<'a>>,
    pub reserved: &'a [u8],
    /// The CA public key, as a blob, exactly as the certificate holds it.
    pub signature_key: &'a [u8],
    /// The signature, as a blob: an algorithm name then the signature
    /// itself, whose shape depends on the algorithm.
    pub signature: &'a [u8],
    /// The bytes the signature covers: the whole blob up to the start of
    /// the signature string.
    pub tbs: &'a [u8],
}

/// A sequence of SSH strings packed inside one string. valid_principals is
/// one of these, and it is NOT a comma-separated name-list, which is the
/// mistake worth not making: a principal may contain a comma.
fn string_seq<'a>(b: &'a [u8], what: &'static str) -> Res<Vec<&'a str>> {
    let mut r = Reader::new(b, what);
    let mut out = Vec::new();
    while !r.at_end() {
        out.push(r.text()?);
    }
    Ok(out)
}

/// A sequence of name and data pairs packed inside one string.
fn opt_seq<'a>(b: &'a [u8], what: &'static str) -> Res<Vec<Opt<'a>>> {
    let mut r = Reader::new(b, what);
    let mut out = Vec::new();
    while !r.at_end() {
        let name = r.text()?;
        let data = r.string()?;
        out.push(Opt { name, data });
    }
    Ok(out)
}

impl<'a> Cert<'a> {
    pub fn parse(blob: &'a [u8], algo: Algo) -> Res<Cert<'a>> {
        if !algo.cert {
            return Err(format!("{} is not a certificate algorithm", algo.name));
        }
        let mut r = Reader::new(blob, "certificate");
        let name = r.text()?;
        if name != algo.name {
            return Err(format!(
                "the certificate blob says {:?} and the line says {:?}",
                name, algo.name
            ));
        }
        let nonce = r.string()?;
        let subject = material(&mut r, algo.plain)?;
        let serial = r.u64()?;
        let cert_type = r.u32()?;
        if cert_type != TYPE_USER && cert_type != TYPE_HOST {
            return Err(format!(
                "certificate type is {}, not 1 (user) or 2 (host)",
                cert_type
            ));
        }
        let key_id = r.text()?;
        let principals = string_seq(r.string()?, "principals")?;
        // OpenSSH refuses a certificate with more than 256 principals and
        // prints "invalid key: invalid format". The number is measured
        // rather than read out of a header: t/craft.py bisects ssh-keygen
        // -L with certificates carrying 1 to 1000 principals and the
        // suite asserts the boundary every run, so a different OpenSSH
        // moving it shows up as a failure rather than as a silent
        // disagreement. A certificate no OpenSSH will load is one this
        // program should not report as fine.
        if principals.len() > MAX_PRINCIPALS {
            return Err(format!(
                "the certificate lists {} principals; OpenSSH refuses more \
                 than {}",
                principals.len(),
                MAX_PRINCIPALS
            ));
        }
        let valid_after = r.u64()?;
        let valid_before = r.u64()?;
        if valid_after > valid_before {
            return Err(format!(
                "validity window is empty: valid after {} is later than \
                 valid before {}",
                valid_after, valid_before
            ));
        }
        let critical = opt_seq(r.string()?, "critical options")?;
        let extensions = opt_seq(r.string()?, "extensions")?;
        let reserved = r.string()?;
        let signature_key = r.string()?;
        // Everything up to here is what the CA signed. Taken at this exact
        // moment rather than recomputed from offsets afterwards.
        let tbs = r.consumed();
        let signature = r.string()?;
        r.end()?;
        Ok(Cert {
            algo,
            nonce,
            subject,
            serial,
            cert_type,
            key_id,
            principals,
            valid_after,
            valid_before,
            critical,
            extensions,
            reserved,
            signature_key,
            signature,
            tbs,
        })
    }

    pub fn type_name(&self) -> &'static str {
        if self.cert_type == TYPE_HOST {
            "host"
        } else {
            "user"
        }
    }

    /// The algorithm name inside the signature blob, which says which
    /// digest and padding the CA used. It can differ from the CA key's own
    /// algorithm: an RSA CA key signs with ssh-rsa, rsa-sha2-256 or
    /// rsa-sha2-512, and ssh-keygen -L prints which.
    pub fn signature_algo(&self) -> Res<&'a str> {
        let mut r = Reader::new(self.signature, "signature");
        r.text()
    }

    /// The CA key's own algorithm name, from its blob.
    pub fn ca_algo(&self) -> Res<&'a str> {
        let mut r = Reader::new(self.signature_key, "CA key");
        r.text()
    }
}
