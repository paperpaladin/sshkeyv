// Dispatch: given a public key blob, a signature blob and the signed
// bytes, say whether the signature is good.
//
// The signature algorithm comes from inside the signature blob, not from
// the key, because an RSA key signs with any of three algorithms and the
// certificate records which one was used. The pair still has to be
// consistent: a signature blob naming rsa-sha2-256 beside an ed25519 CA
// key is a certificate somebody assembled by hand.

use crate::key::{algo, material, Material};
use crate::wire::Reader;

pub enum Outcome {
    Good,
    /// The signature satisfies the verification equation, and the key it
    /// was checked against is one for which that means nothing. Exit 4,
    /// alongside an untrusted CA: the file parsed, the arithmetic held,
    /// and the answer to the question anybody is actually asking is no.
    GoodButMeaningless(String),
    /// The signature is present and wrong, or the key and signature do
    /// not go together. Exit 3.
    Bad(String),
    /// sshkeyv has no verifier for this algorithm. Exit 5, and counted
    /// separately from Bad everywhere: a missing verifier reported as a
    /// bad signature is a refusal dressed up as a catch.
    NoVerifier(String),
}

pub fn verify(key_blob: &[u8], sig_blob: &[u8], msg: &[u8]) -> Outcome {
    let mut kr = Reader::new(key_blob, "signing key");
    let key_name = match kr.text() {
        Ok(s) => s,
        Err(e) => return Outcome::Bad(e),
    };
    let a = match algo(key_name) {
        Some(a) => a,
        None => {
            return Outcome::NoVerifier(format!(
                "unknown signing key algorithm {:?}",
                key_name
            ))
        }
    };
    if a.cert {
        return Outcome::Bad(format!(
            "the signing key is a certificate ({}); a CA key is a plain key",
            key_name
        ));
    }
    let m = match material(&mut kr, a.plain) {
        Ok(m) => m,
        Err(e) => return Outcome::Bad(e),
    };
    if let Err(e) = kr.end() {
        return Outcome::Bad(e);
    }

    let mut sr = Reader::new(sig_blob, "signature");
    let sig_name = match sr.text() {
        Ok(s) => s,
        Err(e) => return Outcome::Bad(e),
    };
    let raw = match sr.string() {
        Ok(s) => s,
        Err(e) => return Outcome::Bad(e),
    };
    if let Err(e) = sr.end() {
        return Outcome::Bad(e);
    }

    match (&m, sig_name) {
        (Material::Rsa { e, n, .. }, "ssh-rsa")
        | (Material::Rsa { e, n, .. }, "rsa-sha2-256")
        | (Material::Rsa { e, n, .. }, "rsa-sha2-512") => {
            match crate::rsa::verify(e, n, sig_name, msg, raw) {
                Ok(()) => Outcome::Good,
                Err(e) => Outcome::Bad(e),
            }
        }
        (Material::Ed25519 { pk }, "ssh-ed25519") => {
            match crate::ed25519::verify(pk, msg, raw) {
                Ok(()) => match crate::ed25519::small_order(pk) {
                    Ok(true) => Outcome::GoodButMeaningless(
                        "the signing key is an Ed25519 point whose order                          divides 8, so the verification equation holds for                          signatures over any message and a good signature                          proves nothing"
                            .to_string(),
                    ),
                    _ => Outcome::Good,
                },
                Err(e) => Outcome::Bad(e),
            }
        }
        (Material::Ecdsa { curve, point }, name)
            if name == format!("ecdsa-sha2-{}", curve.name()) =>
        {
            // The SSH ECDSA signature is a string holding two mpints,
            // which is a second layer of wire format inside the signature
            // blob.
            let mut rr = Reader::new(raw, "ecdsa signature");
            let (r, s) = match (rr.mpint_nc(), rr.mpint_nc()) {
                (Ok((r, _)), Ok((s, _))) => (r, s),
                _ => {
                    return Outcome::Bad(
                        "the ECDSA signature is not two mpints".to_string(),
                    )
                }
            };
            if let Err(e) = rr.end() {
                return Outcome::Bad(e);
            }
            match crate::ecdsa::verify(*curve, point, r, s, msg) {
                Ok(()) => Outcome::Good,
                Err(e) => Outcome::Bad(e),
            }
        }
        _ => Outcome::Bad(format!(
            "a {} signature does not go with a {} key",
            sig_name, key_name
        )),
    }
}
