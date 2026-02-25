// RSA signature verification, PKCS#1 v1.5, as RFC 8017 section 8.2.2
// describes it and as OpenSSH uses it for ssh-rsa, rsa-sha2-256 and
// rsa-sha2-512.
//
// The verification is a comparison of the WHOLE padded block against the
// block that should have been there, byte for byte. That is the part worth
// being careful about. A verifier that instead searches the recovered
// block for the digest, or that skips over the 0xff run without checking
// how long it is, accepts Bleichenbacher's 2006 forgery: a low-exponent
// key and a signature constructed so that the recovered block has the
// right digest somewhere in it and rubbish elsewhere. The forgery needs no
// private key. So there is no searching here and no parsing of the
// DigestInfo: the expected bytes are built and memcmp'd.

use crate::bignum::Nat;
use crate::hash;

/// The DER DigestInfo prefix for each digest, and the digest length. These
/// are constants from RFC 8017 appendix B.1, not something computed: the
/// whole point is that the bytes are fixed.
fn digest_info(alg: &str, msg: &[u8]) -> Option<Vec<u8>> {
    let (prefix, digest): (&[u8], Vec<u8>) = match alg {
        "ssh-rsa" => (
            &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
                0x1a, 0x05, 0x00, 0x04, 0x14,
            ],
            hash::sha1(msg).to_vec(),
        ),
        "rsa-sha2-256" => (
            &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            hash::sha256(msg).to_vec(),
        ),
        "rsa-sha2-512" => (
            &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
            ],
            hash::sha512(msg).to_vec(),
        ),
        _ => return None,
    };
    let mut v = Vec::with_capacity(prefix.len() + digest.len());
    v.extend_from_slice(prefix);
    v.extend_from_slice(&digest);
    Some(v)
}

/// Returns Ok(()) when the signature is good, and Err with the reason when
/// it is not. There is no third outcome: "could not tell" is not a thing a
/// signature verifier may return.
pub fn verify(
    e: &[u8],
    n: &[u8],
    alg: &str,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    let n_nat = Nat::from_be(n);
    let e_nat = Nat::from_be(e);
    if n_nat.is_zero() {
        return Err("the modulus is zero".to_string());
    }
    // OpenSSH refuses a key smaller than 1024 bits outright and so does
    // this, because a 512-bit RSA key is factorable and reporting a good
    // signature from one is worse than refusing to look.
    let bits = n_nat.bits();
    if bits < 1024 {
        return Err(format!(
            "the modulus is {} bits; RSA keys below 1024 bits are refused",
            bits
        ));
    }
    if e_nat.cmp(&Nat::from_u32(3)) == std::cmp::Ordering::Less {
        return Err("the public exponent is less than 3".to_string());
    }
    // The size of the padded block is the size of the modulus in bytes.
    let k = (bits + 7) / 8;
    if sig.len() != k {
        return Err(format!(
            "the signature is {} bytes and the modulus is {}",
            sig.len(),
            k
        ));
    }
    let s = Nat::from_be(sig);
    if s.cmp(&n_nat) != std::cmp::Ordering::Less {
        return Err(
            "the signature as an integer is not less than the modulus"
                .to_string(),
        );
    }
    let m = s.modexp(&e_nat, &n_nat);
    let em = match m.to_be(k) {
        Some(v) => v,
        None => return Err("the recovered block does not fit".to_string()),
    };

    let di = match digest_info(alg, msg) {
        Some(d) => d,
        None => return Err(format!("unknown RSA signature algorithm {}", alg)),
    };
    // 0x00 0x01, then 0xff padding, then 0x00, then the DigestInfo. The
    // padding has to be at least 8 bytes, which RFC 8017 requires and
    // which for every real key size it is by a mile.
    if k < di.len() + 11 {
        return Err(format!(
            "the modulus is {} bytes, too small for a {}-byte DigestInfo",
            k,
            di.len()
        ));
    }
    let mut want = Vec::with_capacity(k);
    want.push(0x00);
    want.push(0x01);
    want.resize(k - di.len() - 1, 0xff);
    want.push(0x00);
    want.extend_from_slice(&di);
    debug_assert_eq!(want.len(), k);
    if em != want {
        // The reason is deliberately not "the digest did not match". Where
        // the block differs says which of several things went wrong, and
        // the first differing byte is the whole message.
        let at = em
            .iter()
            .zip(want.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(format!(
            "the recovered PKCS#1 v1.5 block differs from the expected one \
             at byte {} of {} (got {:02x}, want {:02x})",
            at, k, em[at], want[at]
        ));
    }
    Ok(())
}
