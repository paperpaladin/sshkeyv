// Ed25519 verification, RFC 8032 section 5.1.7.
//
// Nothing here is constant time and nothing here needs to be: a verifier
// holds no secret. That is the one pleasant thing about writing one, and
// it is why this file uses the ordinary bignum with ordinary branches
// rather than a field representation chosen to avoid them.
//
// The three refusals at the bottom are the reason this is more than the
// verification equation. A verifier written from the equation alone
// accepts a non-canonical y, accepts a signature whose S is above the
// group order, and in some spellings accepts a point that is not on the
// curve at all. Each of those is a signature that must not verify, and
// each has its own case in the suite.

use crate::bignum::Nat;
use crate::hash;

fn p() -> Nat {
    // 2^255 - 19
    let mut b = [0xffu8; 32];
    b[0] = 0x7f;
    b[31] = 0xed;
    Nat::from_be(&b)
}

/// The group order, 2^252 + 27742317777372353535851937790883648493.
fn l() -> Nat {
    Nat::from_be(&[
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7,
        0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
    ])
}

/// The curve constant d = -121665/121666 mod p.
fn d() -> Nat {
    Nat::from_be(&[
        0x52, 0x03, 0x6c, 0xee, 0x2b, 0x6f, 0xfe, 0x73, 0x8c, 0xc7, 0x40,
        0x79, 0x77, 0x79, 0xe8, 0x98, 0x00, 0x70, 0x0a, 0x4d, 0x41, 0x41,
        0xd8, 0xab, 0x75, 0xeb, 0x4d, 0xca, 0x13, 0x59, 0x78, 0xa3,
    ])
}

/// sqrt(-1) mod p, needed by the square root.
fn sqrt_m1() -> Nat {
    Nat::from_be(&[
        0x2b, 0x83, 0x24, 0x80, 0x4f, 0xc1, 0xdf, 0x0b, 0x2b, 0x4d, 0x00,
        0x99, 0x3d, 0xfb, 0xd7, 0xa7, 0x2f, 0x43, 0x18, 0x06, 0xad, 0x2f,
        0xe4, 0x78, 0xc4, 0xee, 0x1b, 0x27, 0x4a, 0x0e, 0xa0, 0xb0,
    ])
}

/// The base point, as its 32-byte encoding. Decoded rather than written
/// out as a pair, so that the decoder is on the path for the base point
/// too: a decoder that is only used on attacker-supplied input is a
/// decoder whose first bug is a refusal of everything.
const BASE_ENC: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

struct Field {
    p: Nat,
}

impl Field {
    fn add(&self, a: &Nat, b: &Nat) -> Nat {
        let s = a.add(b);
        if s.cmp(&self.p) == std::cmp::Ordering::Less {
            s
        } else {
            s.sub(&self.p)
        }
    }
    fn sub(&self, a: &Nat, b: &Nat) -> Nat {
        if a.cmp(b) == std::cmp::Ordering::Less {
            a.add(&self.p).sub(b)
        } else {
            a.sub(b)
        }
    }
    fn mul(&self, a: &Nat, b: &Nat) -> Nat {
        a.mulmod(b, &self.p)
    }
    fn sqr(&self, a: &Nat) -> Nat {
        a.mulmod(a, &self.p)
    }
    fn inv(&self, a: &Nat) -> Nat {
        a.invmod_prime(&self.p)
    }
    fn pow(&self, a: &Nat, e: &Nat) -> Nat {
        a.modexp(e, &self.p)
    }
}

/// A point in extended coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z and
/// T = XY/Z.
#[derive(Clone)]
struct Pt {
    x: Nat,
    y: Nat,
    z: Nat,
    t: Nat,
}

fn identity() -> Pt {
    Pt {
        x: Nat::zero(),
        y: Nat::from_u32(1),
        z: Nat::from_u32(1),
        t: Nat::zero(),
    }
}

fn le(b: &[u8]) -> Nat {
    let mut r: Vec<u8> = b.to_vec();
    r.reverse();
    Nat::from_be(&r)
}

fn to_le32(n: &Nat) -> [u8; 32] {
    let be = n.to_be(32).expect("a field element fits in 32 bytes");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = be[31 - i];
    }
    out
}

/// Decode a 32-byte point encoding. The three refusals are named in the
/// error, because "signature invalid" for a malformed key is a different
/// fact from "signature invalid" for a wrong signature.
fn decode(enc: &[u8], f: &Field) -> Result<Pt, String> {
    if enc.len() != 32 {
        return Err(format!("a point encoding is {} bytes, not 32", enc.len()));
    }
    let x_sign = enc[31] >> 7;
    let mut yb = [0u8; 32];
    yb.copy_from_slice(enc);
    yb[31] &= 0x7f;
    let y = le(&yb);
    // y must be below p. A y of p, p+1 or above is a second spelling of a
    // point that already has one, and accepting it means one key has two
    // encodings and two fingerprints.
    if y.cmp(&f.p) != std::cmp::Ordering::Less {
        return Err(
            "the point's y coordinate is not less than p, so the encoding is \
             not canonical"
                .to_string(),
        );
    }
    let one = Nat::from_u32(1);
    let yy = f.sqr(&y);
    let u = f.sub(&yy, &one);
    let v = f.add(&f.mul(&d(), &yy), &one);
    // x = sqrt(u/v), by the standard chain: w = u v^3, t = u v^7,
    // x = w t^((p-5)/8), with a correction by sqrt(-1).
    let v2 = f.sqr(&v);
    let v3 = f.mul(&v2, &v);
    let v7 = f.mul(&f.sqr(&v3), &v);
    let w = f.mul(&u, &v3);
    let t = f.mul(&u, &v7);
    // (p - 5) / 8
    let e = f.p.sub(&Nat::from_u32(5)).divrem(&Nat::from_u32(8)).0;
    let mut x = f.mul(&w, &f.pow(&t, &e));
    if f.mul(&f.sqr(&x), &v) != u {
        x = f.mul(&x, &sqrt_m1());
    }
    if f.mul(&f.sqr(&x), &v) != u {
        return Err(
            "the point is not on the curve: x^2 has no square root"
                .to_string(),
        );
    }
    let x_is_odd = to_le32(&x)[0] & 1;
    if x.is_zero() && x_sign == 1 {
        return Err(
            "the encoding has x = 0 with the sign bit set, which is not a \
             point"
                .to_string(),
        );
    }
    if x_is_odd != x_sign {
        x = f.sub(&Nat::zero(), &x);
    }
    let t = f.mul(&x, &y);
    Ok(Pt {
        x,
        y,
        z: Nat::from_u32(1),
        t,
    })
}

/// The 32-byte encoding of a point: y little-endian with x's low bit in
/// the top bit.
fn encode(pt: &Pt, f: &Field) -> [u8; 32] {
    let zi = f.inv(&pt.z);
    let x = f.mul(&pt.x, &zi);
    let y = f.mul(&pt.y, &zi);
    let mut out = to_le32(&y);
    out[31] |= (to_le32(&x)[0] & 1) << 7;
    out
}

fn double(a: &Pt, f: &Field) -> Pt {
    let aa = f.sqr(&a.x);
    let bb = f.sqr(&a.y);
    let cc = f.add(&f.sqr(&a.z), &f.sqr(&a.z));
    let h = f.add(&aa, &bb);
    let e = f.sub(&h, &f.sqr(&f.add(&a.x, &a.y)));
    let g = f.sub(&aa, &bb);
    let ff = f.add(&cc, &g);
    Pt {
        x: f.mul(&e, &ff),
        y: f.mul(&g, &h),
        t: f.mul(&e, &h),
        z: f.mul(&ff, &g),
    }
}

fn add(a: &Pt, b: &Pt, f: &Field) -> Pt {
    let d2 = f.add(&d(), &d());
    let aa = f.mul(&f.sub(&a.y, &a.x), &f.sub(&b.y, &b.x));
    let bb = f.mul(&f.add(&a.y, &a.x), &f.add(&b.y, &b.x));
    let cc = f.mul(&f.mul(&d2, &a.t), &b.t);
    let dd = f.add(&f.mul(&a.z, &b.z), &f.mul(&a.z, &b.z));
    let e = f.sub(&bb, &aa);
    let ff = f.sub(&dd, &cc);
    let g = f.add(&dd, &cc);
    let h = f.add(&bb, &aa);
    Pt {
        x: f.mul(&e, &ff),
        y: f.mul(&g, &h),
        t: f.mul(&e, &h),
        z: f.mul(&ff, &g),
    }
}

// shortcut: plain double-and-add, one point addition per set bit, and
// the two scalar multiplications in a verification are done separately
// rather than as one multi-scalar multiplication. The ceiling is about
// 7 milliseconds per verification, which the suite spends 200 times. A
// 4-bit window and Straus's trick together are roughly four times
// faster and are the upgrade if that ever matters.
fn scalar_mul(k: &Nat, pt: &Pt, f: &Field) -> Pt {
    let mut acc = identity();
    let bits = k.bits();
    for i in (0..bits).rev() {
        acc = double(&acc, f);
        if bit(k, i) {
            acc = add(&acc, pt, f);
        }
    }
    acc
}

fn bit(n: &Nat, i: usize) -> bool {
    let byte = i / 8;
    let be = match n.to_be((n.bits() + 7) / 8 + 1) {
        Some(v) => v,
        None => return false,
    };
    if byte >= be.len() {
        return false;
    }
    (be[be.len() - 1 - byte] >> (i % 8)) & 1 == 1
}

/// Whether a public key is a point whose order divides 8.
///
/// Ed25519 as RFC 8032 specifies it, and as OpenSSH and OpenSSL implement
/// it, uses the cofactorless equation [S]B = R + [k]A and does not reject
/// a small-order public key. The consequence is worth saying out loud: if
/// A is the identity, then R = identity with S = 0 satisfies the equation
/// for ANY message, so every signature verifies and a verified signature
/// proves nothing at all. Measured here, openssl calls exactly that
/// combination good for the identity and for two of the eight torsion
/// points.
///
/// sshkeyv therefore matches the arithmetic and reports the fact, rather
/// than refusing the key and disagreeing with both oracles about whether
/// the signature is valid. It is the only thing in this program that
/// answers a question about a key instead of about bytes.
pub fn small_order(pk: &[u8]) -> Result<bool, String> {
    let f = Field { p: p() };
    let a = decode(pk, &f)?;
    let eight = double(&double(&double(&a, &f), &f), &f);
    Ok(encode(&eight, &f) == encode(&identity(), &f))
}

/// Verify a 64-byte Ed25519 signature over `msg` with a 32-byte public
/// key. Ok means the signature is good.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    if pk.len() != 32 {
        return Err(format!("the public key is {} bytes, not 32", pk.len()));
    }
    if sig.len() != 64 {
        return Err(format!("the signature is {} bytes, not 64", sig.len()));
    }
    let f = Field { p: p() };
    let big_l = l();
    let s = le(&sig[32..]);
    // S must be reduced. An unreduced S gives a second valid signature for
    // the same message and key, which breaks anything that treats a
    // signature as an identifier, and RFC 8032 section 8.4 says to refuse
    // it. OpenSSH's own ed25519 does.
    if s.cmp(&big_l) != std::cmp::Ordering::Less {
        return Err(
            "the signature's S is not less than the group order, so the \
             signature is not canonical"
                .to_string(),
        );
    }
    let a = decode(pk, &f)?;
    let r = decode(&sig[..32], &f)?;

    let mut h = Vec::with_capacity(32 + 32 + msg.len());
    h.extend_from_slice(&sig[..32]);
    h.extend_from_slice(pk);
    h.extend_from_slice(msg);
    debug_assert_eq!(h.len(), h.capacity());
    let k = le(&hash::sha512(&h)).rem(&big_l);

    let lhs = scalar_mul(&s, &decode(&BASE_ENC, &f)?, &f);
    let rhs = add(&r, &scalar_mul(&k, &a, &f), &f);
    if encode(&lhs, &f) != encode(&rhs, &f) {
        return Err(
            "the verification equation does not hold: [S]B is not R + [k]A"
                .to_string(),
        );
    }
    Ok(())
}
