// ECDSA verification over the three NIST prime curves OpenSSH uses:
// nistp256, nistp384 and nistp521.
//
// Short Weierstrass y^2 = x^3 - 3x + b, with the arithmetic in Jacobian
// coordinates so that no modular inversion happens inside the scalar
// multiplication. One inversion per verification, of s modulo the group
// order, plus one to get the result's affine x. On P-521 that is the
// difference between milliseconds and about a thousand exponentiations.
//
// P-521 is the curve worth having in the corpus: its field is 521 bits, so
// every length here is 66 bytes with 7 unused bits at the top of the first
// one, and a padding rule written for a byte-multiple curve is wrong only
// there.

use crate::bignum::Nat;
use crate::hash;
use crate::key::Curve;

/// A curve constant from its hex spelling.
///
/// The assertion on the length earned itself immediately. The first
/// version of the P-521 group order was written with 131 hex digits
/// instead of 132, and this function silently dropped the last digit,
/// which divided the order by sixteen. Every P-521 signature was then
/// reported as having an r or s at or above the group order: a refusal,
/// with a plausible message, caused by a typing error in a constant.
fn nat(hex: &str) -> Nat {
    assert!(
        hex.len() % 2 == 0,
        "a curve constant must have an even number of hex digits"
    );
    let mut b = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).expect("curve constant");
        let lo = (bytes[i + 1] as char).to_digit(16).expect("curve constant");
        b.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Nat::from_be(&b)
}

pub struct Params {
    pub p: Nat,
    pub n: Nat,
    pub b: Nat,
    pub gx: Nat,
    pub gy: Nat,
    /// Bytes per coordinate: ceil(field bits / 8).
    pub bytes: usize,
}

pub fn params(c: Curve) -> Params {
    match c {
        Curve::P256 => Params {
            p: nat("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
            n: nat("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
            b: nat("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
            gx: nat("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
            gy: nat("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
            bytes: 32,
        },
        Curve::P384 => Params {
            p: nat("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                    ffffffff0000000000000000ffffffff"),
            n: nat("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
                    581a0db248b0a77aecec196accc52973"),
            b: nat("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
                    c656398d8a2ed19d2a85c8edd3ec2aef"),
            gx: nat("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                    5502f25dbf55296c3a545e3872760ab7"),
            gy: nat("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
                    0a60b1ce1d7e819d7a431d7c90ea0e5f"),
            bytes: 48,
        },
        Curve::P521 => Params {
            p: nat("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    ffff"),
            n: nat("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
                    6409"),
            b: nat("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
                    09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
                    3f00"),
            gx: nat("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
                    3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
                    bd66"),
            gy: nat("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
                    662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
                    6650"),
            bytes: 66,
        },
    }
}

/// The digest each curve's SSH algorithm name pairs with.
pub fn digest(c: Curve, msg: &[u8]) -> Vec<u8> {
    match c {
        Curve::P256 => hash::sha256(msg).to_vec(),
        Curve::P384 => hash::sha384(msg).to_vec(),
        Curve::P521 => hash::sha512(msg).to_vec(),
    }
}

/// A point in Jacobian coordinates, with Z = 0 meaning the identity.
#[derive(Clone)]
struct Pt {
    x: Nat,
    y: Nat,
    z: Nat,
}

struct F<'a> {
    p: &'a Nat,
}

impl<'a> F<'a> {
    fn add(&self, a: &Nat, b: &Nat) -> Nat {
        let s = a.add(b);
        if s.cmp(self.p) == std::cmp::Ordering::Less {
            s
        } else {
            s.sub(self.p)
        }
    }
    fn sub(&self, a: &Nat, b: &Nat) -> Nat {
        if a.cmp(b) == std::cmp::Ordering::Less {
            a.add(self.p).sub(b)
        } else {
            a.sub(b)
        }
    }
    fn mul(&self, a: &Nat, b: &Nat) -> Nat {
        a.mulmod(b, self.p)
    }
    fn sqr(&self, a: &Nat) -> Nat {
        a.mulmod(a, self.p)
    }
    fn dbl(&self, a: &Nat) -> Nat {
        self.add(a, a)
    }
}

fn identity() -> Pt {
    Pt {
        x: Nat::from_u32(1),
        y: Nat::from_u32(1),
        z: Nat::zero(),
    }
}

/// Doubling with a = -3, which is what all three NIST prime curves have.
/// The alpha = 3(X - Z^2)(X + Z^2) shortcut is only correct for a = -3,
/// and that is why the curve constant a is not a field of Params: a curve
/// with another a would need a different formula, and carrying the
/// constant would suggest otherwise.
fn double(a: &Pt, f: &F) -> Pt {
    if a.z.is_zero() {
        return identity();
    }
    let delta = f.sqr(&a.z);
    let gamma = f.sqr(&a.y);
    let beta = f.mul(&a.x, &gamma);
    let t = f.mul(&f.sub(&a.x, &delta), &f.add(&a.x, &delta));
    let alpha = f.add(&f.dbl(&t), &t);
    let x3 = f.sub(&f.sqr(&alpha), &f.dbl(&f.dbl(&f.dbl(&beta))));
    let z3 = f.sub(&f.sub(&f.sqr(&f.add(&a.y, &a.z)), &gamma), &delta);
    let y3 = f.sub(
        &f.mul(&alpha, &f.sub(&f.dbl(&f.dbl(&beta)), &x3)),
        &f.dbl(&f.dbl(&f.dbl(&f.sqr(&gamma)))),
    );
    Pt { x: x3, y: y3, z: z3 }
}

fn add(a: &Pt, b: &Pt, f: &F) -> Pt {
    if a.z.is_zero() {
        return b.clone();
    }
    if b.z.is_zero() {
        return a.clone();
    }
    let z1z1 = f.sqr(&a.z);
    let z2z2 = f.sqr(&b.z);
    let u1 = f.mul(&a.x, &z2z2);
    let u2 = f.mul(&b.x, &z1z1);
    let s1 = f.mul(&f.mul(&a.y, &z2z2), &b.z);
    let s2 = f.mul(&f.mul(&b.y, &z1z1), &a.z);
    let h = f.sub(&u2, &u1);
    let r = f.dbl(&f.sub(&s2, &s1));
    if h.is_zero() {
        if r.is_zero() {
            return double(a, f);
        }
        return identity();
    }
    let i = f.sqr(&f.dbl(&h));
    let j = f.mul(&h, &i);
    let v = f.mul(&u1, &i);
    let x3 = f.sub(&f.sub(&f.sqr(&r), &j), &f.dbl(&v));
    let y3 = f.sub(
        &f.mul(&r, &f.sub(&v, &x3)),
        &f.dbl(&f.mul(&s1, &j)),
    );
    let z3 = f.mul(
        &f.sub(&f.sub(&f.sqr(&f.add(&a.z, &b.z)), &z1z1), &z2z2),
        &h,
    );
    Pt { x: x3, y: y3, z: z3 }
}

fn bit(n: &Nat, i: usize) -> bool {
    let bytes = (n.bits() + 7) / 8 + 1;
    let be = match n.to_be(bytes) {
        Some(v) => v,
        None => return false,
    };
    let byte = i / 8;
    if byte >= be.len() {
        return false;
    }
    (be[be.len() - 1 - byte] >> (i % 8)) & 1 == 1
}

// shortcut: the same plain double-and-add as src/ed25519.rs, with the
// same ceiling and the same upgrade. P-521 is the slow case at about 8
// milliseconds.
fn scalar_mul(k: &Nat, pt: &Pt, f: &F) -> Pt {
    let mut acc = identity();
    for i in (0..k.bits()).rev() {
        acc = double(&acc, f);
        if bit(k, i) {
            acc = add(&acc, pt, f);
        }
    }
    acc
}

/// The affine x of a Jacobian point, or None for the identity.
fn affine_x(pt: &Pt, p: &Nat) -> Option<Nat> {
    if pt.z.is_zero() {
        return None;
    }
    let zi = pt.z.invmod_prime(p);
    Some(pt.x.mulmod(&zi.mulmod(&zi, p), p))
}

/// Verify an SSH ECDSA signature. `point` is the uncompressed public key
/// point, 0x04 then X then Y; `r` and `s` are the two mpints out of the
/// signature blob.
pub fn verify(
    c: Curve,
    point: &[u8],
    r: &[u8],
    s: &[u8],
    msg: &[u8],
) -> Result<(), String> {
    let pr = params(c);
    let f = F { p: &pr.p };
    let want = 1 + 2 * pr.bytes;
    if point.len() != want {
        return Err(format!(
            "the public point is {} bytes, not {}",
            point.len(),
            want
        ));
    }
    if point[0] != 4 {
        return Err(format!(
            "the public point starts with 0x{:02x}, not the uncompressed \
             form 0x04",
            point[0]
        ));
    }
    let qx = Nat::from_be(&point[1..1 + pr.bytes]);
    let qy = Nat::from_be(&point[1 + pr.bytes..]);
    if qx.cmp(&pr.p) != std::cmp::Ordering::Less
        || qy.cmp(&pr.p) != std::cmp::Ordering::Less
    {
        return Err(
            "a public point coordinate is not less than the field prime"
                .to_string(),
        );
    }
    // On the curve: y^2 = x^3 - 3x + b. Without this check a verifier can
    // be given a point on a different, weaker curve, and for signature
    // verification alone that is less dangerous than for key agreement,
    // but the point is still not the key anybody issued.
    let lhs = f.sqr(&qy);
    let x3 = f.mul(&f.sqr(&qx), &qx);
    let three_x = f.add(&f.dbl(&qx), &qx);
    let rhs = f.add(&f.sub(&x3, &three_x), &pr.b);
    if lhs != rhs {
        return Err("the public point is not on the curve".to_string());
    }
    let q = Pt {
        x: qx,
        y: qy,
        z: Nat::from_u32(1),
    };

    let rn = Nat::from_be(r);
    let sn = Nat::from_be(s);
    if rn.is_zero() || sn.is_zero() {
        return Err("the signature has r or s equal to zero".to_string());
    }
    if rn.cmp(&pr.n) != std::cmp::Ordering::Less
        || sn.cmp(&pr.n) != std::cmp::Ordering::Less
    {
        return Err(
            "the signature has r or s at or above the group order"
                .to_string(),
        );
    }

    // e is the leftmost bits of the digest, as many bits as the group
    // order has. For P-521 the digest is 512 bits and the order is 521, so
    // nothing is dropped; for P-256 with SHA-256 nothing is dropped
    // either. The shift is only ever a no-op for the three curves OpenSSH
    // uses, and it is here because leaving it out would be right by
    // accident.
    let dg = digest(c, msg);
    let mut e = Nat::from_be(&dg);
    let dbits = dg.len() * 8;
    let nbits = pr.n.bits();
    if dbits > nbits {
        let shift = dbits - nbits;
        let divisor = Nat::from_u32(2).modexp(
            &Nat::from_be(&(shift as u64).to_be_bytes()),
            &pr.p.add(&pr.p),
        );
        e = e.divrem(&divisor).0;
    }
    let e = e.rem(&pr.n);

    let w = sn.invmod_prime(&pr.n);
    let u1 = e.mulmod(&w, &pr.n);
    let u2 = rn.mulmod(&w, &pr.n);
    let g = Pt {
        x: pr.gx.clone(),
        y: pr.gy.clone(),
        z: Nat::from_u32(1),
    };
    let x = add(
        &scalar_mul(&u1, &g, &f),
        &scalar_mul(&u2, &q, &f),
        &f,
    );
    let vx = match affine_x(&x, &pr.p) {
        Some(v) => v,
        None => {
            return Err(
                "u1 G + u2 Q is the identity, so the signature is invalid"
                    .to_string(),
            )
        }
    };
    if vx.rem(&pr.n) != rn {
        return Err(
            "the verification equation does not hold: x of u1 G + u2 Q is \
             not r"
                .to_string(),
        );
    }
    Ok(())
}
