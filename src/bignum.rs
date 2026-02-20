// Unsigned big integers, enough of them for RSA verification and for the
// NIST prime curves. No signed arithmetic anywhere: every subtraction
// asserts its operands are ordered, and the one place a signed value would
// be natural, modular inversion, uses Fermat's little theorem instead,
// because every modulus inverted in this program is prime.
//
// Limbs are u32 little-endian with no trailing zero limb, so the length of
// the Vec is the length of the number. That is the buffer rule from
// METHOD applied here: a Nat carrying a trailing zero limb would be a
// buffer longer than its data, and every comparison and every loop bound
// in this file reads l.len().

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Nat {
    l: Vec<u32>,
}

impl Nat {
    pub fn zero() -> Nat {
        Nat { l: Vec::new() }
    }

    pub fn from_u32(v: u32) -> Nat {
        let mut n = Nat { l: vec![v] };
        n.trim();
        n
    }

    /// Big-endian bytes, as every integer in an SSH key or signature is
    /// written.
    pub fn from_be(b: &[u8]) -> Nat {
        let mut l = Vec::with_capacity((b.len() + 3) / 4);
        let mut i = b.len();
        while i >= 4 {
            l.push(u32::from_be_bytes([
                b[i - 4],
                b[i - 3],
                b[i - 2],
                b[i - 1],
            ]));
            i -= 4;
        }
        if i > 0 {
            let mut v = 0u32;
            for &c in &b[..i] {
                v = (v << 8) | c as u32;
            }
            l.push(v);
        }
        let mut n = Nat { l };
        n.trim();
        n
    }

    /// Big-endian bytes, left-padded to exactly `len`. None when the value
    /// does not fit, which for a signature means the signature is wrong
    /// rather than that the buffer is too small.
    pub fn to_be(&self, len: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; len];
        for (i, &limb) in self.l.iter().enumerate() {
            for k in 0..4 {
                let byte = ((limb >> (8 * k)) & 0xff) as u8;
                let pos = i * 4 + k;
                if pos >= len {
                    if byte != 0 {
                        return None;
                    }
                    continue;
                }
                out[len - 1 - pos] = byte;
            }
        }
        Some(out)
    }

    fn trim(&mut self) {
        while self.l.last() == Some(&0) {
            self.l.pop();
        }
    }

    pub fn is_zero(&self) -> bool {
        self.l.is_empty()
    }

    pub fn is_one(&self) -> bool {
        self.l.len() == 1 && self.l[0] == 1
    }

    pub fn bits(&self) -> usize {
        match self.l.last() {
            None => 0,
            Some(&top) => self.l.len() * 32 - top.leading_zeros() as usize,
        }
    }

    fn bit(&self, i: usize) -> bool {
        let limb = i / 32;
        limb < self.l.len() && (self.l[limb] >> (i % 32)) & 1 == 1
    }

    pub fn cmp(&self, o: &Nat) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        if self.l.len() != o.l.len() {
            return if self.l.len() < o.l.len() { Less } else { Greater };
        }
        for i in (0..self.l.len()).rev() {
            if self.l[i] != o.l[i] {
                return if self.l[i] < o.l[i] { Less } else { Greater };
            }
        }
        Equal
    }

    pub fn add(&self, o: &Nat) -> Nat {
        let n = self.l.len().max(o.l.len());
        let mut l = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let s = carry
                + *self.l.get(i).unwrap_or(&0) as u64
                + *o.l.get(i).unwrap_or(&0) as u64;
            l.push(s as u32);
            carry = s >> 32;
        }
        if carry != 0 {
            l.push(carry as u32);
        }
        let mut r = Nat { l };
        r.trim();
        r
    }

    /// self - o, which the caller must know is not negative.
    pub fn sub(&self, o: &Nat) -> Nat {
        debug_assert!(self.cmp(o) != std::cmp::Ordering::Less);
        let mut l = Vec::with_capacity(self.l.len());
        let mut borrow = 0i64;
        for i in 0..self.l.len() {
            let d = self.l[i] as i64 - *o.l.get(i).unwrap_or(&0) as i64 - borrow;
            if d < 0 {
                l.push((d + (1i64 << 32)) as u32);
                borrow = 1;
            } else {
                l.push(d as u32);
                borrow = 0;
            }
        }
        debug_assert_eq!(borrow, 0);
        let mut r = Nat { l };
        r.trim();
        r
    }

    pub fn mul(&self, o: &Nat) -> Nat {
        if self.is_zero() || o.is_zero() {
            return Nat::zero();
        }
        let mut l = vec![0u32; self.l.len() + o.l.len()];
        for i in 0..self.l.len() {
            let mut carry = 0u64;
            let a = self.l[i] as u64;
            for j in 0..o.l.len() {
                let t = a * o.l[j] as u64 + l[i + j] as u64 + carry;
                l[i + j] = t as u32;
                carry = t >> 32;
            }
            let mut k = i + o.l.len();
            while carry != 0 {
                let t = l[k] as u64 + carry;
                l[k] = t as u32;
                carry = t >> 32;
                k += 1;
            }
        }
        let mut r = Nat { l };
        r.trim();
        r
    }

    fn shl_bits(&self, s: u32) -> Nat {
        if s == 0 {
            return self.clone();
        }
        let mut l = Vec::with_capacity(self.l.len() + 1);
        let mut carry = 0u32;
        for &limb in &self.l {
            l.push((limb << s) | carry);
            carry = limb >> (32 - s);
        }
        if carry != 0 {
            l.push(carry);
        }
        let mut r = Nat { l };
        r.trim();
        r
    }

    fn shr_bits(&self, s: u32) -> Nat {
        if s == 0 {
            return self.clone();
        }
        let mut l = vec![0u32; self.l.len()];
        for i in 0..self.l.len() {
            l[i] = self.l[i] >> s;
            if i + 1 < self.l.len() {
                l[i] |= self.l[i + 1] << (32 - s);
            }
        }
        let mut r = Nat { l };
        r.trim();
        r
    }

    /// Quotient and remainder. Knuth's algorithm D, base 2^32, with the
    /// normalisation shift and the qhat correction. The alternative, one
    /// bit of quotient per iteration, is simpler and is 8192 iterations
    /// for an RSA-4096 product; the curve code does a few thousand
    /// reductions and would be minutes rather than milliseconds.
    pub fn divrem(&self, v: &Nat) -> (Nat, Nat) {
        assert!(!v.is_zero(), "division by zero");
        if self.cmp(v) == std::cmp::Ordering::Less {
            return (Nat::zero(), self.clone());
        }
        if v.l.len() == 1 {
            let d = v.l[0] as u64;
            let mut q = vec![0u32; self.l.len()];
            let mut rem = 0u64;
            for i in (0..self.l.len()).rev() {
                let cur = (rem << 32) | self.l[i] as u64;
                q[i] = (cur / d) as u32;
                rem = cur % d;
            }
            let mut qn = Nat { l: q };
            qn.trim();
            return (qn, Nat::from_u32(rem as u32));
        }

        let shift = v.l[v.l.len() - 1].leading_zeros();
        let vn = v.shl_bits(shift);
        let n = vn.l.len();
        // u gets one extra limb so that u[j + n] always exists.
        let un = self.shl_bits(shift);
        let mut u = un.l.clone();
        u.push(0);
        let m = u.len() - 1 - n;

        let mut q = vec![0u32; m + 1];
        let b = 1u64 << 32;
        for j in (0..=m).rev() {
            let top = ((u[j + n] as u64) << 32) | u[j + n - 1] as u64;
            let mut qhat = top / vn.l[n - 1] as u64;
            let mut rhat = top % vn.l[n - 1] as u64;
            loop {
                if qhat >= b
                    || qhat * vn.l[n - 2] as u64
                        > (rhat << 32) | u[j + n - 2] as u64
                {
                    qhat -= 1;
                    rhat += vn.l[n - 1] as u64;
                    if rhat < b {
                        continue;
                    }
                }
                break;
            }
            // Multiply and subtract.
            let mut borrow = 0i64;
            let mut carry = 0u64;
            for i in 0..n {
                let p = qhat * vn.l[i] as u64 + carry;
                carry = p >> 32;
                let t = u[i + j] as i64 - (p & 0xffff_ffff) as i64 - borrow;
                if t < 0 {
                    u[i + j] = (t + (1i64 << 32)) as u32;
                    borrow = 1;
                } else {
                    u[i + j] = t as u32;
                    borrow = 0;
                }
            }
            let t = u[j + n] as i64 - carry as i64 - borrow;
            if t < 0 {
                u[j + n] = (t + (1i64 << 32)) as u32;
                // qhat was one too big: add v back.
                qhat -= 1;
                let mut c = 0u64;
                for i in 0..n {
                    let s = u[i + j] as u64 + vn.l[i] as u64 + c;
                    u[i + j] = s as u32;
                    c = s >> 32;
                }
                u[j + n] = (u[j + n] as u64 + c) as u32;
            } else {
                u[j + n] = t as u32;
            }
            q[j] = qhat as u32;
        }
        let mut qn = Nat { l: q };
        qn.trim();
        let mut rn = Nat { l: u[..n].to_vec() };
        rn.trim();
        (qn, rn.shr_bits(shift))
    }

    pub fn rem(&self, m: &Nat) -> Nat {
        self.divrem(m).1
    }

    pub fn mulmod(&self, o: &Nat, m: &Nat) -> Nat {
        self.mul(o).rem(m)
    }

    /// Square and multiply, most significant bit first. Not constant time
    /// and it does not need to be: everything exponentiated here is
    /// public. A verifier handles no secrets, which is the one pleasant
    /// thing about writing one.
    pub fn modexp(&self, e: &Nat, m: &Nat) -> Nat {
        if m.is_one() {
            return Nat::zero();
        }
        let mut acc = Nat::from_u32(1);
        let base = self.rem(m);
        for i in (0..e.bits()).rev() {
            acc = acc.mulmod(&acc, m);
            if e.bit(i) {
                acc = acc.mulmod(&base, m);
            }
        }
        acc
    }

    /// The inverse of self modulo a PRIME p, by Fermat: a^(p-2) mod p.
    /// Every modulus inverted in this program is prime, which is why
    /// there is no extended Euclid here and so no signed arithmetic.
    pub fn invmod_prime(&self, p: &Nat) -> Nat {
        self.modexp(&p.sub(&Nat::from_u32(2)), p)
    }
}
