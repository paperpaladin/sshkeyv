// Just enough DER to write and read a SubjectPublicKeyInfo.
//
// Writing is the easy half and the oracle gives the exact bytes:
// ssh-keygen -e -m pkcs8 produces them for RSA and ECDSA, so the
// comparison is byte for byte rather than structural. Reading is where a
// hand-written DER parser fails, and the failure is always the same one: a
// length read as short form where it is long form, which shifts
// everything after it.

/// Definite-length encoding, minimal form.
pub fn len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut b = Vec::new();
    let mut v = n;
    while v > 0 {
        b.push((v & 0xff) as u8);
        v >>= 8;
    }
    b.reverse();
    let mut out = Vec::with_capacity(b.len() + 1);
    out.push(0x80 | b.len() as u8);
    out.extend_from_slice(&b);
    out
}

pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let l = len(body.len());
    let mut out = Vec::with_capacity(1 + l.len() + body.len());
    out.push(tag);
    out.extend_from_slice(&l);
    out.extend_from_slice(body);
    debug_assert_eq!(out.len(), out.capacity());
    out
}

/// INTEGER, from an unsigned big-endian magnitude. Leading zero octets are
/// dropped and one is added back when the top bit is set, because DER
/// integers are two's complement and a modulus is not negative.
pub fn integer(mag: &[u8]) -> Vec<u8> {
    let mut i = 0;
    while i + 1 < mag.len() && mag[i] == 0 {
        i += 1;
    }
    let m = &mag[i..];
    if m.is_empty() || m == [0] {
        return tlv(0x02, &[0]);
    }
    if m[0] & 0x80 != 0 {
        let mut b = Vec::with_capacity(m.len() + 1);
        b.push(0);
        b.extend_from_slice(m);
        return tlv(0x02, &b);
    }
    tlv(0x02, m)
}

/// BIT STRING with no unused bits, which is the only form used here.
pub fn bitstring(body: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(body.len() + 1);
    b.push(0);
    b.extend_from_slice(body);
    tlv(0x03, &b)
}

pub fn sequence(body: &[u8]) -> Vec<u8> {
    tlv(0x30, body)
}

pub fn oid(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID has at least two arcs");
    let mut body = vec![(arcs[0] * 40 + arcs[1]) as u8];
    for &a in &arcs[2..] {
        let mut stack = Vec::new();
        let mut v = a;
        loop {
            stack.push((v & 0x7f) as u8);
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        for (i, &b) in stack.iter().enumerate().rev() {
            body.push(if i == 0 { b } else { b | 0x80 });
        }
    }
    tlv(0x06, &body)
}

pub fn null() -> Vec<u8> {
    vec![0x05, 0x00]
}

/// One parsed TLV: the tag, the body, and how many bytes the whole thing
/// took.
pub struct Tlv<'a> {
    pub tag: u8,
    pub body: &'a [u8],
    pub total: usize,
}

/// Read one TLV from the front of `b`.
///
/// Three refusals, all of them a length encoding that is legal BER and not
/// legal DER: the indefinite form, a long form that could have been short,
/// and a long form with a leading zero octet. A reader that accepts them
/// reads files no DER writer produces, and then two readers of the same
/// file disagree.
pub fn read(b: &[u8]) -> Result<Tlv<'_>, String> {
    if b.len() < 2 {
        return Err(format!("a TLV needs at least 2 bytes, {} left", b.len()));
    }
    let tag = b[0];
    let first = b[1];
    if first == 0x80 {
        return Err("indefinite length is not valid DER".to_string());
    }
    let (body_at, n) = if first < 0x80 {
        (2usize, first as usize)
    } else {
        let k = (first & 0x7f) as usize;
        if k > 8 {
            return Err(format!("a length of {} octets will not fit", k));
        }
        if b.len() < 2 + k {
            return Err("truncated length".to_string());
        }
        let octets = &b[2..2 + k];
        if octets[0] == 0 {
            return Err(
                "a long-form length with a leading zero octet is not valid \
                 DER"
                    .to_string(),
            );
        }
        let mut v = 0usize;
        for &o in octets {
            v = (v << 8) | o as usize;
        }
        if v < 0x80 {
            return Err(format!(
                "length {} is encoded in long form but fits in short form",
                v
            ));
        }
        (2 + k, v)
    };
    if b.len() - body_at < n {
        return Err(format!(
            "a TLV with tag 0x{:02x} claims {} bytes, {} left",
            tag,
            n,
            b.len() - body_at
        ));
    }
    Ok(Tlv {
        tag,
        body: &b[body_at..body_at + n],
        total: body_at + n,
    })
}

/// Read one TLV that must be the whole of `b` and must have this tag.
pub fn expect<'a>(b: &'a [u8], tag: u8, what: &str) -> Result<Tlv<'a>, String> {
    let t = read(b)?;
    if t.tag != tag {
        return Err(format!(
            "{}: expected tag 0x{:02x}, got 0x{:02x}",
            what, tag, t.tag
        ));
    }
    if t.total != b.len() {
        return Err(format!(
            "{}: {} trailing bytes after the TLV",
            what,
            b.len() - t.total
        ));
    }
    Ok(t)
}
