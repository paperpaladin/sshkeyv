// Base64, strict in both directions.
//
// Strict matters here. Every format this program reads is base64 inside
// something, and a lenient decoder turns a corrupt file into a plausible
// key: skipping an unexpected character silently shifts every byte after
// it, and a key that decodes to the wrong bytes has a fingerprint nobody
// recognises and no error anywhere. So the rules are:
//
//   - the standard alphabet only, no URL-safe substitutions
//   - length a multiple of 4 after padding
//   - padding only at the end, one or two characters, never three
//   - the unused bits of the last encoded character must be zero
//
// The last rule is the one most decoders drop. "AA==" and "AB==" both
// decode to one zero byte under a lenient decoder, so a file can be edited
// without changing what it means, and two spellings of the same key have
// different bytes on disk and the same fingerprint.

const ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a') as u32 + 26),
        b'0'..=b'9' => Some((c - b'0') as u32 + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode `s`. Whitespace is not accepted; the callers that need to accept
/// wrapped lines strip them first, because what counts as a line break is a
/// property of the container and not of base64.
pub fn decode(s: &[u8]) -> Result<Vec<u8>, String> {
    if s.len() % 4 != 0 {
        return Err(format!(
            "base64 length {} is not a multiple of 4",
            s.len()
        ));
    }
    let mut pad = 0;
    while pad < 2 && s.len() > pad && s[s.len() - 1 - pad] == b'=' {
        pad += 1;
    }
    if s.len() > pad && s[s.len() - 1 - pad] == b'=' {
        return Err("base64 has three padding characters".to_string());
    }
    let body = &s[..s.len() - pad];
    // The allocation is exactly the output length, not a rounded-up guess.
    // See the buffer section of the README: a buffer longer than its data
    // puts the bounds check in the wrong place.
    let out_len = body.len() * 3 / 4;
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for (i, &c) in body.iter().enumerate() {
        let v = match value(c) {
            Some(v) => v,
            None => {
                if c == b'=' {
                    return Err(format!(
                        "base64 padding at offset {} is not at the end",
                        i
                    ));
                }
                return Err(format!(
                    "base64 character {:?} at offset {} is not in the alphabet",
                    c as char, i
                ));
            }
        };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return Err(format!(
            "base64 final character has {} unused bits that are not zero",
            bits
        ));
    }
    // See Cargo.toml and `make overread`. Rust's bounds check is against
    // the LENGTH of the Vec, so a Vec longer than its data moves the
    // check away from the end of the data and a read one past the end
    // lands on a zero byte with nothing to say about it. This is the
    // shape METHOD's buffer section is about, written out so that the
    // suite can run the same planted over-read both ways.
    #[cfg(feature = "plant_slack")]
    out.resize(out_len + 64, 0);
    #[cfg(not(feature = "plant_slack"))]
    if out.len() != out_len {
        return Err(format!(
            "base64 produced {} bytes, expected {}",
            out.len(),
            out_len
        ));
    }
    Ok(out)
}

/// Encode with padding.
pub fn encode(b: &[u8]) -> String {
    let mut out = String::with_capacity((b.len() + 2) / 3 * 4);
    for chunk in b.chunks(3) {
        let mut acc = 0u32;
        for i in 0..3 {
            acc = (acc << 8) | *chunk.get(i).unwrap_or(&0) as u32;
        }
        let n = chunk.len();
        for i in 0..4 {
            if i <= n {
                out.push(ALPHABET[((acc >> (18 - 6 * i)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Encode without padding. The SHA256 fingerprint form `ssh-keygen -l`
/// prints has the padding stripped, and the SSHSIG and OpenSSH private key
/// containers do not.
pub fn encode_nopad(b: &[u8]) -> String {
    let mut s = encode(b);
    while s.ends_with('=') {
        s.pop();
    }
    s
}
