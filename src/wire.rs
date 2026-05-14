// The SSH wire format, as RFC 4251 section 5 defines it and as every blob
// in this project uses it. uint32, string, string-as-text and mpint; the
// remaining types arrive with the parsers that need them.
//
// A boolean reader is deliberately absent: no field in a key, a
// certificate or an SSHSIG signature is a boolean.
//
// All of it goes through one reader so that the bounds check is written
// once. A parser of this shape fails in exactly one place: a length field
// read out of the input and then used as an index. There are nine such
// fields in a certificate and one of them is the length of a list of
// lengths.

pub struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
    what: &'static str,
}

pub type Res<T> = Result<T, String>;

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8], what: &'static str) -> Reader<'a> {
        Reader { b, pos: 0, what }
    }

    pub fn offset(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }

    pub fn at_end(&self) -> bool {
        self.pos == self.b.len()
    }

    /// Everything consumed so far. A certificate's signature covers the
    /// blob from the start up to but not including the signature string,
    /// so the parser asks for this at the moment it reaches the signature
    /// rather than recomputing the offset afterwards. Recomputing it is
    /// where a verifier comes to hash the wrong range, and a verifier that
    /// hashes the wrong range rejects everything, which looks like
    /// strictness.
    pub fn consumed(&self) -> &'a [u8] {
        &self.b[..self.pos]
    }

    fn need(&self, n: usize) -> Res<()> {
        if self.remaining() < n {
            return Err(format!(
                "{}: want {} bytes at offset {}, {} left",
                self.what, n, self.pos, self.remaining()
            ));
        }
        Ok(())
    }

    pub fn bytes(&mut self, n: usize) -> Res<&'a [u8]> {
        self.need(n)?;
        let r = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(r)
    }

    pub fn u64(&mut self) -> Res<u64> {
        let b = self.bytes(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn u32(&mut self) -> Res<u32> {
        let b = self.bytes(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn string(&mut self) -> Res<&'a [u8]> {
        let at = self.pos;
        let n = self.u32()? as usize;
        // The length is attacker-controlled and is about to be used as an
        // index. need() is the only thing between the two, so the error
        // names the offset of the length field rather than of the data.
        if self.remaining() < n {
            return Err(format!(
                "{}: string at offset {} claims {} bytes, {} left",
                self.what, at, n, self.remaining()
            ));
        }
        let r = self.bytes(n);
        // The planted one-past-the-end read. See `make overread`. It
        // reads the byte immediately after the string just returned,
        // which for the LAST string in a blob is one past the end of the
        // buffer. black_box keeps it from being optimised away.
        #[cfg(feature = "plant_overread")]
        {
            let _ = std::hint::black_box(self.b[self.pos]);
        }
        r
    }

    /// A string that has to be UTF-8 to mean anything: an algorithm name, a
    /// curve name, a principal, a key id.
    pub fn text(&mut self) -> Res<&'a str> {
        let at = self.pos;
        let b = self.string()?;
        match std::str::from_utf8(b) {
            Ok(s) => Ok(s),
            Err(e) => Err(format!(
                "{}: string at offset {} is not UTF-8: {}",
                self.what, at, e
            )),
        }
    }

    /// An mpint, returned as the unsigned big-endian magnitude together
    /// with whether the encoding was canonical.
    ///
    /// A negative value is refused outright: nothing in an SSH key or
    /// signature is ever negative, and a leading 0x80 in a modulus means
    /// the parse is lost rather than that the modulus is negative.
    ///
    /// Redundant leading zero octets are NOT refused, and that is a change
    /// made because the oracle disagreed. RFC 4251 says the value is
    /// stored with the minimum number of octets, so an extra zero is a
    /// violation; ssh-keygen -l reads such a key without complaining. An
    /// over-refusal is a defect rather than caution, so the bytes are
    /// accepted the way OpenSSH accepts them and the fact is reported as a
    /// field instead of as an error.
    pub fn mpint_nc(&mut self) -> Res<(&'a [u8], bool)> {
        let at = self.pos;
        let b = self.string()?;
        if b.is_empty() {
            return Ok((b, false));
        }
        if b[0] & 0x80 != 0 {
            return Err(format!(
                "{}: mpint at offset {} is negative",
                self.what, at
            ));
        }
        let mut i = 0;
        while i < b.len() && b[i] == 0 {
            i += 1;
        }
        // One leading zero is required when the top bit of the magnitude is
        // set, so that case is canonical; any other leading zero is not.
        let canonical = if i == 0 {
            true
        } else if i == 1 && b.len() > 1 && b[1] & 0x80 != 0 {
            true
        } else {
            false
        };
        Ok((&b[i..], canonical))
    }

    /// Refuse trailing bytes. A blob with something after the last field is
    /// not a blob this program understands, and reading the prefix and
    /// ignoring the rest is how one parser comes to disagree with the next.
    /// ssh-keygen -l refuses a key blob with four zero bytes appended, and
    /// this check is here because the refusal comparison caught sshkeyv
    /// reading one.
    pub fn end(&self) -> Res<()> {
        if !self.at_end() {
            return Err(format!(
                "{}: {} trailing bytes after offset {}",
                self.what,
                self.remaining(),
                self.pos
            ));
        }
        Ok(())
    }
}

/// The writer. Only enough of it to re-encode what was read, which is what
/// a fingerprint of a certificate's subject key needs: ssh-keygen -l on a
/// certificate prints the fingerprint of the key inside it, not of the
/// certificate, so the plain key blob has to be rebuilt from the fields
/// the certificate carries inline.
#[derive(Default)]
pub struct Writer {
    pub b: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer { b: Vec::new() }
    }
    pub fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_be_bytes());
    }
    pub fn string(&mut self, s: &[u8]) {
        self.u32(s.len() as u32);
        self.b.extend_from_slice(s);
    }
    /// An mpint, written canonically: no leading zero octets except the one
    /// that keeps a value with its top bit set positive.
    pub fn mpint(&mut self, m: &[u8]) {
        let mut i = 0;
        while i < m.len() && m[i] == 0 {
            i += 1;
        }
        let m = &m[i..];
        if m.is_empty() {
            self.u32(0);
            return;
        }
        if m[0] & 0x80 != 0 {
            self.u32(m.len() as u32 + 1);
            self.b.push(0);
            self.b.extend_from_slice(m);
        } else {
            self.string(m);
        }
    }
}
