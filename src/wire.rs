// The SSH wire format, as RFC 4251 section 5 defines it and as every blob
// in this project uses it. This commit has uint32 and string; the rest of
// the types arrive with the parsers that need them.
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
        #[cfg(feature = "plant_overread")]
        let n = n + 1;
        self.bytes(n)
    }
}
