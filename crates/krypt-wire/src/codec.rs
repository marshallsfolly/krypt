//! A tiny, bounds-checked binary codec: little-endian integers and
//! `u32`-length-prefixed byte strings. Every read states its maximum length,
//! so a decoder can never be talked into a large allocation.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Input ended before the value did.
    Truncated,
    /// A length prefix exceeded the maximum the reader allowed.
    TooLong { len: u64, max: u64 },
    /// An enum discriminant or flag had no meaning.
    BadValue,
    /// Bytes were left over after the value was fully decoded.
    TrailingBytes,
}

#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(capacity),
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn array<const N: usize>(&mut self, v: &[u8; N]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Writes a `u32` length prefix followed by the bytes.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.count(v.len());
        self.buf.extend_from_slice(v);
        self
    }

    /// Writes an element count or length as a `u32`.
    pub fn count(&mut self, n: usize) -> &mut Self {
        self.u32(u32::try_from(n).expect("count exceeds u32::MAX"))
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(out))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Reads a `u32`-length-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, max: usize) -> Result<&'a [u8], DecodeError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(DecodeError::TooLong {
                len: len as u64,
                max: max as u64,
            });
        }
        self.take(len)
    }

    /// Reads a `u32` element count of at most `max`.
    pub fn count(&mut self, max: usize) -> Result<usize, DecodeError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(DecodeError::TooLong {
                len: n as u64,
                max: max as u64,
            });
        }
        Ok(n)
    }

    pub fn remaining(&self) -> usize {
        self.buf.len()
    }

    /// Succeeds only if every byte was consumed.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut w = Writer::new();
        w.u8(7)
            .u32(0xDEAD_BEEF)
            .u64(u64::MAX)
            .array(&[1, 2, 3])
            .bytes(b"xyz");
        let bytes = w.finish();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 7);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.array::<3>().unwrap(), [1, 2, 3]);
        assert_eq!(r.bytes(3).unwrap(), b"xyz");
        r.finish().unwrap();
    }

    #[test]
    fn length_limits_are_enforced_before_reading() {
        let mut w = Writer::new();
        w.u32(u32::MAX);
        let bytes = w.finish();
        assert_eq!(
            Reader::new(&bytes).bytes(16),
            Err(DecodeError::TooLong {
                len: u32::MAX as u64,
                max: 16
            })
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let r = Reader::new(&[0]);
        assert_eq!(r.finish(), Err(DecodeError::TrailingBytes));
    }
}
