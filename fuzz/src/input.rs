//! Fuzzer bytes as a script, and the writer that makes seeds of them.

/// Reads the fuzzer's bytes. Reads past the end return zeros (or fewer
/// bytes), so no input is ever rejected for being short.
#[derive(Debug)]
pub struct Input<'a> {
    data: &'a [u8],
}

impl<'a> Input<'a> {
    pub fn new(data: &'a [u8]) -> Input<'a> {
        Input { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Up to `n` bytes.
    pub fn bytes(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.data.split_at(n.min(self.data.len()));
        self.data = tail;
        head
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        let bytes = self.bytes(N);
        out[..bytes.len()].copy_from_slice(bytes);
        out
    }

    pub fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    pub fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    /// A `u16`-length-prefixed chunk, shorter if the input ends first.
    pub fn chunk(&mut self) -> &'a [u8] {
        let n = self.u16();
        self.bytes(usize::from(n))
    }

    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.data)
    }
}

/// Writes what [`Input`] reads back.
#[derive(Debug, Default)]
pub struct Script {
    buf: Vec<u8>,
}

impl Script {
    pub fn new() -> Script {
        Script::default()
    }

    pub fn u8(&mut self, v: u8) -> &mut Script {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Script {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Script {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Script {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, v: &[u8]) -> &mut Script {
        self.buf.extend_from_slice(v);
        self
    }

    pub fn chunk(&mut self, v: &[u8]) -> &mut Script {
        let n = u16::try_from(v.len()).expect("a chunk fits in a u16 length");
        self.u16(n).bytes(v)
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
