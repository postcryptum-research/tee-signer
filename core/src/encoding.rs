//! Strict canonical binary encoding.
//!
//! This is the only wire format the enclave accepts for mandates, state, messages and receipts.
//! It is deliberately dumb: little-endian fixed-width integers, `0`/`1` booleans, length-prefixed
//! byte strings with hard upper bounds, and nothing else. There is exactly one encoding of a value
//! and the decoder refuses everything that is not it: a truncated buffer, trailing bytes, a
//! boolean that is `2`, a length above its bound, a string that is not UTF-8. A decoder that
//! tolerates a second encoding of the same value is a decoder whose hash does not identify the
//! value — and the owner signs the hash.

use alloc::string::String;
use alloc::vec::Vec;

/// Decoding failure. Deliberately carries no position: the host gets "the bytes are not
/// canonical", not help with crafting them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

/// Encoder: appends canonical bytes.
#[derive(Default)]
pub struct Enc {
    buf: Vec<u8>,
}

impl Enc {
    /// A new, empty encoder.
    pub fn new() -> Self {
        Enc { buf: Vec::new() }
    }
    /// The bytes written so far.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
    /// `u8`.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    /// `u16` little-endian.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// `u32` little-endian.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// `u64` little-endian.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// Boolean as `0` or `1`.
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(u8::from(v));
        self
    }
    /// Fixed-length bytes (no length prefix; the length is part of the schema).
    pub fn fixed(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }
    /// Variable-length bytes: `u32` length then the bytes. The caller's schema states the bound;
    /// the encoder trusts its caller (which is this crate) and the decoder enforces it.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        // Lengths above u32 are impossible for anything this crate encodes; saturate rather than
        // wrap so a bug is a refusal at decode time, never a silently different value.
        let len = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.u32(len);
        self.buf.extend_from_slice(v);
        self
    }
    /// A short string: `u16` length then UTF-8 bytes.
    pub fn str(&mut self, v: &str) -> &mut Self {
        let len = u16::try_from(v.len()).unwrap_or(u16::MAX);
        self.u16(len);
        self.buf.extend_from_slice(v.as_bytes());
        self
    }
    /// An optional value: `0`, or `1` followed by the value written by `f`.
    pub fn option<T>(&mut self, v: Option<&T>, f: impl FnOnce(&mut Self, &T)) -> &mut Self {
        match v {
            None => {
                self.u8(0);
            }
            Some(x) => {
                self.u8(1);
                f(self, x);
            }
        }
        self
    }
    /// A list: `u32` count then each item written by `f`.
    pub fn list<T>(&mut self, v: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        let n = u32::try_from(v.len()).unwrap_or(u32::MAX);
        self.u32(n);
        for item in v {
            f(self, item);
        }
        self
    }
}

/// Decoder: strict, bounded, position-tracking.
pub struct Dec<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    /// Start decoding `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Dec { data, pos: 0 }
    }
    /// Must be called last: refuses trailing bytes.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(DecodeError)
        }
    }
    /// Bytes remaining.
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos.checked_add(n).ok_or(DecodeError)?;
        let s = self.data.get(self.pos..end).ok_or(DecodeError)?;
        self.pos = end;
        Ok(s)
    }
    /// `u8`.
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    /// `u16` little-endian.
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    /// `u32` little-endian.
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    /// `u64` little-endian.
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
    /// Boolean: exactly `0` or `1`.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError),
        }
    }
    /// Fixed-length bytes into an array.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let b = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(b);
        Ok(a)
    }
    /// Variable-length bytes with an upper bound on the length.
    pub fn bytes(&mut self, max_len: usize) -> Result<Vec<u8>, DecodeError> {
        let n = self.u32()? as usize;
        if n > max_len {
            return Err(DecodeError);
        }
        Ok(self.take(n)?.to_vec())
    }
    /// A short string with an upper bound on the byte length; must be UTF-8.
    pub fn str(&mut self, max_len: usize) -> Result<String, DecodeError> {
        let n = self.u16()? as usize;
        if n > max_len {
            return Err(DecodeError);
        }
        let b = self.take(n)?;
        core::str::from_utf8(b).map(String::from).map_err(|_| DecodeError)
    }
    /// An optional value.
    pub fn option<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T, DecodeError>) -> Result<Option<T>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(f(self)?)),
            _ => Err(DecodeError),
        }
    }
    /// A list with an upper bound on the count.
    pub fn list<T>(
        &mut self,
        max_count: usize,
        mut f: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let n = self.u32()? as usize;
        if n > max_count {
            return Err(DecodeError);
        }
        // Each item consumes at least one byte, so a count beyond what remains is refused here
        // rather than after allocating for it.
        if n > self.remaining() {
            return Err(DecodeError);
        }
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_strictness() {
        let mut e = Enc::new();
        e.u8(7).u16(513).u32(1 << 20).u64(u64::MAX).bool(true).bytes(b"abc").str("hi");
        e.option(Some(&5u32), |e, v| {
            e.u32(*v);
        });
        e.list(&[1u8, 2, 3], |e, v| {
            e.u8(*v);
        });
        let bytes = e.finish();
        let mut d = Dec::new(&bytes);
        assert_eq!(d.u8().unwrap(), 7);
        assert_eq!(d.u16().unwrap(), 513);
        assert_eq!(d.u32().unwrap(), 1 << 20);
        assert_eq!(d.u64().unwrap(), u64::MAX);
        assert!(d.bool().unwrap());
        assert_eq!(d.bytes(3).unwrap(), b"abc");
        assert_eq!(d.str(8).unwrap(), "hi");
        assert_eq!(d.option(|d| d.u32()).unwrap(), Some(5));
        assert_eq!(d.list(3, |d| d.u8()).unwrap(), alloc::vec![1, 2, 3]);
        d.finish().unwrap();

        // trailing byte
        let mut extra = bytes.clone();
        extra.push(0);
        let mut d = Dec::new(&extra);
        let _ = d.u8();
        assert!(Dec::new(&extra[extra.len()..]).finish().is_ok());
        let mut d2 = Dec::new(&extra);
        for _ in 0..extra.len().saturating_sub(1) {
            let _ = d2.u8();
        }
        assert!(d2.finish().is_err());
        // bool = 2
        assert_eq!(Dec::new(&[2]).bool(), Err(DecodeError));
        // length above bound
        let mut e = Enc::new();
        e.bytes(&[0u8; 10]);
        assert_eq!(Dec::new(&e.finish()).bytes(9), Err(DecodeError));
        // truncated
        assert_eq!(Dec::new(&[1, 2, 3]).u32(), Err(DecodeError));
        // count beyond remaining
        assert_eq!(Dec::new(&[5, 0, 0, 0, 1]).list(10, |d| d.u8()), Err(DecodeError));
        // bad utf-8
        assert_eq!(Dec::new(&[1, 0, 0xff]).str(4), Err(DecodeError));
    }
}
