//! A bounds-checked cursor over a borrowed message: every read either
//! returns bytes inside the input or fails with `Refusal::Decode`.

use crate::Refusal;

pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Refusal> {
        let (head, tail) = self.rest.split_at_checked(n).ok_or(Refusal::Decode)?;
        self.rest = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Refusal> {
        match self.take(1)? {
            [b] => Ok(*b),
            _ => Err(Refusal::Decode),
        }
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Refusal> {
        match self.take(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(Refusal::Decode),
        }
    }

    /// A vector with a one-byte length.
    pub(crate) fn vec8(&mut self) -> Result<&'a [u8], Refusal> {
        let n = self.u8()?;
        self.take(usize::from(n))
    }

    /// A vector with a two-byte length.
    pub(crate) fn vec16(&mut self) -> Result<&'a [u8], Refusal> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    /// Nothing may follow the last field.
    pub(crate) fn end(&self) -> Result<(), Refusal> {
        if self.rest.is_empty() { Ok(()) } else { Err(Refusal::Decode) }
    }
}

/// The big-endian u16s of an even-length list; an odd length is malformed.
pub(crate) fn u16s(list: &[u8]) -> Result<impl Iterator<Item = u16> + '_, Refusal> {
    let (pairs, odd) = list.as_chunks::<2>();
    if !odd.is_empty() {
        return Err(Refusal::Decode);
    }
    Ok(pairs.iter().map(|&p| u16::from_be_bytes(p)))
}
