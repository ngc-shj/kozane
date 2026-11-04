//! The needle search (after tools/ct-harness/src/residue.rs `Needles`): every
//! 8-byte window of each secret form, matched at every byte offset of a
//! region.

use std::collections::HashMap;

/// The secret forms; a failure line names one.
pub const FORMS: [&str; 8] = ["cookie", "esk", "ck", "kyber-ss", "mce-ss", "txkt", "reply-cookie", "control"];

#[derive(Clone, Copy)]
pub enum Form {
    /// The cookie value sealed into every message (`Handshake::cookie`).
    Cookie,
    /// The ephemeral Kyber secret key (`Handshake::eski`).
    Esk,
    /// The chaining key after IHI8 (`Handshake::ck`).
    Ck,
    /// RHI4's Kyber shared key.
    KyberSs,
    /// IHI5's or RHI5's McEliece shared key.
    MceSs,
    /// tkr, which opens the EmptyData (`Handshake::txkt`).
    Txkt,
    /// The cookie value a CookieReply carries.
    ReplyCookie,
    /// The positive control's kept secret.
    Control,
}

pub struct Needles {
    windows: HashMap<u64, u32>,
}

/// One form's matches in a region: the number of matching offsets.
pub struct Hit {
    pub form: usize,
    pub count: usize,
}

impl Needles {
    pub fn new() -> Self {
        Self { windows: HashMap::new() }
    }

    /// A window counts if it could not be filler: three or more nonzero
    /// bytes, not all equal (the paint is one repeated byte).
    fn distinctive(w: &[u8]) -> bool {
        w.iter().filter(|&&b| b != 0).count() >= 3 && w.iter().any(|&b| b != w[0])
    }

    pub fn add(&mut self, form: Form, bytes: &[u8]) {
        for w in bytes.windows(8).filter(|w| Self::distinctive(w)) {
            *self.windows.entry(u64::from_le_bytes(w.try_into().expect("8"))).or_insert(0) |= 1 << form as u32;
        }
    }

    pub fn scan(&self, region: &[u8]) -> Vec<Hit> {
        let mut per = [0usize; FORMS.len()];
        for w in region.windows(8) {
            let Some(&mask) = self.windows.get(&u64::from_le_bytes(w.try_into().expect("8"))) else {
                continue;
            };
            for (f, count) in per.iter_mut().enumerate() {
                if mask & (1 << f) != 0 {
                    *count += 1;
                }
            }
        }
        per.into_iter().enumerate().filter(|&(_, c)| c > 0).map(|(form, count)| Hit { form, count }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 16] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0, 0x01];

    #[test]
    fn finds_a_planted_secret_at_an_odd_offset() {
        let mut n = Needles::new();
        n.add(Form::Cookie, &SECRET);
        let mut region = vec![0x5c; 256];
        region[37..53].copy_from_slice(&SECRET);
        let hits = n.scan(&region);
        assert_eq!(hits.len(), 1);
        assert_eq!((FORMS[hits[0].form], hits[0].count), ("cookie", 9));
    }

    #[test]
    fn finds_an_eight_byte_fragment() {
        let mut n = Needles::new();
        n.add(Form::Esk, &SECRET);
        let mut region = vec![0u8; 64];
        region[3..11].copy_from_slice(&SECRET[5..13]);
        assert_eq!(n.scan(&region).len(), 1);
    }

    #[test]
    fn paint_and_zeroes_are_never_needles() {
        let mut n = Needles::new();
        n.add(Form::Ck, &[0x5c; 32]);
        n.add(Form::Ck, &[0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0]);
        let region = [vec![0x5c; 64], vec![0; 64], vec![0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0]].concat();
        assert!(n.scan(&region).is_empty());
    }

    #[test]
    fn a_wiped_secret_leaves_no_hit() {
        let mut n = Needles::new();
        n.add(Form::Control, &SECRET);
        let mut region = vec![0x5c; 64];
        region[8..24].copy_from_slice(&SECRET);
        region[8..24].fill(0);
        assert!(n.scan(&region).is_empty());
    }
}
