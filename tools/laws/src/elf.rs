//! W^X over a PD ELF's loadable segments (M9 plan D13). The timer scan
//! (`tools/timer-scan`) reads only the executable segments, so it holds only
//! while no PD can write its own code: no `PT_LOAD` is both writable and
//! executable, and no page is covered by an executable segment and a
//! writable one (Microkit maps each segment's pages with its flags, so a
//! shared page would be mapped twice with different rights).

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PAGE: u64 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub index: usize,
    pub flags: u32,
    pub vaddr: u64,
    pub memsz: u64,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at.checked_add(8)?)?.try_into().ok()?))
}

/// The `PT_LOAD` segments of a little-endian ELF64 file.
pub fn load_segments(bytes: &[u8]) -> Result<Vec<Segment>, String> {
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01".as_slice()) {
        return Err("not a little-endian ELF64 file".to_string());
    }
    let bad = || "bad program header table".to_string();
    let phoff = usize::try_from(u64_at(bytes, 0x20).ok_or_else(bad)?).map_err(|_| bad())?;
    let phentsize = usize::from(u16_at(bytes, 0x36).ok_or_else(bad)?);
    let phnum = usize::from(u16_at(bytes, 0x38).ok_or_else(bad)?);
    if phnum == 0 || phentsize < 56 {
        return Err(bad());
    }
    let mut segments = Vec::new();
    for index in 0..phnum {
        let at = index.checked_mul(phentsize).and_then(|o| o.checked_add(phoff)).ok_or_else(bad)?;
        let field = |off: usize| at.checked_add(off).ok_or_else(bad);
        let p_type = u32_at(bytes, field(0)?).ok_or_else(bad)?;
        let flags = u32_at(bytes, field(4)?).ok_or_else(bad)?;
        let vaddr = u64_at(bytes, field(16)?).ok_or_else(bad)?;
        let memsz = u64_at(bytes, field(40)?).ok_or_else(bad)?;
        if p_type == PT_LOAD {
            segments.push(Segment { index, flags, vaddr, memsz });
        }
    }
    Ok(segments)
}

/// [first page, end page) a segment's memory touches, None if empty.
fn pages(s: &Segment) -> Option<(u64, u64)> {
    if s.memsz == 0 {
        return None;
    }
    let end = s.vaddr.checked_add(s.memsz)?;
    Some((s.vaddr / PAGE, end.div_ceil(PAGE)))
}

/// One message per W^X breach in `name`'s segments.
pub fn wx_violations(name: &str, segments: &[Segment]) -> Vec<String> {
    let mut out = Vec::new();
    for s in segments {
        if s.flags & PF_W != 0 && s.flags & PF_X != 0 {
            out.push(format!("laws: writable executable segment: {name} segment {} at {:#x} is W and X", s.index, s.vaddr));
        }
        if s.memsz != 0 && pages(s).is_none() {
            out.push(format!("laws: segment wraps the address space: {name} segment {}", s.index));
        }
    }
    for x in segments.iter().filter(|s| s.flags & PF_X != 0) {
        for w in segments.iter().filter(|s| s.flags & PF_W != 0 && s.index != x.index) {
            let (Some((xa, xb)), Some((wa, wb))) = (pages(x), pages(w)) else { continue };
            if xa < wb && wa < xb {
                out.push(format!(
                    "laws: writable executable segment: {name} page {:#x} is in executable segment {} and writable segment {}",
                    xa.max(wa).saturating_mul(PAGE),
                    x.index,
                    w.index
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const R: u32 = 4;

    /// An ELF64 header and `PT_LOAD` (flags, vaddr, memsz) program headers.
    fn elf(segments: &[(u32, u64, u64)]) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..6].copy_from_slice(b"\x7fELF\x02\x01");
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3a].copy_from_slice(&u16::try_from(segments.len()).unwrap().to_le_bytes());
        for &(flags, vaddr, memsz) in segments {
            let mut ph = vec![0u8; 56];
            ph[..4].copy_from_slice(&PT_LOAD.to_le_bytes());
            ph[4..8].copy_from_slice(&flags.to_le_bytes());
            ph[16..24].copy_from_slice(&vaddr.to_le_bytes());
            ph[40..48].copy_from_slice(&memsz.to_le_bytes());
            b.extend(ph);
        }
        b
    }

    fn violations(segments: &[(u32, u64, u64)]) -> Vec<String> {
        wx_violations("pd-x.elf", &load_segments(&elf(segments)).unwrap())
    }

    #[test]
    fn the_shipped_layout_is_clean() {
        // pd-audit.elf's: R, then RX from a fresh page, then RW from the next.
        assert!(violations(&[(R, 0x20_0000, 0x7058), (R | PF_X, 0x20_8058, 0x973c), (R | PF_W, 0x21_2798, 0x120)]).is_empty());
    }

    #[test]
    fn a_writable_executable_segment_is_refused() {
        let v = violations(&[(R | PF_W | PF_X, 0x20_0000, 0x1000)]);
        assert_eq!(v, ["laws: writable executable segment: pd-x.elf segment 0 at 0x200000 is W and X"]);
    }

    #[test]
    fn a_page_shared_by_an_executable_and_a_writable_segment_is_refused() {
        let v = violations(&[(R | PF_X, 0x20_0000, 0x1800), (R | PF_W, 0x20_1800, 0x100)]);
        assert_eq!(
            v,
            ["laws: writable executable segment: pd-x.elf page 0x201000 is in executable segment 0 and writable segment 1"]
        );
    }

    #[test]
    fn a_writable_segment_on_the_next_page_is_allowed() {
        assert!(violations(&[(R | PF_X, 0x20_0000, 0x1000), (R | PF_W, 0x20_1000, 0x100)]).is_empty());
    }

    #[test]
    fn a_read_only_segment_sharing_an_executable_page_is_allowed() {
        assert!(violations(&[(R, 0x20_0000, 0x800), (R | PF_X, 0x20_0800, 0x800)]).is_empty());
    }

    #[test]
    fn a_truncated_header_table_is_an_error() {
        let mut b = elf(&[(R | PF_X, 0x20_0000, 0x1000)]);
        b.truncate(100);
        assert!(load_segments(&b).is_err());
        assert!(load_segments(b"\x7fELF\x01\x01").is_err());
    }
}
