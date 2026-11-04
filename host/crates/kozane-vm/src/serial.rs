//! The serial reader (M9 plan C4, C3): an unprivileged child, as
//! `kozane-qemu`, on QEMU's console pipe. It copies every byte to the
//! console log (fd 3, root's, mode 0600: console access is root-only, so
//! nothing goes to the journal), and writes one byte to the launcher (fd 4)
//! per `audit` heartbeat line. Root never parses guest output.
//!
//! The guest chooses how much it prints, so the log is capped at `LOG_MAX`.
//! Past the cap the reader drops console bytes, never heartbeats, and says
//! so in the log: one line when it starts dropping, and one with the count
//! when the log has room again (after a `copytruncate` rotation). `audit`'s
//! own seq and chain numbers show which records the gap took.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;

pub const LOG_FD: i32 = 3;
pub const HEARTBEAT_FD: i32 = 4;

/// A console line longer than this is passed through but never counted.
const MAX_LINE: usize = 4096;

/// The console log's size cap, markers included.
pub const LOG_MAX: u64 = 1 << 30;
/// Room kept below the cap for the two marker lines.
const MARK_ROOM: u64 = 256;
const FULL_MARK: &[u8] = b"\nkozane-vm: console log full; dropping console output until it is rotated\n";

/// `audit`'s heartbeat event (C3): a console line `audit: … Heartbeat …`.
pub fn is_heartbeat(line: &[u8]) -> bool {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    line.starts_with(b"audit: ") && line.split(|&b| b == b' ').any(|t| t == b"Heartbeat")
}

/// Splits the console stream into lines and counts the heartbeats.
#[derive(Default)]
pub struct Lines {
    buf: Vec<u8>,
    overflow: bool,
}

impl Lines {
    /// The heartbeat lines `chunk` completes.
    pub fn feed(&mut self, chunk: &[u8]) -> usize {
        let mut beats = 0;
        for &b in chunk {
            if b == b'\n' {
                if !self.overflow && is_heartbeat(&self.buf) {
                    beats += 1;
                }
                self.buf.clear();
                self.overflow = false;
            } else if self.buf.len() < MAX_LINE {
                self.buf.push(b);
            } else {
                self.overflow = true;
            }
        }
        beats
    }
}

/// Caps the log: what to append for each chunk, given the log's length.
#[derive(Default)]
pub struct Cap {
    dropped: u64,
}

impl Cap {
    /// The bytes to append for `chunk` to a log `len` bytes long: the chunk
    /// (after the count of what was dropped before it, if anything was), the
    /// marker that dropping started, or nothing.
    pub fn admit(&mut self, len: u64, chunk: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        if self.dropped != 0 {
            out.extend_from_slice(format!("\nkozane-vm: {} console bytes dropped while the log was full\n", self.dropped).as_bytes());
        }
        out.extend_from_slice(chunk);
        let size = u64::try_from(out.len()).unwrap_or(u64::MAX);
        if len.saturating_add(size) <= LOG_MAX.saturating_sub(MARK_ROOM) {
            self.dropped = 0;
            return out;
        }
        let first = self.dropped == 0;
        self.dropped = self.dropped.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        let mark = u64::try_from(FULL_MARK.len()).unwrap_or(u64::MAX);
        if first && len.saturating_add(mark) <= LOG_MAX { FULL_MARK.to_vec() } else { Vec::new() }
    }
}

fn inherited(fd: i32) -> Result<File, String> {
    // SAFETY: F_GETFD only asks whether `fd` is open.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
        return Err(format!("fd {fd} is not open (serial-reader runs only under the launcher)"));
    }
    // SAFETY: `fd` is open, and this process takes it over once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub fn reader_main() -> Result<(), String> {
    let mut log = inherited(LOG_FD)?;
    let mut heartbeat = inherited(HEARTBEAT_FD)?;
    let mut stdin = std::io::stdin().lock();
    let mut lines = Lines::default();
    let mut cap = Cap::default();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stdin.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("console: {e}")),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        // The length from fstat, not a count: a rotation shrinks it.
        let len = log.metadata().map_err(|e| format!("console log: {e}"))?.len();
        log.write_all(&cap.admit(len, chunk)).map_err(|e| format!("console log: {e}"))?;
        for _ in 0..lines.feed(chunk) {
            heartbeat.write_all(b"h").map_err(|e| format!("heartbeat pipe: {e}"))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_below_the_cap_is_appended_as_it_is() {
        assert_eq!(Cap::default().admit(0, b"pq: ready\n"), b"pq: ready\n");
    }

    #[test]
    fn at_the_cap_the_first_chunk_becomes_the_full_marker_and_later_ones_nothing() {
        let mut c = Cap::default();
        let near = LOG_MAX - MARK_ROOM - 2;
        assert_eq!(c.admit(near, b"abc"), FULL_MARK);
        assert_eq!(c.admit(near + FULL_MARK.len() as u64, b"defg"), b"");
    }

    #[test]
    fn after_a_rotation_the_dropped_count_comes_before_the_next_chunk() {
        let mut c = Cap::default();
        let _ = c.admit(LOG_MAX, b"abc");
        let _ = c.admit(LOG_MAX, b"defg");
        assert_eq!(c.admit(0, b"x\n"), b"\nkozane-vm: 7 console bytes dropped while the log was full\nx\n");
        assert_eq!(c.admit(100, b"y\n"), b"y\n");
    }

    #[test]
    fn a_log_already_past_the_cap_gets_no_marker_beyond_it() {
        assert_eq!(Cap::default().admit(LOG_MAX, b"abc"), b"");
    }

    #[test]
    fn an_audit_heartbeat_line_counts_once() {
        let mut l = Lines::default();
        assert_eq!(l.feed(b"audit: src=timer Heartbeat ticks=100 lost=0 seq=9\r\n"), 1);
    }

    #[test]
    fn a_heartbeat_split_across_chunks_counts_when_its_line_ends() {
        let mut l = Lines::default();
        assert_eq!(l.feed(b"audit: src=timer Heart"), 0);
        assert_eq!(l.feed(b"beat ticks=1\n"), 1);
    }

    #[test]
    fn other_lines_do_not_count() {
        let mut l = Lines::default();
        let text = b"pq: ready\nHeartbeat\nnot audit: src=x Heartbeat\naudit: src=hs HandshakeOk total=1\naudit: src=x Heartbeats\n";
        assert_eq!(l.feed(text), 0);
    }

    #[test]
    fn an_overlong_line_is_never_counted_and_the_next_one_is() {
        let mut l = Lines::default();
        let mut long = b"audit: src=timer Heartbeat ".to_vec();
        long.resize(MAX_LINE + 10, b'x');
        long.push(b'\n');
        assert_eq!(l.feed(&long), 0);
        assert_eq!(l.feed(b"audit: src=timer Heartbeat ticks=2\n"), 1);
    }
}
