//! The serial reader (M9 plan C4, C3): an unprivileged child, as
//! `kozane-qemu`, on QEMU's console pipe. It copies every byte to the
//! console log (fd 3, root's, mode 0600: console access is root-only, so
//! nothing goes to the journal), and writes one byte to the launcher (fd 4)
//! per `audit` heartbeat line. Root never parses guest output.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;

pub const LOG_FD: i32 = 3;
pub const HEARTBEAT_FD: i32 = 4;

/// A console line longer than this is passed through but never counted.
const MAX_LINE: usize = 4096;

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
    let mut buf = [0u8; 4096];
    loop {
        let n = match stdin.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("console: {e}")),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        log.write_all(chunk).map_err(|e| format!("console log: {e}"))?;
        for _ in 0..lines.feed(chunk) {
            heartbeat.write_all(b"h").map_err(|e| format!("heartbeat pipe: {e}"))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
