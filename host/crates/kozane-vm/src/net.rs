//! The guest's two taps (M9 plan C4): created by the root launcher through
//! `/dev/net/tun`, joined to their bridges and brought up by ioctl, in tree,
//! with no shell-out. QEMU gets only the open tap fd (`-netdev tap,fd=K`),
//! so it needs no network capability, and the tap goes away with the last
//! fd (it is never made persistent).

use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;

/// `struct ifreq`: the name, then a union whose first member is all the
/// launcher uses (flags as `short`, or an ifindex as `int`).
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    data: [u8; 24],
}

impl IfReq {
    fn new(name: &str) -> Result<Self, String> {
        let mut r = Self { name: [0; libc::IFNAMSIZ], data: [0; 24] };
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
            return Err(format!("`{name}` is not an interface name"));
        }
        r.name.get_mut(..bytes.len()).ok_or("name")?.copy_from_slice(bytes);
        Ok(r)
    }

    fn set_short(&mut self, v: libc::c_short) {
        self.data[..2].copy_from_slice(&v.to_ne_bytes());
    }

    fn short(&self) -> libc::c_short {
        libc::c_short::from_ne_bytes([self.data[0], self.data[1]])
    }

    fn set_int(&mut self, v: libc::c_int) {
        self.data[..4].copy_from_slice(&v.to_ne_bytes());
    }

    fn int(&self) -> libc::c_int {
        libc::c_int::from_ne_bytes([self.data[0], self.data[1], self.data[2], self.data[3]])
    }

    fn name(&self) -> &[u8] {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        &self.name[..end]
    }
}

// <linux/if_tun.h>: _IOW('T', 202, int).
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
// <linux/sockios.h>
const SIOCBRADDIF: libc::c_ulong = 0x89a2;

fn ioctl(fd: i32, req: libc::c_ulong, r: &mut IfReq, what: &str) -> Result<(), String> {
    // SAFETY: `r` is a full `struct ifreq`, which each of these requests
    // reads or writes and nothing more.
    if unsafe { libc::ioctl(fd, req as _, r as *mut IfReq) } == -1 {
        return Err(format!("{what}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn ctl_socket() -> Result<OwnedFd, String> {
    // SAFETY: plain socket(2).
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd == -1 {
        return Err(format!("socket: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: a new fd nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A new tap `name` (`IFF_TAP | IFF_NO_PI`), a port of `bridge`, up. An
/// existing interface of that name is refused (TUNSETIFF on a tap another
/// process holds fails), so two launchers never share a tap.
pub fn open_tap(name: &str, bridge: &str) -> Result<File, String> {
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC)
        .open("/dev/net/tun")
        .map_err(|e| format!("/dev/net/tun: {e}"))?;
    let mut r = IfReq::new(name)?;
    r.set_short((libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short);
    ioctl(tun.as_raw_fd(), TUNSETIFF, &mut r, &format!("TUNSETIFF {name}"))?;
    if r.name() != name.as_bytes() {
        return Err(format!("TUNSETIFF {name}: the kernel named it {}", String::from_utf8_lossy(r.name())));
    }
    let sock = ctl_socket()?;
    let mut idx = IfReq::new(name)?;
    ioctl(sock.as_raw_fd(), libc::SIOCGIFINDEX, &mut idx, &format!("SIOCGIFINDEX {name}"))?;
    let mut port = IfReq::new(bridge)?;
    port.set_int(idx.int());
    ioctl(sock.as_raw_fd(), SIOCBRADDIF, &mut port, &format!("adding {name} to bridge {bridge}"))?;
    let mut flags = IfReq::new(name)?;
    ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS, &mut flags, &format!("SIOCGIFFLAGS {name}"))?;
    flags.set_short(flags.short() | libc::IFF_UP as libc::c_short);
    ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS, &mut flags, &format!("bringing {name} up"))?;
    Ok(tun)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_overlong_or_empty_interface_name_is_refused() {
        assert!(IfReq::new("").is_err());
        assert!(IfReq::new("sixteen-bytes-xx").is_err());
        assert!(IfReq::new("fifteen-bytes-x").is_ok());
    }

    #[test]
    fn the_ifreq_is_the_kernels_size() {
        assert_eq!(std::mem::size_of::<IfReq>(), std::mem::size_of::<libc::ifreq>());
    }
}
