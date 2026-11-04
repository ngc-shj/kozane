//! The WireGuard interface `kzc-psk` owns (D6's lifecycle).
//!
//! - At start, a leftover interface of the configured name that carries
//!   the mark is deleted; one without it is refused.
//! - The new interface is marked, configured with the private key, the
//!   listen port and the one peer (with a random PSK in the creating
//!   request), brought up, addressed and routed. Nothing else is touched.
//! - [`Device::scrub`] removes the peer and re-adds it with a fresh random
//!   PSK, which drops every live keypair (S1.11).
//! - Every request is acked or fatal; a failed RNG draw is fatal too, and
//!   no zero PSK is ever sent. The interface is deleted on every exit path
//!   (`Drop` included).

use std::net::SocketAddr;

use kozane_client::{Secret, lock_memory};

use crate::conf::{Cidr, Conf};
use crate::netlink::{NlError, Transport};
use crate::{rtnl, wg};

/// The OS RNG failed.
#[derive(Debug)]
pub struct RngFailed;

/// The PSK source: getrandom(2) in production; a test seam can fail it.
pub type Fill = fn(&mut [u8]) -> Result<(), RngFailed>;

pub fn os_fill(out: &mut [u8]) -> Result<(), RngFailed> {
    getrandom::fill(out).map_err(|_| RngFailed)
}

fn step(what: &str, r: Result<Vec<Vec<u8>>, NlError>) -> Result<Vec<Vec<u8>>, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

/// The link named `name`, or `None`.
fn find<T: Transport>(route: &mut T, name: &str) -> Result<Option<rtnl::Link>, String> {
    match route.call(&mut rtnl::get_link(name)) {
        Err(NlError::Errno(libc::ENODEV)) => Ok(None),
        r => {
            let data = step("get link", r)?;
            let link = data.first().and_then(|p| rtnl::parse_link(p)).ok_or("get link: no link in the reply")?;
            Ok(Some(link))
        }
    }
}

/// Deletes a marked leftover named `name`; refuses an unmarked one. Returns
/// whether one was deleted.
pub fn reclaim<T: Transport>(route: &mut T, name: &str) -> Result<bool, String> {
    let Some(link) = find(route, name)? else {
        return Ok(false);
    };
    if link.alias.as_deref() != Some(rtnl::MARK) || link.kind.as_deref() != Some(rtnl::KIND) {
        return Err(format!("{name}: an interface not created by kzc-psk exists; refusing to touch it"));
    }
    step("delete leftover", route.call(&mut rtnl::del_link(link.index)))?;
    Ok(true)
}

fn locked_psk() -> Result<Box<Secret<32>>, String> {
    let psk = Box::new(Secret::zero());
    lock_memory(&*psk).map_err(|_| "cannot lock PSK memory")?;
    Ok(psk)
}

pub struct Device<T: Transport> {
    route: T,
    genl: T,
    family: u16,
    index: u32,
    gw_wg_pub: [u8; 32],
    endpoint: SocketAddr,
    allowed_ips: Vec<Cidr>,
    fill: Fill,
    /// The random PSK's one buffer, locked and kept out of dumps.
    psk: Box<Secret<32>>,
    alive: bool,
}

impl<T: Transport> Device<T> {
    /// Reclaims a leftover, then creates, marks and configures the
    /// interface. On any failure after the create, the interface is
    /// deleted again.
    pub fn create(mut route: T, mut genl: T, conf: &Conf, private: &Secret<32>, fill: Fill) -> Result<Self, String> {
        let fam = step("wireguard family", genl.call(&mut wg::get_family()))?;
        let family = fam.first().and_then(|p| wg::parse_family(p)).ok_or("wireguard family: no id in the reply")?;
        reclaim(&mut route, &conf.interface)?;
        let psk = locked_psk()?;
        step("create interface", route.call(&mut rtnl::new_wireguard(&conf.interface)))?;
        let index = match find(&mut route, &conf.interface) {
            Ok(Some(link)) => link.index,
            r => {
                // Without an index, delete by name what was just created.
                let _ = route.call(&mut rtnl::del_link_name(&conf.interface));
                return Err(r.err().unwrap_or_else(|| "create interface: gone after create".into()));
            }
        };
        let mut dev = Self::with_psk(route, genl, family, index, conf, fill, psk);
        dev.configure(conf, private)?;
        Ok(dev)
    }

    /// The device over an existing interface `index`, which it deletes on
    /// drop.
    #[cfg(test)]
    pub(crate) fn attached(route: T, genl: T, family: u16, index: u32, conf: &Conf, fill: Fill) -> Result<Self, String> {
        Ok(Self::with_psk(route, genl, family, index, conf, fill, locked_psk()?))
    }

    fn with_psk(route: T, genl: T, family: u16, index: u32, conf: &Conf, fill: Fill, psk: Box<Secret<32>>) -> Self {
        Self {
            route,
            genl,
            family,
            index,
            gw_wg_pub: conf.gw_wg_pub,
            endpoint: conf.wg_endpoint,
            allowed_ips: conf.allowed_ips.clone(),
            fill,
            psk,
            alive: true,
        }
    }

    fn configure(&mut self, conf: &Conf, private: &Secret<32>) -> Result<(), String> {
        step("mark interface", self.route.call(&mut rtnl::set_mark(self.index)))?;
        self.draw()?;
        let peer = wg::Peer { public: &self.gw_wg_pub, endpoint: &self.endpoint, allowed_ips: &self.allowed_ips };
        let mut m = wg::configure(self.family, self.index, private.expose(), conf.wg_listen_port, &peer, self.psk.expose());
        self.psk.wipe();
        step("configure wireguard", self.genl.call(&mut m))?;
        drop(m);
        step("interface up", self.route.call(&mut rtnl::set_up(self.index)))?;
        step("address", self.route.call(&mut rtnl::new_addr(self.index, &conf.address)))?;
        let on_link = Cidr { addr: conf.address.network(), len: conf.address.len };
        // The kernel adds the address's own prefix route.
        for dst in conf.allowed_ips.iter().filter(|c| **c != on_link) {
            step("route", self.route.call(&mut rtnl::new_route(self.index, dst)))?;
        }
        Ok(())
    }

    /// A fresh random PSK in `self.psk`; never zero.
    fn draw(&mut self) -> Result<(), String> {
        self.psk.wipe();
        if (self.fill)(self.psk.expose_mut()).is_err() || self.psk.is_zero() {
            self.psk.wipe();
            return Err("getrandom failed; no PSK installed".into());
        }
        Ok(())
    }

    /// Sets the OSK `kzc` sent as the peer's PSK.
    pub fn install(&mut self, psk: &Secret<32>) -> Result<(), String> {
        if psk.is_zero() {
            return Err("install: a zero PSK, refused".into());
        }
        let mut m = wg::set_psk(self.family, self.index, &self.gw_wg_pub, psk.expose());
        step("install psk", self.genl.call(&mut m)).map(drop)
    }

    /// Replaces the peer with one holding a fresh random PSK, in one
    /// request; the draw comes first, so a failed one changes nothing.
    pub fn scrub(&mut self) -> Result<(), String> {
        self.draw()?;
        let peer = wg::Peer { public: &self.gw_wg_pub, endpoint: &self.endpoint, allowed_ips: &self.allowed_ips };
        let mut m = wg::replace_peer(self.family, self.index, &peer, self.psk.expose());
        self.psk.wipe();
        step("scrub: replace peer", self.genl.call(&mut m)).map(drop)
    }

    /// Deletes the interface.
    pub fn delete(&mut self) -> Result<(), String> {
        if !self.alive {
            return Ok(());
        }
        self.alive = false;
        step("delete interface", self.route.call(&mut rtnl::del_link(self.index))).map(drop)
    }
}

impl<T: Transport> Drop for Device<T> {
    fn drop(&mut self) {
        if let Err(e) = self.delete() {
            eprintln!("kzc-psk: {e}");
        }
    }
}
