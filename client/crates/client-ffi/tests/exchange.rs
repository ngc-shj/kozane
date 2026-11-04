//! M9 plan C9: a full exchange through the exported functions, against
//! the real `rosenpass-core` responder with real KEMs, and a short
//! buffer. The panic seam is the C harness's (`c_harness.rs`).

#![allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../client/tests/support/mod.rs"]
mod support;

use core::ffi::c_int;
use core::ptr;

use kozane_client_ffi::*;
use rosenpass_wire::{INIT_CONF_LEN, INIT_HELLO_LEN, MSG_INIT_CONF, MSG_INIT_HELLO};
use support::{Gateway, S, client_pair, gateway_pair};

struct Handle(*mut kz_client);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { kz_client_free(self.0) };
    }
}

fn new() -> Handle {
    let (gw, me) = (gateway_pair(), client_pair());
    let mut addr = [0u8; 16];
    addr[..4].copy_from_slice(&[192, 0, 2, 1]);
    let config = kz_config {
        rp_endpoint: kz_sockaddr { family: KZ_FAMILY_IPV4, addr, port: 9999 },
        gw_wg_pub: [7; 32],
        gw_rp_pub: gw.public.as_ptr(),
        gw_rp_pub_len: gw.public.len(),
    };
    let keys = kz_keys {
        rp_pub: me.public.as_ptr(),
        rp_pub_len: me.public.len(),
        rp_sk: me.secret_oqs.as_ptr(),
        rp_sk_len: me.secret_oqs.len(),
    };
    let mut h = ptr::null_mut();
    assert_eq!(unsafe { kz_client_new(&config, &keys, &mut h) }, KZ_OK);
    Handle(h)
}

/// Every queued action, in order.
fn drain(h: &Handle) -> Vec<(c_int, Vec<u8>)> {
    let mut out = Vec::new();
    loop {
        let mut buf = [0u8; KZ_MAX_DATAGRAM];
        let (mut kind, mut len) = (0, 0);
        match unsafe { kz_client_take_action(h.0, buf.as_mut_ptr(), buf.len(), &mut kind, &mut len) } {
            KZ_NONE => return out,
            KZ_OK => out.push((kind, buf[..len].to_vec())),
            code => panic!("take_action: {code}"),
        }
    }
}

fn on_timer(h: &Handle, now: u64) -> Vec<(c_int, Vec<u8>)> {
    assert_eq!(unsafe { kz_client_on_timer(h.0, now) }, KZ_OK);
    drain(h)
}

fn on_datagram(h: &Handle, now: u64, msg: &[u8]) -> Vec<(c_int, Vec<u8>)> {
    assert_eq!(unsafe { kz_client_on_datagram(h.0, now, msg.as_ptr(), msg.len()) }, KZ_OK);
    drain(h)
}

#[test]
fn a_whole_exchange_through_the_c_abi_installs_the_gateways_psk() {
    let h = new();
    assert_eq!(drain(&h), [(KZ_ACTION_SCRUB, vec![])]);
    let mut deadline = u64::MAX;
    assert_eq!(unsafe { kz_client_next_deadline(h.0, &mut deadline) }, KZ_OK);
    assert_eq!(deadline, 0);

    let mut gw = Gateway::new(0);
    let t = S;
    let ih = on_timer(&h, t);
    assert_eq!(ih.len(), 1);
    let (kind, ih) = &ih[0];
    assert_eq!((*kind, ih[0], ih.len()), (KZ_ACTION_SEND, MSG_INIT_HELLO, INIT_HELLO_LEN));

    let rh = gw.respond(ih, t);
    let out = on_datagram(&h, t, &rh);
    assert_eq!(out.iter().map(|(k, _)| *k).collect::<Vec<_>>(), [KZ_ACTION_INSTALL_PSK, KZ_ACTION_SEND]);
    let (psk, ic) = (&out[0].1, &out[1].1);
    assert_eq!((ic[0], ic.len()), (MSG_INIT_CONF, INIT_CONF_LEN));
    let (ed, osk) = gw.confirm(ic, t);
    assert_eq!(psk[..], osk);
    assert!(on_datagram(&h, t, &ed).is_empty());
}

#[test]
fn a_short_buffer_keeps_the_psk_queued() {
    let h = new();
    drain(&h);
    let mut gw = Gateway::new(0);
    let ih = on_timer(&h, S).remove(0).1;
    let rh = gw.respond(&ih, S);
    let msg = &rh[..];
    assert_eq!(unsafe { kz_client_on_datagram(h.0, S, msg.as_ptr(), msg.len()) }, KZ_OK);
    // A short buffer leaves the PSK queued, and returns its length.
    let mut buf = [0u8; KZ_PSK_LEN];
    let (mut kind, mut len) = (0, 0);
    let code = unsafe { kz_client_take_action(h.0, buf.as_mut_ptr(), KZ_PSK_LEN - 1, &mut kind, &mut len) };
    assert_eq!((code, kind, len), (KZ_ERR_BUFFER, KZ_ACTION_INSTALL_PSK, KZ_PSK_LEN));
    assert_eq!(buf, [0; KZ_PSK_LEN]);
    let code = unsafe { kz_client_take_action(h.0, buf.as_mut_ptr(), buf.len(), &mut kind, &mut len) };
    assert_eq!((code, kind, len), (KZ_OK, KZ_ACTION_INSTALL_PSK, KZ_PSK_LEN));
    assert_ne!(buf, [0; KZ_PSK_LEN]);
    let ic = drain(&h);
    assert_eq!(ic.len(), 1, "the InitConf follows");
    let (_, osk) = gw.confirm(&ic[0].1, S);
    assert_eq!(buf, osk);
}
