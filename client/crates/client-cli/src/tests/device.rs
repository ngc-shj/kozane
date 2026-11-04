//! The device lifecycle and the scrub against a scripted netlink peer (the
//! kernel boundary): what is sent, in what order, and that every refusal
//! or failed draw is fatal before anything is sent.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use kozane_client::Secret;

use crate::b64;
use crate::conf::Conf;
use crate::device::{Device, RngFailed, reclaim};
use crate::netlink::{self, Msg, NlError, Transport};
use crate::{rtnl, wg};

type Log = Rc<RefCell<Vec<Vec<u8>>>>;

struct Fake {
    sent: Log,
    replies: VecDeque<Result<Vec<Vec<u8>>, NlError>>,
}

impl Transport for Fake {
    fn call(&mut self, msg: &mut Msg) -> Result<Vec<Vec<u8>>, NlError> {
        self.sent.borrow_mut().push(msg.finish(1, 1)?.to_vec());
        match self.replies.pop_front() {
            Some(reply) => reply,
            // A message the test did not script is a failure, not an ack;
            // while unwinding (the Device's drop), only the first panic counts.
            None if std::thread::panicking() => Ok(Vec::new()),
            None => panic!("netlink fake: no reply scripted for message {}", self.sent.borrow().len()),
        }
    }
}

/// `n` plain acks.
fn acks(n: usize) -> Vec<Result<Vec<Vec<u8>>, NlError>> {
    (0..n).map(|_| Ok(Vec::new())).collect()
}

fn fake(replies: Vec<Result<Vec<Vec<u8>>, NlError>>) -> (Fake, Log) {
    let log = Log::default();
    (Fake { sent: log.clone(), replies: replies.into() }, log)
}

fn conf() -> Conf {
    Conf::parse(&format!(
        "interface = kz0\naddress = 10.1.0.2/24\nwg_listen_port = 51821\nwg_endpoint = 192.0.2.1:51820\n\
         rp_listen_port = 9998\nrp_endpoint = 192.0.2.1:9999\ngw_wg_pub = {}\ngw_rp_pub_path = /etc/kozane/gw.pub\n\
         allowed_ips = 10.1.0.0/24,10.2.0.0/24\n",
        b64::encode(&[0xaa; 32])
    ))
    .unwrap()
}

fn ok_fill(out: &mut [u8]) -> Result<(), RngFailed> {
    out.fill(0x5c);
    Ok(())
}

fn failing_fill(_: &mut [u8]) -> Result<(), RngFailed> {
    Err(RngFailed)
}

fn zero_fill(out: &mut [u8]) -> Result<(), RngFailed> {
    out.fill(0);
    Ok(())
}

/// (nlmsg type, top-level attributes after the family header).
fn decode(msg: &[u8], family_hdr: usize) -> (u16, Vec<(u16, Vec<u8>)>) {
    let ty = u16::from_ne_bytes([msg[4], msg[5]]);
    (ty, netlink::attrs(&msg[16 + family_hdr..]).map(|(t, v)| (t, v.to_vec())).collect())
}

/// The peers in a `WG_CMD_SET_DEVICE`, each as its attributes.
fn peers(msg: &[u8]) -> Vec<Vec<(u16, Vec<u8>)>> {
    let (_, top) = decode(msg, 4);
    let Some((_, list)) = top.iter().find(|(t, _)| *t == wg::WGDEVICE_A_PEERS) else {
        return Vec::new();
    };
    netlink::attrs(list).map(|(_, p)| netlink::attrs(p).map(|(t, v)| (t, v.to_vec())).collect()).collect()
}

fn get(attrs: &[(u16, Vec<u8>)], ty: u16) -> Option<&[u8]> {
    attrs.iter().find(|(t, _)| *t == ty).map(|(_, v)| v.as_slice())
}

fn device(genl: Vec<Result<Vec<Vec<u8>>, NlError>>, fill: crate::device::Fill) -> (Device<Fake>, Log, Log) {
    // The route socket's one message is the drop's RTM_DELLINK.
    let (route, rlog) = fake(acks(1));
    let (genl, glog) = fake(genl);
    (Device::attached(route, genl, 30, 5, &conf(), fill).unwrap(), rlog, glog)
}

#[test]
fn scrub_removes_then_re_adds_the_peer_with_a_random_psk() {
    let (mut dev, _, glog) = device(acks(2), ok_fill);
    dev.scrub().unwrap();
    let sent = glog.borrow();
    assert_eq!(sent.len(), 2, "kzc: session survived scrub");
    let remove = &peers(&sent[0])[0];
    assert_eq!(get(remove, wg::WGPEER_A_PUBLIC_KEY), Some(&[0xaa; 32][..]));
    assert_eq!(get(remove, wg::WGPEER_A_FLAGS), Some(&wg::WGPEER_F_REMOVE_ME.to_ne_bytes()[..]), "kzc: session survived scrub");
    let add = &peers(&sent[1])[0];
    assert_eq!(get(add, wg::WGPEER_A_FLAGS), None);
    assert_eq!(get(add, wg::WGPEER_A_PRESHARED_KEY), Some(&[0x5c; 32][..]));
    assert_eq!(get(add, wg::WGPEER_A_ENDPOINT), Some(&wg::sockaddr(&"192.0.2.1:51820".parse().unwrap())[..]));
    assert_eq!(netlink::attrs(get(add, wg::WGPEER_A_ALLOWEDIPS).unwrap()).count(), 2);
}

#[test]
fn a_failed_draw_is_fatal_and_sends_nothing() {
    for fill in [failing_fill as crate::device::Fill, zero_fill] {
        // Acks for a scrub that wrongly goes on, so the assertion judges it.
        let (mut dev, _, glog) = device(acks(2), fill);
        assert!(dev.scrub().is_err(), "kzc-psk: zero psk installed");
        assert!(glog.borrow().is_empty(), "kzc-psk: zero psk installed");
    }
}

#[test]
fn a_refused_remove_is_fatal() {
    let (mut dev, _, glog) = device(vec![Err(NlError::Errno(libc::ENODEV)), Ok(Vec::new())], ok_fill);
    let e = dev.scrub().expect_err("kzc-psk: scrub unconfirmed");
    assert!(e.contains("remove peer"), "{e}");
    assert_eq!(glog.borrow().len(), 1, "no re-add after a refused remove");
}

#[test]
fn a_refused_re_add_is_fatal() {
    let (mut dev, _, _) = device(vec![Ok(Vec::new()), Err(NlError::Errno(libc::EINVAL))], ok_fill);
    dev.scrub().expect_err("kzc-psk: scrub unconfirmed");
}

#[test]
fn install_sets_only_the_psk_and_checks_the_ack() {
    let (mut dev, _, glog) = device(vec![Ok(Vec::new()), Err(NlError::Errno(libc::ENODEV))], ok_fill);
    dev.install(&Secret::copy_from(&[3; 32])).unwrap();
    let p = &peers(&glog.borrow()[0])[0];
    assert_eq!(get(p, wg::WGPEER_A_PRESHARED_KEY), Some(&[3; 32][..]));
    assert_eq!(get(p, wg::WGPEER_A_FLAGS), Some(&wg::WGPEER_F_UPDATE_ONLY.to_ne_bytes()[..]));
    assert_eq!(get(p, wg::WGPEER_A_ENDPOINT), None);
    assert!(dev.install(&Secret::copy_from(&[3; 32])).is_err());
}

#[test]
fn install_refuses_a_zero_psk() {
    let (mut dev, _, glog) = device(acks(1), ok_fill);
    assert!(dev.install(&Secret::zero()).is_err(), "kzc-psk: zero psk installed");
    assert!(glog.borrow().is_empty());
}

#[test]
fn drop_deletes_the_interface() {
    let (dev, rlog, _) = device(Vec::new(), ok_fill);
    drop(dev);
    let sent = rlog.borrow();
    assert_eq!(sent.len(), 1, "kzc-psk: interface left after exit");
    assert_eq!(sent[0], { rtnl::del_link(5).finish(1, 1).unwrap().to_vec() }, "kzc-psk: interface left after exit");
}

fn link_reply(index: u32, alias: Option<&str>, kind: &str) -> Vec<u8> {
    let mut m = Msg::new(rtnl::RTM_NEWLINK, 0);
    m.header(&rtnl::ifinfomsg(index, 0, 0)).str(rtnl::IFLA_IFNAME, "kz0");
    if let Some(a) = alias {
        m.str(rtnl::IFLA_IFALIAS, a);
    }
    m.nest(rtnl::IFLA_LINKINFO).str(rtnl::IFLA_INFO_KIND, kind).end();
    m.finish(0, 0).unwrap()[16..].to_vec()
}

#[test]
fn reclaim_deletes_a_marked_leftover() {
    let (mut route, log) = fake(vec![Ok(vec![link_reply(8, Some(rtnl::MARK), "wireguard")]), Ok(Vec::new())]);
    assert!(reclaim(&mut route, "kz0").expect("kzc-psk: restart refused"));
    assert_eq!(decode(&log.borrow()[1], 16).0, rtnl::RTM_DELLINK);
    let (mut route, _) = fake(vec![Err(NlError::Errno(libc::ENODEV))]);
    assert!(!reclaim(&mut route, "kz0").unwrap());
}

#[test]
fn reclaim_refuses_a_foreign_interface() {
    for (alias, kind) in [(None, "wireguard"), (Some("other"), "wireguard"), (Some(rtnl::MARK), "dummy")] {
        let (mut route, log) = fake(vec![Ok(vec![link_reply(8, alias, kind)]), Ok(Vec::new())]);
        let e = reclaim(&mut route, "kz0").unwrap_err();
        assert!(e.contains("not created by kzc-psk"), "{e}");
        assert_eq!(log.borrow().len(), 1, "a foreign interface was touched");
    }
}

fn family_reply() -> Vec<u8> {
    let mut m = Msg::new(wg::GENL_ID_CTRL, 0);
    m.header(&[1, 2, 0, 0]).u16(wg::CTRL_ATTR_FAMILY_ID, 30).str(wg::CTRL_ATTR_FAMILY_NAME, "wireguard");
    m.finish(0, 0).unwrap()[16..].to_vec()
}

#[test]
fn create_marks_configures_and_routes() {
    let (route, rlog) = fake(vec![
        Err(NlError::Errno(libc::ENODEV)),      // no leftover
        Ok(Vec::new()),                         // create
        Ok(vec![link_reply(9, None, "wireguard")]), // look up the index
        Ok(Vec::new()),                         // mark
        Ok(Vec::new()),                         // up
        Ok(Vec::new()),                         // address
        Ok(Vec::new()),                         // route
        Ok(Vec::new()),                         // the drop's delete
    ]);
    let (genl, glog) = fake(vec![Ok(vec![family_reply()]), Ok(Vec::new())]);
    let dev = Device::create(route, genl, &conf(), &Secret::copy_from(&[0x11; 32]), ok_fill).unwrap();
    let types: Vec<u16> = rlog.borrow().iter().map(|m| decode(m, 16).0).collect();
    // get, create, get, mark, up, address, one route: 10.1.0.0/24 is the
    // address's own prefix.
    assert_eq!(
        types,
        [rtnl::RTM_GETLINK, rtnl::RTM_NEWLINK, rtnl::RTM_GETLINK, rtnl::RTM_NEWLINK, rtnl::RTM_NEWLINK, rtnl::RTM_NEWADDR, rtnl::RTM_NEWROUTE]
    );
    let (_, mark) = decode(&rlog.borrow()[3], 16);
    assert_eq!(get(&mark, rtnl::IFLA_IFALIAS), Some(&b"kozane-psk\0"[..]));
    let cfg = &glog.borrow()[1];
    let (_, top) = decode(cfg, 4);
    assert_eq!(get(&top, wg::WGDEVICE_A_PRIVATE_KEY), Some(&[0x11; 32][..]));
    let p = &peers(cfg)[0];
    assert_eq!(get(p, wg::WGPEER_A_PRESHARED_KEY), Some(&[0x5c; 32][..]), "the peer was created without a PSK");
    drop(dev);
    assert_eq!(decode(rlog.borrow().last().unwrap(), 16).0, rtnl::RTM_DELLINK);
}

#[test]
fn a_failed_configuration_deletes_the_new_interface() {
    let (route, rlog) = fake(vec![
        Err(NlError::Errno(libc::ENODEV)),
        Ok(Vec::new()),
        Ok(vec![link_reply(9, None, "wireguard")]),
        Ok(Vec::new()), // mark
        Ok(Vec::new()), // the delete
    ]);
    let (genl, _) = fake(vec![Ok(vec![family_reply()]), Err(NlError::Errno(libc::EINVAL))]);
    assert!(Device::create(route, genl, &conf(), &Secret::copy_from(&[0x11; 32]), ok_fill).is_err());
    assert_eq!(decode(rlog.borrow().last().unwrap(), 16).0, rtnl::RTM_DELLINK, "kzc-psk: interface left after exit");
}

#[test]
fn create_refuses_a_foreign_interface_and_creates_nothing() {
    let (route, rlog) = fake(vec![Ok(vec![link_reply(8, None, "wireguard")])]);
    let (genl, _) = fake(vec![Ok(vec![family_reply()])]);
    assert!(Device::create(route, genl, &conf(), &Secret::copy_from(&[0x11; 32]), ok_fill).is_err());
    assert_eq!(rlog.borrow().len(), 1);
}
