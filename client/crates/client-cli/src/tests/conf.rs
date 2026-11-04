use std::net::IpAddr;

use crate::b64;
use crate::conf::{Cidr, Conf};

fn good() -> String {
    format!(
        "# client.conf\n\
         interface = kz0\n\
         address = 10.1.0.2/24\n\
         \n\
         wg_listen_port = 51821\n\
         wg_endpoint = 192.0.2.1:51820\n\
         rp_listen_port = 9998\n\
         rp_endpoint = [2001:db8::1]:9999\n\
         gw_wg_pub = {}\n\
         gw_rp_pub_path = /etc/kozane/gateway-rp.pub\n\
         allowed_ips = 10.2.0.0/24, 10.1.0.0/24,fd00::/64\n",
        b64::encode(&[9; 32])
    )
}

fn with(key: &str, value: &str) -> String {
    good().lines().map(|l| if l.starts_with(key) { format!("{key} = {value}") } else { l.to_string() }).collect::<Vec<_>>().join("\n")
}

#[test]
fn accepts_every_key_once() {
    let c = Conf::parse(&good()).unwrap();
    assert_eq!(c.interface, "kz0");
    assert_eq!(c.address, Cidr { addr: "10.1.0.2".parse().unwrap(), len: 24 });
    assert_eq!(c.address.network(), "10.1.0.0".parse::<IpAddr>().unwrap());
    assert_eq!((c.wg_listen_port, c.rp_listen_port), (51821, 9998));
    assert_eq!(c.wg_endpoint, "192.0.2.1:51820".parse().unwrap());
    assert_eq!(c.rp_endpoint, "[2001:db8::1]:9999".parse().unwrap());
    assert_eq!(c.gw_wg_pub, [9; 32]);
    assert_eq!(c.gw_rp_pub_path, "/etc/kozane/gateway-rp.pub");
    assert_eq!(c.allowed_ips.len(), 3);
    assert_eq!(c.allowed_ips[2], Cidr { addr: "fd00::".parse().unwrap(), len: 64 });
}

#[test]
fn refuses_an_unknown_key() {
    let e = Conf::parse(&format!("{}\nfwmark = 1\n", good())).unwrap_err();
    assert!(e.contains("unknown key \"fwmark\""), "{e}");
}

#[test]
fn refuses_a_repeated_key() {
    let e = Conf::parse(&format!("{}\ninterface = kz1\n", good())).unwrap_err();
    assert!(e.contains("repeated"), "{e}");
}

#[test]
fn refuses_a_missing_key() {
    let text: String = good().lines().filter(|l| !l.starts_with("rp_endpoint")).map(|l| format!("{l}\n")).collect();
    assert_eq!(Conf::parse(&text).unwrap_err(), "rp_endpoint: missing");
}

#[test]
fn refuses_a_line_without_equals_or_value() {
    assert!(Conf::parse(&format!("{}\ninterface\n", good())).unwrap_err().contains("want key = value"));
    assert!(Conf::parse(&with("interface", "")).unwrap_err().contains("empty value"));
}

#[test]
fn refuses_bad_values() {
    let cases = [
        ("interface", "a-name-that-is-too-long"),
        ("interface", "kz/0"),
        ("interface", ".."),
        ("address", "10.1.0.2"),
        ("address", "10.1.0.2/33"),
        ("address", "10.1.0.2/+8"),
        ("address", "0.0.0.0/8"),
        ("wg_listen_port", "0"),
        ("wg_listen_port", "65536"),
        ("wg_listen_port", "+80"),
        ("wg_endpoint", "gateway.example:51820"),
        ("wg_endpoint", "192.0.2.1"),
        ("wg_endpoint", "0.0.0.0:51820"),
        ("rp_endpoint", "192.0.2.1:0"),
        ("gw_wg_pub", "AAAA"),
        ("gw_rp_pub_path", "etc/kozane/gw.pub"),
        ("allowed_ips", "10.2.0.1/24"),
        ("allowed_ips", "0.0.0.0/0"),
        ("allowed_ips", "10.2.0.0/24,10.2.0.0/24"),
        ("allowed_ips", "10.2.0.0/24,"),
    ];
    for (k, v) in cases {
        assert!(Conf::parse(&with(k, v)).is_err(), "{k} = {v} accepted");
    }
}
