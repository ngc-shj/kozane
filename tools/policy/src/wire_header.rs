//! A slot's header for the ledger, `sign`, `approve` and `diff` (M8 plan
//! C2), read by `policy_wire::header`, the one walker of the C1 layout:
//! these need the fields across a whole fleet, with no single node to check
//! a slot against.

pub use policy_wire::Header;

pub fn read(slot: &[u8]) -> Result<Header, String> {
    policy_wire::header(slot).map_err(|e| format!("slot: malformed ({e:?})"))
}
