# Running the Linux client (`kzc`)

This guide is for the operator who installs Kozane's client on a Linux
machine, and for the approvers who enroll it. The design is in the M9 plan
(D6, D7, C10).

## What runs

The client is two systemd units, under two users:

- **`kozane-psk.service`** runs `kzc-psk` as the user `kozane-psk`, which
  holds `CAP_NET_ADMIN` and nothing else.
  - It creates the WireGuard interface named in the config. It marks the
    interface as its own and deletes it again when it stops.
  - It sets the interface's address, routes, private key and its one peer,
    the gateway.
  - It holds `wg.sk`.
- **`kozane-net.service`** runs `kzc` as `kozane-net`, with no
  capabilities.
  - It talks Rosenpass with the gateway and hands `kzc-psk` each fresh PSK.
  - It holds `rp.sk` and parses everything that arrives from the network.

The two talk over a socket that only `kozane-net` may connect to.

Two rules hold from first start:

- The peer never exists without a PSK. At start it gets a random one.
- When no exchange has succeeded for 180 seconds (the gateway's L8 window),
  `kzc-psk` replaces the peer with a fresh one holding a random PSK, in
  one kernel request, so no reader of the interface's configuration sees
  it without its peer. If the request fails, `kzc-psk` deletes the
  interface and exits, and systemd restarts it. That ends
  any live WireGuard session, so traffic stops instead of running on a
  stale key.

## Requirements

- Linux with kernel WireGuard. Load the module before the units start
  (`modprobe wireguard`, or `wireguard` in `/etc/modules-load.d/`). The
  unit's `ProtectKernelModules=yes` may keep it from loading on demand.
- systemd 249 or later. `Upholds=` restarts the pair together; an older
  systemd ignores it.
- The two users `kozane-psk` and `kozane-net`, and the group `kozane-net`.

Never `setcap` the binaries. The capability comes from the unit, and only
`kozane-psk.service` grants it.

## Install

1. Install `kzc` and `kzc-psk` to `/usr/bin` (the path the units name),
   and the units from `client/dist/` to `/etc/systemd/system/`.
2. Generate the keys, once, as root:

   ```sh
   kzc keygen
   ```

   This creates two directories, each 0700 and owned by its unit's user:
   - `/var/lib/kozane-psk`, holding `wg.sk` and `wg.pub`;
   - `/var/lib/kozane-net`, holding `rp.sk` and `rp.pub`.

   It refuses to overwrite existing keys. It prints the start of the
   client's `[[peers]]` entry: the Rosenpass digest and `wg_pub`. The PDP
   completes it. It copies `/var/lib/kozane-net/rp.pub` next to
   `peers.toml` (`rp_pub_path = "rp.pub"`), and adds the peer's
   `allowed_ips` and groups.
3. Write `/etc/kozane/client.conf`, root-owned and not group- or
   world-writable. Every key is required, and an unknown key is refused:

   | Key | Value |
   |---|---|
   | `interface` | the WireGuard interface to create (it must not exist) |
   | `address` | the client's tunnel address with prefix |
   | `wg_listen_port`, `rp_listen_port` | local UDP ports |
   | `wg_endpoint`, `rp_endpoint` | the gateway's WireGuard and Rosenpass addresses (IP literals, no DNS) |
   | `gw_wg_pub` | the gateway's WireGuard public key, base64 |
   | `gw_rp_pub_path` | the gateway's Rosenpass public key, a root-owned file under `/etc/kozane` |
   | `allowed_ips` | the networks behind the gateway (`/0` is refused) |

## Enroll

1. The operator sends the PDP the entry `kzc keygen` printed, and
   `rp.pub`.
2. An approver confirms the digest **out of band** with the named person:
   by phone, or face to face, never over the channel the entry came by.
   Add this to the approval checklist in the
   [peer-policy runbook](peer-policy-runbook.md).
3. Two approvers approve the diff, as for any bundle change.
4. The gateway prints its own Rosenpass digest and WireGuard key at boot,
   and the operator publishes them. Put the gateway's keys in
   `/etc/kozane`, and `gw_wg_pub` in `client.conf`.
5. Start the units:

   ```sh
   systemctl enable --now kozane-psk.service kozane-net.service
   ```

   At start, `kzc-psk` prints its own and the gateway's `wg_pub`, and `kzc`
   prints the gateway's Rosenpass digest. Compare them with the published
   values before trusting the tunnel.

## Revoke and replace

- **A stolen or retired machine** is revoked at the gateway: a bundle
  without its peer, under the 15-minute SLA. Group rules limit what the
  peer can reach until then.
- **New keys:**
  1. Stop the units.
  2. Move the old key directories away.
  3. Run `kzc keygen` again.
  4. Enroll the new digest.

## What is not covered

- Keys are not encrypted at rest on Linux. Protect the machine's disk.
- A `SIGKILL` of `kzc-psk` leaves its interface with the last PSK until the
  next start deletes it, or until the gateway's L8 window ends.
- Windows, macOS, iOS and Android clients are future work. They build on
  the same library, `kozane-client`, through its C ABI.
