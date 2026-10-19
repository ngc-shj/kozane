# Manual Test: secureos-m3-rosenpass (M3a)

The diff changes `docker/Dockerfile` (new `rosenpass-oracle` stage) and the
gateway's key-exchange path (Rosenpass responder, OSK → WireGuard PSK). The
integration suite automates most of this. The steps below are the manual
cross-check a reviewer runs on a fresh checkout.

## Pre-conditions
- Docker on an aarch64 or x86_64 host with at least 64 GB free for the dev
  container (Kani alone peaks near 28 GB).
- No dev container from an older image: `make -C docker rm`.
- A throwaway output directory outside the repository for secrets, e.g.
  `/tmp/m3-manual`. Secrets never go into the repository.

## Steps
1. **Image build:** `make -C docker build run`.
   - The `rosenpass-oracle` stage builds with `--network=none` after its
     fetch layer.
   - In the container, run `sha256sum /opt/rosenpass-master/rosenpass
     /opt/rosenpass-023/rosenpass`. The hashes must equal
     `tests/integration/rosenpass-oracle.sha256`.
   - Check the memory cap: `docker inspect -f '{{.HostConfig.Memory}}'
     secureos-dev` prints `68719476736`.
2. **Secrets and image:**
   - In the container, run `cargo run -p mksecrets -- --template
     config/gateway.toml --peers 1 --out /tmp/m3-manual`.
   - Then run `SECUREOS_CONFIG=/tmp/m3-manual/gateway.toml make package
     SECRETS=/tmp/m3-manual/secrets.bin
     PQ_SECRETS=/tmp/m3-manual/pqkey-secrets.bin OUT=/tmp/m3-manual/pkg`.
3. **Boot:** `make run LOADER=/tmp/m3-manual/pkg/loader.img`.
   - The console shows `pqkey: secrets valid` and then `pq: ready`.
4. **Key exchange:** on the host side of the forwarded ports, run upstream
   `rosenpass exchange-config /tmp/m3-manual/peer-0.rosenpass.toml`.
   - Expect `audit: src=pq RpPskExported`.
   - Expect `peer-0.osk` to appear.
5. **WireGuard:** bring up wireguard-go with `peer-0.conf` and set its
   preshared key from `peer-0.osk`. A handshake and ping succeed.
6. **Expiry:** stop the rosenpass client and wait 185 s.
   - The next WireGuard handshake is refused with
     `audit: src=hs HandshakePskStale`.
   - Restarting the client restores the tunnel.

## Expected result
- Steps 3–5 succeed with the PSK coming only from Rosenpass. `peer-0.conf`
  carries no `PresharedKey`.
- Step 6 refuses the stale PSK and recovers once a fresh OSK is exported.
- No `HandshakeOk` appears for any peer before its first `RpPskExported`.

## Rollback
- Stop QEMU with `Ctrl-a x`.
- Delete the throwaway directory: `rm -rf /tmp/m3-manual`.
- Run `make -C docker rm` to drop the container. Dev images are not
  deployable (SC20, and waivers SC23 and SC26 are open), so there is no
  deployed state to roll back.

## Adversarial scenarios
- **Replay:**
  - Capture a client InitHello and resend it 10 times from the same
    source. The first is answered at most once per 20 s; the rest draw
    `RpRateLimited`.
  - Resend a captured InitConf after the exchange completes. It is
    answered from the known-InitConf cache and exports nothing new.
- **Forged mac:** flip one byte of the envelope mac. Expect `RpBadMac`,
  no decapsulation, and no `RpCostHighWater` rise.
- **Cross-peer binding:** use peer 1's Rosenpass key with peer 0's
  WireGuard key. Peer 0's handshake is refused with `HandshakePskMissing`.
- **Reboot replay:**
  - Capture a WireGuard initiation.
  - Reset QEMU with `system_reset` from the monitor.
  - Resend the initiation before any Rosenpass exchange. It is refused
    with `HandshakePskMissing`.
- **Secrets mapping:**
  - Edit `system/secureos.system` to map `pq_secrets` as `rw`, or into
    `pq`. `make image` must refuse it at the laws step (L2).
  - Add a channel from `pq` to `key`, declared in the policy too. `laws`
    refuses it (L2).
