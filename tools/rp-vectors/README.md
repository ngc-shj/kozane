# rp-vectors

Captures the Rosenpass V02 golden vectors that `crates/rosenpass-core` pins
(M3 plan C1, T1). Not a workspace member: it builds upstream rosenpass
`9e72f1eb871c4c403e99e9b78262fff8dd8d7357` with `expose_internal_modules`
(std, liboqs through `oqs-sys`, so it needs cmake) under upstream's own
toolchain (`rust-toolchain.toml`), with its own `Cargo.lock` seeded from
upstream's.

One upstream initiator and one upstream responder run a full V02 handshake
without a PSK. Only the responder runs under `assert_tv::TestVectorActive` in
init mode, so the recorded values (ck chain IHR4–RHR7, sidr, both
encapsulations, the biscuit) are the ones the kozane responder must
reproduce. Hash domains, the mac key, peer ids, the ICR1–ICR4 ck values and
the OSK come from upstream's own functions. The two KEM KATs drive liboqs with
a SplitMix64 `randombytes` stream that the Rust side re-implements.

Outputs (all regenerated together; the keys are fresh on every run):
- `crates/rosenpass-core/tests/vectors/v02.txt` (`name hex` lines with a
  header naming the upstream revision and features),
- `crates/rosenpass-core/tests/vectors/{spkm,spkt}.bin` (McEliece public
  keys of the responder and the initiator),
- `crates/rosenpass-wire/src/__fuzz__/tests__parsers_never_panic_and_round_trip/corpus/seed-*`
  (the four captured messages).

Regenerate (rare; network needed for the first build). The dev image does
not ship cmake, which liboqs needs. Run the driver in a container from the
Dockerfile's `rosenpass-oracle` stage, which has cmake and the pinned
toolchain from the same apt snapshot:

    docker build --target rosenpass-oracle -t kozane-rp-oracle docker
    docker run --rm -v "$PWD":/work -w /work/tools/rp-vectors kozane-rp-oracle \
        sh -c 'cargo +1.93.1 run --locked --release -- /work'

The cookie vectors (`crates/rosenpass-core/tests/vectors/cookie.txt`, M3b plan
C1) are a separate mode. It reads the committed `spkm.bin` and InitHello seed,
so it does not touch `v02.txt` or the keys:

    docker run --rm -v "$PWD":/work -w /work/tools/rp-vectors kozane-rp-oracle \
        sh -c 'cargo +1.93.1 run --locked --release -- /work --cookie'

`v02.txt` still lists `domain.cookie*` from before M3b. Those are the V02
(BLAKE2b) tree's cookie labels, which upstream's cookie code never uses, so
rosenpass-core no longer pins them; the next full regeneration drops them.

Upstream quirk the driver accounts for: `handle_msg` first tries every
InitHello as V03 (SHAKE256). That attempt records IHR4 and IHR5 (including a
McEliece decapsulation) before failing at IHR6, and only then runs the V02
attempt, so the driver keeps the last recorded sequence.

A second quirk: upstream casts the EmptyData envelope over its transmit buffer
and never writes the cookie field, so on the wire that field carries bytes 48..64
of whatever the buffer held before (the previous RespHello in a long-running
responder). The driver hands the responder a zeroed buffer for that message, so
the captured EmptyData has the all-zero cookie the kozane responder sends.

The McEliece vectors for `crates/mce460896` (M4 plan C8) are one more mode.
It does not touch the files above.

- `--mce` writes `crates/mce460896/tests/vectors/liboqs.txt`, from liboqs
  0.8's round-3 mceliece460896, the code the peers run. For each of three
  keys it records:
  - the SplitMix64 keygen seed;
  - SHA3-256 of the public key;
  - the secret key in liboqs's layout;
  - one encapsulation;
  - decapsulations in four classes: valid, C0 corrupt, C1 corrupt, both.

`crates/mce460896/tests/vectors/cmr-2.0.2.txt` was captured the same way from
classic-mceliece-rust 2.0.2 (the blob's layout) before the cut-over to
`mce460896` (M4 C11). That was a `--cmr` mode here, now removed along with
its classic-mceliece-rust and rand_core dependencies; the file itself is
frozen and never regenerated.

    docker run --rm -v "$PWD":/work -w /work/tools/rp-vectors kozane-rp-oracle \
        sh -c 'cargo +1.93.1 run --locked --release -- /work --mce'
