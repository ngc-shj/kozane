# The kozane boot command (M5 plan C8), compiled into U-Boot as
# CONFIG_BOOTCOMMAND by tools/uboot-config: one command per line, `#` lines
# dropped, REFUSE expanded. Layout (fixed addresses, little-endian):
#   0x6ff00000  boot descriptor v3, 128 bytes: magic "SOSBOOT1", version
#               u32 3, count u32 6, image_len u64, (offset u64, len u64) for
#               the secrets, pq_secrets, tls_secrets and audit_secrets
#               envelopes and the policy_a and policy_b bundle slots,
#               reserved u64 0 (M8 plan C4, deviation D-5)
#   0x6fc00000  secrets envelope;  0x6fd00000  pq_secrets envelope;
#   0x6fe00000  tls_secrets envelope;  0x6f000000  audit_secrets envelope
#   0x6f100000  bundle slot A;  0x6f600000  bundle slot B (BUNDLE_MAX each)
#   0x70000000  published loader.img, also the entry
#   0x6fb00000  scratch for digests
# Order: measure the descriptor, then the image; check the descriptor;
# measure slot A, then slot B, into PCR 9; copy each envelope and each slot
# into the image at its range; run. Every failure powers off and then
# spins, so no failure falls through to a later command or a prompt.
# TF-A's BL1 has started the TPM and extended PCR 0 (M7 plan C3); a TPM
# nothing started fails the first extend below, which refuses.
tpm2 init || REFUSE
hash sha256 0x6ff00000 0x80 *0x6fb00000 || REFUSE
tpm2 pcr_extend 8 0x6fb00000 || REFUSE
setexpr.q img *0x6ff00010
# setexpr wraps at 64 bits and test reads signed values: every field must
# fit in 32 bits before it is compared.
setexpr hi 0x$img / 0x100000000; if test 0x$hi -ne 0; then REFUSE; fi
if test 0x$img -eq 0; then REFUSE; fi
if test 0x$img -gt 0x10000000; then REFUSE; fi
hash sha256 0x70000000 $img *0x6fb00020 || REFUSE
tpm2 pcr_extend 8 0x6fb00020 || REFUSE
setexpr.q magic *0x6ff00000; if test 0x$magic -ne 0x31544f4f42534f53; then REFUSE; fi
setexpr.l ver *0x6ff00008; if test 0x$ver -ne 3; then REFUSE; fi
setexpr.l cnt *0x6ff0000c; if test 0x$cnt -ne 6; then REFUSE; fi
setexpr.q rsv *0x6ff00078; if test 0x$rsv -ne 0; then REFUSE; fi
setexpr.q o0 *0x6ff00018; setexpr.q l0 *0x6ff00020; setexpr.q o1 *0x6ff00028; setexpr.q l1 *0x6ff00030
setexpr.q o2 *0x6ff00038; setexpr.q l2 *0x6ff00040; setexpr.q o3 *0x6ff00048; setexpr.q l3 *0x6ff00050
setexpr.q o4 *0x6ff00058; setexpr.q l4 *0x6ff00060; setexpr.q o5 *0x6ff00068; setexpr.q l5 *0x6ff00070
for v in $o0 $l0 $o1 $l1 $o2 $l2 $o3 $l3 $o4 $l4 $o5 $l5; do setexpr hi 0x$v / 0x100000000; if test 0x$hi -ne 0; then REFUSE; fi; done
# Each range fits its kind's load slot (measure.ROOMS: ENVELOPE_ROOM for an
# envelope, BUNDLE_MAX for a slot), as the host model requires: the two
# adjudicators refuse the same descriptors.
if test 0x$l0 -gt 0x100000; then REFUSE; fi
if test 0x$l1 -gt 0x100000; then REFUSE; fi
if test 0x$l2 -gt 0x100000; then REFUSE; fi
if test 0x$l3 -gt 0x100000; then REFUSE; fi
# A slot range is exactly BUNDLE_MAX (M8 plan C1, F8): the bytes PCR 9
# measures and the bytes copied into the slot MR are then the same.
if test 0x$l4 -ne 0x480000; then REFUSE; fi
if test 0x$l5 -ne 0x480000; then REFUSE; fi
# offset <= image_len, then len <= image_len - offset (no wrap); the end at
# exactly image_len is allowed.
if test 0x$o0 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o0; if test 0x$l0 -gt 0x$room; then REFUSE; fi
if test 0x$o1 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o1; if test 0x$l1 -gt 0x$room; then REFUSE; fi
if test 0x$o2 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o2; if test 0x$l2 -gt 0x$room; then REFUSE; fi
if test 0x$o3 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o3; if test 0x$l3 -gt 0x$room; then REFUSE; fi
if test 0x$o4 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o4; if test 0x$l4 -gt 0x$room; then REFUSE; fi
if test 0x$o5 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o5; if test 0x$l5 -gt 0x$room; then REFUSE; fi
# Pairwise disjoint: of every two ranges, one ends at or before the other
# starts (one line a pair, measure.PAIRS).
setexpr e0 0x$o0 + 0x$l0; setexpr e1 0x$o1 + 0x$l1; setexpr e2 0x$o2 + 0x$l2
setexpr e3 0x$o3 + 0x$l3; setexpr e4 0x$o4 + 0x$l4; setexpr e5 0x$o5 + 0x$l5
if test 0x$e0 -gt 0x$o1 && test 0x$e1 -gt 0x$o0; then REFUSE; fi
if test 0x$e0 -gt 0x$o2 && test 0x$e2 -gt 0x$o0; then REFUSE; fi
if test 0x$e0 -gt 0x$o3 && test 0x$e3 -gt 0x$o0; then REFUSE; fi
if test 0x$e0 -gt 0x$o4 && test 0x$e4 -gt 0x$o0; then REFUSE; fi
if test 0x$e0 -gt 0x$o5 && test 0x$e5 -gt 0x$o0; then REFUSE; fi
if test 0x$e1 -gt 0x$o2 && test 0x$e2 -gt 0x$o1; then REFUSE; fi
if test 0x$e1 -gt 0x$o3 && test 0x$e3 -gt 0x$o1; then REFUSE; fi
if test 0x$e1 -gt 0x$o4 && test 0x$e4 -gt 0x$o1; then REFUSE; fi
if test 0x$e1 -gt 0x$o5 && test 0x$e5 -gt 0x$o1; then REFUSE; fi
if test 0x$e2 -gt 0x$o3 && test 0x$e3 -gt 0x$o2; then REFUSE; fi
if test 0x$e2 -gt 0x$o4 && test 0x$e4 -gt 0x$o2; then REFUSE; fi
if test 0x$e2 -gt 0x$o5 && test 0x$e5 -gt 0x$o2; then REFUSE; fi
if test 0x$e3 -gt 0x$o4 && test 0x$e4 -gt 0x$o3; then REFUSE; fi
if test 0x$e3 -gt 0x$o5 && test 0x$e5 -gt 0x$o3; then REFUSE; fi
if test 0x$e4 -gt 0x$o5 && test 0x$e5 -gt 0x$o4; then REFUSE; fi
# M8 plan D3: both slots measured into PCR 9, A then B, each over its full
# BUNDLE_MAX whatever its range's length; `policy` selects between them.
hash sha256 0x6f100000 0x480000 *0x6fb00060 || REFUSE
tpm2 pcr_extend 9 0x6fb00060 || REFUSE
hash sha256 0x6f600000 0x480000 *0x6fb00080 || REFUSE
tpm2 pcr_extend 9 0x6fb00080 || REFUSE
setexpr d0 0x70000000 + 0x$o0
cp.b 0x6fc00000 $d0 $l0 || REFUSE
setexpr d1 0x70000000 + 0x$o1
cp.b 0x6fd00000 $d1 $l1 || REFUSE
setexpr d2 0x70000000 + 0x$o2
cp.b 0x6fe00000 $d2 $l2 || REFUSE
setexpr d3 0x70000000 + 0x$o3
cp.b 0x6f000000 $d3 $l3 || REFUSE
setexpr d4 0x70000000 + 0x$o4
cp.b 0x6f100000 $d4 $l4 || REFUSE
setexpr d5 0x70000000 + 0x$o5
cp.b 0x6f600000 $d5 $l5 || REFUSE
RUN
