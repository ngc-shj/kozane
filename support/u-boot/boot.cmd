# The kozane boot command (M5 plan C8), compiled into U-Boot as
# CONFIG_BOOTCOMMAND by tools/uboot-config: one command per line, `#` lines
# dropped, REFUSE expanded. Layout (fixed addresses, little-endian):
#   0x6ff00000  boot descriptor v2, 80 bytes: magic "SOSBOOT1", version
#               u32 2, count u32 3, image_len u64, (offset u64, len u64) for
#               the secrets, pq_secrets and tls_secrets envelopes, reserved
#               u64 0 (M6 plan Re-plan R1)
#   0x6fc00000  secrets envelope;  0x6fd00000  pq_secrets envelope;
#   0x6fe00000  tls_secrets envelope
#   0x70000000  published loader.img, also the entry
#   0x6fb00000  scratch for digests
# Order: measure the descriptor, then the image; check the descriptor; copy
# each envelope into the image at its range; run. Every failure powers off
# and then spins, so no failure falls through to a later command or a prompt.
# TF-A's BL1 has started the TPM and extended PCR 0 (M7 plan C3); a TPM
# nothing started fails the first extend below, which refuses.
tpm2 init || REFUSE
hash sha256 0x6ff00000 0x50 *0x6fb00000 || REFUSE
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
setexpr.l ver *0x6ff00008; if test 0x$ver -ne 2; then REFUSE; fi
setexpr.l cnt *0x6ff0000c; if test 0x$cnt -ne 3; then REFUSE; fi
setexpr.q rsv *0x6ff00048; if test 0x$rsv -ne 0; then REFUSE; fi
setexpr.q o0 *0x6ff00018; setexpr.q l0 *0x6ff00020; setexpr.q o1 *0x6ff00028; setexpr.q l1 *0x6ff00030
setexpr.q o2 *0x6ff00038; setexpr.q l2 *0x6ff00040
for v in $o0 $l0 $o1 $l1 $o2 $l2; do setexpr hi 0x$v / 0x100000000; if test 0x$hi -ne 0; then REFUSE; fi; done
# Each envelope fits its load slot (measure.ENVELOPE_ROOM), as the host
# model requires: the two adjudicators refuse the same descriptors.
if test 0x$l0 -gt 0x100000; then REFUSE; fi
if test 0x$l1 -gt 0x100000; then REFUSE; fi
if test 0x$l2 -gt 0x100000; then REFUSE; fi
# offset <= image_len, then len <= image_len - offset (no wrap); the end at
# exactly image_len is allowed.
if test 0x$o0 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o0; if test 0x$l0 -gt 0x$room; then REFUSE; fi
if test 0x$o1 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o1; if test 0x$l1 -gt 0x$room; then REFUSE; fi
if test 0x$o2 -gt 0x$img; then REFUSE; fi
setexpr room 0x$img - 0x$o2; if test 0x$l2 -gt 0x$room; then REFUSE; fi
# Pairwise disjoint: of every two ranges, one ends at or before the other
# starts.
setexpr e0 0x$o0 + 0x$l0; setexpr e1 0x$o1 + 0x$l1; setexpr e2 0x$o2 + 0x$l2
if test 0x$e0 -gt 0x$o1 && test 0x$e1 -gt 0x$o0; then REFUSE; fi
if test 0x$e0 -gt 0x$o2 && test 0x$e2 -gt 0x$o0; then REFUSE; fi
if test 0x$e1 -gt 0x$o2 && test 0x$e2 -gt 0x$o1; then REFUSE; fi
setexpr d0 0x70000000 + 0x$o0
cp.b 0x6fc00000 $d0 $l0 || REFUSE
setexpr d1 0x70000000 + 0x$o1
cp.b 0x6fd00000 $d1 $l1 || REFUSE
setexpr d2 0x70000000 + 0x$o2
cp.b 0x6fe00000 $d2 $l2 || REFUSE
RUN
