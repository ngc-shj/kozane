//! Sliding-window replay protection for transport counters (RFC 6479 idea,
//! semantics of Linux `drivers/net/wireguard/receive.c:counter_validate`).
//!
//! The window is exact: a counter is accepted iff it is below
//! `REJECT_AFTER_MESSAGES`, not seen before, and no more than `WINDOW` below
//! the highest accepted counter. Linux keeps one redundant word so that it
//! can clear whole words (window = bits - 64); this version keeps one flag
//! per slot and clears slot by slot, so the window is `BITS - 1`.

use crate::REJECT_AFTER_MESSAGES;
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::{
    lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse, lemma_mod_bound,
    lemma_mod_equivalence, lemma_mod_multiples_vanish,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::mul::{lemma_mul_inequality, lemma_mul_is_commutative};
use vstd::prelude::*;

verus! {

/// Whether a counter `c` (plus one) lies more than `window` below `top`:
/// the saturating sum never wraps, so this is the comparison over the
/// integers.
#[inline]
fn below_window(c: u64, window: u64, top: u64) -> (r: bool)
    ensures
        r == (c + window < top),
{
    c.saturating_add(window) < top
}

/// The sliding window's model: `accepted` (ghost) is every counter ever
/// accepted. `top` is the highest accepted counter plus one (0 before any
/// accept); for `cs = c + 1`, `seen[cs % BITS]` must agree with whether `c`
/// is in `accepted` for every `c` still inside the `BITS - 1` window below
/// `top`.
pub open spec fn window_wf<const BITS: usize>(top: u64, seen: Seq<bool>, accepted: Set<int>) -> bool {
    &&& BITS >= 2
    // Keeps the clearing loop's step counter, bounded by `BITS as u64`, away
    // from wrapping: true for every `BITS` this crate (or any real caller)
    // instantiates.
    &&& (BITS as u64) < u64::MAX
    &&& seen.len() == BITS
    &&& (top == 0 ==> accepted.is_empty())
    &&& (top > 0 ==> accepted.contains(top as int - 1))
    &&& (forall|c: int| accepted.contains(c) ==> 0 <= c && c + 1 <= top)
    &&& (forall|cs: int|
        1 <= cs && cs <= top as int && top as int - cs <= (BITS - 1) as int
            ==> #[trigger] seen[cs % (BITS as int)] == accepted.contains(cs - 1))
}

/// Adding a multiple of `bits` to the dividend doesn't change the residue.
proof fn lemma_mod_add_shift(base: int, bits: int, d: int)
    requires
        bits > 0,
    ensures
        (base + d) % bits == (base + d % bits) % bits,
{
    lemma_fundamental_div_mod(d, bits);
    assert(base + d == bits * (d / bits) + (base + d % bits));
    lemma_mod_multiples_vanish(d / bits, base + d % bits, bits);
}

/// There is exactly one `x` in `0..bits` with `(base + x) % bits == target`:
/// the residue a counter must have, `bits` apart, to land in `target`'s slot.
proof fn lemma_unique_residue(base: int, bits: int, target: int) -> (x: int)
    requires
        bits > 0,
        0 <= target < bits,
    ensures
        0 <= x < bits,
        (base + x) % bits == target,
        forall|x2: int| 0 <= x2 < bits && #[trigger] ((base + x2) % bits) == target ==> x2 == x,
{
    let x = (target - base) % bits;
    lemma_mod_bound(target - base, bits);
    lemma_mod_add_shift(base, bits, target - base);
    assert(base + (target - base) == target);
    lemma_fundamental_div_mod_converse(target, bits, 0, target);
    assert((base + x) % bits == target);
    assert forall|x2: int| 0 <= x2 < bits && #[trigger] ((base + x2) % bits) == target implies x2 == x by {
        lemma_mod_equivalence(base + x2, base + x, bits);
        assert((x2 - x) % bits == 0);
        lemma_fundamental_div_mod(x2 - x, bits);
        let q = (x2 - x) / bits;
        assert(x2 - x == bits * q);
        assert(-bits < x2 - x < bits);
        if q >= 1 {
            lemma_mul_inequality(1, q, bits);
            lemma_mul_is_commutative(q, bits);
            assert(1 * bits == bits);
            assert(bits <= x2 - x);
            assert(false);
        } else if q <= -1 {
            lemma_mul_inequality(q, -1, bits);
            lemma_mul_is_commutative(q, bits);
            lemma_mul_is_commutative(-1, bits);
            assert(-1 * bits == -bits);
            assert(x2 - x <= -bits);
            assert(false);
        }
        assert(q == 0);
        assert(bits * q == 0) by (nonlinear_arith)
            requires
                q == 0,
        ;
        assert(x2 == x);
    };
    x
}

/// There is exactly one `k` in `1..=bits` with `(base + k) % bits == target`:
/// the step, after `base`, at which a slot of residue `target` is next
/// visited by a loop walking `base + 1, base + 2, ...`.
proof fn lemma_unique_slot_step(base: int, bits: int, target: int) -> (k: int)
    requires
        bits > 0,
        0 <= target < bits,
    ensures
        1 <= k <= bits,
        (base + k) % bits == target,
        forall|k2: int| 1 <= k2 <= bits && #[trigger] ((base + k2) % bits) == target ==> k2 == k,
{
    let x = lemma_unique_residue(base, bits, target);
    let k = if x == 0 {
        bits
    } else {
        x
    };
    if x == 0 {
        lemma_mod_multiples_vanish(1, base, bits);
        assert(bits * 1 + base == base + bits);
    }
    assert((base + k) % bits == target);
    assert forall|k2: int| 1 <= k2 <= bits && #[trigger] ((base + k2) % bits) == target implies k2 == k by {
        lemma_mod_bound(k2, bits);
        let x2 = k2 % bits;
        lemma_mod_add_shift(base, bits, k2);
        assert((base + x2) % bits == target);
        assert(x2 == x);
        if k2 == bits {
            lemma_fundamental_div_mod_converse(bits, bits, 1, 0);
            assert(x2 == 0);
        } else {
            lemma_fundamental_div_mod_converse(k2, bits, 0, k2);
            assert(x2 == k2);
        }
        assert(k2 == k);
    };
    k
}

/// After the clearing loop runs for `steps = min(c - old_top, BITS)` steps
/// starting at `old_top`, with `c > old_top`: every slot still inside the
/// window below the new top `c` agrees with `accepted` (unchanged by the
/// loop; the just-accepted counter `c - 1` is inserted once the caller sets
/// its own slot). This excludes the two `window_wf` clauses that mention
/// `top` directly, which only become true again once that insert happens.
proof fn lemma_window_advance<const BITS: usize>(
    old_top: u64,
    c: u64,
    steps: u64,
    old_seen: Seq<bool>,
    new_seen: Seq<bool>,
    accepted: Set<int>,
)
    requires
        window_wf::<BITS>(old_top, old_seen, accepted),
        c as int > old_top as int,
        steps as int == if c as int - old_top as int <= BITS as int {
            c as int - old_top as int
        } else {
            BITS as int
        },
        new_seen.len() == BITS,
        forall|r: int|
            0 <= r < BITS as int ==> new_seen[r] == if exists|k: int|
                1 <= k <= steps as int && #[trigger] ((old_top as int + k) % (BITS as int)) == r
            {
                false
            } else {
                old_seen[r]
            },
    ensures
        forall|cs: int|
            1 <= cs <= c as int && c as int - cs <= (BITS - 1) as int ==> #[trigger] new_seen[cs
                % (BITS as int)] == accepted.contains(cs - 1),
{
    assert forall|cs: int|
        1 <= cs <= c as int && c as int - cs <= (BITS - 1) as int implies #[trigger] new_seen[cs
        % (BITS as int)] == accepted.contains(cs - 1) by {
        let r = cs % (BITS as int);
        lemma_mod_bound(cs, BITS as int);
        if cs > old_top as int {
            // Never accepted before this call (`window_wf` at `old_top`
            // bounds every accepted counter below `old_top`), and cleared
            // by the loop.
            if c as int - old_top as int <= BITS as int {
                // `steps == c - old_top`: `cs`'s own slot, `old_top + (cs -
                // old_top) == cs`, is visited directly.
                let k = cs - old_top as int;
                assert(1 <= k <= steps as int);
                assert((old_top as int + k) % (BITS as int) == r) by {
                    assert(old_top as int + k == cs);
                };
            } else {
                // `steps == BITS`: every residue is visited exactly once in
                // `1..=BITS`, `cs`'s own included.
                let k = lemma_unique_slot_step(old_top as int, BITS as int, r);
                assert(1 <= k <= steps as int) by {
                    assert(steps as int == BITS as int);
                };
            }
            assert(exists|k2: int| 1 <= k2 <= steps as int && #[trigger] ((old_top as int + k2) % (BITS as int)) == r);
            assert(new_seen[r] == false);
            assert(!accepted.contains(cs - 1));
        } else {
            // Still inside the old window too: the loop only clears values
            // `old_top + 1 ..= old_top + steps`, each strictly above `cs`
            // by less than `BITS` (since `cs` is also in the new window),
            // so none of them can share `cs`'s residue.
            assert forall|k: int| 1 <= k <= steps as int implies #[trigger] ((old_top as int + k) % (BITS as int)) != r by {
                let diff = old_top as int + k - cs;
                assert(1 <= diff <= (BITS - 1) as int);
                lemma_fundamental_div_mod_converse(diff, BITS as int, 0, diff);
                assert(diff % (BITS as int) == diff);
                if (old_top as int + k) % (BITS as int) == r {
                    assert((old_top as int + k) % (BITS as int) == cs % (BITS as int));
                    lemma_mod_equivalence(old_top as int + k, cs, BITS as int);
                    assert((old_top as int + k - cs) % (BITS as int) == 0);
                    assert(false);
                }
            };
            assert(!(exists|k2: int| 1 <= k2 <= steps as int && #[trigger] ((old_top as int + k2) % (BITS as int)) == r));
            assert(new_seen[r] == old_seen[r]);
            assert(old_seen[r] == accepted.contains(cs - 1));
        }
    };
}

/// `accepted`: every counter the window has ever accepted. A ghost field,
/// erased outside proof, so `ReplayWindow`'s real layout (and its `.text`)
/// is unchanged; `window_wf` ties it to `top` and `seen`.
pub struct ReplayWindow<const BITS: usize> {
    /// Highest accepted counter plus one; 0 before the first accept.
    top: u64,
    seen: [bool; BITS],
    /// `Ghost<T>` has no runtime representation, so this adds nothing to
    /// the compiled type; its only reader is the proof code in
    /// `well_formed`/`has_accepted`, which `cfg(not(verus_keep_ghost))`
    /// erases from the real build.
    #[allow(dead_code)]
    accepted: Ghost<Set<int>>,
}

} // verus!

impl<const BITS: usize> Default for ReplayWindow<BITS> {
    fn default() -> Self {
        Self::new()
    }
}

verus! {

impl<const BITS: usize> ReplayWindow<BITS> {
    /// How far below the highest accepted counter a counter may still be accepted.
    pub const WINDOW: u64 = if BITS == 0 {
        0
    } else {
        (BITS - 1) as u64
    };

    /// Closed (not `open`): `ReplayWindow` keeps `top` and `seen` private,
    /// so a public spec function cannot expose them in its body, which a
    /// `pub open spec fn` must allow callers to unfold everywhere. Proofs in
    /// this module recover the definition with `reveal`.
    pub closed spec fn well_formed(&self) -> bool {
        window_wf::<BITS>(self.top, self.seen@, self.accepted@)
    }

    /// The highest accepted counter plus one (0 before any accept): the
    /// public, opaque view of the private `top` field that contracts use.
    pub closed spec fn top_value(&self) -> u64 {
        self.top
    }

    /// Whether `c` has ever been accepted: the public, opaque view of the
    /// ghost `accepted` field that contracts use.
    pub closed spec fn has_accepted(&self, c: int) -> bool {
        self.accepted@.contains(c)
    }

    /// `new`'s obligations that Verus cannot express as the usual
    /// compile-time `const { assert!(...) }` (unsupported inside `verus!`):
    /// `BITS >= 2`, so there both is a window and the top's own slot is
    /// distinct from the one `BITS - 1` below it, and `BITS` small enough
    /// that the clearing loop's step counter cannot wrap. `well_formed`
    /// only holds for such `BITS`, so Verus requires it as a precondition;
    /// the `assert!` below still fails every bad instantiation at runtime.
    pub fn new() -> (r: Self)
        requires
            BITS >= 2,
            (BITS as u64) < u64::MAX,
        ensures
            r.well_formed(),
            r.top_value() == 0,
    {
        assert!(BITS >= 2, "replay window needs at least two slots");
        let r = Self { top: 0, seen: [false; BITS], accepted: Ghost(Set::empty()) };
        proof {
            reveal(ReplayWindow::well_formed);
            reveal(ReplayWindow::top_value);
        }
        r
    }

    /// Accepts `counter` once. Call only after the packet authenticated.
    pub fn check_and_update(&mut self, counter: u64) -> (result: bool)
        requires
            old(self).well_formed(),
        ensures
            final(self).well_formed(),
            result == (
                counter < REJECT_AFTER_MESSAGES && (
                    old(self).top_value() == 0
                    || counter as int + 1 > old(self).top_value() as int
                    || (old(self).top_value() as int - (counter as int + 1) <= (BITS - 1) as int
                        && !old(self).has_accepted(counter as int))
                )
            ),
            result ==> (
                forall|x: int|
                    final(self).has_accepted(x) == (old(self).has_accepted(x) || x == counter as int)
            ),
            !result ==> (forall|x: int| final(self).has_accepted(x) == old(self).has_accepted(x)),
    {
        proof {
            reveal(ReplayWindow::well_formed);
            reveal(ReplayWindow::top_value);
            reveal(ReplayWindow::has_accepted);
        }
        if counter >= REJECT_AFTER_MESSAGES {
            return false;
        }
        let Some(c) = counter.checked_add(1) else {
            return false;
        };
        if below_window(c, Self::WINDOW, self.top) {
            return false;
        }
        assert(BITS >= 2);
        assert((BITS as u64) < u64::MAX);
        assert(Self::WINDOW == (BITS - 1) as u64);
        let ghost old_top = self.top;
        let ghost old_seen = self.seen@;
        let ghost accepted = self.accepted@;
        if c > self.top {
            let steps = c.saturating_sub(self.top).min(BITS as u64);
            let mut i: u64 = 1;
            while i <= steps
                invariant
                    1 <= i,
                    i <= steps + 1,
                    steps <= BITS as u64,
                    (BITS as u64) < u64::MAX,
                    steps as int == if c as int - old_top as int <= BITS as int {
                        c as int - old_top as int
                    } else {
                        BITS as int
                    },
                    self.top == old_top,
                    self.accepted@ == accepted,
                    self.seen@.len() == BITS,
                    forall|r: int|
                        0 <= r < BITS as int ==> self.seen@[r] == if exists|k: int|
                            1 <= k < i as int && #[trigger] ((old_top as int + k) % (BITS as int)) == r
                        {
                            false
                        } else {
                            old_seen[r]
                        },
                decreases steps + 1 - i,
            {
                if let Some(flag) = self.slot(self.top.wrapping_add(i)) {
                    *flag = false;
                }
                i = i.wrapping_add(1);
            }
            proof {
                lemma_window_advance::<BITS>(old_top, c, steps, old_seen, self.seen@, accepted);
            }
            self.top = c;
            assert forall|cs: int|
                1 <= cs && cs <= self.top as int && self.top as int - cs <= (BITS - 1) as int
                    implies #[trigger] self.seen@[cs % (BITS as int)] == self.accepted@.contains(
                cs - 1,
            ) by {}
        } else {
            assert(self.top == old(self).top);
            assert(self.seen@ == old(self).seen@);
            assert(self.accepted@ == old(self).accepted@);
            assert forall|cs: int|
                1 <= cs && cs <= self.top as int && self.top as int - cs <= (BITS - 1) as int
                    implies #[trigger] self.seen@[cs % (BITS as int)] == self.accepted@.contains(
                cs - 1,
            ) by {}
        }
        let ghost pre_seen = self.seen@;
        let ghost pre_accepted = self.accepted@;
        let ghost pre_top = self.top;
        match self.slot(c) {
            Some(flag) if !*flag => {
                *flag = true;
                proof {
                    self.accepted = Ghost(self.accepted@.insert(c as int - 1));
                    let idx = (c as int) % (BITS as int);
                    assert forall|cs: int|
                        1 <= cs && cs <= pre_top as int && pre_top as int - cs <= (BITS - 1)
                            as int implies #[trigger] self.seen@[cs % (BITS as int)]
                        == self.accepted@.contains(cs - 1) by {
                        if cs == c as int {
                            assert(self.seen@[idx] == true);
                            assert(self.accepted@.contains(c as int - 1));
                        } else {
                            let r_cs = cs % (BITS as int);
                            assert(r_cs != idx) by {
                                if r_cs == idx {
                                    lemma_mod_equivalence(cs, c as int, BITS as int);
                                    assert((cs - c as int) % (BITS as int) == 0);
                                    assert((-(BITS as int) < (cs - c as int)) && ((cs - c as int) < (BITS as int)));
                                    lemma_fundamental_div_mod(cs - c as int, BITS as int);
                                    let q = (cs - c as int) / (BITS as int);
                                    assert(cs - c as int == (BITS as int) * q);
                                    if q >= 1 {
                                        lemma_mul_inequality(1, q, BITS as int);
                                        lemma_mul_is_commutative(q, BITS as int);
                                        assert(1 * (BITS as int) == BITS as int);
                                        assert(false);
                                    } else if q <= -1 {
                                        lemma_mul_inequality(q, -1, BITS as int);
                                        lemma_mul_is_commutative(q, BITS as int);
                                        lemma_mul_is_commutative(-1, BITS as int);
                                        assert(-1 * (BITS as int) == -(BITS as int));
                                        assert(false);
                                    }
                                    assert(cs == c as int);
                                }
                            };
                            assert(self.seen@[r_cs] == pre_seen[r_cs]);
                            assert(pre_seen[r_cs] == pre_accepted.contains(cs - 1));
                            assert(self.accepted@.contains(cs - 1) == pre_accepted.contains(
                                cs - 1,
                            ));
                        }
                    };
                    assert(self.top > 0 ==> self.accepted@.contains(self.top as int - 1)) by {
                        if self.top as int == c as int {
                            assert(self.accepted@.contains(c as int - 1));
                        } else {
                            assert(pre_accepted.contains(self.top as int - 1));
                        }
                    };
                    assert forall|x: int| self.accepted@.contains(x) implies (0 <= x
                        && x + 1 <= self.top as int) by {
                        if x == c as int - 1 {
                            assert(c as int <= self.top as int);
                        } else {
                            assert(pre_accepted.contains(x));
                        }
                    };
                }
                true
            }
            _ => false,
        }
    }

    /// `BITS >= 1` (always true: `well_formed` requires `BITS >= 2`) makes
    /// the slot index total, so `slot` always returns `Some`: the window
    /// has no "empty" case to account for.
    fn slot(&mut self, c: u64) -> (r: Option<&mut bool>)
        requires
            BITS >= 1,
            old(self).seen@.len() == BITS,
        ensures
            r is Some,
            final(self).accepted@ == old(self).accepted@,
            final(self).top == old(self).top,
            ({
                let idx = (c as int) % (BITS as int);
                match r {
                    None => final(self).seen@ == old(self).seen@,
                    Some(flag) => {
                        &&& 0 <= idx < BITS as int
                        &&& *flag == old(self).seen@[idx]
                        &&& final(self).seen@ == old(self).seen@.update(idx, *final(flag))
                    },
                }
            }),
    {
        match c.checked_rem(BITS as u64) {
            None => None,
            Some(rem) => match usize::try_from(rem) {
                Err(_) => None,
                Ok(i) => self.seen.get_mut(i),
            },
        }
    }
}

} // verus!
