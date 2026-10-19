//! The bounded handler loop every PD with several inputs shares (M2.5 plan,
//! "Handler loop"). In M2 each input was drained in an unbounded `while`
//! and peers were notified only at the end, so a flood on one input starved
//! the others and every notification. Here each input takes at most a cap
//! per pass, and every pass ends with `end_pass`. The PDs reach their rings
//! only through this code, so the bound and the per-pass notification are
//! the ones they execute; each PD's input order is in its core crate.

/// One PD's handler-loop pass.
pub trait Pass {
    /// Serves every input once, in the PD's order, each through `drain`
    /// with its cap, plus any per-pass work; true if some input took its
    /// full cap and may hold more.
    fn serve(&mut self) -> bool;
    /// Notifies every peer this pass gave work to and flushes audit.
    fn end_pass(&mut self);
}

/// Runs passes until one finds every input below its cap. Every pass,
/// including the last, ends with `end_pass`.
pub fn run_passes(io: &mut impl Pass) {
    loop {
        let more = io.serve();
        io.end_pass();
        if !more {
            return;
        }
    }
}

/// Runs `step` until it reports an empty input (`false`) or `max` messages
/// were taken, and returns how many were taken. Every PD input loop is this
/// call, so the per-pass cap is enforced here, where it is tested.
pub fn drain(max: usize, mut step: impl FnMut() -> bool) -> usize {
    let mut moved: usize = 0;
    while moved < max && step() {
        moved = moved.saturating_add(1);
    }
    moved
}

/// Whether another pass is due: some input moved its full `max` this pass.
pub fn any_full(moved: &[usize], max: usize) -> bool {
    moved.iter().any(|&n| n >= max)
}
