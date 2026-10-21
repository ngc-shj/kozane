//! mceliece460896 parameters (libmceliece `params.h`, `gf_params.h`).

pub const GFBITS: usize = 13;
pub const GFMASK: u16 = 0x1fff;
pub const SYS_N: usize = 4608;
pub const SYS_T: usize = 96;
pub const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS - 1);
pub const IRR_BYTES: usize = SYS_T * 2;
pub const PK_NROWS: usize = SYS_T * GFBITS;
pub const PK_NCOLS: usize = SYS_N - PK_NROWS;
pub const PK_ROW_BYTES: usize = PK_NCOLS.div_ceil(8);
pub const SYND_BYTES: usize = PK_NROWS.div_ceil(8);
