use crate::params::{DilithiumParams, D, Q};

#[must_use]
pub(crate) fn power2round(a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D - 1)) - 1) >> D;
    let a0 = a - (a1 << D);
    (a0, a1)
}

#[must_use]
pub(crate) fn decompose(p: &DilithiumParams, a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;

    if p.GAMMA2 == (Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else if p.GAMMA2 == (Q - 1) / 88 {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    } else {
        unreachable!("invalid GAMMA2 value ({})", p.GAMMA2);
    }
    let mut a0 = a - a1 * 2 * p.GAMMA2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    (a1, a0)
}

#[must_use]
pub(crate) fn use_hint(p: &DilithiumParams, coeff: i32, hint: i32) -> i32 {
    let (a1, a0) = decompose(p, coeff);
    if hint == 0 {
        a1
    } else if p.GAMMA2 == (Q - 1) / 32 {
        if a0 > 0 {
            a1.wrapping_add(1) & 0xF
        } else {
            a1.wrapping_sub(1) & 0xF
        }
    } else if p.GAMMA2 == (Q - 1) / 88 {
        match () {
            () if a0 > 0 && a1 == 43 => 0,
            () if a0 > 0 => a1.wrapping_add(1),
            () if a1 == 0 => 43,
            () => a1.wrapping_sub(1),
        }
    } else {
        unreachable!("invalid GAMMA2 value ({})", p.GAMMA2);
    }
}
