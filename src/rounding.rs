use crate::params::{D, DilithiumParams, Q};

pub(crate) fn power2round(mut a0: i32, a: i32) -> (i32, i32) {
    let a1 = (a + (1 << (D-1)) - 1) >> D;
    a0 = a - (a1 << D);
    (a0, a1)
}

pub(crate) fn decompose(p: &DilithiumParams, a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;

    if p.GAMMA2 == (Q - 1) / 32 {
        a1  = (a1*1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else if p.GAMMA2 == (Q-1)/88 {
        a1  = (a1*11275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    } else {
        unreachable!("invalid GAMMA2 value ({})", p.GAMMA2);
    }
    let mut a0  = a - a1*2*p.GAMMA2;
    a0 -= (((Q-1)/2 - a0) >> 31) & Q;
    (a1, a0)
}
