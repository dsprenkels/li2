use crate::params::Q;

pub const MONT_MOD: i64 = 1 << 32;
pub const Q_INV: i32 = modinverse(Q as i64, MONT_MOD) as i32;
pub const MONT_R: i32 = (MONT_MOD % Q as i64) as i32;

pub(crate) const fn egcd(a: i64, b: i64) -> (i64, i64, i64) {
    if a == 0 {
        (b, 0, 1)
    } else {
        let (g, x, y) = egcd(b % a, a);
        (g, y - (b / a) * x, x)
    }
}

pub(crate) const fn cmod(mut x: i64, m: i64) -> i64 {
    x %= m;
    if x > m / 2 {
        x -= m;
    } else if x < -m / 2 {
        x += m;
    }
    x
}

pub(crate) const fn modinverse(a: i64, m: i64) -> i64 {
    let (g, x, _) = egcd(a, m);
    if g != 1 {
        panic!();
    }
    cmod(x, m)
}

pub(crate) const fn montgomery_reduce(a: i64) -> i32 {
    const Q_I64: i64 = Q as i64;
    const QINV_I64: i64 = Q_INV as i64;
    let t: i32 = ((a as i32 as i64).wrapping_mul(QINV_I64)) as i32;
    let t: i64 = a.wrapping_sub((t as i64).wrapping_mul(Q_I64)) >> 32;
    t as i32
}

pub(crate) const fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    let t = a - t * Q;
    t
}

pub(crate) const fn caddq(mut a: i32) -> i32 {
    a += (a >> 31) & Q;
    a
}
