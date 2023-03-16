use crate::{
    params::{N, Q},
    poly::Poly,
    reduce,
};

/// PSI is the primitive root of unity modulo Q.
const PSI: i32 = 1753;

/// Array of twiddle factors used by the mod-Q NTT algorithms.
const ZETAS: [i32; N - 1] = {
    /// Naive computation of `a` to the power `x` mod `m`.
    const fn pow(a: i64, mut x: u8, m: i64) -> i64 {
        let mut acc = 1;
        while x > 0 {
            acc *= a;
            acc %= m;
            x -= 1;
        }
        acc
    }

    let mut zetas = [0i32; N - 1];
    let mut idx = 0;

    while idx < N - 1 {
        let power = (idx + 1) as u8;
        let brv = power.reverse_bits();
        let mut twiddle = pow(PSI as i64, brv, Q as i64);
        twiddle *= crate::reduce::MONT_R as i64;
        twiddle = reduce::cmod(twiddle, Q as i64);
        if twiddle < i32::MIN as i64 || twiddle > i32::MAX as i64 {
            panic!();
        }
        zetas[idx] = twiddle as i32;
        idx += 1;
    }
    zetas
};

pub(crate) fn poly_ntt(p: &mut Poly) {
    let mut twiddles = ZETAS.iter();

    for layer in 0..8 {
        let subpoly_len = 0x80 >> layer;
        for subpoly_offset in (0..N).step_by(2 * subpoly_len) {
            let zeta = *twiddles.next().expect("twiddle index error") as i64;
            for idx in subpoly_offset..subpoly_offset + subpoly_len {
                let t0 = zeta.wrapping_mul(p.coeffs[idx + subpoly_len] as i64);
                let t1 = reduce::montgomery_reduce(t0);
                p.coeffs[idx + subpoly_len] = p.coeffs[idx].wrapping_sub(t1);
                p.coeffs[idx] = p.coeffs[idx].wrapping_add(t1);
            }
        }
    }
    debug_assert!(twiddles.next().is_none());
}

pub(crate) fn poly_invntt_tomont(p: &mut Poly) {
    const MONT_R_I64: i64 = reduce::MONT_R as i64;
    const N_INV: i64 = reduce::modinverse(N as i64, Q as i64);
    const F: i64 = reduce::cmod(MONT_R_I64 * MONT_R_I64 * N_INV, Q as i64);

    let mut twiddles = ZETAS.iter().rev();

    for layer in (0..8).rev() {
        let subpoly_len = 0x80 >> layer;
        for subpoly_offset in (0..N).step_by(2 * subpoly_len) {
            let zeta = -*twiddles.next().expect("twiddle index") as i64;
            for idx in subpoly_offset..subpoly_offset + subpoly_len {
                let t0 = p.coeffs[idx];
                let t1 = t0.wrapping_sub(p.coeffs[idx + subpoly_len]);
                let t2 = i64::from(t1).wrapping_mul(zeta);
                p.coeffs[idx] = t0.wrapping_add(p.coeffs[idx + subpoly_len]);
                p.coeffs[idx + subpoly_len] = reduce::montgomery_reduce(t2);
            }
        }
    }
    for coeff in p.coeffs.iter_mut() {
        *coeff = reduce::montgomery_reduce(F.wrapping_mul(i64::from(*coeff)));
    }
    debug_assert!(twiddles.next().is_none());
}

pub(crate) fn polyvec_ntt(vec: &mut [Poly]) {
    for poly in vec.iter_mut() {
        poly_ntt(poly)
    }
}

pub(crate) fn polyvec_invntt_tomont(vec: &mut [Poly]) {
    for poly in vec.iter_mut() {
        poly_invntt_tomont(poly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::N;

    const ZETAS_REF: [i32; N] = [
        0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
        -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928,
        -549488, -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237,
        -19422, 4010497, 280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516,
        3915439, -3861115, -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299,
        -1699267, -1643818, 3505694, -3821735, 3507263, -2140649, -1600420, 3699596, 811944,
        531354, 954230, 3881043, 3900724, -2556880, 2071892, -2797779, -3930395, -1528703,
        -3677745, -3041255, -1452451, 3475950, 2176455, -1585221, -1257611, 1939314, -4083598,
        -1000202, -3190144, -3157330, -3632928, 126922, 3412210, -983419, 2147896, 2715295,
        -2967645, -3693493, -411027, -2477047, -671102, -1228525, -22981, -1308169, -381987,
        1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992, 44288, -1100098, 904516,
        3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969, -1316856, 189548,
        -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669, -1584928,
        -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
        3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181,
        -3520352, -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174,
        -43260, -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838,
        342297, 286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481,
        -2590150, 1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921,
        -3548272, -2994039, 1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225,
        -451100, 1312455, 3306115, -1962642, -1279661, 1917081, -2546312, -1374803, 1500165,
        777191, 2235880, 3406031, -542412, -2831860, -1671176, -1846953, -2584293, -3724270,
        594136, -3776993, -2013608, 2432395, 2454455, -164721, 1957272, 3369112, 185531, -1207385,
        -3183426, 162844, 1616392, 3014001, 810149, 1652634, -3694233, -1799107, -3038916, 3523897,
        3866901, 269760, 2213111, -975884, 1717735, 472078, -426683, 1723600, -1803090, 1910376,
        -1667432, -1104333, -260646, -3833893, -2939036, -2235985, -420899, -2286327, 183443,
        -976891, 1612842, -3545687, -554416, 3919660, -48306, -1362209, 3937738, 1400424, -846154,
        1976782,
    ];

    #[test]
    fn test_zetas() {
        assert_eq!(reduce::Q_INV, 58728449);
        assert_eq!(reduce::MONT_R, 4193792);
        assert_eq!(&ZETAS[..], &ZETAS_REF[1..]);
    }
}
