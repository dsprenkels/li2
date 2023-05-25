use crate::{params::*, reduce};

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct Poly {
    pub(crate) coeffs: [i32; N],
}

impl Poly {
    pub(crate) fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    pub(crate) fn copy_from_compressed_poly(&mut self, compressed_poly: &CompressedPoly) {
        for idx in 0..N {
            self.coeffs[idx] = compressed_poly.get(idx);
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct CompressedPoly {
    pub(crate) coeffs: [u32; 3 * N / 4],
}

impl CompressedPoly {
    pub(crate) fn zero() -> Self {
        Self {
            coeffs: [0; 3 * N / 4],
        }
    }

    #[inline]
    pub(crate) fn get(&self, idx: usize) -> i32 {
        let limb = 3 * idx / 4;
        let offset = 3 * idx % 4;
        let bits = match offset {
            0 => self.coeffs[limb] & 0xFFFFFF,
            1 => self.coeffs[limb] >> 8,
            2 => (self.coeffs[limb] >> 16) | ((self.coeffs[limb + 1] & 0xFF) << 16),
            3 => (self.coeffs[limb] >> 24) | ((self.coeffs[limb + 1] & 0xFFFF) << 8),
            _ => unreachable!(),
        };
        // Sign-extend from 24 to 32 bits
        (bits << 8) as i32 >> 8
    }

    #[inline]
    pub(crate) fn set(&mut self, idx: usize, coeff: i32) {
        let limb = 3 * idx / 4;
        let offset = 3 * idx % 4;
        let value = coeff as u32;
        match offset {
            0 => {
                self.coeffs[limb] &= !0x00FFFFFF;
                self.coeffs[limb] |= value & 0xFFFFFF;
            }
            1 => {
                self.coeffs[limb] &= !0xFFFFFF00;
                self.coeffs[limb] |= (value & 0xFFFFFF) << 8;
            }
            2 => {
                self.coeffs[limb] &= !0xFFFF0000;
                self.coeffs[limb] |= (value & 0x00FFFF) << 16;
                self.coeffs[limb + 1] &= !0x000000FF;
                self.coeffs[limb + 1] |= (value & 0xFF0000) >> 16;
            }
            3 => {
                self.coeffs[limb] &= !0xFF000000;
                self.coeffs[limb] |= (value & 0x0000FF) << 24;
                self.coeffs[limb + 1] &= !0x0000FFFF;
                self.coeffs[limb + 1] |= (value & 0xFFFF00) >> 8;
            }
            _ => unreachable!(),
        };
    }

    pub(crate) fn copy_from_poly(&mut self, poly: &Poly) {
        for idx in 0..N {
            self.set(idx, poly.coeffs[idx]);
        }
    }
}

pub(crate) fn poly_pointwise_montgomery(c: &mut Poly, a: &Poly, b: &Poly) {
    let dest = c.coeffs.iter_mut();
    let src = a.coeffs.iter().zip(b.coeffs.iter());
    for (c_coeff, (a_coeff, b_coeff)) in Iterator::zip(dest, src) {
        *c_coeff = reduce::montgomery_reduce((*a_coeff as i64).wrapping_mul(*b_coeff as i64));
    }
}

pub(crate) fn polyvec_pointwise_montgomery(c: &mut [Poly], a_poly: &Poly, b: &[Poly]) {
    debug_assert_eq!(c.len(), b.len());
    for (c_poly, b_poly) in Iterator::zip(c.iter_mut(), b.iter()) {
        poly_pointwise_montgomery(c_poly, a_poly, b_poly);
    }
}

pub(crate) fn poly_pointwise_montgomery_inplace(a: &mut Poly, b: &Poly) {
    let dest = a.coeffs.iter_mut();
    let src = b.coeffs.iter();
    for (a_coeff, b_coeff) in Iterator::zip(dest, src) {
        *a_coeff = reduce::montgomery_reduce((*a_coeff as i64).wrapping_mul(*b_coeff as i64));
    }
}

pub(crate) fn polyvec_pointwise_montgomery_inplace(a: &mut [Poly], b: &Poly) {
    for poly in a.iter_mut() {
        poly_pointwise_montgomery_inplace(poly, b);
    }
}

pub(crate) fn polyvec_matrix_pointwise_montgomery(
    p: &DilithiumParams,
    t: &mut [Poly],
    mat: &[Poly],
    v: &[Poly],
) {
    debug_assert_eq!(t.len(), p.k);
    debug_assert_eq!(v.len(), p.l);
    debug_assert_eq!(mat.len(), p.k * p.l);
    for (idx, t_elem) in t.iter_mut().enumerate() {
        polyvecl_pointwise_acc_montgomery(t_elem, &mat[p.l * idx..p.l * (idx + 1)], v);
    }
}

/// Compute dot product between mat_row and v
pub(crate) fn polyvecl_pointwise_acc_montgomery(w: &mut Poly, u: &[Poly], v: &[Poly]) {
    debug_assert_eq!(u.len(), v.len());
    *w = Poly::zero();
    for (u_elem, v_elem) in u.iter().zip(v.iter()) {
        let mut tmp = Poly::zero();
        poly_pointwise_montgomery(&mut tmp, u_elem, v_elem);
        poly_add(w, &tmp);
    }
}

pub(crate) fn poly_add(poly: &mut Poly, poly_rhs: &Poly) {
    for (acc, x) in poly.coeffs.iter_mut().zip(poly_rhs.coeffs.iter()) {
        *acc = acc.wrapping_add(*x);
    }
}

pub(crate) fn polyvec_add(vec: &mut [Poly], vec_rhs: &[Poly]) {
    for (poly, poly_rhs) in vec.iter_mut().zip(vec_rhs.iter()) {
        poly_add(poly, poly_rhs);
    }
}

pub(crate) fn poly_sub(poly: &mut Poly, poly_rhs: &Poly) {
    for (acc, x) in poly.coeffs.iter_mut().zip(poly_rhs.coeffs.iter()) {
        *acc = acc.wrapping_sub(*x);
    }
}

pub(crate) fn polyvec_sub(vec: &mut [Poly], vec_rhs: &[Poly]) {
    for (poly, poly_rhs) in vec.iter_mut().zip(vec_rhs.iter()) {
        poly_sub(poly, poly_rhs);
    }
}

pub(crate) fn poly_pointwise<F: Fn(i32) -> i32>(poly: &mut Poly, f: F) {
    for coeff in poly.coeffs.iter_mut() {
        *coeff = f(*coeff);
    }
}

pub(crate) fn polyvec_pointwise<F: Fn(i32) -> i32>(vec: &mut [Poly], f: F) {
    for poly in vec.iter_mut() {
        poly_pointwise(poly, &f);
    }
}

pub(crate) fn polyveck_decompose(p: &DilithiumParams, vec1: &mut [Poly], vec0: &mut [Poly]) {
    for (poly1, poly0) in Iterator::zip(vec1.iter_mut(), vec0.iter_mut()) {
        poly_decompose(p, poly1, poly0);
    }
}

pub(crate) fn poly_decompose(p: &DilithiumParams, poly1: &mut Poly, poly0: &mut Poly) {
    for (coeff1, coeff0) in Iterator::zip(poly1.coeffs.iter_mut(), poly0.coeffs.iter_mut()) {
        let a = *coeff1;
        let (a1, a0) = crate::rounding::decompose(p, a);
        *coeff1 = a1;
        *coeff0 = a0;
    }
}

pub(crate) fn polyvec_chknorm(vec: &[Poly], bound: i32) -> Result<(), ()> {
    for poly in vec {
        poly_chknorm(poly, bound)?;
    }
    Ok(())
}

pub(crate) fn poly_chknorm(poly: &Poly, bound: i32) -> Result<(), ()> {
    // It is ok to leak which coefficient violates the bound since
    // the probability for each coefficient is independent of secret
    // data but we must not leak the sign of the centralized representative.

    for coeff in poly.coeffs {
        if abs(coeff) >= bound {
            return Err(());
        }
    }
    Ok(())
}

fn abs(mut x: i32) -> i32 {
    let negative_mask = core::hint::black_box(x >> 31);
    let y = x & negative_mask;
    x = x.wrapping_sub(2 * y);
    x
}

pub(crate) fn polyvec_use_hint(p: &DilithiumParams, vec: &mut [Poly], hint: &[Poly]) {
    for (vec_elem, hint_elem) in Iterator::zip(vec.iter_mut(), hint.iter()) {
        poly_use_hint(p, vec_elem, hint_elem);
    }
}

pub(crate) fn poly_use_hint(p: &DilithiumParams, poly: &mut Poly, hint: &Poly) {
    for (coeff, hint_coeff) in Iterator::zip(poly.coeffs.iter_mut(), hint.coeffs.iter()) {
        *coeff = crate::rounding::use_hint(p, *coeff, *hint_coeff);
    }
}

pub(crate) fn poly_make_hint(p: &DilithiumParams, poly0: &mut Poly, poly1: &Poly) -> usize {
    let mut popcount = 0;
    for (coeff0, coeff1) in Iterator::zip(poly0.coeffs.iter_mut(), poly1.coeffs.iter()) {
        let hint = crate::rounding::make_hint(p, *coeff0, *coeff1);
        *coeff0 = i32::from(hint);
        popcount += usize::from(hint);
    }
    popcount
}

pub(crate) fn polyvec_make_hint(p: &DilithiumParams, vec0: &mut [Poly], vec1: &[Poly]) -> usize {
    let mut popcount = 0;
    for (poly0, poly1) in Iterator::zip(vec0.iter_mut(), vec1.iter()) {
        popcount += poly_make_hint(p, poly0, poly1);
    }
    popcount
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_compressed_poly() {
        for _ in 0..10000 {
            // Generate random poly
            let mut poly = super::Poly::zero();
            for coeff in poly.coeffs.iter_mut() {
                *coeff = rand::random::<i32>() & 0x7FFFFF;
                if rand::random::<bool>() {
                    *coeff = -*coeff;
                }
            }
            let mut compressed = super::CompressedPoly::zero();
            for (idx, coeff) in poly.coeffs.iter().enumerate() {
                compressed.set(idx, *coeff);
            }
            for (idx, expected) in poly.coeffs.iter().enumerate() {
                let actual = compressed.get(idx);
                assert_eq!(actual, *expected);
            }
        }
    }
}
