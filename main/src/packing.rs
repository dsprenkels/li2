use crate::params::*;
use crate::poly;

pub(crate) fn pack_sk(
    p: &DilithiumParams,
    sk: &mut [u8],
    rho: &[u8],
    tr: &[u8],
    key: &[u8],
    t0: &mut [poly::Poly],
    s1: &mut [poly::Poly],
    s2: &mut [poly::Poly],
) {
    debug_assert_eq!(sk.len(), p.secret_key_len);
    debug_assert_eq!(rho.len(), SEEDBYTES);
    debug_assert_eq!(tr.len(), SEEDBYTES);
    debug_assert_eq!(key.len(), SEEDBYTES);
    debug_assert_eq!(t0.len(), p.k);
    debug_assert_eq!(s1.len(), p.l);
    debug_assert_eq!(s2.len(), p.k);

    let mut offset = 0;
    sk[offset..offset + SEEDBYTES].copy_from_slice(rho);
    offset += SEEDBYTES;
    sk[offset..offset + SEEDBYTES].copy_from_slice(key);
    offset += SEEDBYTES;
    sk[offset..offset + SEEDBYTES].copy_from_slice(tr);
    offset += SEEDBYTES;

    for poly in s1 {
        pack_poly_eta(p, &mut sk[offset..offset + p.eta_poly_packed_len], poly);
        offset += p.eta_poly_packed_len;
    }

    for poly in s2 {
        pack_poly_eta(p, &mut sk[offset..offset + p.eta_poly_packed_len], poly);
        offset += p.eta_poly_packed_len;
    }

    for poly in t0 {
        pack_poly_t0(p, &mut sk[offset..offset + p.t0_poly_packed_len], poly);
        offset += p.t0_poly_packed_len;
    }
    debug_assert_eq!(offset, p.secret_key_len);
}



pub(crate) fn sk_split<'a>(
    p: &DilithiumParams,
    sk: &'a[u8],
) -> (&'a[u8], &'a[u8], &'a[u8], &'a[u8], &'a[u8], &'a[u8]) {
    debug_assert_eq!(sk.len(), p.secret_key_len);
    
    let (rho, sk) = sk.split_at(SEEDBYTES);
    let (key, sk) = sk.split_at(SEEDBYTES);
    let (tr, sk) = sk.split_at(SEEDBYTES);
    let (s1, sk) = sk.split_at(p.l * p.eta_poly_packed_len);
    let (s2, sk) = sk.split_at(p.k * p.eta_poly_packed_len);
    let (t0, sk) = sk.split_at(p.k * p.t0_poly_packed_len);
    debug_assert_eq!(sk.len(), 0);
    
    (rho, key, tr, s1, s2, t0)
}

pub(crate) fn unpack_sk(
    p: &DilithiumParams,
    rho: &mut [u8],
    tr: &mut [u8],
    key: &mut [u8],
    t0: &mut [poly::Poly],
    s1: &mut [poly::Poly],
    s2: &mut [poly::Poly],
    sk: &[u8],
) {
    debug_assert_eq!(rho.len(), SEEDBYTES);
    debug_assert_eq!(tr.len(), SEEDBYTES);
    debug_assert_eq!(key.len(), SEEDBYTES);
    debug_assert_eq!(t0.len(), p.k);
    debug_assert_eq!(s1.len(), p.l);
    debug_assert_eq!(s2.len(), p.k);
    debug_assert_eq!(sk.len(), p.secret_key_len);

    let mut offset = 0;
    rho.copy_from_slice(&sk[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;
    key.copy_from_slice(&sk[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;
    tr.copy_from_slice(&sk[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;

    for poly in s1.iter_mut() {
        decode_poly_eta(p, poly, &sk[offset..offset + p.eta_poly_packed_len]);
        offset += p.eta_poly_packed_len;
    }
    for poly in s2.iter_mut() {
        decode_poly_eta(p, poly, &sk[offset..offset + p.eta_poly_packed_len]);
        offset += p.eta_poly_packed_len;
    }
    for poly in t0.iter_mut() {
        unpack_poly_t0(p, poly, &sk[offset..offset + p.t0_poly_packed_len]);
        offset += p.t0_poly_packed_len;
    }

    debug_assert_eq!(offset, p.secret_key_len);
}

pub(crate) fn pack_pk(p: &DilithiumParams, pk: &mut [u8], rho: &[u8], t1: &[poly::Poly]) {
    debug_assert_eq!(pk.len(), p.public_key_len);
    debug_assert_eq!(t1.len(), p.k);

    let mut offset = 0;
    pk[offset..offset + SEEDBYTES].copy_from_slice(rho);
    offset += SEEDBYTES;

    for poly in t1 {
        pack_poly_t1(p, &mut pk[offset..offset + p.t1_poly_packed_len], poly);
        offset += p.t1_poly_packed_len;
    }
    debug_assert_eq!(offset, p.public_key_len);
}

pub(crate) fn unpack_pk(p: &DilithiumParams, rho: &mut [u8], t1: &mut [poly::Poly], pk: &[u8]) {
    debug_assert_eq!(rho.len(), SEEDBYTES);
    debug_assert_eq!(t1.len(), p.k);
    debug_assert_eq!(pk.len(), p.public_key_len);


    let mut offset = 0;
    rho.copy_from_slice(&pk[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;

    for poly in t1 {
        unpack_poly_t1(p, poly, &pk[offset..offset + p.t1_poly_packed_len]);
        offset += p.t1_poly_packed_len;
    }
    debug_assert_eq!(offset, p.public_key_len);
}

pub(crate) fn pack_sig(
    p: &DilithiumParams,
    sig: &mut [u8],
    c: &[u8],
    z: &[poly::Poly],
    h: &[poly::Poly],
) {
    debug_assert_eq!(sig.len(), p.signature_len);
    debug_assert_eq!(c.len(), SEEDBYTES);
    debug_assert_eq!(z.len(), p.l);
    debug_assert_eq!(h.len(), p.k);

    let mut offset = 0;

    // Output challenge
    sig[offset..offset + SEEDBYTES].copy_from_slice(c);
    offset += SEEDBYTES;

    // Output z
    for poly in z {
        pack_poly_z(p, &mut sig[offset..offset + p.z_poly_packed_len], poly);
        offset += p.z_poly_packed_len;
    }

    // Output hints
    pack_vec_hints(p, &mut sig[offset..offset + p.omega + p.k], h);
    offset += p.omega + p.k;

    debug_assert_eq!(offset, p.signature_len);
}

pub(crate) fn unpack_sig(
    p: &DilithiumParams,
    c: &mut [u8],
    z: &mut [poly::Poly],
    h: &mut [poly::Poly],
    sig: &[u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(c.len(), SEEDBYTES);
    debug_assert_eq!(z.len(), p.l);
    debug_assert_eq!(h.len(), p.k);
    debug_assert_eq!(sig.len(), p.signature_len);

    let mut offset = 0;

    // Load challenge
    c.copy_from_slice(&sig[offset..offset + SEEDBYTES]);
    offset += SEEDBYTES;

    // Load z
    for poly in z {
        unpack_poly_z(p, poly, &sig[offset..offset + p.z_poly_packed_len]);
        offset += p.z_poly_packed_len;
    }

    // Load hints
    unpack_vec_hints(p, h, &sig[offset..offset + p.omega + p.k])?;
    offset += p.omega + p.k;

    debug_assert_eq!(offset, p.signature_len);
    Ok(())
}

pub(crate) fn pack_poly_eta(p: &DilithiumParams, sk: &mut [u8], poly: &poly::Poly) {
    debug_assert_eq!(sk.len(), p.eta_poly_packed_len);

    if p.eta == 2 {
        let sk_chunks = sk.chunks_exact_mut(3);
        let poly_chunks = poly.coeffs.chunks_exact(8);
        for (sk_chunk, poly_chunk) in Iterator::zip(sk_chunks, poly_chunks) {
            let t0 = p.eta - poly_chunk[0];
            let t1 = p.eta - poly_chunk[1];
            let t2 = p.eta - poly_chunk[2];
            let t3 = p.eta - poly_chunk[3];
            let t4 = p.eta - poly_chunk[4];
            let t5 = p.eta - poly_chunk[5];
            let t6 = p.eta - poly_chunk[6];
            let t7 = p.eta - poly_chunk[7];

            sk_chunk[0] = ((t0 >> 0) | (t1 << 3) | (t2 << 6)) as u8;
            sk_chunk[1] = ((t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7)) as u8;
            sk_chunk[2] = ((t5 >> 1) | (t6 << 2) | (t7 << 5)) as u8;
        }
    } else if p.eta == 4 {
        let chunks = poly.coeffs.chunks_exact(2);
        for (offset, chunk) in Iterator::zip(0.., chunks) {
            let t0 = p.eta - chunk[0];
            let t1 = p.eta - chunk[1];
            sk[offset] = (t0 | (t1 << 4)) as u8;
        }
    } else {
        unreachable!("invalid ETA value ({})", p.eta);
    }
}

pub(crate) fn decode_poly_eta(p: &DilithiumParams, poly: &mut poly::Poly, packed: &[u8]) {
    debug_assert_eq!(packed.len(), p.eta_poly_packed_len);

    if p.eta == 2 {
        let dest = poly.coeffs.chunks_exact_mut(8);
        let src = packed.chunks_exact(3);
        for (coeffs_chunk, packed_chunk) in Iterator::zip(dest, src) {
            let t0 = ((packed_chunk[0] >> 0) & 0x7) as i32;
            let t1 = ((packed_chunk[0] >> 3) & 0x7) as i32;
            let t2 = (((packed_chunk[0] >> 6) | (packed_chunk[1] << 2)) & 0x7) as i32;
            let t3 = ((packed_chunk[1] >> 1) & 0x7) as i32;
            let t4 = ((packed_chunk[1] >> 4) & 0x7) as i32;
            let t5 = (((packed_chunk[1] >> 7) | (packed_chunk[2] << 1)) & 0x7) as i32;
            let t6 = ((packed_chunk[2] >> 2) & 0x7) as i32;
            let t7 = ((packed_chunk[2] >> 5) & 0x7) as i32;

            coeffs_chunk[0] = p.eta - t0;
            coeffs_chunk[1] = p.eta - t1;
            coeffs_chunk[2] = p.eta - t2;
            coeffs_chunk[3] = p.eta - t3;
            coeffs_chunk[4] = p.eta - t4;
            coeffs_chunk[5] = p.eta - t5;
            coeffs_chunk[6] = p.eta - t6;
            coeffs_chunk[7] = p.eta - t7;
        }
    } else if p.eta == 4 {
        let dest = poly.coeffs.chunks_exact_mut(2);
        for (coeffs_chunk, packed_byte) in Iterator::zip(dest, packed) {
            let t0 = (packed_byte & 0x0F) as i32;
            let t1 = (packed_byte >> 4) as i32;

            coeffs_chunk[0] = p.eta - t0;
            coeffs_chunk[1] = p.eta - t1;
        }
    } else {
        unreachable!("invalid ETA value ({})", p.eta);
    }
}

pub(crate) fn pack_poly_t0(p: &DilithiumParams, sk: &mut [u8], poly: &poly::Poly) {
    debug_assert_eq!(sk.len(), p.t0_poly_packed_len);

    let sk_chunks = sk.chunks_exact_mut(13);
    let poly_chunks = poly.coeffs.chunks_exact(8);
    for (sk_chunk, poly_chunk) in Iterator::zip(sk_chunks, poly_chunks) {
        let t0 = (1 << (D - 1)) - poly_chunk[0];
        let t1 = (1 << (D - 1)) - poly_chunk[1];
        let t2 = (1 << (D - 1)) - poly_chunk[2];
        let t3 = (1 << (D - 1)) - poly_chunk[3];
        let t4 = (1 << (D - 1)) - poly_chunk[4];
        let t5 = (1 << (D - 1)) - poly_chunk[5];
        let t6 = (1 << (D - 1)) - poly_chunk[6];
        let t7 = (1 << (D - 1)) - poly_chunk[7];

        sk_chunk[0] = (t0) as u8;
        sk_chunk[1] = (t0 >> 8) as u8;
        sk_chunk[1] |= (t1 << 5) as u8;
        sk_chunk[2] = (t1 >> 3) as u8;
        sk_chunk[3] = (t1 >> 11) as u8;
        sk_chunk[3] |= (t2 << 2) as u8;
        sk_chunk[4] = (t2 >> 6) as u8;
        sk_chunk[4] |= (t3 << 7) as u8;
        sk_chunk[5] = (t3 >> 1) as u8;
        sk_chunk[6] = (t3 >> 9) as u8;
        sk_chunk[6] |= (t4 << 4) as u8;
        sk_chunk[7] = (t4 >> 4) as u8;
        sk_chunk[8] = (t4 >> 12) as u8;
        sk_chunk[8] |= (t5 << 1) as u8;
        sk_chunk[9] = (t5 >> 7) as u8;
        sk_chunk[9] |= (t6 << 6) as u8;
        sk_chunk[10] = (t6 >> 2) as u8;
        sk_chunk[11] = (t6 >> 10) as u8;
        sk_chunk[11] |= (t7 << 3) as u8;
        sk_chunk[12] = (t7 >> 5) as u8;
    }
}

pub(crate) fn unpack_poly_t0(p: &DilithiumParams, poly: &mut poly::Poly, packed: &[u8]) {
    debug_assert_eq!(packed.len(), p.t0_poly_packed_len);

    let dest = poly.coeffs.chunks_exact_mut(8);
    let src = packed.chunks_exact(13);

    for (coeffs_chunk, packed_chunk) in Iterator::zip(dest, src) {
        let t0 = packed_chunk[0] as i32;
        let t1 = packed_chunk[1] as i32;
        let t2 = packed_chunk[2] as i32;
        let t3 = packed_chunk[3] as i32;
        let t4 = packed_chunk[4] as i32;
        let t5 = packed_chunk[5] as i32;
        let t6 = packed_chunk[6] as i32;
        let t7 = packed_chunk[7] as i32;
        let t8 = packed_chunk[8] as i32;
        let t9 = packed_chunk[9] as i32;
        let t10 = packed_chunk[10] as i32;
        let t11 = packed_chunk[11] as i32;
        let t12 = packed_chunk[12] as i32;

        coeffs_chunk[0] = t0;
        coeffs_chunk[0] |= t1 << 8;
        coeffs_chunk[0] &= 0x1FFF;

        coeffs_chunk[1] = t1 >> 5;
        coeffs_chunk[1] |= t2 << 3;
        coeffs_chunk[1] |= t3 << 11;
        coeffs_chunk[1] &= 0x1FFF;

        coeffs_chunk[2] = t3 >> 2;
        coeffs_chunk[2] |= t4 << 6;
        coeffs_chunk[2] &= 0x1FFF;

        coeffs_chunk[3] = t4 >> 7;
        coeffs_chunk[3] |= t5 << 1;
        coeffs_chunk[3] |= t6 << 9;
        coeffs_chunk[3] &= 0x1FFF;

        coeffs_chunk[4] = t6 >> 4;
        coeffs_chunk[4] |= t7 << 4;
        coeffs_chunk[4] |= t8 << 12;
        coeffs_chunk[4] &= 0x1FFF;

        coeffs_chunk[5] = t8 >> 1;
        coeffs_chunk[5] |= t9 << 7;
        coeffs_chunk[5] &= 0x1FFF;

        coeffs_chunk[6] = t9 >> 6;
        coeffs_chunk[6] |= t10 << 2;
        coeffs_chunk[6] |= t11 << 10;
        coeffs_chunk[6] &= 0x1FFF;

        coeffs_chunk[7] = t11 >> 3;
        coeffs_chunk[7] |= t12 << 5;
        coeffs_chunk[7] &= 0x1FFF;

        coeffs_chunk[0] = (1 << (D - 1)) - coeffs_chunk[0];
        coeffs_chunk[1] = (1 << (D - 1)) - coeffs_chunk[1];
        coeffs_chunk[2] = (1 << (D - 1)) - coeffs_chunk[2];
        coeffs_chunk[3] = (1 << (D - 1)) - coeffs_chunk[3];
        coeffs_chunk[4] = (1 << (D - 1)) - coeffs_chunk[4];
        coeffs_chunk[5] = (1 << (D - 1)) - coeffs_chunk[5];
        coeffs_chunk[6] = (1 << (D - 1)) - coeffs_chunk[6];
        coeffs_chunk[7] = (1 << (D - 1)) - coeffs_chunk[7];
    }
}

pub(crate) fn pack_poly_t1(p: &DilithiumParams, pk: &mut [u8], poly: &poly::Poly) {
    debug_assert_eq!(pk.len(), p.t1_poly_packed_len);

    let pk_chunks = pk.chunks_exact_mut(5);
    let poly_chunks = poly.coeffs.chunks_exact(4);
    for (pk_chunk, poly_chunk) in Iterator::zip(pk_chunks, poly_chunks) {
        pk_chunk[0] = (poly_chunk[0] >> 0) as u8;
        pk_chunk[1] = ((poly_chunk[0] >> 8) | (poly_chunk[1] << 2)) as u8;
        pk_chunk[2] = ((poly_chunk[1] >> 6) | (poly_chunk[2] << 4)) as u8;
        pk_chunk[3] = ((poly_chunk[2] >> 4) | (poly_chunk[3] << 6)) as u8;
        pk_chunk[4] = (poly_chunk[3] >> 2) as u8;
    }
}

pub(crate) fn unpack_poly_t1(p: &DilithiumParams, poly: &mut poly::Poly, pk: &[u8]) {
    debug_assert_eq!(pk.len(), p.t1_poly_packed_len);

    let poly_chunks = poly.coeffs.chunks_exact_mut(4);
    let pk_chunks = pk.chunks_exact(5);
    for (poly_chunk, pk_chunk) in Iterator::zip(poly_chunks, pk_chunks) {
        poly_chunk[0] = (((pk_chunk[0] as u32 >> 0) | ((pk_chunk[1] as u32) << 8)) & 0x3FF) as i32;
        poly_chunk[1] = (((pk_chunk[1] as u32 >> 2) | ((pk_chunk[2] as u32) << 6)) & 0x3FF) as i32;
        poly_chunk[2] = (((pk_chunk[2] as u32 >> 4) | ((pk_chunk[3] as u32) << 4)) & 0x3FF) as i32;
        poly_chunk[3] = (((pk_chunk[3] as u32 >> 6) | ((pk_chunk[4] as u32) << 2)) & 0x3FF) as i32;
    }
}

pub(crate) fn pack_polyvec_w1(p: &DilithiumParams, w1packed: &mut [u8], w1: &[poly::Poly]) {
    debug_assert_eq!(w1packed.len(), p.k * p.w1_poly_packed_len);
    let mut offset = 0;
    for poly in w1 {
        let poly_bytes = &mut w1packed[offset..offset + p.w1_poly_packed_len];
        pack_poly_w1(p, poly_bytes, poly);
        offset += p.w1_poly_packed_len;
    }
    debug_assert_eq!(offset, p.k * p.w1_poly_packed_len);
}

pub(crate) fn pack_poly_w1(p: &DilithiumParams, w1packed: &mut [u8], poly: &poly::Poly) {
    debug_assert_eq!(w1packed.len(), p.w1_poly_packed_len);

    if p.gamma2 == (Q - 1) / 88 {
        let w1packed_chunks = w1packed.chunks_exact_mut(3);
        let poly_chunks = poly.coeffs.chunks_exact(4);
        for (w1packed_chunk, poly_chunk) in Iterator::zip(w1packed_chunks, poly_chunks) {
            w1packed_chunk[0] = (poly_chunk[0]) as u8;
            w1packed_chunk[0] |= (poly_chunk[1] << 6) as u8;
            w1packed_chunk[1] = (poly_chunk[1] >> 2) as u8;
            w1packed_chunk[1] |= (poly_chunk[2] << 4) as u8;
            w1packed_chunk[2] = (poly_chunk[2] >> 4) as u8;
            w1packed_chunk[2] |= (poly_chunk[3] << 2) as u8;
        }
    } else if p.gamma2 == (Q - 1) / 32 {
        let poly_chunks = poly.coeffs.chunks_exact(2);
        for (w1packed_byte, poly_chunk) in Iterator::zip(w1packed.iter_mut(), poly_chunks) {
            *w1packed_byte = (poly_chunk[0] | (poly_chunk[1] << 4)) as u8;
        }
    } else {
        unreachable!("invalid GAMMA2 value ({})", p.gamma2);
    }
}

pub(crate) fn pack_poly_z(p: &DilithiumParams, packed: &mut [u8], poly: &poly::Poly) {
    debug_assert_eq!(packed.len(), p.z_poly_packed_len);

    if p.gamma1 == 2i32.pow(17) {
        let dest = packed.chunks_exact_mut(9);
        let src = poly.coeffs.chunks_exact(4);
        for (packed_chunk, poly_chunk) in Iterator::zip(dest, src) {
            let t0 = p.gamma1 - poly_chunk[0];
            let t1 = p.gamma1 - poly_chunk[1];
            let t2 = p.gamma1 - poly_chunk[2];
            let t3 = p.gamma1 - poly_chunk[3];

            packed_chunk[0] = (t0) as u8;
            packed_chunk[1] = (t0 >> 8) as u8;
            packed_chunk[2] = (t0 >> 16) as u8;
            packed_chunk[2] |= (t1 << 2) as u8;
            packed_chunk[3] = (t1 >> 6) as u8;
            packed_chunk[4] = (t1 >> 14) as u8;
            packed_chunk[4] |= (t2 << 4) as u8;
            packed_chunk[5] = (t2 >> 4) as u8;
            packed_chunk[6] = (t2 >> 12) as u8;
            packed_chunk[6] |= (t3 << 6) as u8;
            packed_chunk[7] = (t3 >> 2) as u8;
            packed_chunk[8] = (t3 >> 10) as u8;
        }
    } else if p.gamma1 == 2i32.pow(19) {
        let dest = packed.chunks_exact_mut(5);
        let src = poly.coeffs.chunks_exact(2);
        for (zpacked_chunk, poly_chunk) in Iterator::zip(dest, src) {
            let t0 = p.gamma1 - poly_chunk[0];
            let t1 = p.gamma1 - poly_chunk[1];

            zpacked_chunk[0] = (t0) as u8;
            zpacked_chunk[1] = (t0 >> 8) as u8;
            zpacked_chunk[2] = (t0 >> 16) as u8;
            zpacked_chunk[2] |= (t1 << 4) as u8;
            zpacked_chunk[3] = (t1 >> 4) as u8;
            zpacked_chunk[4] = (t1 >> 12) as u8;
        }
    } else {
        unreachable!("invalid GAMMA1 value ({})", p.gamma1);
    }
}

pub(crate) fn unpack_poly_z(p: &DilithiumParams, poly: &mut poly::Poly, zpacked: &[u8]) {
    assert_eq!(zpacked.len(), p.z_poly_packed_len);
    if p.gamma1 == 2i32.pow(17) {
        let dest = poly.coeffs.chunks_exact_mut(4);
        let src = zpacked.chunks_exact(9);
        for (poly_chunk, zpacked_chunk) in Iterator::zip(dest, src) {
            poly_chunk[0] = zpacked_chunk[0] as i32;
            poly_chunk[0] |= (zpacked_chunk[1] as i32) << 8;
            poly_chunk[0] |= (zpacked_chunk[2] as i32) << 16;
            poly_chunk[0] &= 0x3FFFF;

            poly_chunk[1] = (zpacked_chunk[2] as i32) >> 2;
            poly_chunk[1] |= (zpacked_chunk[3] as i32) << 6;
            poly_chunk[1] |= (zpacked_chunk[4] as i32) << 14;
            poly_chunk[1] &= 0x3FFFF;

            poly_chunk[2] = (zpacked_chunk[4] as i32) >> 4;
            poly_chunk[2] |= (zpacked_chunk[5] as i32) << 4;
            poly_chunk[2] |= (zpacked_chunk[6] as i32) << 12;
            poly_chunk[2] &= 0x3FFFF;

            poly_chunk[3] = (zpacked_chunk[6] as i32) >> 6;
            poly_chunk[3] |= (zpacked_chunk[7] as i32) << 2;
            poly_chunk[3] |= (zpacked_chunk[8] as i32) << 10;
            poly_chunk[3] &= 0x3FFFF;

            poly_chunk[0] = p.gamma1 - poly_chunk[0];
            poly_chunk[1] = p.gamma1 - poly_chunk[1];
            poly_chunk[2] = p.gamma1 - poly_chunk[2];
            poly_chunk[3] = p.gamma1 - poly_chunk[3];
        }
    } else if p.gamma1 == 2i32.pow(19) {
        let dest = poly.coeffs.chunks_exact_mut(2);
        let src = zpacked.chunks_exact(5);
        for (poly_chunk, zpacked_chunk) in Iterator::zip(dest, src) {
            poly_chunk[0] = zpacked_chunk[0] as i32;
            poly_chunk[0] |= (zpacked_chunk[1] as i32) << 8;
            poly_chunk[0] |= (zpacked_chunk[2] as i32) << 16;
            poly_chunk[0] &= 0xFFFFF;

            poly_chunk[1] = (zpacked_chunk[2] as i32) >> 4;
            poly_chunk[1] |= (zpacked_chunk[3] as i32) << 4;
            poly_chunk[1] |= (zpacked_chunk[4] as i32) << 12;
            poly_chunk[0] &= 0xFFFFF;

            poly_chunk[0] = p.gamma1 - poly_chunk[0];
            poly_chunk[1] = p.gamma1 - poly_chunk[1];
        }
    } else {
        unreachable!("invalid GAMMA1 value ({})", p.gamma1);
    }
}

fn unpack_vec_hints(
    p: &DilithiumParams,
    h: &mut [poly::Poly],
    sig: &[u8],
) -> Result<(), crate::Error> {
    debug_assert_eq!(h.len(), p.k);
    debug_assert_eq!(sig.len(), p.omega + p.k);

    let mut offset = 0usize;
    for (poly_idx, poly) in h.iter_mut().enumerate() {
        let hints_start = offset;
        let hints_end = sig[p.omega + poly_idx] as usize;
        if hints_end < hints_start || hints_end > p.omega {
            return Err(crate::Error::default());
        }

        for sig_idx in hints_start..hints_end {
            let coeff_idx = sig[sig_idx] as usize;
            if sig_idx > hints_start {
                // Assert that the coefficients are ordered for strong unforgeability
                let prev_coeff_idx = sig[sig_idx - 1] as usize;
                if prev_coeff_idx >= coeff_idx {
                    return Err(crate::Error::default());
                }
            }
            poly.coeffs[coeff_idx] = 1;
        }
        offset = hints_end;
    }

    // Assert that the rest of the signature is zeroed
    if !sig[offset..p.omega].iter().all(|b| *b == 0) {
        return Err(crate::Error::default());
    }

    Ok(())
}

pub(crate) fn pack_vec_hints(p: &DilithiumParams, hints_packed: &mut [u8], h: &[poly::Poly]) {
    debug_assert_eq!(hints_packed.len(), p.omega + p.k);
    debug_assert_eq!(h.len(), p.k);

    hints_packed.fill(0);

    let mut offset = 0u8;
    for (vec_idx, h_poly) in h.iter().enumerate() {
        for (poly_idx, coeff) in h_poly.coeffs.iter().enumerate() {
            if *coeff != 0 {
                debug_assert!(TryInto::<u8>::try_into(poly_idx).is_ok());
                hints_packed[offset as usize] = poly_idx as u8;
                offset += 1;
            }
        }
        hints_packed[p.omega + vec_idx] = offset;
    }
}
