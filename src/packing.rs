use crate::{
    params::{DilithiumParams, SEEDBYTES},
    poly,
};

pub(crate) fn pack_sk(
    p: &DilithiumParams,
    sk: &mut [u8],
    rho: &[u8],
    tr: &[u8],
    key: &[u8],
    t0: &mut [crate::poly::Poly],
    s1: &mut [crate::poly::Poly],
    s2: &mut [crate::poly::Poly],
) {
    debug_assert_eq!(sk.len(), p.CRYPTO_SECRETKEYBYTES);
    debug_assert_eq!(rho.len(), SEEDBYTES);
    debug_assert_eq!(tr.len(), SEEDBYTES);
    debug_assert_eq!(key.len(), SEEDBYTES);
    debug_assert_eq!(t0.len(), p.k);
    debug_assert_eq!(s1.len(), p.l);
    debug_assert_eq!(s2.len(), p.k);

    let mut offset = 0;
    (&mut sk[offset..offset + SEEDBYTES]).copy_from_slice(rho);
    offset += SEEDBYTES;
    (&mut sk[offset..offset + SEEDBYTES]).copy_from_slice(key);
    offset += SEEDBYTES;
    (&mut sk[offset..offset + SEEDBYTES]).copy_from_slice(tr);
    offset += SEEDBYTES;

    for poly in s1 {
        polyeta_pack(p, &mut sk[offset..offset + p.POLYETA_PACKEDBYTES], poly);
        offset += p.POLYETA_PACKEDBYTES;
    }

    for poly in s2 {
        polyeta_pack(p, &mut sk[offset..offset + p.POLYETA_PACKEDBYTES], poly);
        offset += p.POLYETA_PACKEDBYTES;
    }

    for poly in t0 {
        polyt0_pack(p, &mut sk[offset..offset + p.POLYT0_PACKEDBYTES], poly);
        offset += p.POLYT0_PACKEDBYTES;
    }
    debug_assert_eq!(offset, p.CRYPTO_SECRETKEYBYTES);
}

pub(crate) fn polyeta_pack(p: &DilithiumParams, sk: &mut [u8], poly: &crate::poly::Poly) {
    debug_assert_eq!(sk.len(), p.POLYETA_PACKEDBYTES);

    if p.ETA == 2 {
        let sk_chunks = sk.chunks_exact_mut(3);
        let poly_chunks = poly.coeffs.chunks_exact(8);
        for (sk_chunk, poly_chunk) in Iterator::zip(sk_chunks, poly_chunks) {
            let t0 = p.ETA - poly_chunk[0];
            let t1 = p.ETA - poly_chunk[1];
            let t2 = p.ETA - poly_chunk[2];
            let t3 = p.ETA - poly_chunk[3];
            let t4 = p.ETA - poly_chunk[4];
            let t5 = p.ETA - poly_chunk[5];
            let t6 = p.ETA - poly_chunk[6];
            let t7 = p.ETA - poly_chunk[7];

            sk_chunk[0] = ((t0 >> 0) | (t1 << 3) | (t2 << 6)) as u8;
            sk_chunk[1] = ((t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7)) as u8;
            sk_chunk[2] = ((t5 >> 1) | (t6 << 2) | (t7 << 5)) as u8;
        }
    } else if p.ETA == 4 {
        let chunks = poly.coeffs.chunks_exact(2);
        for (offset, chunk) in Iterator::zip(0.., chunks) {
            let t0 = p.ETA - chunk[0];
            let t1 = p.ETA - chunk[1];
            sk[offset] = (t0 | (t1 << 4)) as u8;
        }
    } else {
        unreachable!("invalid ETA value ({})", p.ETA);
    }
}

pub(crate) fn polyt0_pack(p: &DilithiumParams, sk: &mut [u8], poly: &crate::poly::Poly) {
    use crate::params::D;

    debug_assert_eq!(sk.len(), p.POLYT0_PACKEDBYTES);

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

pub(crate) fn pack_pk(p: &DilithiumParams, pk: &mut [u8], rho: &[u8], t1: &[crate::poly::Poly]) {
    debug_assert_eq!(t1.len(), p.k);

    let mut offset = 0;
    (&mut pk[offset..offset + SEEDBYTES]).copy_from_slice(rho);
    offset += SEEDBYTES;

    for poly in t1 {
        polyt1_pack(p, &mut pk[offset..offset + p.POLYT1_PACKEDBYTES], poly);
        offset += p.POLYT1_PACKEDBYTES;
    }
    debug_assert_eq!(offset, p.CRYPTO_PUBLICKEYBYTES);
}

pub(crate) fn polyt1_pack(p: &DilithiumParams, pk: &mut [u8], poly: &crate::poly::Poly) {
    debug_assert_eq!(pk.len(), p.POLYT1_PACKEDBYTES);

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

pub(crate) fn polyvec_pack_w1(p: &DilithiumParams, w1packed: &mut [u8], w1: &[crate::poly::Poly]) {
    debug_assert_eq!(w1packed.len(), p.k * p.POLYW1_PACKEDBYTES);
    let mut offset = 0;
    for poly in w1 {
        polyw1_pack(
            p,
            &mut w1packed[offset..offset + p.POLYW1_PACKEDBYTES],
            poly,
        );
        offset += p.POLYW1_PACKEDBYTES;
    }
    debug_assert_eq!(offset, p.k * p.POLYW1_PACKEDBYTES);
}

pub(crate) fn polyw1_pack(p: &DilithiumParams, w1packed: &mut [u8], poly: &crate::poly::Poly) {
    debug_assert_eq!(w1packed.len(), p.POLYW1_PACKEDBYTES);

    if p.GAMMA2 == (crate::params::Q - 1) / 88 {
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
    } else if p.GAMMA2 == (crate::params::Q - 1) / 32 {
        let poly_chunks = poly.coeffs.chunks_exact(2);
        for (w1packed_byte, poly_chunk) in Iterator::zip(w1packed.iter_mut(), poly_chunks) {
            *w1packed_byte = (poly_chunk[0] | (poly_chunk[1] << 4)) as u8;
        }
    } else {
        unreachable!("invalid GAMMA2 value ({})", p.GAMMA2);
    }
}

pub(crate) fn polyz_unpack(p: &DilithiumParams, poly: &mut crate::poly::Poly, zpacked: &[u8]) {
    assert_eq!(zpacked.len(), p.POLYZ_PACKEDBYTES);
    if p.GAMMA1 == 2i32.pow(17) {
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

            poly_chunk[0] = p.GAMMA1 - poly_chunk[0];
            poly_chunk[1] = p.GAMMA1 - poly_chunk[1];
            poly_chunk[2] = p.GAMMA1 - poly_chunk[2];
            poly_chunk[3] = p.GAMMA1 - poly_chunk[3];
        }
    } else if p.GAMMA1 == 2i32.pow(19) {
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

            poly_chunk[0] = p.GAMMA1 - poly_chunk[0];
            poly_chunk[1] = p.GAMMA1 - poly_chunk[1];
        }
    } else {
        unreachable!("invalid GAMMA1 value ({})", p.GAMMA1);
    }
}