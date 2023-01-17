use crate::params::{DilithiumParams, SEEDBYTES};

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

fn polyeta_pack(p: &DilithiumParams, sk: &mut [u8], poly: &crate::poly::Poly) {
    debug_assert_eq!(sk.len(), p.POLYETA_PACKEDBYTES);

    if p.ETA == 2 {
        let chunks = poly.coeffs.chunks_exact(8);
        for (offset, chunk) in (0..).step_by(3).zip(chunks) {
            let t0 = p.ETA - chunk[0];
            let t1 = p.ETA - chunk[1];
            let t2 = p.ETA - chunk[2];
            let t3 = p.ETA - chunk[3];
            let t4 = p.ETA - chunk[4];
            let t5 = p.ETA - chunk[5];
            let t6 = p.ETA - chunk[6];
            let t7 = p.ETA - chunk[7];

            sk[offset + 0] = ((t0 >> 0) | (t1 << 3) | (t2 << 6)) as u8;
            sk[offset + 1] = ((t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7)) as u8;
            sk[offset + 2] = ((t5 >> 1) | (t6 << 2) | (t7 << 5)) as u8;
        }
    } else if p.ETA == 4 {
        let chunks = poly.coeffs.chunks_exact(2);
        for (offset, chunk) in (0..).zip(chunks) {
            let t0 = p.ETA - chunk[0];
            let t1 = p.ETA - chunk[1];
            sk[offset] = (t0 | (t1 << 4)) as u8;
        }
    } else {
        unreachable!("invalid ETA value ({})", p.ETA);
    }
}

fn polyt0_pack(p: &DilithiumParams, sk: &mut [u8], poly: &crate::poly::Poly) {
    use crate::params::D;

    debug_assert_eq!(sk.len(), p.POLYT0_PACKEDBYTES);

    let sk_chunks = sk.chunks_exact_mut(13);
    let poly_chunks = poly.coeffs.chunks_exact(8);
    for (sk_chunk, poly_chunk) in sk_chunks.zip(poly_chunks) {
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
