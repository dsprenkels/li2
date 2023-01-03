use crate::params::DilithiumParams;


#[derive(Debug, Clone, Copy)]
pub(crate) struct Poly {
    pub(crate) coeffs: [u32; 256],
}

// fn poly_uniform(params: &DilithiumParams, poly: &mut Poly, seed: &[u8], nonce: u16) {
//     const BUF_LEN = 
// }


// void poly_uniform(poly *a,
//                   const uint8_t seed[SEEDBYTES],
//                   uint16_t nonce)
// {
//   unsigned int i, ctr, off;
//   unsigned int buflen = POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES;
//   uint8_t buf[POLY_UNIFORM_NBLOCKS*STREAM128_BLOCKBYTES + 2];
//   stream128_state state;

//   stream128_init(&state, seed, nonce);
//   stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS, &state);

//   ctr = rej_uniform(a->coeffs, N, buf, buflen);

//   while(ctr < N) {
//     off = buflen % 3;
//     for(i = 0; i < off; ++i)
//       buf[i] = buf[buflen - off + i];

//     stream128_squeezeblocks(buf + off, 1, &state);
//     buflen = STREAM128_BLOCKBYTES + off;
//     ctr += rej_uniform(a->coeffs + ctr, N - ctr, buf, buflen);
//   }
// }