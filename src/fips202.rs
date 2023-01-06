#![allow(non_snake_case)]

use core::mem::size_of;

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;
const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;
const NROUNDS: usize = 24;

#[derive(Clone, Debug, Default)]
// TODO: Can this struct be hidden at some point?
pub(crate) struct KeccakState {
    s: [u64; 25],
    pos: usize,
}

#[derive(Debug)]
pub struct SHAKE256<'a> {
    keccak: &'a mut KeccakState,
}

#[derive(Debug)]
pub struct SHAKE256Reader<'a> {
    shake: SHAKE256<'a>,
}

impl<'a> digest::Update for SHAKE256<'a> {
    fn update(&mut self, data: &[u8]) {
        self.keccak.pos = keccak_absorb(&mut self.keccak.s, self.keccak.pos, SHAKE256_RATE, data);
    }
}

impl<'a> digest::ExtendableOutput for SHAKE256<'a> {
    type Reader = SHAKE256Reader<'a>;

    fn finalize_xof(mut self) -> Self::Reader {
        keccak_finalize(&mut self.keccak.s, self.keccak.pos, SHAKE256_RATE, 0x1F);
        self.keccak.pos = SHAKE256_RATE;
        SHAKE256Reader { shake: self }
    }
}

impl<'a> SHAKE256<'a> {
    pub(crate) fn new(keccak: &'a mut KeccakState) -> Self {
        let mut xof = SHAKE256 { keccak };
        xof.reset();
        xof
    }

    fn reset(&mut self) -> &mut Self {
        keccak_init(&mut self.keccak.s);
        self.keccak.pos = 0;
        self
    }
}

impl<'a> digest::XofReader for SHAKE256Reader<'a> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.shake.keccak.pos = keccak_squeeze(
            buffer,
            &mut self.shake.keccak.s,
            self.shake.keccak.pos,
            SHAKE256_RATE,
        );
    }
}

impl<'a> Drop for SHAKE256Reader<'a> {
    fn drop(&mut self) {
        // Reset the writer such that it is ready for new input
        self.shake.reset();
    }
}

#[derive(Debug)]
pub struct SHAKE128<'a> {
    keccak: &'a mut KeccakState,
}

#[derive(Debug)]
pub struct SHAKE128Reader<'a> {
    shake: SHAKE128<'a>,
}

impl<'a> digest::Update for SHAKE128<'a> {
    fn update(&mut self, data: &[u8]) {
        self.keccak.pos = keccak_absorb(&mut self.keccak.s, self.keccak.pos, SHAKE128_RATE, data);
    }
}

impl<'a> digest::ExtendableOutput for SHAKE128<'a> {
    type Reader = SHAKE128Reader<'a>;

    fn finalize_xof(mut self) -> Self::Reader {
        keccak_finalize(&mut self.keccak.s, self.keccak.pos, SHAKE128_RATE, 0x1F);
        self.keccak.pos = SHAKE128_RATE;
        SHAKE128Reader { shake: self }
    }
}

impl<'a> SHAKE128<'a> {
    pub(crate) fn new(keccak: &'a mut KeccakState) -> Self {
        let mut xof = Self { keccak };
        xof.reset();
        xof
    }

    fn reset(&mut self) -> &mut Self {
        keccak_init(&mut self.keccak.s);
        self.keccak.pos = 0;
        self
    }
}

impl<'a> digest::XofReader for SHAKE128Reader<'a> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.shake.keccak.pos = keccak_squeeze(
            buffer,
            &mut self.shake.keccak.s,
            self.shake.keccak.pos,
            SHAKE128_RATE,
        );
    }
}

impl<'a> Drop for SHAKE128Reader<'a> {
    fn drop(&mut self) {
        // Reset the writer such that it is ready for new input
        self.shake.reset();
    }
}

/*************************************************
 * Name:        load64
 *
 * Description: Load 8 bytes into uint64_t in little-endian order
 *
 * Arguments:   - const uint8_t *x: pointer to input byte array
 *
 * Returns the loaded 64-bit unsigned integer
 **************************************************/
#[inline]
fn load64(x: &[u8]) -> u64 {
    let mut arr = [0; size_of::<u64>()];
    arr.copy_from_slice(x);
    u64::from_le_bytes(arr)
}

//  /*************************************************
//  * Name:        store64
//  *
//  * Description: Store a 64-bit integer to array of 8 bytes in little-endian order
//  *
//  * Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
//  *              - uint64_t u: input 64-bit unsigned integer
//  **************************************************/
#[inline]
fn store64(x: &mut [u8], u: u64) {
    x.copy_from_slice(&u.to_le_bytes())
}

//  /* Keccak round constants */
const KeccakF_RoundConstants: [u64; NROUNDS] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

//  /*************************************************
//  * Name:        KeccakF1600_StatePermute
//  *
//  * Description: The Keccak F1600 Permutation
//  *
//  * Arguments:   - uint64_t *state: pointer to input/output Keccak state
//  **************************************************/
pub(crate) fn KeccakF1600_StatePermute(state: &mut [u64; 25]) {
    // copyFromState(A, state)
    let mut Aba = state[0];
    let mut Abe = state[1];
    let mut Abi = state[2];
    let mut Abo = state[3];
    let mut Abu = state[4];
    let mut Aga = state[5];
    let mut Age = state[6];
    let mut Agi = state[7];
    let mut Ago = state[8];
    let mut Agu = state[9];
    let mut Aka = state[10];
    let mut Ake = state[11];
    let mut Aki = state[12];
    let mut Ako = state[13];
    let mut Aku = state[14];
    let mut Ama = state[15];
    let mut Ame = state[16];
    let mut Ami = state[17];
    let mut Amo = state[18];
    let mut Amu = state[19];
    let mut Asa = state[20];
    let mut Ase = state[21];
    let mut Asi = state[22];
    let mut Aso = state[23];
    let mut Asu = state[24];

    for round in (0..NROUNDS).step_by(2) {
        // prepareTheta
        let mut BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
        let mut BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
        let mut BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
        let mut BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
        let mut BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

        //thetaRhoPiChiIotaPrepareTheta(round, A, E)
        let Da = BCu ^ BCe.rotate_left(1);
        let De = BCa ^ BCi.rotate_left(1);
        let Di = BCe ^ BCo.rotate_left(1);
        let Do = BCi ^ BCu.rotate_left(1);
        let Du = BCo ^ BCa.rotate_left(1);

        Aba ^= Da;
        BCa = Aba;
        Age ^= De;
        BCe = Age.rotate_left(44);
        Aki ^= Di;
        BCi = Aki.rotate_left(43);
        Amo ^= Do;
        BCo = Amo.rotate_left(21);
        Asu ^= Du;
        BCu = Asu.rotate_left(14);
        let mut Eba = BCa ^ ((!BCe) & BCi);
        Eba ^= KeccakF_RoundConstants[round];
        let mut Ebe = BCe ^ ((!BCi) & BCo);
        let mut Ebi = BCi ^ ((!BCo) & BCu);
        let mut Ebo = BCo ^ ((!BCu) & BCa);
        let mut Ebu = BCu ^ ((!BCa) & BCe);

        Abo ^= Do;
        BCa = Abo.rotate_left(28);
        Agu ^= Du;
        BCe = Agu.rotate_left(20);
        Aka ^= Da;
        BCi = Aka.rotate_left(3);
        Ame ^= De;
        BCo = Ame.rotate_left(45);
        Asi ^= Di;
        BCu = Asi.rotate_left(61);
        let mut Ega = BCa ^ ((!BCe) & BCi);
        let mut Ege = BCe ^ ((!BCi) & BCo);
        let mut Egi = BCi ^ ((!BCo) & BCu);
        let mut Ego = BCo ^ ((!BCu) & BCa);
        let mut Egu = BCu ^ ((!BCa) & BCe);

        Abe ^= De;
        BCa = Abe.rotate_left(1);
        Agi ^= Di;
        BCe = Agi.rotate_left(6);
        Ako ^= Do;
        BCi = Ako.rotate_left(25);
        Amu ^= Du;
        BCo = Amu.rotate_left(8);
        Asa ^= Da;
        BCu = Asa.rotate_left(18);
        let mut Eka = BCa ^ ((!BCe) & BCi);
        let mut Eke = BCe ^ ((!BCi) & BCo);
        let mut Eki = BCi ^ ((!BCo) & BCu);
        let mut Eko = BCo ^ ((!BCu) & BCa);
        let mut Eku = BCu ^ ((!BCa) & BCe);

        Abu ^= Du;
        BCa = Abu.rotate_left(27);
        Aga ^= Da;
        BCe = Aga.rotate_left(36);
        Ake ^= De;
        BCi = Ake.rotate_left(10);
        Ami ^= Di;
        BCo = Ami.rotate_left(15);
        Aso ^= Do;
        BCu = Aso.rotate_left(56);
        let mut Ema = BCa ^ ((!BCe) & BCi);
        let mut Eme = BCe ^ ((!BCi) & BCo);
        let mut Emi = BCi ^ ((!BCo) & BCu);
        let mut Emo = BCo ^ ((!BCu) & BCa);
        let mut Emu = BCu ^ ((!BCa) & BCe);

        Abi ^= Di;
        BCa = Abi.rotate_left(62);
        Ago ^= Do;
        BCe = Ago.rotate_left(55);
        Aku ^= Du;
        BCi = Aku.rotate_left(39);
        Ama ^= Da;
        BCo = Ama.rotate_left(41);
        Ase ^= De;
        BCu = Ase.rotate_left(2);
        let mut Esa = BCa ^ ((!BCe) & BCi);
        let mut Ese = BCe ^ ((!BCi) & BCo);
        let mut Esi = BCi ^ ((!BCo) & BCu);
        let mut Eso = BCo ^ ((!BCu) & BCa);
        let mut Esu = BCu ^ ((!BCa) & BCe);

        // prepareTheta
        BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
        BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
        BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
        BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
        BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

        // thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
        let Da = BCu ^ BCe.rotate_left(1);
        let De = BCa ^ BCi.rotate_left(1);
        let Di = BCe ^ BCo.rotate_left(1);
        let Do = BCi ^ BCu.rotate_left(1);
        let Du = BCo ^ BCa.rotate_left(1);

        Eba ^= Da;
        BCa = Eba;
        Ege ^= De;
        BCe = Ege.rotate_left(44);
        Eki ^= Di;
        BCi = Eki.rotate_left(43);
        Emo ^= Do;
        BCo = Emo.rotate_left(21);
        Esu ^= Du;
        BCu = Esu.rotate_left(14);
        Aba = BCa ^ ((!BCe) & BCi);
        Aba ^= KeccakF_RoundConstants[round + 1];
        Abe = BCe ^ ((!BCi) & BCo);
        Abi = BCi ^ ((!BCo) & BCu);
        Abo = BCo ^ ((!BCu) & BCa);
        Abu = BCu ^ ((!BCa) & BCe);

        Ebo ^= Do;
        BCa = Ebo.rotate_left(28);
        Egu ^= Du;
        BCe = Egu.rotate_left(20);
        Eka ^= Da;
        BCi = Eka.rotate_left(3);
        Eme ^= De;
        BCo = Eme.rotate_left(45);
        Esi ^= Di;
        BCu = Esi.rotate_left(61);
        Aga = BCa ^ ((!BCe) & BCi);
        Age = BCe ^ ((!BCi) & BCo);
        Agi = BCi ^ ((!BCo) & BCu);
        Ago = BCo ^ ((!BCu) & BCa);
        Agu = BCu ^ ((!BCa) & BCe);

        Ebe ^= De;
        BCa = Ebe.rotate_left(1);
        Egi ^= Di;
        BCe = Egi.rotate_left(6);
        Eko ^= Do;
        BCi = Eko.rotate_left(25);
        Emu ^= Du;
        BCo = Emu.rotate_left(8);
        Esa ^= Da;
        BCu = Esa.rotate_left(18);
        Aka = BCa ^ ((!BCe) & BCi);
        Ake = BCe ^ ((!BCi) & BCo);
        Aki = BCi ^ ((!BCo) & BCu);
        Ako = BCo ^ ((!BCu) & BCa);
        Aku = BCu ^ ((!BCa) & BCe);

        Ebu ^= Du;
        BCa = Ebu.rotate_left(27);
        Ega ^= Da;
        BCe = Ega.rotate_left(36);
        Eke ^= De;
        BCi = Eke.rotate_left(10);
        Emi ^= Di;
        BCo = Emi.rotate_left(15);
        Eso ^= Do;
        BCu = Eso.rotate_left(56);
        Ama = BCa ^ ((!BCe) & BCi);
        Ame = BCe ^ ((!BCi) & BCo);
        Ami = BCi ^ ((!BCo) & BCu);
        Amo = BCo ^ ((!BCu) & BCa);
        Amu = BCu ^ ((!BCa) & BCe);

        Ebi ^= Di;
        BCa = Ebi.rotate_left(62);
        Ego ^= Do;
        BCe = Ego.rotate_left(55);
        Eku ^= Du;
        BCi = Eku.rotate_left(39);
        Ema ^= Da;
        BCo = Ema.rotate_left(41);
        Ese ^= De;
        BCu = Ese.rotate_left(2);
        Asa = BCa ^ ((!BCe) & BCi);
        Ase = BCe ^ ((!BCi) & BCo);
        Asi = BCi ^ ((!BCo) & BCu);
        Aso = BCo ^ ((!BCu) & BCa);
        Asu = BCu ^ ((!BCa) & BCe);
    }

    // copyToState(state, A)
    state[0] = Aba;
    state[1] = Abe;
    state[2] = Abi;
    state[3] = Abo;
    state[4] = Abu;
    state[5] = Aga;
    state[6] = Age;
    state[7] = Agi;
    state[8] = Ago;
    state[9] = Agu;
    state[10] = Aka;
    state[11] = Ake;
    state[12] = Aki;
    state[13] = Ako;
    state[14] = Aku;
    state[15] = Ama;
    state[16] = Ame;
    state[17] = Ami;
    state[18] = Amo;
    state[19] = Amu;
    state[20] = Asa;
    state[21] = Ase;
    state[22] = Asi;
    state[23] = Aso;
    state[24] = Asu;
}

//  /*************************************************
//  * Name:        keccak_init
//  *
//  * Description: Initializes the Keccak state.
//  *
//  * Arguments:   - uint64_t *s: pointer to Keccak state
//  **************************************************/
fn keccak_init(s: &mut [u64; 25]) {
    s.fill(0);
}

//  /*************************************************
//  * Name:        keccak_absorb
//  *
//  * Description: Absorb step of Keccak; incremental.
//  *
//  * Arguments:   - uint64_t *s: pointer to Keccak state
//  *              - unsigned int pos: position in current block to be absorbed
//  *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//  *              - const uint8_t *in: pointer to input to be absorbed into s
//  *              - size_t inlen: length of input in bytes
//  *
//  * Returns new position pos in current block
//  **************************************************/
fn keccak_absorb(s: &mut [u64; 25], mut pos: usize, rate: usize, mut input: &[u8]) -> usize {
    while pos + input.len() >= rate {
        for i in pos..rate {
            s[i / 8] ^= u64::from(input[0]) << 8 * (i % 8);
            input = &input[1..];
            pos += 1;
        }
        KeccakF1600_StatePermute(s);
        pos = 0;
    }

    for i in pos..pos + input.len() {
        s[i / 8] ^= u64::from(input[0]) << 8 * (i % 8);
        input = &input[1..];
        pos += 1;
    }

    debug_assert_eq!(input, &[]);
    pos
}

//  static unsigned int keccak_absorb(uint64_t s[25],
//                                    unsigned int pos,
//                                    unsigned int r,
//                                    const uint8_t *in,
//                                    size_t inlen)
//  {
//    unsigned int i;

//    while(pos+inlen >= r) {
//      for(i=pos;i<r;i++)
//        s[i/8] ^= (uint64_t)*in++ << 8*(i%8);
//      inlen -= r-pos;
//      KeccakF1600_StatePermute(s);
//      pos = 0;
//    }

//    for(i=pos;i<pos+inlen;i++)
//      s[i/8] ^= (uint64_t)*in++ << 8*(i%8);

//    return i;
//  }

//  /*************************************************
//  * Name:        keccak_finalize
//  *
//  * Description: Finalize absorb step.
//  *
//  * Arguments:   - uint64_t *s: pointer to Keccak state
//  *              - unsigned int pos: position in current block to be absorbed
//  *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//  *              - uint8_t p: domain separation byte
//  **************************************************/
fn keccak_finalize(s: &mut [u64; 25], pos: usize, rate: usize, ds: u8) {
    s[pos / 8] ^= u64::from(ds) << 8 * (pos % 8);
    s[rate / 8 - 1] ^= 1 << 63;
}

//  static void keccak_finalize(uint64_t s[25], unsigned int pos, unsigned int r, uint8_t p)
//  {
//    s[pos/8] ^= (uint64_t)p << 8*(pos%8);
//    s[r/8-1] ^= 1ULL << 63;
//  }

//  /*************************************************
//  * Name:        keccak_squeeze
//  *
//  * Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
//  *              Modifies the state. Can be called multiple times to keep
//  *              squeezing, i.e., is incremental.
//  *
//  * Arguments:   - uint8_t *out: pointer to output
//  *              - size_t outlen: number of bytes to be squeezed (written to out)
//  *              - uint64_t *s: pointer to input/output Keccak state
//  *              - unsigned int pos: number of bytes in current block already squeezed
//  *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//  *
//  * Returns new position pos in current block
//  **************************************************/
fn keccak_squeeze(mut out: &mut [u8], s: &mut [u64; 25], mut pos: usize, rate: usize) -> usize {
    while out.len() > 0 {
        if pos == rate {
            KeccakF1600_StatePermute(s);
            pos = 0;
        }
        for i in pos..core::cmp::min(rate, pos + out.len()) {
            out[0] = (s[i / 8] >> (8 * (i % 8))) as u8;
            out = &mut out[1..];
            pos += 1;
        }
    }
    assert_eq!(out, &[]);
    pos
}

//  static unsigned int keccak_squeeze(uint8_t *out,
//                                     size_t outlen,
//                                     uint64_t s[25],
//                                     unsigned int pos,
//                                     unsigned int r)
//  {
//    unsigned int i;

//    while(outlen) {
//      if(pos == r) {
//        KeccakF1600_StatePermute(s);
//        pos = 0;
//      }
//      for(i=pos;i < r && i < pos+outlen; i++)
//        *out++ = s[i/8] >> 8*(i%8);
//      outlen -= i-pos;
//      pos = i;
//    }

//    return pos;
//  }

//  /*************************************************
//  * Name:        keccak_absorb_once
//  *
//  * Description: Absorb step of Keccak;
//  *              non-incremental, starts by zeroeing the state.
//  *
//  * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
//  *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//  *              - const uint8_t *in: pointer to input to be absorbed into s
//  *              - size_t inlen: length of input in bytes
//  *              - uint8_t p: domain-separation byte for different Keccak-derived functions
//  **************************************************/
//  static void keccak_absorb_once(uint64_t s[25],
//                                 unsigned int r,
//                                 const uint8_t *in,
//                                 size_t inlen,
//                                 uint8_t p)
//  {
//    unsigned int i;

//    for(i=0;i<25;i++)
//      s[i] = 0;

//    while(inlen >= r) {
//      for(i=0;i<r/8;i++)
//        s[i] ^= load64(in+8*i);
//      in += r;
//      inlen -= r;
//      KeccakF1600_StatePermute(s);
//    }

//    for(i=0;i<inlen;i++)
//      s[i/8] ^= (uint64_t)in[i] << 8*(i%8);

//    s[i/8] ^= (uint64_t)p << 8*(i%8);
//    s[(r-1)/8] ^= 1ULL << 63;
//  }

//  /*************************************************
//  * Name:        keccak_squeezeblocks
//  *
//  * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
//  *              Modifies the state. Can be called multiple times to keep
//  *              squeezing, i.e., is incremental. Assumes zero bytes of current
//  *              block have already been squeezed.
//  *
//  * Arguments:   - uint8_t *out: pointer to output blocks
//  *              - size_t nblocks: number of blocks to be squeezed (written to out)
//  *              - uint64_t *s: pointer to input/output Keccak state
//  *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
//  **************************************************/
//  static void keccak_squeezeblocks(uint8_t *out,
//                                   size_t nblocks,
//                                   uint64_t s[25],
//                                   unsigned int r)
//  {
//    unsigned int i;

//    while(nblocks) {
//      KeccakF1600_StatePermute(s);
//      for(i=0;i<r/8;i++)
//        store64(out+8*i, s[i]);
//      out += r;
//      nblocks -= 1;
//    }
//  }

//  /*************************************************
//  * Name:        shake128_init
//  *
//  * Description: Initilizes Keccak state for use as SHAKE128 XOF
//  *
//  * Arguments:   - keccak_state *state: pointer to (uninitialized) Keccak state
//  **************************************************/
pub(crate) fn shake128_init(state: &mut KeccakState) {
    keccak_init(&mut state.s);
    state.pos = 0;
}

//  void shake128_init(keccak_state *state)
//  {
//    keccak_init(state->s);
//    state->pos = 0;
//  }

//  /*************************************************
//  * Name:        shake128_absorb
//  *
//  * Description: Absorb step of the SHAKE128 XOF; incremental.
//  *
//  * Arguments:   - keccak_state *state: pointer to (initialized) output Keccak state
//  *              - const uint8_t *in: pointer to input to be absorbed into s
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
pub(crate) fn shake128_absorb(state: &mut KeccakState, input: &[u8]) {
    state.pos = keccak_absorb(&mut state.s, state.pos, SHAKE128_RATE, input);
}

//  void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen)
//  {
//    state->pos = keccak_absorb(state->s, state->pos, SHAKE128_RATE, in, inlen);
//  }

//  /*************************************************
//  * Name:        shake128_finalize
//  *
//  * Description: Finalize absorb step of the SHAKE128 XOF.
//  *
//  * Arguments:   - keccak_state *state: pointer to Keccak state
//  **************************************************/
pub(crate) fn shake128_finalize(state: &mut KeccakState) {
    keccak_finalize(&mut state.s, state.pos, SHAKE128_RATE, 0x1F);
    state.pos = SHAKE128_RATE;
}

//  void shake128_finalize(keccak_state *state)
//  {
//    keccak_finalize(state->s, state->pos, SHAKE128_RATE, 0x1F);
//    state->pos = SHAKE128_RATE;
//  }

//  /*************************************************
//  * Name:        shake128_squeeze
//  *
//  * Description: Squeeze step of SHAKE128 XOF. Squeezes arbitraily many
//  *              bytes. Can be called multiple times to keep squeezing.
//  *
//  * Arguments:   - uint8_t *out: pointer to output blocks
//  *              - size_t outlen : number of bytes to be squeezed (written to output)
//  *              - keccak_state *s: pointer to input/output Keccak state
//  **************************************************/
pub(crate) fn shake128_squeeze(out: &mut [u8], state: &mut KeccakState) {
    state.pos = keccak_squeeze(out, &mut state.s, state.pos, SHAKE128_RATE);
}
//  void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state)
//  {
//    state->pos = keccak_squeeze(out, outlen, state->s, state->pos, SHAKE128_RATE);
//  }

//  /*************************************************
//  * Name:        shake128_absorb_once
//  *
//  * Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
//  *
//  * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
//  *              - const uint8_t *in: pointer to input to be absorbed into s
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
//  void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
//  {
//    keccak_absorb_once(state->s, SHAKE128_RATE, in, inlen, 0x1F);
//    state->pos = SHAKE128_RATE;
//  }

//  /*************************************************
//  * Name:        shake128_squeezeblocks
//  *
//  * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
//  *              SHAKE128_RATE bytes each. Can be called multiple times
//  *              to keep squeezing. Assumes new block has not yet been
//  *              started (state->pos = SHAKE128_RATE).
//  *
//  * Arguments:   - uint8_t *out: pointer to output blocks
//  *              - size_t nblocks: number of blocks to be squeezed (written to output)
//  *              - keccak_state *s: pointer to input/output Keccak state
//  **************************************************/
//  void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
//  {
//    keccak_squeezeblocks(out, nblocks, state->s, SHAKE128_RATE);
//  }

//  /*************************************************
//  * Name:        shake256_absorb_once
//  *
//  * Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
//  *
//  * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
//  *              - const uint8_t *in: pointer to input to be absorbed into s
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
//  void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen)
//  {
//    keccak_absorb_once(state->s, SHAKE256_RATE, in, inlen, 0x1F);
//    state->pos = SHAKE256_RATE;
//  }

//  /*************************************************
//  * Name:        shake256_squeezeblocks
//  *
//  * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
//  *              SHAKE256_RATE bytes each. Can be called multiple times
//  *              to keep squeezing. Assumes next block has not yet been
//  *              started (state->pos = SHAKE256_RATE).
//  *
//  * Arguments:   - uint8_t *out: pointer to output blocks
//  *              - size_t nblocks: number of blocks to be squeezed (written to output)
//  *              - keccak_state *s: pointer to input/output Keccak state
//  **************************************************/
//  void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state)
//  {
//    keccak_squeezeblocks(out, nblocks, state->s, SHAKE256_RATE);
//  }

//  /*************************************************
//  * Name:        shake128
//  *
//  * Description: SHAKE128 XOF with non-incremental API
//  *
//  * Arguments:   - uint8_t *out: pointer to output
//  *              - size_t outlen: requested output length in bytes
//  *              - const uint8_t *in: pointer to input
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
//  void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
//  {
//    size_t nblocks;
//    keccak_state state;

//    shake128_absorb_once(&state, in, inlen);
//    nblocks = outlen/SHAKE128_RATE;
//    shake128_squeezeblocks(out, nblocks, &state);
//    outlen -= nblocks*SHAKE128_RATE;
//    out += nblocks*SHAKE128_RATE;
//    shake128_squeeze(out, outlen, &state);
//  }

//  /*************************************************
//  * Name:        shake256
//  *
//  * Description: SHAKE256 XOF with non-incremental API
//  *
//  * Arguments:   - uint8_t *out: pointer to output
//  *              - size_t outlen: requested output length in bytes
//  *              - const uint8_t *in: pointer to input
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
//  void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
//  {
//    size_t nblocks;
//    keccak_state state;

//    shake256_absorb_once(&state, in, inlen);
//    nblocks = outlen/SHAKE256_RATE;
//    shake256_squeezeblocks(out, nblocks, &state);
//    outlen -= nblocks*SHAKE256_RATE;
//    out += nblocks*SHAKE256_RATE;
//    shake256_squeeze(out, outlen, &state);
//  }

//  /*************************************************
//  * Name:        sha3_256
//  *
//  * Description: SHA3-256 with non-incremental API
//  *
//  * Arguments:   - uint8_t *h: pointer to output (32 bytes)
//  *              - const uint8_t *in: pointer to input
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
//  void sha3_256(uint8_t h[32], const uint8_t *in, size_t inlen)
//  {
//    unsigned int i;
//    uint64_t s[25];

//    keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
//    KeccakF1600_StatePermute(s);
//    for(i=0;i<4;i++)
//      store64(h+8*i,s[i]);
//  }

//  /*************************************************
//  * Name:        sha3_512
//  *
//  * Description: SHA3-512 with non-incremental API
//  *
//  * Arguments:   - uint8_t *h: pointer to output (64 bytes)
//  *              - const uint8_t *in: pointer to input
//  *              - size_t inlen: length of input in bytes
//  **************************************************/
//  void sha3_512(uint8_t h[64], const uint8_t *in, size_t inlen)
//  {
//    unsigned int i;
//    uint64_t s[25];

//    keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
//    KeccakF1600_StatePermute(s);
//    for(i=0;i<8;i++)
//      store64(h+8*i,s[i]);
//  }
