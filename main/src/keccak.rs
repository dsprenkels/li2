#![allow(non_snake_case)]

const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;
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

//  /* Keccak round constants */
const KECCAK_F_ROUND_CONSTANTS: [u64; NROUNDS] = [
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
        Eba ^= KECCAK_F_ROUND_CONSTANTS[round];
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
        Aba ^= KECCAK_F_ROUND_CONSTANTS[round + 1];
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

fn keccak_init(s: &mut [u64; 25]) {
    s.fill(0);
}

fn keccak_absorb(s: &mut [u64; 25], mut pos: usize, rate: usize, mut input: &[u8]) -> usize {
    while pos + input.len() >= rate {
        for i in pos..rate {
            s[i / 8] ^= u64::from(input[0]) << (8 * (i % 8));
            input = &input[1..];
            pos += 1;
        }
        KeccakF1600_StatePermute(s);
        pos = 0;
    }

    for i in pos..pos + input.len() {
        s[i / 8] ^= u64::from(input[0]) << (8 * (i % 8));
        input = &input[1..];
        pos += 1;
    }

    debug_assert!(input.is_empty());
    pos
}

fn keccak_finalize(s: &mut [u64; 25], pos: usize, rate: usize, ds: u8) {
    s[pos / 8] ^= u64::from(ds) << (8 * (pos % 8));
    s[rate / 8 - 1] ^= 1 << 63;
}

fn keccak_squeeze(mut out: &mut [u8], s: &mut [u64; 25], mut pos: usize, rate: usize) -> usize {
    while !out.is_empty() {
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
    debug_assert!(out.is_empty());
    pos
}
