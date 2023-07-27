use std::fs;
use std::io;
use std::sync;
use std::ptr;

use rand_core::RngCore;

use crystals_dilithium_sys::dilithium2::{randombytes_init, randombytes};

static RANDOM_BYTES_MUTEX: sync::OnceLock<sync::Mutex<()>> = sync::OnceLock::new();

struct KATRng {
}

impl KATRng {
    fn new(entropy_input: &mut [u8; 48]) -> Self {
        let guard = RANDOM_BYTES_MUTEX.get_or_init(|| sync::Mutex::new(())).lock().expect("randombytes mutex lock");
        unsafe {
            randombytes_init(entropy_input.as_mut_ptr(), ptr::null_mut(), 256);
        }
        drop(guard);
        KATRng {        }
    }
}

impl rand_core::RngCore for KATRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let guard = RANDOM_BYTES_MUTEX.get_or_init(|| sync::Mutex::new(())).lock().expect("randombytes mutex lock");
        unsafe {
            randombytes(dest.as_mut_ptr(), dest.len() as u64);
        }
        drop(guard);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for KATRng {}

struct SignatureScheme {
    keygen: fn(sk: &mut [u8], pk: &mut [u8], seed: &[u8]) -> Result<(), li2::Error>,
    signature: fn(sk: &[u8], m: &[u8], sig: &mut [u8]) -> Result<(), li2::Error>,
    signature_randomized: fn(sk: &[u8], m: &[u8], sig: &mut [u8], rng: &mut KATRng) -> Result<(), li2::Error>,
    verify: fn(pk: &[u8], m: &[u8], sig: &[u8]) -> Result<(), li2::Error>,
}

const DILITHIUM2_SCHEME: SignatureScheme = SignatureScheme {
    keygen: li2::dilithium2_keygen_from_seed,
    signature: li2::dilithium2_signature,
    signature_randomized: li2::dilithium2_signature_randomized,
    verify: li2::dilithium2_verify,
};
const DILITHIUM3_SCHEME: SignatureScheme = SignatureScheme {
    keygen: li2::dilithium3_keygen_from_seed,
    signature: li2::dilithium3_signature,
    signature_randomized: li2::dilithium3_signature_randomized,
    verify: li2::dilithium3_verify,
};
const DILITHIUM5_SCHEME: SignatureScheme = SignatureScheme {
    keygen: li2::dilithium5_keygen_from_seed,
    signature: li2::dilithium5_signature,
    signature_randomized: li2::dilithium5_signature_randomized,
    verify: li2::dilithium5_verify,
};

fn main() {
    let kat_param_sets = [
        ("Dilithium2", &li2::DILITHIUM2, &DILITHIUM2_SCHEME, false),
        ("Dilithium3", &li2::DILITHIUM3, &DILITHIUM3_SCHEME, false),
        ("Dilithium5", &li2::DILITHIUM5, &DILITHIUM5_SCHEME, false),
        ("Dilithium2", &li2::DILITHIUM2, &DILITHIUM2_SCHEME, true),
        ("Dilithium3", &li2::DILITHIUM3, &DILITHIUM3_SCHEME, true),
        ("Dilithium5", &li2::DILITHIUM5, &DILITHIUM5_SCHEME, true),
    ];
    for (name, p, scheme, randomized) in kat_param_sets {
        let randomized_suffix = if randomized { "_randomized" } else { "" };
        let filename = format!("PQCsignKAT_{}{}.rsp", name, randomized_suffix);
        let mut w = io::BufWriter::new(fs::File::create(filename).unwrap());
        kat_dilithium(&mut w, name, p, scheme, randomized);
    }
}

fn kat_dilithium(
    w: &mut dyn io::Write,
    name: &str,
    p: &li2::DilithiumParams,
    scheme: &SignatureScheme,
    randomized: bool,
) {
    write!(w, "# {}\n\n", name).unwrap();

    let mut seeds = [[0; 48]; 100];
    let mut msgs = [[0; 3300]; 100];

    let mut entropy_input = [0; 48];
    for (idx, b) in entropy_input.iter_mut().enumerate() {
        *b = idx as u8;
    }

    // Simulate generating the request KAT file
    let mut rng = KATRng::new(&mut entropy_input);
    for (idx, seed) in seeds.iter_mut().enumerate() {
        let mlen = 33 * (idx + 1);
        rng.fill_bytes(&mut seed[..]);
        rng.fill_bytes(&mut msgs[idx][0..mlen]);
    }
    drop(rng);

    // Generate the response KAT file
    for (idx, seed) in seeds.iter_mut().enumerate() {
        let mlen = 33 * (idx + 1);
        let msg = &msgs[idx][0..mlen];
        let mut sk = vec![0; p.secret_key_len as usize];
        let mut pk = vec![0; p.public_key_len as usize];
        let mut sig = vec![0; p.signature_len as usize];

        // Generate the actual values
        let mut keygen_seed = [0; li2::SEEDBYTES as usize];
        let mut rng = KATRng::new(seed);
        rng.fill_bytes(&mut keygen_seed);
        (scheme.keygen)(&mut sk, &mut pk, &keygen_seed).unwrap();
        if !randomized {
            (scheme.signature)(&sk, msg, &mut sig).unwrap();
        }
        else {
            (scheme.signature_randomized)(&sk, msg, &mut sig, &mut rng).unwrap();
        }
        let verify_actual = (scheme.verify)(&pk, msg, &sig);
        assert!(verify_actual.is_ok());

        // Write out the response
        writeln!(w, "count = {}", idx).unwrap();
        write!(w, "seed = ").unwrap();
        write_hex(w, seed).unwrap();
        write!(w, "\n").unwrap();
        writeln!(w, "mlen = {}", msg.len()).unwrap();
        write!(w, "msg = ").unwrap();
        write_hex(w, msg).unwrap();
        write!(w, "\n").unwrap();
        write!(w, "pk = ").unwrap();
        write_hex(w, &pk).unwrap();
        write!(w, "\n").unwrap();
        write!(w, "sk = ").unwrap();
        write_hex(w, &sk).unwrap();
        write!(w, "\n").unwrap();
        writeln!(w, "smlen = {}", mlen + p.signature_len).unwrap();
        write!(w, "sm = ").unwrap();
        write_hex(w, &sig).unwrap();
        write_hex(w, msg).unwrap();
        write!(w, "\n\n").unwrap();
    }
}

/// Write a byte buffer to the Write, in hex encoding
fn write_hex(w: &mut dyn io::Write, buf: &[u8]) -> io::Result<()> {
    for b in buf {
        write!(w, "{:02X}", b)?;
    }
    Ok(())
}
