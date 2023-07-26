use std::fs;
use std::io;
use std::ptr;

struct SignatureScheme {
    keygen: fn(sk: &mut [u8], pk: &mut [u8], seed: &[u8]) -> Result<(), li2::Error>,
    signature: fn(sk: &[u8], m: &[u8], sig: &mut [u8]) -> Result<(), li2::Error>,
    verify: fn(pk: &[u8], m: &[u8], sig: &[u8]) -> Result<(), li2::Error>,
}

const DILITHIUM2_SCHEME: SignatureScheme = SignatureScheme {
    keygen: li2::dilithium2_keygen_from_seed,
    signature: li2::dilithium2_signature,
    verify: li2::dilithium2_verify,
};
const DILITHIUM3_SCHEME: SignatureScheme = SignatureScheme {
    keygen: li2::dilithium3_keygen_from_seed,
    signature: li2::dilithium3_signature,
    verify: li2::dilithium3_verify,
};
const DILITHIUM5_SCHEME: SignatureScheme = SignatureScheme {
    keygen: li2::dilithium5_keygen_from_seed,
    signature: li2::dilithium5_signature,
    verify: li2::dilithium5_verify,
};

// Unfortunately the deterministic KAT rng state is global.
fn main() {
    let mut w = io::BufWriter::new(fs::File::create("PQCsignKAT_Dilithium2.rsp").unwrap());
    kat_dilithium(&mut w, "Dilithium2", &li2::DILITHIUM2, &DILITHIUM2_SCHEME);
    drop(w);
    let mut w = io::BufWriter::new(fs::File::create("PQCsignKAT_Dilithium3.rsp").unwrap());
    kat_dilithium(&mut w, "Dilithium3", &li2::DILITHIUM3, &DILITHIUM3_SCHEME);
    drop(w);
    let mut w = io::BufWriter::new(fs::File::create("PQCsignKAT_Dilithium5.rsp").unwrap());
    kat_dilithium(&mut w, "Dilithium5", &li2::DILITHIUM5, &DILITHIUM5_SCHEME);
    drop(w);
}

fn kat_dilithium(
    w: &mut dyn io::Write,
    name: &str,
    p: &li2::DilithiumParams,
    scheme: &SignatureScheme,
) {
    use crystals_dilithium_sys::dilithium2::*;

    write!(w, "# {}\n\n", name).unwrap();

    let mut seeds = [[0; 48]; 100];
    let mut msgs = [[0; 3300]; 100];

    let mut entropy_input = [0; 48];
    for (idx, b) in entropy_input.iter_mut().enumerate() {
        *b = idx as u8;
    }

    // Simulate generating the request KAT file
    unsafe {
        randombytes_init(entropy_input.as_mut_ptr(), ptr::null_mut(), 256);
    }
    for (idx, seed) in seeds.iter_mut().enumerate() {
        let mlen = 33 * (idx + 1);
        unsafe {
            randombytes(seed.as_mut_ptr(), seed.len() as u64);
            randombytes(msgs[idx].as_mut_ptr(), mlen as u64);
        }
    }

    // Generate the response KAT file
    for (idx, seed) in seeds.iter_mut().enumerate() {
        let mlen = 33 * (idx + 1);
        let msg = &msgs[idx][0..mlen];
        let mut sk = vec![0; p.secret_key_len as usize];
        let mut pk = vec![0; p.public_key_len as usize];
        let mut sig = vec![0; p.signature_len as usize];

        let mut keygen_seed = [0; li2::SEEDBYTES as usize];
        unsafe {
            // Generate the actual values
            randombytes_init(seed.as_mut_ptr(), ptr::null_mut(), 256);
            randombytes(keygen_seed.as_mut_ptr(), li2::SEEDBYTES as u64);
            (scheme.keygen)(&mut sk, &mut pk, &keygen_seed).unwrap();
            (scheme.signature)(&sk, msg, &mut sig).unwrap();
            let verify_actual = (scheme.verify)(&pk, msg, &sig);
            assert!(verify_actual.is_ok());
        }

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
