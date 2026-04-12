//! rnid — Reticulum Identity & Encryption Utility.
//!
//! Manages Reticulum identities and performs cryptographic operations:
//! generate keys, encrypt/decrypt files, sign/verify data.

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;
use ferret_rns::identity::Identity;

const ENCRYPT_EXT: &str = "rfe";
const SIG_EXT: &str = "rsg";

/// Reticulum Identity & Encryption Utility
#[derive(Parser)]
#[command(name = "rnid", version, about = "Reticulum Identity & Encryption Utility")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (repeatable)
    #[arg(short = 'q', action = clap::ArgAction::Count)]
    quiet: u8,

    /// Hexadecimal identity hash or path to Identity file
    #[arg(short = 'i', long = "identity")]
    identity: Option<String>,

    /// Generate a new Identity and write to file
    #[arg(short = 'g', long = "generate")]
    generate: Option<PathBuf>,

    /// Write output even if it overwrites existing files
    #[arg(short = 'f', long = "force")]
    force: bool,

    /// Print identity info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// Allow displaying private keys
    #[arg(short = 'P', long = "print-private")]
    print_private: bool,

    /// Export identity private key
    #[arg(short = 'x', long = "export")]
    export: bool,

    /// Use base64-encoded input and output
    #[arg(short = 'b', long = "base64")]
    base64: bool,

    /// Use base32-encoded input and output
    #[arg(short = 'B', long = "base32")]
    base32: bool,

    /// Import identity from hex, base32 or base64 data
    #[arg(short = 'm', long = "import")]
    import_str: Option<String>,

    /// Write imported identity to file
    #[arg(short = 'w')]
    write: Option<PathBuf>,

    /// Encrypt file for the specified identity
    #[arg(short = 'e', long = "encrypt")]
    encrypt: Option<PathBuf>,

    /// Decrypt file using the specified identity
    #[arg(short = 'd', long = "decrypt")]
    decrypt: Option<PathBuf>,

    /// Sign file
    #[arg(short = 's', long = "sign")]
    sign: Option<PathBuf>,

    /// Validate signature file
    #[arg(long = "validate")]
    validate: Option<PathBuf>,

    /// Show destination hash for given aspects
    #[arg(short = 'H', long = "hash")]
    hash_aspects: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // Handle import
    if let Some(ref import_data) = cli.import_str {
        handle_import(&cli, import_data);
        return;
    }

    // Handle generate
    if let Some(ref gen_path) = cli.generate {
        handle_generate(&cli, gen_path);
        return;
    }

    // All other operations require an identity
    let identity_str = match &cli.identity {
        Some(s) => s.clone(),
        None => {
            eprintln!("No identity provided, cannot continue");
            process::exit(2);
        }
    };

    let identity = load_identity(&identity_str);

    if cli.print_identity {
        handle_print_identity(&cli, &identity);
    } else if cli.export {
        handle_export(&cli, &identity);
    } else if let Some(ref hash_aspects) = cli.hash_aspects {
        handle_hash(&identity, hash_aspects);
    } else if let Some(ref file) = cli.encrypt {
        handle_encrypt(&cli, &identity, file);
    } else if let Some(ref file) = cli.decrypt {
        handle_decrypt(&cli, &identity, file);
    } else if let Some(ref file) = cli.sign {
        handle_sign(&cli, &identity, file);
    } else if let Some(ref sig_file) = cli.validate {
        handle_validate(&cli, &identity, sig_file);
    } else {
        handle_print_identity(&cli, &identity);
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn handle_generate(cli: &Cli, path: &Path) {
    if !cli.force && path.exists() {
        eprintln!("Identity file {} already exists. Not overwriting.", path.display());
        process::exit(3);
    }

    let identity = Identity::new();
    if let Err(e) = identity.to_file(path) {
        eprintln!("Error saving generated Identity: {}", e);
        process::exit(4);
    }

    let hash = identity.hash().map(|h| hex_encode(h)).unwrap_or_default();
    println!("New identity <{}> written to {}", hash, path.display());
}

fn handle_import(cli: &Cli, data: &str) {
    let bytes = if cli.base64 {
        base64_decode(data).unwrap_or_else(|| {
            eprintln!("Invalid base64 identity data");
            process::exit(41);
        })
    } else if cli.base32 {
        base32_decode(data).unwrap_or_else(|| {
            eprintln!("Invalid base32 identity data");
            process::exit(41);
        })
    } else {
        hex_decode(data).unwrap_or_else(|| {
            eprintln!("Invalid hex identity data");
            process::exit(41);
        })
    };

    let identity = Identity::from_private_key(&bytes).unwrap_or_else(|e| {
        eprintln!("Could not create Identity from data: {}", e);
        process::exit(42);
    });

    println!("Identity imported");
    print_public_key(cli, &identity);

    if let Some(ref wp) = cli.write {
        if !cli.force && wp.exists() {
            eprintln!("File {} already exists, not overwriting", wp.display());
            process::exit(43);
        }
        if let Err(e) = identity.to_file(wp) {
            eprintln!("Error writing imported identity: {}", e);
            process::exit(44);
        }
        println!("Wrote imported identity to {}", wp.display());
    }
}

fn handle_print_identity(cli: &Cli, identity: &Identity) {
    print_public_key(cli, identity);
    if identity.get_private_key().is_ok() {
        if cli.print_private {
            let prv = identity.get_private_key().unwrap();
            let encoded = encode_bytes(cli, &prv);
            println!("Private Key : {}", encoded);
        } else {
            println!("Private Key : Hidden");
        }
    }
}

fn handle_export(cli: &Cli, identity: &Identity) {
    match identity.get_private_key() {
        Ok(prv) => {
            let encoded = encode_bytes(cli, &prv);
            println!("Exported Identity : {}", encoded);
        }
        Err(_) => {
            eprintln!("Identity doesn't hold a private key, cannot export");
            process::exit(50);
        }
    }
}

fn handle_hash(identity: &Identity, aspects: &str) {
    let parts: Vec<&str> = aspects.split('.').collect();
    if parts.is_empty() {
        eprintln!("Invalid destination aspects specified");
        process::exit(32);
    }

    match identity.get_public_key() {
        Ok(pub_key) => {
            // Compute destination hash: truncated_hash(name_hash + identity_hash)
            let name_hash = Identity::full_hash(aspects.as_bytes());
            let id_hash = identity.hash().unwrap();
            let mut combined = Vec::with_capacity(32 + 16);
            combined.extend_from_slice(&name_hash[..10]); // NAME_HASH_LENGTH/8 = 10
            combined.extend_from_slice(id_hash);
            let dest_hash = Identity::truncated_hash(&combined);
            println!("The {} destination hash is <{}>", aspects, hex_encode(&dest_hash));
            let _ = pub_key; // used for validation
        }
        Err(_) => {
            eprintln!("No public key known");
            process::exit(32);
        }
    }
}

fn handle_encrypt(cli: &Cli, identity: &Identity, file: &Path) {
    let data = read_file_or_exit(file);
    let output_path = cli.write.clone().unwrap_or_else(|| {
        PathBuf::from(format!("{}.{}", file.display(), ENCRYPT_EXT))
    });

    if !cli.force && output_path.exists() {
        eprintln!("Output file {} already exists. Not overwriting.", output_path.display());
        process::exit(15);
    }

    match identity.encrypt(&data, None) {
        Ok(ciphertext) => {
            if let Err(e) = fs::write(&output_path, &ciphertext) {
                eprintln!("Error writing encrypted file: {}", e);
                process::exit(15);
            }
            println!("File {} encrypted to {}", file.display(), output_path.display());
        }
        Err(e) => {
            eprintln!("Encryption failed: {}", e);
            process::exit(16);
        }
    }
}

fn handle_decrypt(cli: &Cli, identity: &Identity, file: &Path) {
    if identity.get_private_key().is_err() {
        eprintln!("Specified Identity does not hold a private key. Cannot decrypt.");
        process::exit(16);
    }

    let data = read_file_or_exit(file);
    let output_path = cli.write.clone().unwrap_or_else(|| {
        let s = file.to_string_lossy();
        if s.ends_with(&format!(".{}", ENCRYPT_EXT)) {
            PathBuf::from(s.trim_end_matches(&format!(".{}", ENCRYPT_EXT)))
        } else {
            PathBuf::from(format!("{}.decrypted", s))
        }
    });

    if !cli.force && output_path.exists() {
        eprintln!("Output file {} already exists. Not overwriting.", output_path.display());
        process::exit(15);
    }

    match identity.decrypt(&data, None, false) {
        Ok(Some(plaintext)) => {
            if let Err(e) = fs::write(&output_path, &plaintext) {
                eprintln!("Error writing decrypted file: {}", e);
                process::exit(15);
            }
            println!("File {} decrypted to {}", file.display(), output_path.display());
        }
        Ok(None) => {
            eprintln!("Decryption failed: no valid key found");
            process::exit(17);
        }
        Err(e) => {
            eprintln!("Decryption failed: {}", e);
            process::exit(17);
        }
    }
}

fn handle_sign(cli: &Cli, identity: &Identity, file: &Path) {
    if identity.get_private_key().is_err() {
        eprintln!("Specified Identity does not hold a private key. Cannot sign.");
        process::exit(14);
    }

    let data = read_file_or_exit(file);
    let output_path = cli.write.clone().unwrap_or_else(|| {
        PathBuf::from(format!("{}.{}", file.display(), SIG_EXT))
    });

    if !cli.force && output_path.exists() {
        eprintln!("Output file {} already exists. Not overwriting.", output_path.display());
        process::exit(15);
    }

    match identity.sign(&data) {
        Ok(signature) => {
            if let Err(e) = fs::write(&output_path, signature) {
                eprintln!("Error writing signature: {}", e);
                process::exit(15);
            }
            println!("File {} signed to {}", file.display(), output_path.display());
        }
        Err(e) => {
            eprintln!("Signing failed: {}", e);
            process::exit(16);
        }
    }
}

fn handle_validate(_cli: &Cli, identity: &Identity, sig_file: &Path) {
    let sig_data = read_file_or_exit(sig_file);
    if sig_data.len() != 64 {
        eprintln!("Invalid signature file (expected 64 bytes, got {})", sig_data.len());
        process::exit(10);
    }

    // Determine the data file: strip .rsg extension
    let data_file = {
        let s = sig_file.to_string_lossy();
        if s.ends_with(&format!(".{}", SIG_EXT)) {
            PathBuf::from(s.trim_end_matches(&format!(".{}", SIG_EXT)))
        } else {
            eprintln!("Cannot determine data file from signature path. Use -r to specify.");
            process::exit(11);
        }
    };

    let data = read_file_or_exit(&data_file);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_data);

    match identity.validate(&sig, &data) {
        Ok(true) => {
            println!("Signature is valid");
            process::exit(0);
        }
        _ => {
            println!("Signature is NOT valid");
            process::exit(22);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn load_identity(identity_str: &str) -> Identity {
    let path = Path::new(identity_str);
    if path.exists() {
        Identity::from_file(path).unwrap_or_else(|e| {
            eprintln!("Could not load Identity from {}: {}", identity_str, e);
            process::exit(9);
        })
    } else {
        // Try as hex hash — load from known identities
        let bytes = hex_decode(identity_str).unwrap_or_else(|| {
            eprintln!("Identity file not found and not a valid hex hash: {}", identity_str);
            process::exit(8);
        });
        // Try loading from public key bytes
        Identity::from_public_key(&bytes).or_else(|_| Identity::from_private_key(&bytes)).unwrap_or_else(|e| {
            eprintln!("Could not create Identity from hash {}: {}", identity_str, e);
            process::exit(7);
        })
    }
}

fn read_file_or_exit(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("Could not read file {}: {}", path.display(), e);
        process::exit(12);
    })
}

fn print_public_key(cli: &Cli, identity: &Identity) {
    if let Ok(pub_key) = identity.get_public_key() {
        let encoded = encode_bytes(cli, &pub_key);
        println!("Public Key  : {}", encoded);
    }
}

fn encode_bytes(cli: &Cli, data: &[u8]) -> String {
    if cli.base64 {
        base64_encode(data)
    } else if cli.base32 {
        base32_encode(data)
    } else {
        hex_encode(data)
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// Minimal base64 encode/decode (URL-safe, no padding)
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { out.push(CHARS[((n >> 6) & 63) as usize] as char); }
        if chunk.len() > 2 { out.push(CHARS[(n & 63) as usize] as char); }
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let bytes: Vec<u8> = s.bytes().collect();
    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk.iter().map(|&b| {
            CHARS.iter().position(|&c| c == b).unwrap_or(0) as u8
        }).collect();
        let n = (vals[0] as u32) << 18
            | vals.get(1).map(|&v| (v as u32) << 12).unwrap_or(0)
            | vals.get(2).map(|&v| (v as u32) << 6).unwrap_or(0)
            | vals.get(3).map(|&v| v as u32).unwrap_or(0);
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Some(out)
}

fn base32_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut bits = 0u64;
    let mut nbits = 0;
    for &b in data {
        bits = (bits << 8) | b as u64;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(CHARS[((bits >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(CHARS[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let s = s.trim_end_matches('=').to_uppercase();
    let mut out = Vec::new();
    let mut bits = 0u64;
    let mut nbits = 0;
    for b in s.bytes() {
        let val = CHARS.iter().position(|&c| c == b)? as u64;
        bits = (bits << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(out)
}
