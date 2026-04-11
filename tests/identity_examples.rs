// Example-based tests for the identity module: edge cases and error conditions.
// Requirements: 4.6, 4.7, 5.4, 5.5, 8.7, 8.8, 8.9, 8.10, 9.6, 9.7, 9.10, 10.1, 10.2, 10.3, 11.6, 11.7

use ferret_rns::identity::{
    validate_announce, AnnounceData, Identity, IdentityStore, RatchetStore,
    DERIVED_KEY_LENGTH, RATCHET_EXPIRY,
};
use ferret_rns::FerretError;

// ---------------------------------------------------------------------------
// Constant value assertions (Req 10.1, 10.2, 10.3)
// ---------------------------------------------------------------------------

#[test]
fn derived_key_length_is_64() {
    assert_eq!(DERIVED_KEY_LENGTH, 64);
}

#[test]
fn ratchet_expiry_is_30_days() {
    assert_eq!(RATCHET_EXPIRY, 2_592_000);
}

// ---------------------------------------------------------------------------
// Missing key errors (Req 11.1, 11.2, 11.3, 11.4)
// ---------------------------------------------------------------------------

#[test]
fn encrypt_without_public_key_returns_missing_public_key() {
    let id = Identity::new_empty();
    let err = id.encrypt(b"hello", None).unwrap_err();
    assert!(matches!(err, FerretError::MissingPublicKey));
}

#[test]
fn decrypt_without_private_key_returns_missing_private_key() {
    let full = Identity::new();
    let ct = full.encrypt(b"hello", None).unwrap();
    let pub_only = Identity::from_public_key(&full.get_public_key().unwrap()).unwrap();
    let err = pub_only.decrypt(&ct, None, false).unwrap_err();
    assert!(matches!(err, FerretError::MissingPrivateKey));
}

#[test]
fn sign_without_private_key_returns_missing_private_key() {
    let full = Identity::new();
    let pub_only = Identity::from_public_key(&full.get_public_key().unwrap()).unwrap();
    let err = pub_only.sign(b"msg").unwrap_err();
    assert!(matches!(err, FerretError::MissingPrivateKey));
}

#[test]
fn validate_without_public_key_returns_missing_public_key() {
    let full = Identity::new();
    let sig = full.sign(b"msg").unwrap();
    let empty = Identity::new_empty();
    let err = empty.validate(&sig, b"msg").unwrap_err();
    assert!(matches!(err, FerretError::MissingPublicKey));
}


// ---------------------------------------------------------------------------
// Invalid key lengths (Req 1.8, 1.10)
// ---------------------------------------------------------------------------

#[test]
fn from_private_key_rejects_non_64_bytes() {
    let result = Identity::from_private_key(&[0u8; 32]);
    assert!(matches!(result, Err(FerretError::KeyLength { expected: 64, got: 32 })));

    let result = Identity::from_private_key(&[0u8; 65]);
    assert!(matches!(result, Err(FerretError::KeyLength { expected: 64, got: 65 })));

    let result = Identity::from_private_key(&[]);
    assert!(matches!(result, Err(FerretError::KeyLength { expected: 64, got: 0 })));
}

#[test]
fn from_public_key_rejects_non_64_bytes() {
    let result = Identity::from_public_key(&[0u8; 32]);
    assert!(matches!(result, Err(FerretError::KeyLength { expected: 64, got: 32 })));

    let result = Identity::from_public_key(&[0u8; 128]);
    assert!(matches!(result, Err(FerretError::KeyLength { expected: 64, got: 128 })));
}

// ---------------------------------------------------------------------------
// Short ciphertext rejection (Req 4.6)
// ---------------------------------------------------------------------------

#[test]
fn decrypt_rejects_ciphertext_32_bytes_or_shorter() {
    let id = Identity::new();

    // Exactly 32 bytes — should be rejected
    let err = id.decrypt(&[0u8; 32], None, false).unwrap_err();
    assert!(matches!(err, FerretError::Token(_)));

    // Less than 32 bytes
    let err = id.decrypt(&[0u8; 16], None, false).unwrap_err();
    assert!(matches!(err, FerretError::Token(_)));

    // Empty
    let err = id.decrypt(&[], None, false).unwrap_err();
    assert!(matches!(err, FerretError::Token(_)));
}

// ---------------------------------------------------------------------------
// Ratchet enforcement (Req 4.4)
// ---------------------------------------------------------------------------

#[test]
fn enforce_ratchets_returns_none_when_no_ratchet_matches() {
    let id = Identity::new();
    let plaintext = b"secret message";
    // Encrypt with identity key (no ratchet)
    let ct = id.encrypt(plaintext, None).unwrap();

    // Provide a random ratchet key that won't match, with enforcement on
    let wrong_ratchet = ferret_rns::identity::RatchetStore::generate();
    let ratchets = vec![wrong_ratchet.to_vec()];
    let result = id.decrypt(&ct, Some(&ratchets), true).unwrap();
    assert!(result.is_none());
}

#[test]
fn enforce_ratchets_false_falls_back_to_identity_key() {
    let id = Identity::new();
    let plaintext = b"secret message";
    let ct = id.encrypt(plaintext, None).unwrap();

    let wrong_ratchet = RatchetStore::generate();
    let ratchets = vec![wrong_ratchet.to_vec()];
    let result = id.decrypt(&ct, Some(&ratchets), false).unwrap().unwrap();
    assert_eq!(result, plaintext);
}


// ---------------------------------------------------------------------------
// Expired ratchet handling (Req 8.7, 8.8)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct RatchetData {
    ratchet: Vec<u8>,
    received: f64,
}

#[test]
fn expired_ratchet_returns_none_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let ratchet_dir = dir.path().join("ratchets");
    let store = RatchetStore::new(ratchet_dir.clone());

    let dest_hash = [0xABu8; 16];
    let ratchet_prv = RatchetStore::generate();

    // Write a ratchet file with a timestamp far in the past (expired)
    let expired_data = rmp_serde::to_vec(&RatchetData {
        ratchet: ratchet_prv.to_vec(),
        received: 0.0, // epoch = definitely expired
    })
    .unwrap();

    let hexhash = ferret_rns::util::hex::hexrep_no_delimit(&dest_hash);
    std::fs::write(ratchet_dir.join(&hexhash), &expired_data).unwrap();

    // get_ratchet should return None for expired ratchet
    let result = store.get_ratchet(&dest_hash);
    assert!(result.is_none());
}

// ---------------------------------------------------------------------------
// Corrupted ratchet cleanup (Req 8.9, 8.10)
// ---------------------------------------------------------------------------

#[test]
fn clean_ratchets_removes_corrupt_files() {
    let dir = tempfile::tempdir().unwrap();
    let ratchet_dir = dir.path().join("ratchets");
    std::fs::create_dir_all(&ratchet_dir).unwrap();

    // Write a corrupted file (not valid msgpack)
    std::fs::write(ratchet_dir.join("corrupt_ratchet"), b"not valid msgpack").unwrap();

    // Write an expired ratchet file
    let expired_data = rmp_serde::to_vec(&RatchetData {
        ratchet: vec![0u8; 32],
        received: 0.0,
    })
    .unwrap();
    std::fs::write(ratchet_dir.join("expired_ratchet"), &expired_data).unwrap();

    let store = RatchetStore::new(ratchet_dir.clone());
    store.clean_ratchets().unwrap();

    // Both files should be removed
    let remaining: Vec<_> = std::fs::read_dir(&ratchet_dir)
        .unwrap()
        .collect();
    assert!(remaining.is_empty(), "Expected all corrupt/expired files removed, found {}", remaining.len());
}


// ---------------------------------------------------------------------------
// Helper: build a valid signed announce
// ---------------------------------------------------------------------------

fn build_signed_announce(
    id: &Identity,
    name_hash: &[u8; 10],
    random_hash: &[u8; 10],
    ratchet: Option<&[u8; 32]>,
    app_data: Option<&[u8]>,
) -> (Vec<u8>, AnnounceData) {
    let pub_key = id.get_public_key().unwrap();
    let identity_hash = id.hash().unwrap();

    // dest_hash = truncated_hash(name_hash + identity_hash)
    let mut hash_material = Vec::new();
    hash_material.extend_from_slice(name_hash);
    hash_material.extend_from_slice(identity_hash);
    let full = Identity::full_hash(&hash_material);
    let dest_hash = full[..16].to_vec();

    // signed_data = dest_hash + pub_key + name_hash + random_hash + ratchet + app_data
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&dest_hash);
    signed_data.extend_from_slice(&pub_key);
    signed_data.extend_from_slice(name_hash);
    signed_data.extend_from_slice(random_hash);
    let ratchet_bytes = ratchet.map(|r| r.to_vec()).unwrap_or_default();
    signed_data.extend_from_slice(&ratchet_bytes);
    if let Some(ad) = app_data {
        signed_data.extend_from_slice(ad);
    }

    let signature = id.sign(&signed_data).unwrap();

    let announce = AnnounceData {
        destination_hash: dest_hash.clone(),
        public_key: pub_key.to_vec(),
        name_hash: name_hash.to_vec(),
        random_hash: random_hash.to_vec(),
        ratchet: ratchet_bytes,
        signature: signature.to_vec(),
        app_data: app_data.map(|d| d.to_vec()),
        context_flag: ratchet.is_some(),
    };

    (dest_hash, announce)
}

// ---------------------------------------------------------------------------
// Announce collision detection (Req 9.10)
// ---------------------------------------------------------------------------

#[test]
fn announce_collision_with_different_pub_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::new();
    let ratchet_store = RatchetStore::new(dir.path().join("ratchets"));

    let id1 = Identity::new();
    let name_hash = [0x11u8; 10];
    let random_hash = [0x22u8; 10];

    // First announce succeeds
    let (dest_hash, announce1) = build_signed_announce(&id1, &name_hash, &random_hash, None, None);
    let fake_packet_hash = Identity::full_hash(&announce1.destination_hash);
    let valid = validate_announce(&announce1, &store, &ratchet_store, false, &fake_packet_hash).unwrap();
    assert!(valid, "First announce should succeed");

    // Second announce with a different identity but same dest_hash should be rejected
    // We manually store a different public key for the same dest_hash
    let id2 = Identity::new();
    let pub2 = id2.get_public_key().unwrap();
    store
        .remember(&[0u8; 32], &dest_hash, &pub2, None)
        .unwrap();

    // Now re-validate the first announce — collision detected
    let result = validate_announce(&announce1, &store, &ratchet_store, false, &fake_packet_hash).unwrap();
    assert!(!result, "Announce with colliding dest_hash but different pub key should be rejected");
}

// ---------------------------------------------------------------------------
// Signature-only validation (Req 9.7)
// ---------------------------------------------------------------------------

#[test]
fn signature_only_validation_skips_dest_hash_check() {
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::new();
    let ratchet_store = RatchetStore::new(dir.path().join("ratchets"));

    let id = Identity::new();
    let pub_key = id.get_public_key().unwrap();
    let name_hash = [0x33u8; 10];
    let random_hash = [0x44u8; 10];

    // Use a wrong dest_hash (not derived from name_hash + identity_hash)
    let wrong_dest_hash = vec![0xFFu8; 16];

    // Sign over the wrong dest_hash so the signature is valid for this data
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&wrong_dest_hash);
    signed_data.extend_from_slice(&pub_key);
    signed_data.extend_from_slice(&name_hash);
    signed_data.extend_from_slice(&random_hash);
    let signature = id.sign(&signed_data).unwrap();

    let announce = AnnounceData {
        destination_hash: wrong_dest_hash,
        public_key: pub_key.to_vec(),
        name_hash: name_hash.to_vec(),
        random_hash: random_hash.to_vec(),
        ratchet: Vec::new(),
        signature: signature.to_vec(),
        app_data: None,
        context_flag: false,
    };

    // Signature-only should pass (signature is valid, dest_hash check skipped)
    let fake_packet_hash = Identity::full_hash(&announce.destination_hash);
    let result = validate_announce(&announce, &store, &ratchet_store, true, &fake_packet_hash).unwrap();
    assert!(result, "Signature-only validation should pass even with wrong dest_hash");

    // Full validation should fail (dest_hash doesn't match expected)
    let result = validate_announce(&announce, &store, &ratchet_store, false, &fake_packet_hash).unwrap();
    assert!(!result, "Full validation should fail with wrong dest_hash");
}

// ---------------------------------------------------------------------------
// Invalid signature rejection (Req 9.6)
// ---------------------------------------------------------------------------

#[test]
fn announce_with_invalid_signature_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::new();
    let ratchet_store = RatchetStore::new(dir.path().join("ratchets"));

    let id = Identity::new();
    let name_hash = [0x55u8; 10];
    let random_hash = [0x66u8; 10];

    let (_, mut announce) = build_signed_announce(&id, &name_hash, &random_hash, None, None);

    // Corrupt the signature
    announce.signature = vec![0u8; 64];

    let fake_packet_hash = Identity::full_hash(&announce.destination_hash);
    let result = validate_announce(&announce, &store, &ratchet_store, false, &fake_packet_hash).unwrap();
    assert!(!result, "Announce with invalid signature should be rejected");
}
