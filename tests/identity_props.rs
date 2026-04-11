use proptest::prelude::*;

// Feature: ferret-identity, Property 1: Private Key Round-Trip
// **Validates: Requirements 1.3, 1.4, 1.5, 1.7, 1.9**
proptest! {
    #[test]
    fn private_key_round_trip(_seed in any::<[u8; 32]>()) {
        let id = ferret_rns::identity::Identity::new();
        let prv_bytes = id.get_private_key().unwrap();
        let id2 = ferret_rns::identity::Identity::from_private_key(&prv_bytes).unwrap();
        prop_assert_eq!(id.get_public_key().unwrap(), id2.get_public_key().unwrap());
        prop_assert_eq!(id.hash().unwrap(), id2.hash().unwrap());
    }
}

// Feature: ferret-identity, Property 2: File Persistence Round-Trip
// **Validates: Requirements 2.1, 2.2, 2.5**
proptest! {
    #[test]
    fn file_persistence_round_trip(_seed in any::<[u8; 32]>()) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_identity");
        let id = ferret_rns::identity::Identity::new();
        id.to_file(&path).unwrap();
        let id2 = ferret_rns::identity::Identity::from_file(&path).unwrap();
        prop_assert_eq!(id.get_public_key().unwrap(), id2.get_public_key().unwrap());
        prop_assert_eq!(id.hash().unwrap(), id2.hash().unwrap());
    }
}

// Feature: ferret-identity, Property 3: Encrypt/Decrypt Round-Trip
// **Validates: Requirements 3.1, 3.2, 3.4, 3.5, 3.6, 4.1, 4.5, 4.8**
proptest! {
    #[test]
    fn encrypt_decrypt_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        let id = ferret_rns::identity::Identity::new();
        let encrypted = id.encrypt(&plaintext, None).unwrap();
        let decrypted = id.decrypt(&encrypted, None, false).unwrap().unwrap();
        prop_assert_eq!(&decrypted, &plaintext);
    }
}

// Feature: ferret-identity, Property 4: Ratchet Encrypt/Decrypt Round-Trip
// **Validates: Requirements 3.3, 4.2, 4.3, 4.9**
proptest! {
    #[test]
    fn ratchet_encrypt_decrypt_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 1..512),
    ) {
        use ferret_rns::crypto::x25519::X25519PrivateKey;
        let id = ferret_rns::identity::Identity::new();
        let ratchet_prv = X25519PrivateKey::generate();
        let ratchet_pub = ratchet_prv.public_key().to_bytes();
        let ratchet_prv_bytes = ratchet_prv.to_bytes().to_vec();

        let encrypted = id.encrypt(&plaintext, Some(&ratchet_pub)).unwrap();
        let decrypted = id.decrypt(&encrypted, Some(&[ratchet_prv_bytes]), false).unwrap().unwrap();
        prop_assert_eq!(&decrypted, &plaintext);
    }
}

// Feature: ferret-identity, Property 5: Sign/Verify Round-Trip
// **Validates: Requirements 5.1, 5.2, 5.6**
proptest! {
    #[test]
    fn sign_verify_round_trip(
        message in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let id = ferret_rns::identity::Identity::new();
        let sig = id.sign(&message).unwrap();
        let valid = id.validate(&sig, &message).unwrap();
        prop_assert!(valid);
    }
}

// Feature: ferret-identity, Property 6: Wrong-Key Signature Rejection
// **Validates: Requirements 5.3, 5.7**
proptest! {
    #[test]
    fn wrong_key_signature_rejection(
        message in proptest::collection::vec(any::<u8>(), 1..1024),
    ) {
        let id1 = ferret_rns::identity::Identity::new();
        let id2 = ferret_rns::identity::Identity::new();
        let sig = id1.sign(&message).unwrap();
        let valid = id2.validate(&sig, &message).unwrap();
        prop_assert!(!valid);
    }
}

// Feature: ferret-identity, Property 7: IdentityStore Remember/Recall Round-Trip
// **Validates: Requirements 7.2, 7.4, 7.7, 7.10**
proptest! {
    #[test]
    fn identity_store_remember_recall(
        dest_hash in proptest::collection::vec(any::<u8>(), 16..=16),
        packet_hash in proptest::collection::vec(any::<u8>(), 32..=32),
        app_data in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let store = ferret_rns::identity::IdentityStore::new();
        let id = ferret_rns::identity::Identity::new();
        let pub_key = id.get_public_key().unwrap();

        store.remember(&packet_hash, &dest_hash, &pub_key, Some(&app_data)).unwrap();

        let recalled = store.recall(&dest_hash).unwrap();
        prop_assert_eq!(recalled.get_public_key().unwrap(), pub_key);

        let recalled_app = store.recall_app_data(&dest_hash).unwrap();
        prop_assert_eq!(recalled_app, app_data);
    }
}

// Feature: ferret-identity, Property 8: IdentityStore Save/Load Round-Trip
// **Validates: Requirements 7.8, 7.9**
proptest! {
    #[test]
    fn identity_store_save_load(
        dest_hash in proptest::collection::vec(any::<u8>(), 16..=16),
        packet_hash in proptest::collection::vec(any::<u8>(), 32..=32),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_destinations");

        let store = ferret_rns::identity::IdentityStore::new();
        let id = ferret_rns::identity::Identity::new();
        let pub_key = id.get_public_key().unwrap();
        store.remember(&packet_hash, &dest_hash, &pub_key, None).unwrap();
        store.save(&path).unwrap();

        let store2 = ferret_rns::identity::IdentityStore::new();
        store2.load(&path).unwrap();
        let recalled = store2.recall(&dest_hash).unwrap();
        prop_assert_eq!(recalled.get_public_key().unwrap(), pub_key);
    }
}

// Feature: ferret-identity, Property 9: RatchetStore Remember/Get Round-Trip
// **Validates: Requirements 8.3, 8.4, 8.6, 8.11**
proptest! {
    #[test]
    fn ratchet_store_remember_get(
        dest_hash in proptest::collection::vec(any::<u8>(), 16..=16),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let store = ferret_rns::identity::RatchetStore::new(dir.path().to_path_buf());

        let ratchet_prv = ferret_rns::identity::RatchetStore::generate();
        store.remember_ratchet(&dest_hash, &ratchet_prv).unwrap();

        let retrieved = store.get_ratchet(&dest_hash).unwrap();
        prop_assert_eq!(&retrieved, &ratchet_prv.to_vec());

        // current_ratchet_id should match
        let ratchet_pub = ferret_rns::identity::RatchetStore::ratchet_public_bytes(&ratchet_prv);
        let expected_id = ferret_rns::identity::RatchetStore::get_ratchet_id(&ratchet_pub);
        let actual_id = store.current_ratchet_id(&dest_hash).unwrap();
        prop_assert_eq!(actual_id, expected_id);
    }
}

// Feature: ferret-identity, Property 10: Announce Validation Round-Trip
// **Validates: Requirements 9.2, 9.3, 9.4, 9.5, 9.8, 9.11, 9.12**
proptest! {
    #[test]
    fn announce_validation_round_trip(
        app_data in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        use ferret_rns::identity::{Identity, IdentityStore, RatchetStore, AnnounceData, validate_announce};
        use ferret_rns::crypto::hashes::sha256;
        use ferret_rns::types::constants::TRUNCATED_HASHLENGTH;

        let id = Identity::new();
        let pub_key = id.get_public_key().unwrap();
        let identity_hash = id.hash().unwrap();

        // Compute name_hash and destination_hash
        let name_hash = &sha256(b"testapp.testaspect")[..10]; // 10 bytes
        let mut hash_material = Vec::new();
        hash_material.extend_from_slice(name_hash);
        hash_material.extend_from_slice(identity_hash);
        let dest_hash = &Identity::full_hash(&hash_material)[..TRUNCATED_HASHLENGTH / 8];

        // Build random_hash (10 bytes)
        let random_hash = &sha256(b"random")[..10];

        // Build signed data and sign
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(dest_hash);
        signed_data.extend_from_slice(&pub_key);
        signed_data.extend_from_slice(name_hash);
        signed_data.extend_from_slice(random_hash);
        if !app_data.is_empty() {
            signed_data.extend_from_slice(&app_data);
        }
        let signature = id.sign(&signed_data).unwrap();

        // Build announce data bytes (no ratchet)
        let mut data = Vec::new();
        data.extend_from_slice(&pub_key);
        data.extend_from_slice(name_hash);
        data.extend_from_slice(random_hash);
        data.extend_from_slice(&signature);
        if !app_data.is_empty() {
            data.extend_from_slice(&app_data);
        }

        let announce = AnnounceData::parse(&data, dest_hash, false).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let store = IdentityStore::new();
        let ratchet_store = RatchetStore::new(dir.path().to_path_buf());

        let fake_packet_hash = Identity::full_hash(dest_hash);
        let valid = validate_announce(&announce, &store, &ratchet_store, false, &fake_packet_hash).unwrap();
        prop_assert!(valid);

        // Verify identity is recallable
        let recalled = store.recall(dest_hash).unwrap();
        prop_assert_eq!(recalled.get_public_key().unwrap(), pub_key);
    }
}
