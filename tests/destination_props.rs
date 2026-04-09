use proptest::prelude::*;

// Feature: ferret-packet-transport, Property 1: Destination hash determinism
// **Validates: Requirements 1.6, 1.7, 1.8, 1.9**
proptest! {
    #[test]
    fn destination_hash_determinism(_seed in any::<[u8; 32]>()) {
        let id = ferret_rns::identity::Identity::new();
        let pub_key = id.get_public_key().unwrap();

        // Create two destinations from the same public key
        let id1 = ferret_rns::identity::Identity::from_public_key(&pub_key).unwrap();
        let id2 = ferret_rns::identity::Identity::from_public_key(&pub_key).unwrap();

        let d1 = ferret_rns::destination::Destination::new(
            Some(id1),
            ferret_rns::types::destination::DestinationDirection::Out,
            ferret_rns::types::destination::DestinationType::Single,
            "testapp",
            &["aspect1"],
        )
        .unwrap();

        let d2 = ferret_rns::destination::Destination::new(
            Some(id2),
            ferret_rns::types::destination::DestinationDirection::Out,
            ferret_rns::types::destination::DestinationType::Single,
            "testapp",
            &["aspect1"],
        )
        .unwrap();

        prop_assert_eq!(d1.hash, d2.hash, "same identity must produce same hash");
        prop_assert_eq!(d1.name_hash, d2.name_hash, "same name must produce same name_hash");
        prop_assert_eq!(d1.hexhash, d2.hexhash, "same identity must produce same hexhash");

        // Verify hash matches manual computation
        let name_without_hexhash = "testapp.aspect1";
        let name_hash_full = ferret_rns::crypto::sha256(name_without_hexhash.as_bytes());
        let mut expected_name_hash = [0u8; 10];
        expected_name_hash.copy_from_slice(&name_hash_full[..10]);
        prop_assert_eq!(d1.name_hash, expected_name_hash);

        let id_hash = ferret_rns::identity::Identity::from_public_key(&pub_key)
            .unwrap();
        let mut addr_material = Vec::new();
        addr_material.extend_from_slice(&expected_name_hash);
        addr_material.extend_from_slice(id_hash.hash().unwrap());
        let expected_hash = ferret_rns::identity::Identity::truncated_hash(&addr_material);
        prop_assert_eq!(d1.hash, expected_hash);
    }
}

// Feature: ferret-packet-transport, Property 2: PLAIN and Proof encryption is identity
// **Validates: Requirements 2.1, 2.6, 12.2**
proptest! {
    #[test]
    fn plain_encrypt_is_identity(data in proptest::collection::vec(any::<u8>(), 0..464)) {
        let dest = ferret_rns::destination::Destination::new(
            None,
            ferret_rns::types::destination::DestinationDirection::In,
            ferret_rns::types::destination::DestinationType::Plain,
            "testapp",
            &["plain"],
        )
        .unwrap();

        let encrypted = dest.encrypt_data(&data, None).unwrap();
        prop_assert_eq!(&encrypted, &data, "PLAIN encrypt must return input unchanged");

        let decrypted = dest.decrypt(&data).unwrap().unwrap();
        prop_assert_eq!(&decrypted, &data, "PLAIN decrypt must return input unchanged");

        // Also test ProofDestination
        let proof_dest = ferret_rns::packet::proof::ProofDestination::new([0u8; 16]);
        use ferret_rns::packet::Encryptable;
        let proof_encrypted = proof_dest.encrypt(&data).unwrap();
        prop_assert_eq!(&proof_encrypted, &data, "ProofDestination encrypt must return input unchanged");
    }
}

// Feature: ferret-packet-transport, Property 3: SINGLE Destination encrypt/decrypt round-trip
// **Validates: Requirements 2.2, 2.7, 2.8, 2.11**
proptest! {
    #[test]
    fn single_encrypt_decrypt_round_trip(
        data in proptest::collection::vec(any::<u8>(), 0..383),
    ) {
        // Create a SINGLE IN destination with a full-keypair identity
        let id = ferret_rns::identity::Identity::new();
        let prv_key = id.get_private_key().unwrap();

        // Build an OUT destination from the public key (for encryption)
        let pub_key = id.get_public_key().unwrap();
        let id_out = ferret_rns::identity::Identity::from_public_key(&pub_key).unwrap();
        let dest_out = ferret_rns::destination::Destination::new(
            Some(id_out),
            ferret_rns::types::destination::DestinationDirection::Out,
            ferret_rns::types::destination::DestinationType::Single,
            "testapp",
            &["single"],
        )
        .unwrap();

        // Build an IN destination from the private key (for decryption)
        let id_in = ferret_rns::identity::Identity::from_private_key(&prv_key).unwrap();
        let dest_in = ferret_rns::destination::Destination::new(
            Some(id_in),
            ferret_rns::types::destination::DestinationDirection::In,
            ferret_rns::types::destination::DestinationType::Single,
            "testapp",
            &["single"],
        )
        .unwrap();

        let ciphertext = dest_out.encrypt_data(&data, None).unwrap();
        let plaintext = dest_in.decrypt(&ciphertext).unwrap().unwrap();
        prop_assert_eq!(&plaintext, &data, "SINGLE encrypt then decrypt must return original");
    }
}

// Feature: ferret-packet-transport, Property 4: GROUP Destination encrypt/decrypt round-trip
// **Validates: Requirements 2.4, 2.9, 2.12**
proptest! {
    #[test]
    fn group_encrypt_decrypt_round_trip(
        data in proptest::collection::vec(any::<u8>(), 0..383),
    ) {
        // Create a GROUP IN destination (auto-generates identity)
        let mut dest = ferret_rns::destination::Destination::new(
            None,
            ferret_rns::types::destination::DestinationDirection::In,
            ferret_rns::types::destination::DestinationType::Group,
            "testapp",
            &["group"],
        )
        .unwrap();

        dest.create_keys().unwrap();
        let key = dest.get_private_key().unwrap().to_vec();

        let ciphertext = dest.encrypt_data(&data, None).unwrap();
        let plaintext = dest.decrypt(&ciphertext).unwrap().unwrap();
        prop_assert_eq!(&plaintext, &data, "GROUP encrypt then decrypt must return original");

        // Also verify loading the same key into another GROUP destination works
        let mut dest2 = ferret_rns::destination::Destination::new(
            None,
            ferret_rns::types::destination::DestinationDirection::In,
            ferret_rns::types::destination::DestinationType::Group,
            "testapp",
            &["group2"],
        )
        .unwrap();
        dest2.load_private_key(&key).unwrap();
        let plaintext2 = dest2.decrypt(&ciphertext).unwrap().unwrap();
        prop_assert_eq!(&plaintext2, &data, "GROUP decrypt with loaded key must return original");
    }
}
