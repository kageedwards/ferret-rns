use proptest::prelude::*;

// Feature: ferret-crypto-foundation, Property 6: SHA Hash Output Size Invariant
// **Validates: Requirements 4.1, 4.2**
proptest! {
    #[test]
    fn sha256_produces_32_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let hash = ferret_rns::crypto::hashes::sha256(&data);
        prop_assert_eq!(hash.len(), 32);
    }

    #[test]
    fn sha512_produces_64_bytes(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let hash = ferret_rns::crypto::hashes::sha512(&data);
        prop_assert_eq!(hash.len(), 64);
    }
}

// Feature: ferret-crypto-foundation, Property 7: HMAC-SHA256 Output Invariant
// **Validates: Requirements 5.1, 5.4**
proptest! {
    #[test]
    fn hmac_sha256_produces_32_bytes(
        key in proptest::collection::vec(any::<u8>(), 0..256),
        data in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let tag = ferret_rns::crypto::hmac::hmac_sha256(&key, &data);
        prop_assert_eq!(tag.len(), 32);
    }
}

// Feature: ferret-crypto-foundation, Property 11: PKCS7 Padding Round-Trip
// **Validates: Requirements 8.1, 8.3, 8.5, 8.6**
proptest! {
    #[test]
    fn pkcs7_pad_unpad_round_trip(
        data in proptest::collection::vec(any::<u8>(), 0..512),
        block_size in 1u8..=255u8,
    ) {
        let bs = block_size as usize;
        let padded = ferret_rns::crypto::pkcs7::pad(&data, bs);
        let unpadded = ferret_rns::crypto::pkcs7::unpad(&padded, bs).unwrap();
        prop_assert_eq!(&unpadded, &data);

        // Padded length is always a multiple of block_size
        prop_assert_eq!(padded.len() % bs, 0);

        // When input is already aligned, padded length == input.len() + block_size
        if !data.is_empty() && data.len() % bs == 0 {
            prop_assert_eq!(padded.len(), data.len() + bs);
        }
    }
}

// Feature: ferret-crypto-foundation, Property 1: X25519 DH Commutativity
// **Validates: Requirements 2.5**
proptest! {
    #[test]
    fn x25519_dh_commutativity(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
    ) {
        let key_a = ferret_rns::crypto::x25519::X25519PrivateKey::from_bytes(&seed_a);
        let key_b = ferret_rns::crypto::x25519::X25519PrivateKey::from_bytes(&seed_b);

        let pub_a = key_a.public_key();
        let pub_b = key_b.public_key();

        let shared_ab = key_a.exchange(&pub_b);
        let shared_ba = key_b.exchange(&pub_a);

        prop_assert_eq!(shared_ab.len(), 32);
        prop_assert_eq!(shared_ba.len(), 32);
        prop_assert_eq!(shared_ab, shared_ba);
    }
}

// Feature: ferret-crypto-foundation, Property 2: X25519 Public Key Derivation Round-Trip
// **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
proptest! {
    #[test]
    fn x25519_public_key_derivation_round_trip(seed in any::<[u8; 32]>()) {
        let priv_key = ferret_rns::crypto::x25519::X25519PrivateKey::from_bytes(&seed);
        let pub_key = priv_key.public_key();
        let pub_bytes = pub_key.to_bytes();

        // Derivation is deterministic: same seed → same public key bytes
        let priv_key2 = ferret_rns::crypto::x25519::X25519PrivateKey::from_bytes(&seed);
        let pub_bytes2 = priv_key2.public_key().to_bytes();
        prop_assert_eq!(pub_bytes, pub_bytes2);

        // Public key from_bytes → to_bytes is identity
        let reconstructed = ferret_rns::crypto::x25519::X25519PublicKey::from_bytes(&pub_bytes);
        prop_assert_eq!(reconstructed.to_bytes(), pub_bytes);
    }
}

// Feature: ferret-crypto-foundation, Property 3: Ed25519 Sign-then-Verify
// **Validates: Requirements 3.1, 3.2, 3.3, 3.5, 3.6**
proptest! {
    #[test]
    fn ed25519_sign_then_verify(
        seed in any::<[u8; 32]>(),
        message in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let signing_key = ferret_rns::crypto::ed25519::Ed25519SigningKey::from_seed(&seed);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(&message);
        prop_assert!(verifying_key.verify(&message, &signature).is_ok());
    }
}

// Feature: ferret-crypto-foundation, Property 4: Ed25519 Seed Round-Trip
// **Validates: Requirements 3.3, 3.4**
proptest! {
    #[test]
    fn ed25519_seed_round_trip(seed in any::<[u8; 32]>()) {
        let signing_key = ferret_rns::crypto::ed25519::Ed25519SigningKey::from_seed(&seed);

        // from_seed → to_seed returns original
        prop_assert_eq!(signing_key.to_seed(), seed);

        // verifying_key → to_bytes → from_bytes → to_bytes is identity
        let vk = signing_key.verifying_key();
        let vk_bytes = vk.to_bytes();
        let vk2 = ferret_rns::crypto::ed25519::Ed25519VerifyingKey::from_bytes(&vk_bytes).unwrap();
        prop_assert_eq!(vk2.to_bytes(), vk_bytes);
    }
}

// Feature: ferret-crypto-foundation, Property 5: Ed25519 Wrong-Key Rejection
// **Validates: Requirements 3.7**
proptest! {
    #[test]
    fn ed25519_wrong_key_rejection(
        seed_a in any::<[u8; 32]>(),
        seed_b in any::<[u8; 32]>(),
        message in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        prop_assume!(seed_a != seed_b);
        let signing_key_a = ferret_rns::crypto::ed25519::Ed25519SigningKey::from_seed(&seed_a);
        let signing_key_b = ferret_rns::crypto::ed25519::Ed25519SigningKey::from_seed(&seed_b);
        let vk_b = signing_key_b.verifying_key();
        let signature = signing_key_a.sign(&message);
        prop_assert!(vk_b.verify(&message, &signature).is_err());
    }
}

// Feature: ferret-crypto-foundation, Property 8: HKDF Output Length
// **Validates: Requirements 6.1, 6.7**
proptest! {
    #[test]
    fn hkdf_output_length(
        length in 1usize..=256,
        derive_from in proptest::collection::vec(any::<u8>(), 1..128),
        salt in proptest::collection::vec(any::<u8>(), 0..64),
        context in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let salt_opt = if salt.is_empty() { None } else { Some(salt.as_slice()) };
        let ctx_opt = if context.is_empty() { None } else { Some(context.as_slice()) };
        let result = ferret_rns::crypto::hkdf::hkdf(length, &derive_from, salt_opt, ctx_opt).unwrap();
        prop_assert_eq!(result.len(), length);
    }
}

// Feature: ferret-crypto-foundation, Property 9: HKDF Default Parameter Equivalence
// **Validates: Requirements 6.2, 6.3**
proptest! {
    #[test]
    fn hkdf_default_parameter_equivalence(
        derive_from in proptest::collection::vec(any::<u8>(), 1..128),
        length in 1usize..=256,
    ) {
        // salt=None should equal salt=&[0u8; 32]
        let out_none_salt = ferret_rns::crypto::hkdf::hkdf(length, &derive_from, None, Some(b"ctx")).unwrap();
        let out_zero_salt = ferret_rns::crypto::hkdf::hkdf(length, &derive_from, Some(&[0u8; 32]), Some(b"ctx")).unwrap();
        prop_assert_eq!(&out_none_salt, &out_zero_salt);

        // context=None should equal context=b""
        let out_none_ctx = ferret_rns::crypto::hkdf::hkdf(length, &derive_from, Some(b"salt"), None).unwrap();
        let out_empty_ctx = ferret_rns::crypto::hkdf::hkdf(length, &derive_from, Some(b"salt"), Some(b"")).unwrap();
        prop_assert_eq!(&out_none_ctx, &out_empty_ctx);
    }
}

// Feature: ferret-crypto-foundation, Property 10: AES-CBC Encryption Round-Trip
// **Validates: Requirements 7.1, 7.2, 7.3, 7.4**
proptest! {
    #[test]
    fn aes128_cbc_encrypt_decrypt_round_trip(
        num_blocks in 1usize..=32,
        block_data in proptest::collection::vec(any::<u8>(), 512),
        key in any::<[u8; 16]>(),
        iv in any::<[u8; 16]>(),
    ) {
        let len = num_blocks * 16;
        let plaintext = &block_data[..len];
        let ciphertext = ferret_rns::crypto::aes_cbc::aes128_cbc_encrypt(plaintext, &key, &iv);
        let decrypted = ferret_rns::crypto::aes_cbc::aes128_cbc_decrypt(&ciphertext, &key, &iv).unwrap();
        prop_assert_eq!(&decrypted, &plaintext);
    }

    #[test]
    fn aes256_cbc_encrypt_decrypt_round_trip(
        num_blocks in 1usize..=32,
        block_data in proptest::collection::vec(any::<u8>(), 512),
        key in any::<[u8; 32]>(),
        iv in any::<[u8; 16]>(),
    ) {
        let len = num_blocks * 16;
        let plaintext = &block_data[..len];
        let ciphertext = ferret_rns::crypto::aes_cbc::aes256_cbc_encrypt(plaintext, &key, &iv);
        let decrypted = ferret_rns::crypto::aes_cbc::aes256_cbc_decrypt(&ciphertext, &key, &iv).unwrap();
        prop_assert_eq!(&decrypted, &plaintext);
    }
}

// Feature: ferret-crypto-foundation, Property 12: Token Encrypt-Decrypt Round-Trip
// **Validates: Requirements 9.2, 9.3, 9.9**
proptest! {
    #[test]
    fn token_aes128_encrypt_decrypt_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        key in any::<[u8; 32]>(),
    ) {
        let token = ferret_rns::crypto::token::Token::new(&key).unwrap();
        let encrypted = token.encrypt(&plaintext);
        let decrypted = token.decrypt(&encrypted).unwrap();
        prop_assert_eq!(&decrypted, &plaintext);

        // Token length == PKCS7-padded plaintext length + TOKEN_OVERHEAD (48)
        let padded_len = plaintext.len() + (16 - (plaintext.len() % 16));
        prop_assert_eq!(encrypted.len(), padded_len + 48);
    }

    #[test]
    fn token_aes256_encrypt_decrypt_round_trip(
        plaintext in proptest::collection::vec(any::<u8>(), 0..512),
        key in any::<[u8; 64]>(),
    ) {
        let token = ferret_rns::crypto::token::Token::new(&key).unwrap();
        let encrypted = token.encrypt(&plaintext);
        let decrypted = token.decrypt(&encrypted).unwrap();
        prop_assert_eq!(&decrypted, &plaintext);

        // Token length == PKCS7-padded plaintext length + TOKEN_OVERHEAD (48)
        let padded_len = plaintext.len() + (16 - (plaintext.len() % 16));
        prop_assert_eq!(encrypted.len(), padded_len + 48);
    }
}
