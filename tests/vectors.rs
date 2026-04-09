//! Cross-implementation test vectors, RFC test vectors, constant assertions,
//! and edge-case tests for the ferret-rns crate.
//!
//! Cross-implementation vectors were generated from the Python RNS reference
//! implementation (lxcf/_ref_rns/) to ensure byte-for-byte compatibility.

use ferret_rns::crypto::{
    self, sha256, sha512, hmac_sha256, hkdf,
    aes128_cbc_encrypt, aes128_cbc_decrypt,
    aes256_cbc_encrypt, aes256_cbc_decrypt,
    X25519PrivateKey, X25519PublicKey,
    Ed25519SigningKey, Ed25519VerifyingKey,
    Token,
};
use ferret_rns::crypto::pkcs7;
use ferret_rns::types;
use ferret_rns::util::{hex, msgpack};

fn h(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
}

// ===========================================================================
// 1. Protocol and crypto constant assertions (Req 10.14)
// ===========================================================================

#[test]
fn constants_protocol() {
    assert_eq!(types::MTU, 500);
    assert_eq!(types::TRUNCATED_HASHLENGTH, 128);
    assert_eq!(types::HEADER_MINSIZE, 19);
    assert_eq!(types::HEADER_MAXSIZE, 35);
    assert_eq!(types::IFAC_MIN_SIZE, 1);
    assert_eq!(types::MDU, 464);
    assert_eq!(types::MDU, types::MTU - types::HEADER_MAXSIZE - types::IFAC_MIN_SIZE);
    assert_eq!(types::HEADER_MINSIZE, 2 + 1 + (types::TRUNCATED_HASHLENGTH / 8));
    assert_eq!(types::HEADER_MAXSIZE, 2 + 1 + (types::TRUNCATED_HASHLENGTH / 8) * 2);
}

#[test]
fn constants_crypto() {
    assert_eq!(crypto::KEYSIZE, 512);
    assert_eq!(crypto::RATCHETSIZE, 256);
    assert_eq!(crypto::AES128_BLOCKSIZE, 16);
    assert_eq!(crypto::HASHLENGTH, 256);
    assert_eq!(crypto::SIGLENGTH, 512);
    assert_eq!(crypto::NAME_HASH_LENGTH, 80);
    assert_eq!(crypto::TOKEN_OVERHEAD, 48);
    assert_eq!(crypto::SIGLENGTH, crypto::KEYSIZE);
}


// ===========================================================================
// 2. SHA-256 cross-implementation vectors (Req 4.3, 4.5)
// ===========================================================================

#[test]
fn sha256_empty() {
    assert_eq!(sha256(b"").to_vec(), h("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

#[test]
fn sha256_abc() {
    assert_eq!(sha256(b"abc").to_vec(), h("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

#[test]
fn sha256_hello_reticulum() {
    // Cross-impl: Python reference Hashes.sha256(b"Hello Reticulum")
    assert_eq!(sha256(b"Hello Reticulum").to_vec(), h("0ef1748e1c4f0b841b24e0addb711023506d020188c1c6fc1e0e7911574a5847"));
}

#[test]
fn sha256_bytes_0_to_255() {
    let input: Vec<u8> = (0..=255).collect();
    assert_eq!(sha256(&input).to_vec(), h("40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"));
}

#[test]
fn sha256_nist_two_block() {
    // NIST: SHA-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    assert_eq!(
        sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        h("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    );
}

// ===========================================================================
// 3. SHA-512 cross-implementation vectors (Req 4.4, 4.6)
// ===========================================================================

#[test]
fn sha512_empty() {
    assert_eq!(sha512(b"").to_vec(), h("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));
}

#[test]
fn sha512_abc() {
    assert_eq!(sha512(b"abc").to_vec(), h("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

#[test]
fn sha512_hello_reticulum() {
    assert_eq!(sha512(b"Hello Reticulum").to_vec(), h("12e5a7faa7799037293129ab3825f02bd97c53af0f774b1e077c8b65d910e68ae6a7cba846b3899019c93479b5576694faba5d81d11a83c48315d7a6ffa20d52"));
}

#[test]
fn sha512_bytes_0_to_255() {
    let input: Vec<u8> = (0..=255).collect();
    assert_eq!(sha512(&input).to_vec(), h("1e7b80bc8edc552c8feeb2780e111477e5bc70465fac1a77b29b35980c3f0ce4a036a6c9462036824bd56801e62af7e9feba5c22ed8a5af877bf7de117dcac6d"));
}


// ===========================================================================
// 4. HMAC-SHA256 cross-implementation + RFC 4231 vectors (Req 5.2)
// ===========================================================================

#[test]
fn hmac_rfc4231_test1() {
    // RFC 4231 TC1 — also matches Python reference
    assert_eq!(
        hmac_sha256(&h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There").to_vec(),
        h("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

#[test]
fn hmac_rfc4231_test2() {
    // RFC 4231 TC2 — key = "Jefe"
    assert_eq!(
        hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
        h("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}

#[test]
fn hmac_rfc4231_test3() {
    // RFC 4231 TC3 — 20 bytes of 0xaa key, 50 bytes of 0xdd data
    assert_eq!(
        hmac_sha256(&vec![0xaa; 20], &vec![0xdd; 50]).to_vec(),
        h("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    );
}

#[test]
fn hmac_rfc4231_test6() {
    // RFC 4231 TC6 — key longer than block size (131 bytes of 0xaa)
    assert_eq!(
        hmac_sha256(&vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First").to_vec(),
        h("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    );
}

#[test]
fn hmac_cross_impl_custom_key() {
    // Cross-impl: Python reference HMAC.new(key=bytes(range(1,26)), msg=b"Test message")
    assert_eq!(
        hmac_sha256(&h("0102030405060708090a0b0c0d0e0f10111213141516171819"), b"Test message").to_vec(),
        h("dcdf96cd3ae2bc063c5dd72d2bc5f50d2e5975a76d36ab354fedc09827226653")
    );
}

#[test]
fn hmac_empty_message() {
    // Cross-impl: Python reference HMAC with 32 bytes of 0xff key, empty message
    assert_eq!(
        hmac_sha256(&vec![0xff; 32], b"").to_vec(),
        h("b20ae80e1d70f49e9bb56625a4c9cf02a5547bd2e2ef7cf0657e59f44cc0c017")
    );
}


// ===========================================================================
// 5. HKDF cross-implementation + RFC 5869 vectors (Req 6.6)
// ===========================================================================

#[test]
fn hkdf_rfc5869_test1() {
    // RFC 5869 TC1 (SHA-256) — also matches Python reference
    assert_eq!(
        hkdf(42, &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), Some(&h("000102030405060708090a0b0c")), Some(&h("f0f1f2f3f4f5f6f7f8f9"))).unwrap(),
        h("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn hkdf_rfc5869_test2() {
    // RFC 5869 TC2 (SHA-256) — longer inputs
    assert_eq!(
        hkdf(82,
            &h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
            Some(&h("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")),
            Some(&h("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
        ).unwrap(),
        h("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
    );
}

#[test]
fn hkdf_rfc5869_test3() {
    // RFC 5869 TC3 — zero-length salt and info (matches our None defaults)
    assert_eq!(
        hkdf(42, &h("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), None, None).unwrap(),
        h("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn hkdf_cross_impl_none_salt_none_ctx() {
    // Cross-impl: Python reference hkdf(64, bytes(range(32)), salt=None, context=None)
    assert_eq!(
        hkdf(64, &(0..32).collect::<Vec<u8>>(), None, None).unwrap(),
        h("37ad29109f43265287804b674e2653d0a513718907f97fca97c95bded8104bbf9601b7e7a7d5a882b151679d3bba7d1ecf9681ad0509bfa68434e1bfa767a51d")
    );
}

#[test]
fn hkdf_cross_impl_with_salt_ctx() {
    // Cross-impl: Python reference hkdf(16, bytes([0x42]*16), salt=b"salt", context=b"context")
    assert_eq!(
        hkdf(16, &vec![0x42; 16], Some(b"salt"), Some(b"context")).unwrap(),
        h("33945b78871ccc4e292c68767ee23040")
    );
}

#[test]
fn hkdf_cross_impl_explicit_zero_salt() {
    // Cross-impl: Python reference hkdf(48, bytes(range(1,33)), salt=bytes(32), context=b"")
    assert_eq!(
        hkdf(48, &(1..=32).collect::<Vec<u8>>(), Some(&[0u8; 32]), Some(b"")).unwrap(),
        h("fd7d6735042b686edd0f296a1d215460f6e2f0036f0a05067e3caebf41f7f6e6a9adabf7067936149bef521d2ac800b4")
    );
}

// HKDF error conditions
#[test]
fn hkdf_error_zero_length() { assert!(hkdf(0, b"input", None, None).is_err()); }
#[test]
fn hkdf_error_empty_input() { assert!(hkdf(32, b"", None, None).is_err()); }
#[test]
fn hkdf_error_length_too_large() { assert!(hkdf(8161, b"input", None, None).is_err()); }

// HKDF default parameter equivalence
#[test]
fn hkdf_none_salt_equals_zero_salt() {
    let ikm = b"test input key material";
    assert_eq!(hkdf(32, ikm, None, Some(b"ctx")).unwrap(), hkdf(32, ikm, Some(&[0u8; 32]), Some(b"ctx")).unwrap());
}

#[test]
fn hkdf_empty_salt_equals_none_salt() {
    let ikm = b"test input key material";
    assert_eq!(hkdf(32, ikm, Some(b""), Some(b"ctx")).unwrap(), hkdf(32, ikm, None, Some(b"ctx")).unwrap());
}

#[test]
fn hkdf_none_context_equals_empty_context() {
    let ikm = b"test input key material";
    assert_eq!(hkdf(32, ikm, Some(b"salt"), None).unwrap(), hkdf(32, ikm, Some(b"salt"), Some(b"")).unwrap());
}


// ===========================================================================
// 6. X25519 cross-implementation vectors (Req 2.6, 2.7)
// ===========================================================================

#[test]
fn x25519_cross_impl_public_key_derivation() {
    // Cross-impl: Python reference X25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let sk = X25519PrivateKey::from_bytes(&seed);
    assert_eq!(sk.public_key().to_bytes().to_vec(), h("8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"));
}

#[test]
fn x25519_cross_impl_shared_secret() {
    // Cross-impl: two key pairs, verify shared secret matches Python reference
    let seed_a: [u8; 32] = core::array::from_fn(|i| i as u8);
    let seed_b: [u8; 32] = core::array::from_fn(|i| (i + 32) as u8);

    let sk_a = X25519PrivateKey::from_bytes(&seed_a);
    let sk_b = X25519PrivateKey::from_bytes(&seed_b);
    let pk_a = sk_a.public_key();
    let pk_b = sk_b.public_key();

    assert_eq!(pk_b.to_bytes().to_vec(), h("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"));

    let shared_ab = sk_a.exchange(&pk_b);
    let shared_ba = sk_b.exchange(&pk_a);
    assert_eq!(shared_ab, shared_ba); // commutativity
    assert_eq!(shared_ab.to_vec(), h("9663aa1da97e848a914a436d04163dfbb89178f107f1b5b77ed3854203382854"));
}

#[test]
fn x25519_rfc7748_vector_1() {
    // RFC 7748 Section 6.1 — first test vector
    let sk = X25519PrivateKey::from_bytes(&h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").try_into().unwrap());
    let pk = X25519PublicKey::from_bytes(&h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").try_into().unwrap());
    assert_eq!(sk.exchange(&pk).to_vec(), h("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
}

#[test]
fn x25519_rfc7748_vector_2() {
    // RFC 7748 Section 6.1 — second test vector
    let sk = X25519PrivateKey::from_bytes(&h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").try_into().unwrap());
    let pk = X25519PublicKey::from_bytes(&h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").try_into().unwrap());
    assert_eq!(sk.exchange(&pk).to_vec(), h("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
}

#[test]
fn x25519_public_key_round_trip() {
    let seed: [u8; 32] = [0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a];
    let sk = X25519PrivateKey::from_bytes(&seed);
    let pk = sk.public_key();
    assert_eq!(pk.to_bytes().to_vec(), h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    let pk2 = X25519PublicKey::from_bytes(&pk.to_bytes());
    assert_eq!(pk2.to_bytes(), pk.to_bytes());
}


// ===========================================================================
// 7. Ed25519 cross-implementation vectors (Req 3.8, 3.9)
// ===========================================================================

#[test]
fn ed25519_cross_impl_seed_zeros() {
    // Cross-impl: Python reference Ed25519PrivateKey(bytes(32))
    let seed = [0u8; 32];
    let sk = Ed25519SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    assert_eq!(vk.to_bytes().to_vec(), h("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"));

    // Sign empty message — matches Python reference
    let sig = sk.sign(b"");
    assert_eq!(sig.to_vec(), h("8f895b3cafe2c9506039d0e2a66382568004674fe8d237785092e40d6aaf483e4fc60168705f31f101596138ce21aa357c0d32a064f423dc3ee4aa3abf53f803"));
    vk.verify(b"", &sig).unwrap();

    // Sign "Hello Reticulum"
    let sig2 = sk.sign(b"Hello Reticulum");
    assert_eq!(sig2.to_vec(), h("e88ccfcfb24ba7127093d47942deb458b2f5266da3dfd2c3d533c8e60e6d07cc64964a49662a934d84ee44a8c32617a3d3c565d95042fbf796456bc304156b05"));
    vk.verify(b"Hello Reticulum", &sig2).unwrap();
}

#[test]
fn ed25519_cross_impl_seed_sequential() {
    // Cross-impl: Python reference Ed25519PrivateKey(bytes(range(32)))
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let sk = Ed25519SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    assert_eq!(vk.to_bytes().to_vec(), h("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"));

    let sig = sk.sign(b"");
    assert_eq!(sig.to_vec(), h("9ca53579530654d5c3df77089ef45eda613e2fedf670e96bedac4639504e5845ef4b95d5793077233dd16817b2532e9c5525872a73a4ad74b759369a9e05c102"));
    vk.verify(b"", &sig).unwrap();

    let sig2 = sk.sign(b"Hello Reticulum");
    assert_eq!(sig2.to_vec(), h("a1914ab3ab67bbb73bd7b21e8b54d214cb455d8d84f7f3298563066cc586a78771eb9aac3fbf69c2bd055bd1b9672cc1ef0cb38a40205300983a71c504e0ce0a"));
    vk.verify(b"Hello Reticulum", &sig2).unwrap();
}

#[test]
fn ed25519_cross_impl_seed_0x42() {
    // Cross-impl: Python reference Ed25519PrivateKey(bytes([0x42]*32))
    let seed = [0x42u8; 32];
    let sk = Ed25519SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    assert_eq!(vk.to_bytes().to_vec(), h("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"));

    let sig = sk.sign(b"Hello Reticulum");
    assert_eq!(sig.to_vec(), h("d447c410302ab7607a33ea63fd7c2b93d3ee3e9fb25c45f431706f5d55c3ee7b98fa47b0715196504d770faaad897b9220f0b9eae0e5603f45ae5455cd14880d"));
    vk.verify(b"Hello Reticulum", &sig).unwrap();
}

#[test]
fn ed25519_cross_impl_large_message() {
    // Cross-impl: sign bytes(range(256)) with seed=bytes(32)
    let seed = [0u8; 32];
    let sk = Ed25519SigningKey::from_seed(&seed);
    let vk = sk.verifying_key();
    let msg: Vec<u8> = (0..=255).collect();
    let sig = sk.sign(&msg);
    assert_eq!(sig.to_vec(), h("854ff4be13f4ae338ed96ddf1459541b4ec99f5764b7e8b11d4bf615ff4c9ee821ee6b01feb3b95e4269c531ffba4c691c909ab8f674fb2ecf2ec48102b84103"));
    vk.verify(&msg, &sig).unwrap();
}

#[test]
fn ed25519_seed_round_trip() {
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let sk = Ed25519SigningKey::from_seed(&seed);
    assert_eq!(sk.to_seed(), seed);
    let vk = sk.verifying_key();
    let vk2 = Ed25519VerifyingKey::from_bytes(&vk.to_bytes()).unwrap();
    assert_eq!(vk2.to_bytes(), vk.to_bytes());
}

#[test]
fn ed25519_wrong_key_rejects() {
    let sk1 = Ed25519SigningKey::from_seed(&[1u8; 32]);
    let sk2 = Ed25519SigningKey::from_seed(&[2u8; 32]);
    let sig = sk1.sign(b"test message");
    assert!(sk2.verifying_key().verify(b"test message", &sig).is_err());
}


// ===========================================================================
// 8. AES-CBC cross-implementation + NIST vectors (Req 7.6)
// ===========================================================================

#[test]
fn aes128_cbc_nist_vector() {
    // NIST SP 800-38A F.2.1 CBC-AES128
    let key: [u8; 16] = h("2b7e151628aed2a6abf7158809cf4f3c").try_into().unwrap();
    let iv: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let pt = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    let expected = h("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");
    let ct = aes128_cbc_encrypt(&pt, &key, &iv);
    assert_eq!(ct, expected);
    assert_eq!(aes128_cbc_decrypt(&ct, &key, &iv).unwrap(), pt);
}

#[test]
fn aes256_cbc_nist_vector() {
    // NIST SP 800-38A F.2.5 CBC-AES256
    let key: [u8; 32] = h("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").try_into().unwrap();
    let iv: [u8; 16] = h("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let pt = h("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
    let expected = h("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b");
    let ct = aes256_cbc_encrypt(&pt, &key, &iv);
    assert_eq!(ct, expected);
    assert_eq!(aes256_cbc_decrypt(&ct, &key, &iv).unwrap(), pt);
}

#[test]
fn aes128_cbc_cross_impl() {
    // Cross-impl: Python reference AES_128_CBC.encrypt(PKCS7.pad(b"Hello Reticulum!"), key=bytes(range(16)), iv=bytes([0x10]*16))
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 16] = [0x10; 16];
    let padded = h("48656c6c6f205265746963756c756d2110101010101010101010101010101010");
    let expected = h("16fd22e162af18285519b1a4035903551a558e0eb7f71356a8d140588d86e1a0");
    assert_eq!(aes128_cbc_encrypt(&padded, &key, &iv), expected);
    assert_eq!(aes128_cbc_decrypt(&expected, &key, &iv).unwrap(), padded);
}

#[test]
fn aes256_cbc_cross_impl() {
    // Cross-impl: Python reference AES_256_CBC.encrypt(PKCS7.pad(b"Hello Reticulum!"), key=bytes(range(32)), iv=bytes([0x10]*16))
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let iv: [u8; 16] = [0x10; 16];
    let padded = h("48656c6c6f205265746963756c756d2110101010101010101010101010101010");
    let expected = h("179c2f1e288a42852bc3e09a9c895028f6da72132073671cefed49221e7e005d");
    assert_eq!(aes256_cbc_encrypt(&padded, &key, &iv), expected);
    assert_eq!(aes256_cbc_decrypt(&expected, &key, &iv).unwrap(), padded);
}


// ===========================================================================
// 9. Token cross-implementation vectors (Req 9.7, 9.8)
// ===========================================================================

#[test]
fn token_decrypt_python_aes128() {
    // Cross-impl: Token encrypted by Python reference with known IV, key=bytes(range(32))
    // Plaintext: b"Ferret cross-implementation test"
    let key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let token_bytes = h("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0ac238fe0fee1fc2d86789928779cf90d907a965b16105d3abb086290d7c23af76ef886a89fbcae6be466c985778991d659bd8cda6c72eb79342114464b918dfd561f2aecc285e07943e139afb5568af");
    let token = Token::new(&key).unwrap();
    let plaintext = token.decrypt(&token_bytes).unwrap();
    assert_eq!(plaintext, b"Ferret cross-implementation test");
}

#[test]
fn token_decrypt_python_aes256() {
    // Cross-impl: Token encrypted by Python reference with known IV, key=bytes(range(64))
    let key = h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    let token_bytes = h("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacdf64e6d8fc606b95aa5688d5d3af6c802ba029079e32cd63b0190d1972184edf82a74ed815890ad18e683c61a0347af6c6c1287ed68d4c894030d7e95c22aa7d19ef9f77247267c4cd3c29a0ff7a283");
    let token = Token::new(&key).unwrap();
    let plaintext = token.decrypt(&token_bytes).unwrap();
    assert_eq!(plaintext, b"Ferret cross-implementation test");
}

#[test]
fn token_round_trip_aes128() {
    let key = [0x42u8; 32];
    let token = Token::new(&key).unwrap();
    let pt = b"Hello, Reticulum!";
    let encrypted = token.encrypt(pt);
    assert_eq!(encrypted.len(), 32 + 48); // 17 bytes padded to 32 + 48 overhead
    assert_eq!(token.decrypt(&encrypted).unwrap(), pt);
}

#[test]
fn token_round_trip_aes256() {
    let key = [0x55u8; 64];
    let token = Token::new(&key).unwrap();
    let pt = b"Ferret crypto foundation";
    let encrypted = token.encrypt(pt);
    assert_eq!(token.decrypt(&encrypted).unwrap(), pt);
}

#[test]
fn token_empty_plaintext() {
    let token = Token::new(&[0x42u8; 32]).unwrap();
    let encrypted = token.encrypt(b"");
    assert_eq!(encrypted.len(), 16 + 48); // empty → 16 bytes padded + 48 overhead
    assert!(token.decrypt(&encrypted).unwrap().is_empty());
}

#[test]
fn token_invalid_key_length() {
    assert!(Token::new(&[0u8; 16]).is_err());
    assert!(Token::new(&[0u8; 48]).is_err());
    assert!(Token::new(&[0u8; 0]).is_err());
}

#[test]
fn token_too_short() {
    let token = Token::new(&[0x42u8; 32]).unwrap();
    assert!(token.decrypt(&[0u8; 32]).is_err());
    assert!(token.decrypt(&[0u8; 16]).is_err());
    assert!(token.decrypt(&[0u8; 0]).is_err());
}

#[test]
fn token_hmac_tamper_detected() {
    let token = Token::new(&[0x42u8; 32]).unwrap();
    let mut enc = token.encrypt(b"secret");
    let last = enc.len() - 1;
    enc[last] ^= 0x01;
    assert!(token.decrypt(&enc).is_err());
}

#[test]
fn token_ciphertext_tamper_detected() {
    let token = Token::new(&[0x42u8; 32]).unwrap();
    let mut enc = token.encrypt(b"secret");
    enc[20] ^= 0x01;
    assert!(token.decrypt(&enc).is_err());
}


// ===========================================================================
// 10. PKCS7 edge cases
// ===========================================================================

#[test]
fn pkcs7_aligned_adds_full_block() {
    let padded = pkcs7::pad(&[0xaa; 16], 16);
    assert_eq!(padded.len(), 32);
    assert!(padded[16..].iter().all(|&b| b == 16));
    assert_eq!(pkcs7::unpad(&padded, 16).unwrap(), vec![0xaa; 16]);
}

#[test]
fn pkcs7_empty_input() {
    let padded = pkcs7::pad(b"", 16);
    assert_eq!(padded.len(), 16);
    assert!(padded.iter().all(|&b| b == 16));
    assert!(pkcs7::unpad(&padded, 16).unwrap().is_empty());
}

#[test]
fn pkcs7_invalid_padding_byte_too_large() {
    let mut data = vec![0u8; 16];
    data[15] = 17;
    assert!(pkcs7::unpad(&data, 16).is_err());
}

#[test]
fn pkcs7_invalid_padding_byte_zero() {
    assert!(pkcs7::unpad(&vec![0u8; 16], 16).is_err());
}

#[test]
fn pkcs7_invalid_inconsistent_padding() {
    let mut data = vec![0xaa; 14];
    data.push(0x02);
    data.push(0x03);
    assert!(pkcs7::unpad(&data, 16).is_err());
}

#[test]
fn pkcs7_unpad_empty() {
    assert!(pkcs7::unpad(b"", 16).is_err());
}

// ===========================================================================
// 11. MessagePack edge cases (Req 16.3)
// ===========================================================================

#[test]
fn msgpack_round_trip_integer() {
    let bytes = msgpack::serialize(&42i64).unwrap();
    assert_eq!(msgpack::deserialize::<i64>(&bytes).unwrap(), 42);
}

#[test]
fn msgpack_round_trip_string() {
    let bytes = msgpack::serialize(&"hello reticulum").unwrap();
    assert_eq!(msgpack::deserialize::<String>(&bytes).unwrap(), "hello reticulum");
}

#[test]
fn msgpack_round_trip_vec() {
    let v = vec![1u32, 2, 3, 4, 5];
    let bytes = msgpack::serialize(&v).unwrap();
    assert_eq!(msgpack::deserialize::<Vec<u32>>(&bytes).unwrap(), v);
}

#[test]
fn msgpack_malformed() { assert!(msgpack::deserialize::<i64>(&[0xc1]).is_err()); }

#[test]
fn msgpack_empty() { assert!(msgpack::deserialize::<i64>(&[]).is_err()); }

#[test]
fn msgpack_truncated_string() { assert!(msgpack::deserialize::<String>(&[0xa5, 0x68, 0x69]).is_err()); }

// ===========================================================================
// 12. Hex formatting known vectors
// ===========================================================================

#[test]
fn hex_known() {
    assert_eq!(hex::hexrep(&[0xde, 0xad, 0xbe, 0xef]), "de:ad:be:ef");
    assert_eq!(hex::hexrep_no_delimit(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    assert_eq!(hex::prettyhexrep(&[0xde, 0xad, 0xbe, 0xef]), "<deadbeef>");
}

#[test]
fn hex_single_byte() {
    assert_eq!(hex::hexrep(&[0xff]), "ff");
    assert_eq!(hex::hexrep_no_delimit(&[0xff]), "ff");
    assert_eq!(hex::prettyhexrep(&[0xff]), "<ff>");
}

#[test]
fn hex_empty() {
    assert_eq!(hex::hexrep(&[]), "");
    assert_eq!(hex::hexrep_no_delimit(&[]), "");
    assert_eq!(hex::prettyhexrep(&[]), "<>");
}
