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
