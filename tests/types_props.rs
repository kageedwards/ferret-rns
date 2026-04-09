// Feature: ferret-crypto-foundation, Property 13: Enum Wire-Format Round-Trip
// **Validates: Requirements 11.5, 12.4, 13.2, 14.4, 15.2**

use proptest::prelude::*;
use ferret_rns::types::{
    PacketType, HeaderType, PacketContext, ContextFlag,
    DestinationType, DestinationDirection, ProofStrategy,
    TransportType, LinkEncryptionMode, LinkState, InterfaceMode,
};

fn packet_type_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x00u8), Just(0x01), Just(0x02), Just(0x03),
    ]
}

fn header_type_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x00u8), Just(0x01)]
}

fn packet_context_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x00u8), Just(0x01), Just(0x02), Just(0x03),
        Just(0x04), Just(0x05), Just(0x06), Just(0x07),
        Just(0x08), Just(0x09), Just(0x0A), Just(0x0B),
        Just(0x0C), Just(0x0D), Just(0x0E),
        Just(0xFA), Just(0xFB), Just(0xFC), Just(0xFD),
        Just(0xFE), Just(0xFF),
    ]
}

fn context_flag_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x00u8), Just(0x01)]
}

fn destination_type_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x00u8), Just(0x01), Just(0x02), Just(0x03)]
}

fn destination_direction_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x11u8), Just(0x12)]
}

fn proof_strategy_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x21u8), Just(0x22), Just(0x23)]
}

fn transport_type_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x00u8), Just(0x01), Just(0x02), Just(0x03)]
}

fn link_encryption_mode_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x00u8), Just(0x01), Just(0x02), Just(0x03),
        Just(0x04), Just(0x05), Just(0x06), Just(0x07),
    ]
}

fn link_state_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x00u8), Just(0x01), Just(0x02), Just(0x03), Just(0x04),
    ]
}

fn interface_mode_strategy() -> impl Strategy<Value = u8> {
    prop_oneof![
        Just(0x01u8), Just(0x02), Just(0x03), Just(0x04), Just(0x05), Just(0x06),
    ]
}

proptest! {
    #[test]
    fn packet_type_round_trip(v in packet_type_strategy()) {
        let e = PacketType::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn header_type_round_trip(v in header_type_strategy()) {
        let e = HeaderType::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn packet_context_round_trip(v in packet_context_strategy()) {
        let e = PacketContext::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn context_flag_round_trip(v in context_flag_strategy()) {
        let e = ContextFlag::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn destination_type_round_trip(v in destination_type_strategy()) {
        let e = DestinationType::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn destination_direction_round_trip(v in destination_direction_strategy()) {
        let e = DestinationDirection::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn proof_strategy_round_trip(v in proof_strategy_strategy()) {
        let e = ProofStrategy::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn transport_type_round_trip(v in transport_type_strategy()) {
        let e = TransportType::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn link_encryption_mode_round_trip(v in link_encryption_mode_strategy()) {
        let e = LinkEncryptionMode::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn link_state_round_trip(v in link_state_strategy()) {
        let e = LinkState::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }

    #[test]
    fn interface_mode_round_trip(v in interface_mode_strategy()) {
        let e = InterfaceMode::try_from(v).unwrap();
        let back: u8 = e.into();
        prop_assert_eq!(back, v);
    }
}
