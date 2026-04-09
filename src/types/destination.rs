use crate::error::FerretError;

/// Destination type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationType {
    Single = 0x00,
    Group  = 0x01,
    Plain  = 0x02,
    Link   = 0x03,
}

impl TryFrom<u8> for DestinationType {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Single),
            0x01 => Ok(Self::Group),
            0x02 => Ok(Self::Plain),
            0x03 => Ok(Self::Link),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "DestinationType", value }),
        }
    }
}

impl From<DestinationType> for u8 {
    fn from(v: DestinationType) -> u8 { v as u8 }
}

/// Destination direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationDirection {
    In  = 0x11,
    Out = 0x12,
}

impl TryFrom<u8> for DestinationDirection {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x11 => Ok(Self::In),
            0x12 => Ok(Self::Out),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "DestinationDirection", value }),
        }
    }
}

impl From<DestinationDirection> for u8 {
    fn from(v: DestinationDirection) -> u8 { v as u8 }
}

/// Proof strategy for a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProofStrategy {
    ProveNone = 0x21,
    ProveApp  = 0x22,
    ProveAll  = 0x23,
}

impl TryFrom<u8> for ProofStrategy {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x21 => Ok(Self::ProveNone),
            0x22 => Ok(Self::ProveApp),
            0x23 => Ok(Self::ProveAll),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "ProofStrategy", value }),
        }
    }
}

impl From<ProofStrategy> for u8 {
    fn from(v: ProofStrategy) -> u8 { v as u8 }
}
