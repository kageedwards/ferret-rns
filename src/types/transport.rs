use crate::error::FerretError;

/// Transport type discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransportType {
    Broadcast = 0x00,
    Transport = 0x01,
    Relay     = 0x02,
    Tunnel    = 0x03,
}

impl TryFrom<u8> for TransportType {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Broadcast),
            0x01 => Ok(Self::Transport),
            0x02 => Ok(Self::Relay),
            0x03 => Ok(Self::Tunnel),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "TransportType", value }),
        }
    }
}

impl From<TransportType> for u8 {
    fn from(v: TransportType) -> u8 { v as u8 }
}
