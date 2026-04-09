use crate::error::FerretError;

/// Link encryption mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkEncryptionMode {
    Aes128Cbc   = 0x00,
    Aes256Cbc   = 0x01,
    Aes256Gcm   = 0x02,
    OtpReserved = 0x03,
    PqReserved1 = 0x04,
    PqReserved2 = 0x05,
    PqReserved3 = 0x06,
    PqReserved4 = 0x07,
}

impl TryFrom<u8> for LinkEncryptionMode {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Aes128Cbc),
            0x01 => Ok(Self::Aes256Cbc),
            0x02 => Ok(Self::Aes256Gcm),
            0x03 => Ok(Self::OtpReserved),
            0x04 => Ok(Self::PqReserved1),
            0x05 => Ok(Self::PqReserved2),
            0x06 => Ok(Self::PqReserved3),
            0x07 => Ok(Self::PqReserved4),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "LinkEncryptionMode", value }),
        }
    }
}

impl From<LinkEncryptionMode> for u8 {
    fn from(v: LinkEncryptionMode) -> u8 { v as u8 }
}

/// Default link encryption mode.
pub const LINK_MODE_DEFAULT: LinkEncryptionMode = LinkEncryptionMode::Aes256Cbc;

/// Link lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinkState {
    Pending   = 0x00,
    Handshake = 0x01,
    Active    = 0x02,
    Stale     = 0x03,
    Closed    = 0x04,
}

impl TryFrom<u8> for LinkState {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Pending),
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::Active),
            0x03 => Ok(Self::Stale),
            0x04 => Ok(Self::Closed),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "LinkState", value }),
        }
    }
}

impl From<LinkState> for u8 {
    fn from(v: LinkState) -> u8 { v as u8 }
}
