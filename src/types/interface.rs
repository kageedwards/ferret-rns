use crate::error::FerretError;

/// Interface operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum InterfaceMode {
    Full         = 0x01,
    PointToPoint = 0x02,
    AccessPoint  = 0x03,
    Roaming      = 0x04,
    Boundary     = 0x05,
    Gateway      = 0x06,
}

impl TryFrom<u8> for InterfaceMode {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Full),
            0x02 => Ok(Self::PointToPoint),
            0x03 => Ok(Self::AccessPoint),
            0x04 => Ok(Self::Roaming),
            0x05 => Ok(Self::Boundary),
            0x06 => Ok(Self::Gateway),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "InterfaceMode", value }),
        }
    }
}

impl From<InterfaceMode> for u8 {
    fn from(v: InterfaceMode) -> u8 { v as u8 }
}
