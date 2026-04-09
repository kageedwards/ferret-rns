use crate::error::FerretError;

/// Packet type discriminant on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketType {
    Data        = 0x00,
    Announce    = 0x01,
    LinkRequest = 0x02,
    Proof       = 0x03,
}

impl TryFrom<u8> for PacketType {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Data),
            0x01 => Ok(Self::Announce),
            0x02 => Ok(Self::LinkRequest),
            0x03 => Ok(Self::Proof),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "PacketType", value }),
        }
    }
}

impl From<PacketType> for u8 {
    fn from(v: PacketType) -> u8 { v as u8 }
}

/// Header type discriminant on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeaderType {
    Header1 = 0x00,
    Header2 = 0x01,
}

impl TryFrom<u8> for HeaderType {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Header1),
            0x01 => Ok(Self::Header2),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "HeaderType", value }),
        }
    }
}

impl From<HeaderType> for u8 {
    fn from(v: HeaderType) -> u8 { v as u8 }
}

/// Packet context discriminant on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketContext {
    None          = 0x00,
    Resource      = 0x01,
    ResourceAdv   = 0x02,
    ResourceReq   = 0x03,
    ResourceHmu   = 0x04,
    ResourcePrf   = 0x05,
    ResourceIcl   = 0x06,
    ResourceRcl   = 0x07,
    CacheRequest  = 0x08,
    Request       = 0x09,
    Response      = 0x0A,
    PathResponse  = 0x0B,
    Command       = 0x0C,
    CommandStatus = 0x0D,
    Channel       = 0x0E,
    Keepalive     = 0xFA,
    LinkIdentify  = 0xFB,
    LinkClose     = 0xFC,
    LinkProof     = 0xFD,
    Lrrtt         = 0xFE,
    LrProof       = 0xFF,
}

impl TryFrom<u8> for PacketContext {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::None),
            0x01 => Ok(Self::Resource),
            0x02 => Ok(Self::ResourceAdv),
            0x03 => Ok(Self::ResourceReq),
            0x04 => Ok(Self::ResourceHmu),
            0x05 => Ok(Self::ResourcePrf),
            0x06 => Ok(Self::ResourceIcl),
            0x07 => Ok(Self::ResourceRcl),
            0x08 => Ok(Self::CacheRequest),
            0x09 => Ok(Self::Request),
            0x0A => Ok(Self::Response),
            0x0B => Ok(Self::PathResponse),
            0x0C => Ok(Self::Command),
            0x0D => Ok(Self::CommandStatus),
            0x0E => Ok(Self::Channel),
            0xFA => Ok(Self::Keepalive),
            0xFB => Ok(Self::LinkIdentify),
            0xFC => Ok(Self::LinkClose),
            0xFD => Ok(Self::LinkProof),
            0xFE => Ok(Self::Lrrtt),
            0xFF => Ok(Self::LrProof),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "PacketContext", value }),
        }
    }
}

impl From<PacketContext> for u8 {
    fn from(v: PacketContext) -> u8 { v as u8 }
}

/// Context flag value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContextFlag {
    Unset = 0x00,
    Set   = 0x01,
}

impl TryFrom<u8> for ContextFlag {
    type Error = FerretError;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Unset),
            0x01 => Ok(Self::Set),
            _ => Err(FerretError::InvalidEnumValue { enum_name: "ContextFlag", value }),
        }
    }
}

impl From<ContextFlag> for u8 {
    fn from(v: ContextFlag) -> u8 { v as u8 }
}
