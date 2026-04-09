/// MessagePack serialization helpers wrapping `rmp-serde`.
///
/// Provides compact MessagePack encoding compatible with Python's `umsgpack`.

pub fn serialize<T: serde::Serialize>(value: &T) -> crate::Result<Vec<u8>> {
    rmp_serde::to_vec(value).map_err(|e| crate::FerretError::Serialization(e.to_string()))
}

pub fn deserialize<'a, T: serde::Deserialize<'a>>(bytes: &'a [u8]) -> crate::Result<T> {
    rmp_serde::from_slice(bytes).map_err(|e| crate::FerretError::Deserialization(e.to_string()))
}
