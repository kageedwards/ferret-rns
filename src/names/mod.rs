//! Human-readable name service for Reticulum (ferret-original).
//!
//! Names follow the format `<label>.<suffix>` where `<suffix>` is the last
//! 4 hex characters of the registrant's identity hash.

pub mod record;
pub mod store;
pub mod resolver;
pub mod stamp;

pub use record::NameRecord;
pub use store::NameStore;
pub use resolver::NameResolver;
pub use stamp::{generate_stamp, verify_stamp};
