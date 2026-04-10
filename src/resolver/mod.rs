// Resolver module: placeholder for future destination name resolution

use crate::identity::Identity;

/// Placeholder for future destination name resolution.
pub struct Resolver;

impl Resolver {
    /// Always returns None. Will be implemented in a future spec.
    pub fn resolve_identity(_full_name: &str) -> Option<Identity> {
        None
    }
}
