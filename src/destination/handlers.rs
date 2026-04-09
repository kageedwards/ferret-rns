// Request handler registration and helper types

use crate::identity::Identity;

/// A registered request handler for a Destination.
pub struct RequestHandler {
    pub path: String,
    pub response_generator:
        Box<dyn Fn(&str, &[u8], &[u8], &[u8], Option<&Identity>, f64) -> Option<Vec<u8>> + Send + Sync>,
    pub allow: u8,
    pub allowed_list: Option<Vec<Vec<u8>>>,
}
