// Destination-level ratchet rotation
//
// Methods (enable_ratchets, rotate_ratchets, enforce_ratchets, set_retained_ratchets,
// set_ratchet_interval, persist_ratchets) are implemented directly on Destination
// in destination.rs since Rust doesn't allow impl blocks across modules for the
// same type.
