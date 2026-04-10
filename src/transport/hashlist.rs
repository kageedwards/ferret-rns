// Packet hashlist — dedup set with generation rotation

use std::collections::HashSet;

/// A two-generation dedup set for packet hashes.
///
/// Hashes are inserted into the `current` set. When `rotate()` is called,
/// `current` becomes `previous` and a fresh empty set takes its place.
/// Lookups check both generations, giving each hash a lifetime of up to
/// two rotation periods before it is forgotten.
pub struct PacketHashlist {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
    max_size: usize,
}

impl PacketHashlist {
    /// Create a new hashlist with the given maximum size per generation.
    pub fn new(max_size: usize) -> Self {
        Self {
            current: HashSet::new(),
            previous: HashSet::new(),
            max_size,
        }
    }

    /// Insert a hash into the current generation.
    ///
    /// If the current set has reached `max_size`, a rotation is triggered
    /// automatically before inserting.
    pub fn add(&mut self, hash: &[u8; 32]) {
        if self.current.len() >= self.max_size {
            self.rotate();
        }
        self.current.insert(*hash);
    }

    /// Check whether a hash exists in either the current or previous generation.
    pub fn contains(&self, hash: &[u8; 32]) -> bool {
        self.current.contains(hash) || self.previous.contains(hash)
    }

    /// Rotate generations: current becomes previous, current is cleared.
    pub fn rotate(&mut self) {
        self.previous = std::mem::take(&mut self.current);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_contains() {
        let mut hl = PacketHashlist::new(1024);
        let hash = [0xABu8; 32];
        assert!(!hl.contains(&hash));
        hl.add(&hash);
        assert!(hl.contains(&hash));
    }

    #[test]
    fn test_rotate_preserves_previous() {
        let mut hl = PacketHashlist::new(1024);
        let hash = [0x01u8; 32];
        hl.add(&hash);
        hl.rotate();
        // Still findable in previous generation
        assert!(hl.contains(&hash));
        // Second rotation drops it
        hl.rotate();
        assert!(!hl.contains(&hash));
    }

    #[test]
    fn test_auto_rotate_on_max_size() {
        let mut hl = PacketHashlist::new(2);
        let h1 = [0x01u8; 32];
        let h2 = [0x02u8; 32];
        let h3 = [0x03u8; 32];
        hl.add(&h1);
        hl.add(&h2);
        // current is full (2), next add triggers rotation
        hl.add(&h3);
        // h1 and h2 moved to previous, h3 in current
        assert!(hl.contains(&h1));
        assert!(hl.contains(&h2));
        assert!(hl.contains(&h3));
    }

    #[test]
    fn test_empty_contains_nothing() {
        let hl = PacketHashlist::new(100);
        assert!(!hl.contains(&[0u8; 32]));
    }
}
