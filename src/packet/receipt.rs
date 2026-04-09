use crate::identity::Identity;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ReceiptStatus {
    Failed = 0x00,
    Sent = 0x01,
    Delivered = 0x02,
    Culled = 0xFF,
}

/// Explicit proof: 32-byte hash + 64-byte signature = 96 bytes.
pub const EXPL_LENGTH: usize = 96;
/// Implicit proof: 64-byte signature = 64 bytes.
pub const IMPL_LENGTH: usize = 64;

pub struct PacketReceipt {
    pub hash: [u8; 32],
    pub truncated_hash: [u8; 16],
    pub sent_at: f64,
    pub status: ReceiptStatus,
    pub timeout: f64,
    pub concluded_at: Option<f64>,
    pub proved: bool,
    delivery_callback: Option<Box<dyn Fn(&PacketReceipt) + Send + Sync>>,
    timeout_callback: Option<Box<dyn Fn(&PacketReceipt) + Send + Sync>>,
    /// Stored as 64-byte public key bytes for proof validation.
    /// We store bytes rather than Identity to avoid needing Clone on Identity.
    destination_pub_key: Option<[u8; 64]>,
}

impl PacketReceipt {
    /// Create a new receipt for a sent packet.
    pub fn new(
        hash: [u8; 32],
        truncated_hash: [u8; 16],
        timeout: f64,
        destination_pub_key: Option<[u8; 64]>,
    ) -> Self {
        let sent_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        Self {
            hash,
            truncated_hash,
            sent_at,
            status: ReceiptStatus::Sent,
            timeout,
            concluded_at: None,
            proved: false,
            delivery_callback: None,
            timeout_callback: None,
            destination_pub_key,
        }
    }

    /// Validate a delivery proof.
    ///
    /// Explicit proof (96 bytes): 32-byte hash + 64-byte signature.
    /// Implicit proof (64 bytes): 64-byte signature only.
    pub fn validate_proof(&mut self, proof: &[u8]) -> bool {
        if proof.len() == EXPL_LENGTH {
            // Explicit proof: hash(32) + signature(64)
            let proof_hash: [u8; 32] = match proof[..32].try_into() {
                Ok(h) => h,
                Err(_) => return false,
            };
            if proof_hash != self.hash {
                return false;
            }
            let signature: [u8; 64] = match proof[32..96].try_into() {
                Ok(s) => s,
                Err(_) => return false,
            };
            self.verify_signature(&signature)
        } else if proof.len() == IMPL_LENGTH {
            // Implicit proof: signature(64)
            let signature: [u8; 64] = match proof[..64].try_into() {
                Ok(s) => s,
                Err(_) => return false,
            };
            self.verify_signature(&signature)
        } else {
            false
        }
    }

    /// Verify a signature against the stored hash using the destination identity.
    fn verify_signature(&mut self, signature: &[u8; 64]) -> bool {
        let pub_key = match self.destination_pub_key {
            Some(k) => k,
            None => return false,
        };
        let identity = match Identity::from_public_key(&pub_key) {
            Ok(id) => id,
            Err(_) => return false,
        };
        match identity.validate(signature, &self.hash) {
            Ok(true) => {
                self.status = ReceiptStatus::Delivered;
                self.proved = true;
                self.concluded_at = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs_f64())
                        .unwrap_or(0.0),
                );
                if let Some(ref cb) = self.delivery_callback {
                    cb(self);
                }
                true
            }
            _ => false,
        }
    }

    /// Check if the receipt has timed out.
    pub fn check_timeout(&mut self) {
        if self.status != ReceiptStatus::Sent {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);

        if now > self.sent_at + self.timeout {
            self.status = if self.timeout == -1.0 {
                ReceiptStatus::Culled
            } else {
                ReceiptStatus::Failed
            };
            self.concluded_at = Some(now);
            if let Some(ref cb) = self.timeout_callback {
                cb(self);
            }
        }
    }

    /// Get the round-trip time if the receipt has been concluded.
    pub fn get_rtt(&self) -> Option<f64> {
        self.concluded_at.map(|c| c - self.sent_at)
    }

    /// Get the current receipt status.
    pub fn get_status(&self) -> ReceiptStatus {
        self.status
    }

    /// Set the delivery callback.
    pub fn set_delivery_callback(&mut self, cb: Box<dyn Fn(&PacketReceipt) + Send + Sync>) {
        self.delivery_callback = Some(cb);
    }

    /// Set the timeout callback.
    pub fn set_timeout_callback(&mut self, cb: Box<dyn Fn(&PacketReceipt) + Send + Sync>) {
        self.timeout_callback = Some(cb);
    }

    /// Set the receipt timeout.
    pub fn set_timeout(&mut self, timeout: f64) {
        self.timeout = timeout;
    }

    /// Check if the receipt has timed out (status is Failed or Culled).
    pub fn is_timed_out(&self) -> bool {
        self.status == ReceiptStatus::Failed || self.status == ReceiptStatus::Culled
    }
}
