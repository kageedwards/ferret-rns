// Request/response handling, RequestReceipt

use crate::identity::Identity;
use crate::link::link::{now, Link};
use crate::link::LinkStatus;
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::transport::TransportState;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{FerretError, Result};

// ── RequestReceiptStatus ──

/// Status of a pending request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestReceiptStatus {
    Failed    = 0x00,
    Sent      = 0x01,
    Delivered = 0x02,
    Receiving = 0x03,
    Ready     = 0x04,
}

// ── RequestReceipt ──

/// Tracks the status and response of a request sent over a Link.
pub struct RequestReceipt {
    pub request_id: [u8; 16],
    pub status: RequestReceiptStatus,
    pub response: Option<Vec<u8>>,
    pub sent_at: f64,
    pub timeout: f64,
    pub concluded_at: Option<f64>,
    pub response_concluded_at: Option<f64>,
    pub request_size: usize,
    response_callback: Option<Box<dyn Fn(&RequestReceipt) + Send + Sync>>,
    failed_callback: Option<Box<dyn Fn(&RequestReceipt) + Send + Sync>>,
}

impl RequestReceipt {
    pub fn get_status(&self) -> RequestReceiptStatus {
        self.status
    }

    pub fn get_response(&self) -> Option<&[u8]> {
        self.response.as_deref()
    }

    pub fn get_response_time(&self) -> Option<f64> {
        match (self.response_concluded_at, self.concluded_at) {
            (Some(resp), Some(conc)) => Some(resp - conc),
            _ => None,
        }
    }

    pub fn set_response_callback(
        &mut self,
        cb: Box<dyn Fn(&RequestReceipt) + Send + Sync>,
    ) {
        self.response_callback = Some(cb);
    }

    pub fn set_failed_callback(
        &mut self,
        cb: Box<dyn Fn(&RequestReceipt) + Send + Sync>,
    ) {
        self.failed_callback = Some(cb);
    }

    pub(crate) fn response_received(&mut self, response: Vec<u8>) {
        self.response = Some(response);
        self.status = RequestReceiptStatus::Ready;
        self.response_concluded_at = Some(now());
        if let Some(ref cb) = self.response_callback {
            cb(self);
        }
    }

    pub(crate) fn request_timed_out(&mut self) {
        self.status = RequestReceiptStatus::Failed;
        self.concluded_at = Some(now());
        if let Some(ref cb) = self.failed_callback {
            cb(self);
        }
    }
}

// ── Link request/response methods ──

impl Link {
    /// Send a request over the link.
    /// Builds msgpack [timestamp, path_hash, data], encrypts, sends as Request context.
    pub fn request(
        &self,
        path: &str,
        data: Option<&[u8]>,
        transport: &TransportState,
        timeout: Option<f64>,
    ) -> Result<RequestReceipt> {
        let status = self.read()?.status;
        if status != LinkStatus::Active {
            return Err(FerretError::LinkEstablishmentFailed(
                "link not active for request".into(),
            ));
        }

        let path_hash = Identity::truncated_hash(path.as_bytes());
        let timestamp = now();

        // Build msgpack: [timestamp_f64, path_hash, data]
        let request_payload: (f64, &[u8; 16], Option<&[u8]>) =
            (timestamp, &path_hash, data);
        let packed = crate::util::msgpack::serialize(&request_payload)?;

        let encrypted = self.encrypt(&packed)?;
        let request_size = encrypted.len();

        let mdu = self.read()?.mdu;
        if encrypted.len() <= mdu {
            // Fits in a single packet
            let mut packet = Packet::new(
                self as &dyn Encryptable,
                encrypted,
                PacketType::Data,
                PacketContext::Request,
                TransportType::Broadcast,
                HeaderType::Header1,
                None,
                false,
                ContextFlag::Unset,
            );
            packet.pack(self as &dyn Encryptable)?;
            transport.outbound(&mut packet)?;

            let mut inner = self.write()?;
            inner.last_outbound = now();
            inner.tx += 1;
            inner.txbytes += packet.raw.len() as u64;
        }
        // else: Resource transfer (deferred to Layer 5)

        let request_id = Identity::get_random_hash();
        let default_timeout = {
            let inner = self.read()?;
            inner.rtt.unwrap_or(10.0) * super::TRAFFIC_TIMEOUT_FACTOR as f64
        };

        let receipt = RequestReceipt {
            request_id,
            status: RequestReceiptStatus::Sent,
            response: None,
            sent_at: now(),
            timeout: timeout.unwrap_or(default_timeout),
            concluded_at: None,
            response_concluded_at: None,
            request_size,
            response_callback: None,
            failed_callback: None,
        };

        // Store receipt for response matching
        self.write()?.pending_requests.push(RequestReceipt {
            request_id: receipt.request_id,
            status: receipt.status,
            response: None,
            sent_at: receipt.sent_at,
            timeout: receipt.timeout,
            concluded_at: None,
            response_concluded_at: None,
            request_size: receipt.request_size,
            response_callback: None,
            failed_callback: None,
        });

        Ok(receipt)
    }

    /// Handle a received Request packet (responder side).
    pub(crate) fn handle_request(
        &self,
        packet: &Packet,
        transport: &TransportState,
    ) -> Result<()> {
        let plaintext = self.decrypt(&packet.data)?;
        let plaintext = match plaintext {
            Some(pt) => pt,
            None => return Ok(()),
        };

        // Unpack msgpack [timestamp, path_hash, request_data]
        let (timestamp, path_hash, request_data): (f64, [u8; 16], Option<Vec<u8>>) =
            crate::util::msgpack::deserialize(&plaintext)?;

        // Look up handler by path_hash in destination's request_handlers
        let owner = self.read()?.owner.clone();
        let owner = match owner {
            Some(o) => o,
            None => return Ok(()),
        };

        let response = {
            let owner_guard = owner
                .read()
                .map_err(|_| FerretError::Token("lock poisoned".into()))?;

            let handler = match owner_guard.get_request_handler(&path_hash) {
                Some(h) => h,
                None => return Ok(()),
            };

            let empty = Vec::new();
            let req_data = request_data.as_deref().unwrap_or(&empty);
            let link_id = self.read()?.link_id;

            (handler.response_generator)(
                &handler.path,
                &path_hash,
                req_data,
                &link_id,
                None,
                timestamp,
            )
        };

        // If response generated, send it back
        if let Some(response_data) = response {
            let request_id = Identity::get_random_hash();
            let response_payload: (&[u8; 16], &[u8]) = (&request_id, &response_data);
            let packed = crate::util::msgpack::serialize(&response_payload)?;
            let encrypted = self.encrypt(&packed)?;

            let mdu = self.read()?.mdu;
            if encrypted.len() <= mdu {
                let mut resp_packet = Packet::new(
                    self as &dyn Encryptable,
                    encrypted,
                    PacketType::Data,
                    PacketContext::Response,
                    TransportType::Broadcast,
                    HeaderType::Header1,
                    None,
                    false,
                    ContextFlag::Unset,
                );
                resp_packet.pack(self as &dyn Encryptable)?;
                transport.outbound(&mut resp_packet)?;

                let mut inner = self.write()?;
                inner.last_outbound = now();
                inner.tx += 1;
                inner.txbytes += resp_packet.raw.len() as u64;
            }
        }

        Ok(())
    }

    /// Handle a received Response packet (initiator side).
    pub(crate) fn handle_response(&self, packet: &Packet) -> Result<()> {
        let plaintext = self.decrypt(&packet.data)?;
        let plaintext = match plaintext {
            Some(pt) => pt,
            None => return Ok(()),
        };

        // Unpack msgpack [request_id, response_data]
        let (request_id, response_data): ([u8; 16], Vec<u8>) =
            crate::util::msgpack::deserialize(&plaintext)?;

        // Find matching RequestReceipt
        let mut inner = self.write()?;
        if let Some(receipt) = inner
            .pending_requests
            .iter_mut()
            .find(|r| r.request_id == request_id)
        {
            receipt.response_received(response_data);
        }

        Ok(())
    }
}
