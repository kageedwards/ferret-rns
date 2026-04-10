// Keepalive, stale detection, timeout logic

use crate::link::{
    LinkStatus, TeardownReason, KEEPALIVE_MAX, KEEPALIVE_MAX_RTT, KEEPALIVE_MIN, STALE_FACTOR,
};
use crate::packet::packet::Packet;
use crate::packet::Encryptable;
use crate::transport::transport::TransportState;
use crate::types::packet::{ContextFlag, HeaderType, PacketContext, PacketType};
use crate::types::transport::TransportType;
use crate::{Result};

use super::link::{now, Link};

/// Keepalive request byte (sent by initiator).
pub const KEEPALIVE_REQUEST: u8 = 0xFF;
/// Keepalive response byte (sent by responder).
pub const KEEPALIVE_RESPONSE: u8 = 0xFE;

/// Compute the keepalive interval from RTT.
/// Formula: clamp(RTT * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT), KEEPALIVE_MIN, KEEPALIVE_MAX)
pub fn compute_keepalive(rtt: f64) -> f64 {
    (rtt * (KEEPALIVE_MAX / KEEPALIVE_MAX_RTT)).clamp(KEEPALIVE_MIN, KEEPALIVE_MAX)
}

impl Link {
    /// Send a keepalive request (0xFF) encrypted with Keepalive context.
    pub fn send_keepalive(&self, transport: &TransportState) -> Result<()> {
        let status = self.read()?.status;
        if status != LinkStatus::Active && status != LinkStatus::Stale {
            return Ok(());
        }

        let data = vec![KEEPALIVE_REQUEST];

        let mut packet = Packet::new(
            self as &dyn Encryptable,
            data,
            PacketType::Data,
            PacketContext::Keepalive,
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
        inner.last_keepalive = now();
        inner.tx += 1;
        inner.txbytes += packet.raw.len() as u64;

        Ok(())
    }

    /// Handle an incoming keepalive packet.
    /// 0xFF = request → responder replies with 0xFE.
    /// 0xFE = response → treat as inbound traffic (no last_data update).
    pub fn handle_keepalive(
        &self,
        data: &[u8],
        transport: &TransportState,
    ) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        match data[0] {
            KEEPALIVE_REQUEST => {
                // Responder replies with 0xFE
                let response = vec![KEEPALIVE_RESPONSE];
                let mut packet = Packet::new(
                    self as &dyn Encryptable,
                    response,
                    PacketType::Data,
                    PacketContext::Keepalive,
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
            KEEPALIVE_RESPONSE => {
                // Initiator received response — inbound traffic already tracked
                // by receive(), no additional action needed here.
            }
            _ => {
                // Unknown keepalive byte, ignore
            }
        }

        Ok(())
    }

    /// Check if the link is stale (no inbound for keepalive * STALE_FACTOR).
    /// Returns true if the link transitioned to Stale.
    pub fn check_stale(&self) -> Result<bool> {
        let inner = self.read()?;
        if inner.status != LinkStatus::Active {
            return Ok(false);
        }
        let elapsed = now() - inner.last_inbound;
        let stale_threshold = inner.keepalive * STALE_FACTOR as f64;
        drop(inner);

        if elapsed > stale_threshold {
            let mut inner = self.write()?;
            if inner.status == LinkStatus::Active {
                inner.status = LinkStatus::Stale;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Check if establishment has timed out (Pending/Handshake exceeds timeout).
    /// Returns true if the link transitioned to Closed with Timeout reason.
    pub fn check_establishment_timeout(&self) -> Result<bool> {
        let inner = self.read()?;
        let status = inner.status;
        if status != LinkStatus::Pending && status != LinkStatus::Handshake {
            return Ok(false);
        }
        let request_time = inner.request_time.unwrap_or(now());
        let timeout = inner.establishment_timeout;
        drop(inner);

        let elapsed = now() - request_time;
        if elapsed > timeout {
            self.link_closed(TeardownReason::Timeout)?;
            return Ok(true);
        }
        Ok(false)
    }
}
