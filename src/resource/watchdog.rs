// Resource watchdog: timeout computation, check, and handling logic
//
// These are pure computation methods — no background threads.
// The actual watchdog loop would be driven externally.

use crate::resource::resource::Resource;
use crate::resource::{
    ResourceStatus, MAX_RETRIES, PART_TIMEOUT_FACTOR,
    PER_RETRY_DELAY, PROCESSING_GRACE, PROOF_TIMEOUT_FACTOR, RETRY_GRACE_TIME,
    SENDER_GRACE_TIME, WATCHDOG_MAX_SLEEP,
};
use crate::transport::transport::TransportState;
use crate::Result;

impl Resource {
    /// Compute the watchdog timeout for the current resource state.
    ///
    /// Returns the number of seconds to wait before the resource should
    /// be considered timed out.
    pub fn compute_watchdog_timeout(&self) -> f64 {
        match self.status {
            ResourceStatus::Advertised => {
                // Wait for timeout + processing grace
                self.timeout + PROCESSING_GRACE
            }
            ResourceStatus::Transferring if !self.initiator => {
                // Receiver: compute expected time-of-flight for outstanding parts
                let eifr = self.eifr.unwrap_or(1.0).max(1.0);
                let expected_tof =
                    (self.outstanding_parts as f64 * self.sdu as f64 * 8.0) / eifr;
                let retries_used = MAX_RETRIES.saturating_sub(self.retries_left);
                let per_retry = PER_RETRY_DELAY * retries_used as f64;
                PART_TIMEOUT_FACTOR as f64 * expected_tof + RETRY_GRACE_TIME + per_retry
            }
            ResourceStatus::Transferring => {
                // Initiator: wait for RTT * timeout_factor * max_retries + grace
                let rtt = self.rtt.unwrap_or(self.timeout);
                let retries_used = MAX_RETRIES.saturating_sub(self.retries_left);
                let cumulative_delay = PER_RETRY_DELAY * retries_used as f64;
                rtt * self.timeout_factor * self.max_retries as f64
                    + SENDER_GRACE_TIME
                    + cumulative_delay
            }
            ResourceStatus::AwaitingProof => {
                // Wait for RTT * proof timeout factor + grace
                let rtt = self.rtt.unwrap_or(self.timeout);
                rtt * PROOF_TIMEOUT_FACTOR as f64 + SENDER_GRACE_TIME
            }
            _ => {
                // For other states, use a default large timeout
                WATCHDOG_MAX_SLEEP
            }
        }
    }

    /// Check if the resource has timed out based on elapsed time since
    /// last activity.
    ///
    /// Returns true if the resource has exceeded its computed timeout.
    pub fn check_timeout(&self) -> bool {
        let elapsed = crate::link::link::now() - self.last_activity;
        let timeout = self.compute_watchdog_timeout();
        elapsed > timeout
    }

    /// Compute the watchdog sleep interval, capped at WATCHDOG_MAX_SLEEP.
    pub fn watchdog_sleep_interval(&self) -> f64 {
        let timeout = self.compute_watchdog_timeout();
        let elapsed = crate::link::link::now() - self.last_activity;
        let remaining = (timeout - elapsed).max(0.0);
        remaining.min(WATCHDOG_MAX_SLEEP)
    }

    /// Handle a timeout event based on the current resource state.
    ///
    /// - Advertised: retry advertisement up to MAX_ADV_RETRIES, then cancel
    /// - Transferring (receiver): retry request_next, decrement retries, shrink window
    /// - Transferring (initiator): cancel
    /// - AwaitingProof: retry up to 3 times, then cancel
    pub fn handle_timeout(
        &mut self,
        transport: &TransportState,
    ) -> Result<()> {
        match self.status {
            ResourceStatus::Advertised => {
                if self.max_adv_retries > 0 {
                    self.max_adv_retries -= 1;
                    // Retry advertisement
                    self.advertise(transport)?;
                } else {
                    // Exhausted retries — cancel
                    self.cancel(transport)?;
                }
            }
            ResourceStatus::Transferring if !self.initiator => {
                // Receiver: retry request, shrink window
                if self.retries_left > 0 {
                    self.retries_left -= 1;
                    self.shrink_window();
                    self.request_next(transport)?;
                    self.last_activity = crate::link::link::now();
                } else {
                    // Exhausted retries — fail
                    self.status = ResourceStatus::Failed;
                    if let Some(ref cb) = self.callback {
                        cb(self);
                    }
                }
            }
            ResourceStatus::Transferring => {
                // Initiator: cancel on timeout
                self.cancel(transport)?;
            }
            ResourceStatus::AwaitingProof => {
                // Retry up to 3 times (using retries_left as counter),
                // then cancel
                if self.retries_left > 0 {
                    self.retries_left -= 1;
                    // TODO: query cache for proof when cache API is available
                    self.last_activity = crate::link::link::now();
                } else {
                    self.cancel(transport)?;
                }
            }
            _ => {
                // No timeout handling for other states
            }
        }
        Ok(())
    }
}
