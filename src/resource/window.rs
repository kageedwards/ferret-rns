// Resource window adaptation: EIFR, RTT smoothing, grow/shrink, rate tiers

use crate::resource::resource::Resource;
use crate::resource::{
    FAST_RATE_THRESHOLD, RATE_FAST, RATE_VERY_SLOW, VERY_SLOW_RATE_THRESHOLD,
    WINDOW_FLEXIBILITY, WINDOW_MAX_FAST, WINDOW_MAX_VERY_SLOW,
};

impl Resource {
    /// Update the Estimated Inflight Rate (EIFR) from current rate measurements.
    ///
    /// Computes req_data_rtt_rate from bytes received during the round divided
    /// by the round RTT, then converts to bits/sec for EIFR.
    pub fn update_eifr(&mut self) {
        self.previous_eifr = self.eifr;

        // Try to compute from request data round-trip rate
        if let (Some(req_sent), Some(rtt)) = (self.req_sent, self.rtt) {
            let round_rtt = rtt.max(0.001); // avoid division by zero
            let bytes_this_round = self.rtt_rxd_bytes
                .saturating_sub(self.rtt_rxd_bytes_at_part_req);

            if bytes_this_round > 0 {
                self.req_data_rtt_rate = bytes_this_round as f64 / round_rtt;
                self.eifr = Some(self.req_data_rtt_rate * 8.0);
                return;
            }

            // Try req_resp_rtt_rate from first response
            if let Some(req_resp) = self.req_resp {
                let resp_rtt = (req_resp - req_sent).max(0.001);
                if resp_rtt > 0.0 && self.req_sent_bytes > 0 {
                    self.req_resp_rtt_rate =
                        self.req_sent_bytes as f64 / resp_rtt;
                    self.eifr = Some(self.req_resp_rtt_rate * 8.0);
                    return;
                }
            }
        }

        // Fall back to previous EIFR
        if self.previous_eifr.is_some() {
            self.eifr = self.previous_eifr;
            return;
        }

        // Fall back to Link estimate: (establishment_cost * 8) / link_rtt
        if let Ok(link_rtt) = self.link.rtt() {
            if let Some(rtt) = link_rtt {
                if rtt > 0.0 {
                    // Use a rough estimate from link establishment
                    let est_cost = self.sdu as f64; // approximate
                    self.eifr = Some((est_cost * 8.0) / rtt);
                }
            }
        }
    }

    /// Update RTT with exponential smoothing (±5% max change per update).
    ///
    /// If new_rtt < current_rtt: updated = max(current * 0.95, new_rtt)
    /// If new_rtt > current_rtt: updated = min(current * 1.05, new_rtt)
    /// Falls back to Link RTT if no current RTT is set.
    pub fn update_rtt(&mut self, new_rtt: f64) {
        if new_rtt <= 0.0 {
            return;
        }

        match self.rtt {
            Some(current) if current > 0.0 => {
                let updated = if new_rtt < current {
                    (current * 0.95).max(new_rtt)
                } else {
                    (current * 1.05).min(new_rtt)
                };
                self.rtt = Some(updated);
            }
            _ => {
                // No current RTT — try Link RTT, else use new_rtt directly
                if let Ok(Some(link_rtt)) = self.link.rtt() {
                    if link_rtt > 0.0 {
                        // Apply smoothing from link RTT
                        let updated = if new_rtt < link_rtt {
                            (link_rtt * 0.95).max(new_rtt)
                        } else {
                            (link_rtt * 1.05).min(new_rtt)
                        };
                        self.rtt = Some(updated);
                    } else {
                        self.rtt = Some(new_rtt);
                    }
                } else {
                    self.rtt = Some(new_rtt);
                }
            }
        }
    }

    /// Grow window after a successful round.
    ///
    /// Increases window by 1 up to window_max.
    /// Increases window_min by 1 if (window - window_min) > (window_flexibility - 1).
    pub fn grow_window(&mut self) {
        if self.window < self.window_max {
            self.window += 1;
        }
        if self.window.saturating_sub(self.window_min)
            > WINDOW_FLEXIBILITY.saturating_sub(1)
        {
            self.window_min += 1;
        }
    }

    /// Shrink window after a timeout.
    ///
    /// Decreases window by 1 down to window_min.
    /// Decreases window_max by 1, but never below
    /// (window + window_flexibility - 1) to maintain the minimum gap.
    pub fn shrink_window(&mut self) {
        if self.window > self.window_min {
            self.window -= 1;
        }
        let min_max = self.window + WINDOW_FLEXIBILITY.saturating_sub(1);
        if self.window_max > min_max {
            self.window_max -= 1;
            // Don't drop below the minimum gap
            if self.window_max < min_max {
                self.window_max = min_max;
            }
        }
    }

    /// Check and apply fast/very-slow rate tier thresholds.
    ///
    /// If EIFR > RATE_FAST * 8 for FAST_RATE_THRESHOLD consecutive rounds:
    ///   set window_max = WINDOW_MAX_FAST
    /// If EIFR < RATE_VERY_SLOW * 8 for VERY_SLOW_RATE_THRESHOLD consecutive rounds:
    ///   set window_max = WINDOW_MAX_VERY_SLOW
    pub fn update_rate_tier(&mut self) {
        let eifr = match self.eifr {
            Some(e) => e,
            None => return,
        };

        let fast_threshold_bps = (RATE_FAST * 8) as f64;
        let very_slow_threshold_bps = (RATE_VERY_SLOW * 8) as f64;

        // Track fast rate rounds
        if eifr > fast_threshold_bps {
            self.fast_rate_rounds += 1;
            self.very_slow_rate_rounds = 0;
        } else if eifr < very_slow_threshold_bps {
            self.very_slow_rate_rounds += 1;
            self.fast_rate_rounds = 0;
        } else {
            self.fast_rate_rounds = 0;
            self.very_slow_rate_rounds = 0;
        }

        // Apply tier changes
        if self.fast_rate_rounds >= FAST_RATE_THRESHOLD {
            self.window_max = WINDOW_MAX_FAST;
        } else if self.very_slow_rate_rounds >= VERY_SLOW_RATE_THRESHOLD {
            self.window_max = WINDOW_MAX_VERY_SLOW;
            // Clamp window down if it exceeds new max
            if self.window > self.window_max {
                self.window = self.window_max;
            }
            // Clamp window_min if needed
            if self.window_min > self.window {
                self.window_min = self.window;
            }
        }
    }
}
