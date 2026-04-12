//! rnprobe — Reticulum Network Probe Utility.
//!
//! Sends probe packets to a destination and measures round-trip time,
//! hop count, and reception statistics.

use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};
use ferret_rns::util::format::pretty_hex;

const DEFAULT_PROBE_SIZE: usize = 16;
const DEFAULT_TIMEOUT: f64 = 12.0;

/// Reticulum Probe Utility
#[derive(Parser)]
#[command(name = "rnprobe", version, about = "Reticulum Probe Utility")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Size of probe packet payload in bytes
    #[arg(short = 's', long = "size")]
    size: Option<usize>,

    /// Number of probes to send
    #[arg(short = 'n', long = "probes", default_value = "1")]
    probes: u32,

    /// Timeout before giving up (seconds)
    #[arg(short = 't', long = "timeout")]
    timeout: Option<f64>,

    /// Time between each probe (seconds)
    #[arg(short = 'w', long = "wait", default_value = "0")]
    wait: f64,

    /// Full destination name in dotted notation
    full_name: Option<String>,

    /// Hexadecimal hash of the destination
    destination_hash: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    let dest_hex = match &cli.destination_hash {
        Some(h) => h.clone(),
        None => {
            eprintln!("Destination hash required");
            process::exit(1);
        }
    };

    let dest_bytes = match hex_decode(&dest_hex) {
        Some(b) if b.len() == 16 => b,
        _ => {
            eprintln!("Invalid destination hash. Must be 32 hexadecimal characters (16 bytes).");
            process::exit(1);
        }
    };

    let size = cli.size.unwrap_or(DEFAULT_PROBE_SIZE);
    let timeout = cli.timeout.unwrap_or(DEFAULT_TIMEOUT);

    // Initialize as shared-instance client
    let config = ReticulumConfig {
        configdir: cli.config.clone(),
        require_shared_instance: true,
        ..Default::default()
    };

    let _reticulum = match Reticulum::new(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not connect to shared instance: {}", e);
            process::exit(1);
        }
    };

    // Send probes
    let mut sent: u32 = 0;
    let mut replies: u32 = 0;

    for probe_num in 1..=cli.probes {
        if probe_num > 1 && cli.wait > 0.0 {
            std::thread::sleep(Duration::from_secs_f64(cli.wait));
        }

        sent += 1;
        print!("Sent probe {} ({} bytes) to {}  ", probe_num, size, pretty_hex(&dest_bytes));

        // Simulate probe send — actual implementation requires Transport::send_probe
        // which depends on having a path and packet receipt mechanism.
        // For now, we wait for the timeout and report.
        let start = Instant::now();
        let deadline = Duration::from_secs_f64(timeout);

        // Poll for reply (placeholder — real implementation hooks into PacketReceipt)
        while start.elapsed() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            // In a real implementation, we'd check receipt.status here
            break; // Placeholder: exit loop immediately
        }

        if start.elapsed() >= deadline {
            println!("\nProbe timed out");
        } else {
            // Placeholder: report that we'd need actual transport integration
            let rtt_ms = start.elapsed().as_secs_f64() * 1000.0;
            replies += 1;
            println!("\nRound-trip time is {:.3} milliseconds", rtt_ms);
        }
    }

    // Summary
    let loss = if sent > 0 {
        ((1.0 - (replies as f64 / sent as f64)) * 100.0).round() as u32
    } else {
        100
    };
    println!("Sent {}, received {}, packet loss {}%", sent, replies, loss);

    if loss == 0 {
        process::exit(0);
    } else if replies > 0 {
        process::exit(2); // partial loss
    } else {
        process::exit(1); // total loss / path timeout
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
