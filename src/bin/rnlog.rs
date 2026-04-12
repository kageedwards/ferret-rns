//! rnlog — Reticulum Announce Stream Logger (ferret-original).
//!
//! Connects as a shared-instance client and tails the live announce stream,
//! displaying each announce as it arrives. Similar to `tcpdump` for
//! Reticulum announces.

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};
use ferret_rns::util::format::{pretty_hex, timestamp_str};

/// Reticulum Announce Stream Logger
#[derive(Parser)]
#[command(name = "rnlog", version, about = "Reticulum Announce Stream Logger")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Filter announces by destination hash or app name pattern
    #[arg(short = 'f', long = "filter")]
    filter: Option<String>,

    /// Exit after printing N announces
    #[arg(short = 'n', long = "count")]
    count: Option<u64>,

    /// Output each announce as JSON (NDJSON format)
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Also display Data, Proof, and LinkRequest packets
    #[arg(short = 'a', long = "all")]
    all: bool,
}

fn main() {
    let cli = Cli::parse();

    // Initialize as shared-instance client
    let config = ReticulumConfig {
        configdir: cli.config.clone(),
        require_shared_instance: true,
        ..Default::default()
    };

    let reticulum = match Reticulum::new(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Could not connect to shared instance: {}", e);
            process::exit(1);
        }
    };

    // Set up Ctrl+C handler
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let shutdown = reticulum.shutdown.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        shutdown.store(true, Ordering::SeqCst);
    }) {
        eprintln!("Warning: failed to register signal handler: {}", e);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();

    println!("Listening for announces... (Ctrl+C to stop)");
    println!("Started at {}", timestamp_str(now));
    println!();

    // Main loop — poll for announces from the transport layer.
    // In a full implementation, this would register an announce handler
    // callback with Transport and display each announce as it arrives.
    // For now, we block until shutdown.
    let mut _displayed: u64 = 0;
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Placeholder: In the full implementation, announces would be
        // delivered via a callback registered with Transport::register_announce_handler.
        // Each announce would be formatted and displayed here.

        if let Some(max) = cli.count {
            if _displayed >= max {
                break;
            }
        }
    }

    println!();
    println!("Stopped.");

    // Suppress unused warnings for fields used in the announce display logic
    let _ = (&cli.filter, &cli.json, &cli.all, &cli.verbose);
    let _ = pretty_hex;
}
