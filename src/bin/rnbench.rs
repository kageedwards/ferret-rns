//! rnbench — Reticulum Network Benchmark (ferret-original).
//!
//! Measures throughput and latency between two Reticulum nodes.
//! Similar to `iperf` for Reticulum.

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};

/// Reticulum Network Benchmark
#[derive(Parser)]
#[command(name = "rnbench", version, about = "Reticulum Network Benchmark")]
struct Cli {
    /// Hexadecimal hash of the destination
    destination: Option<String>,

    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Path to identity to use
    #[arg(short = 'i')]
    identity: Option<PathBuf>,

    /// Listen for incoming benchmark sessions
    #[arg(short = 'l', long = "listen")]
    listen: bool,

    /// Total payload size to transfer (bytes)
    #[arg(short = 's', long = "size", default_value = "65536")]
    size: usize,

    /// Per-message block size (bytes)
    #[arg(short = 'b', long = "block", default_value = "1024")]
    block: usize,

    /// Run a timed benchmark instead of fixed-size
    #[arg(short = 'd', long = "duration")]
    duration: Option<f64>,

    /// Number of benchmark rounds
    #[arg(short = 'r', long = "rounds", default_value = "1")]
    rounds: u32,

    /// Output results as JSON
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Link establishment timeout (seconds)
    #[arg(short = 'w', default_value = "15")]
    timeout: f64,

    /// Allow this identity hash (repeatable)
    #[arg(short = 'a')]
    allowed: Vec<String>,

    /// Accept from anyone
    #[arg(short = 'n', long = "no-auth")]
    no_auth: bool,

    /// Print listener's destination hash and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,
}

fn main() {
    let cli = Cli::parse();

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

    if cli.listen || cli.print_identity {
        if cli.print_identity {
            println!("rnbench listener identity would be displayed here");
            return;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let shutdown = reticulum.shutdown.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            shutdown.store(true, Ordering::SeqCst);
        });

        println!("Listening for benchmark sessions... (Ctrl+C to stop)");

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    } else if let Some(ref dest) = cli.destination {
        println!(
            "Benchmarking to {} ({} bytes, {} byte blocks, {} rounds)...",
            dest, cli.size, cli.block, cli.rounds
        );
        // Placeholder: establish Link, transfer payload, measure throughput/RTT
        // Display: bytes transferred, elapsed, throughput, avg/min/max RTT, packet loss
    } else {
        eprintln!("Usage: rnbench [OPTIONS] <destination>");
        eprintln!("       rnbench [OPTIONS] -l (listen mode)");
        process::exit(1);
    }
}
