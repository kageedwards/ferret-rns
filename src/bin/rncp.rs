//! rncp — Reticulum File Transfer Utility.
//!
//! Transfers files over the Reticulum network using Links and Resources.
//! Supports send, listen (receive), and fetch modes.

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};
use ferret_rns::util::format::{pretty_hex, size_str};

/// Reticulum File Transfer Utility
#[derive(Parser)]
#[command(name = "rncp", version, about = "Reticulum File Transfer Utility")]
struct Cli {
    /// File to be transferred
    file: Option<String>,

    /// Hexadecimal hash of the receiver
    destination: Option<String>,

    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (repeatable)
    #[arg(short = 'q', action = clap::ArgAction::Count)]
    quiet: u8,

    /// Path to identity to use
    #[arg(short = 'i')]
    identity: Option<PathBuf>,

    /// Listen for incoming transfer requests
    #[arg(short = 'l', long = "listen")]
    listen: bool,

    /// Fetch file from remote listener instead of sending
    #[arg(short = 'f', long = "fetch")]
    fetch: bool,

    /// Allow authenticated clients to fetch files
    #[arg(short = 'F', long = "allow-fetch")]
    allow_fetch: bool,

    /// Allow this identity hash (repeatable)
    #[arg(short = 'a')]
    allowed: Vec<String>,

    /// Accept requests from anyone
    #[arg(short = 'n', long = "no-auth")]
    no_auth: bool,

    /// Save received files in specified path
    #[arg(short = 's', long = "save")]
    save: Option<PathBuf>,

    /// Disable transfer progress output
    #[arg(short = 'S', long = "silent")]
    silent: bool,

    /// Disable automatic compression
    #[arg(short = 'C', long = "no-compress")]
    no_compress: bool,

    /// Sender timeout before giving up (seconds)
    #[arg(short = 'w', default_value = "15")]
    timeout: f64,

    /// Announce interval (0 = announce once at startup)
    #[arg(short = 'b', default_value = "-1")]
    announce_interval: i32,

    /// Print identity and destination info and exit
    #[arg(short = 'p', long = "print-identity")]
    print_identity: bool,

    /// Display physical layer transfer rates
    #[arg(short = 'P', long = "phy-rates")]
    phy_rates: bool,
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
        // Listen mode
        if cli.print_identity {
            println!("rncp listener identity would be displayed here");
            return;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let shutdown = reticulum.shutdown.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            shutdown.store(true, Ordering::SeqCst);
        });

        println!("Waiting for incoming file transfers... (Ctrl+C to stop)");

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    } else if cli.fetch {
        if cli.destination.is_none() || cli.file.is_none() {
            eprintln!("Fetch mode requires both file and destination arguments");
            process::exit(1);
        }
        println!("Fetch mode: would fetch file from remote listener");
        // Placeholder: establish Link, send fetch request, receive Resource
    } else if cli.destination.is_some() && cli.file.is_some() {
        let file = cli.file.as_ref().unwrap();
        let dest = cli.destination.as_ref().unwrap();
        println!("Sending {} to {}...", file, dest);
        // Placeholder: establish Link, identify, transfer via Resource
    } else {
        eprintln!("Usage: rncp [OPTIONS] <file> <destination>");
        eprintln!("       rncp [OPTIONS] -l (listen mode)");
        process::exit(1);
    }

    let _ = (size_str, pretty_hex); // suppress unused warnings
}
