//! rnlink — Reticulum Raw Link Pipe (ferret-original).
//!
//! Establishes a raw bidirectional Link to a Reticulum destination and
//! pipes data through it. Similar to `netcat` for Reticulum Links.

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};

/// Reticulum Raw Link Pipe
#[derive(Parser)]
#[command(name = "rnlink", version, about = "Reticulum Raw Link Pipe")]
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

    /// Listen for incoming Link and pipe to stdin/stdout
    #[arg(short = 'l', long = "listen")]
    listen: bool,

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

    /// Announce interval in listener mode (0 = once at startup)
    #[arg(short = 'b', default_value = "0")]
    announce_interval: u32,
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
            println!("rnlink listener identity would be displayed here");
            return;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let shutdown = reticulum.shutdown.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            shutdown.store(true, Ordering::SeqCst);
        });

        println!("Listening for incoming Link... (Ctrl+C to stop)");
        // Placeholder: accept one Link, pipe stdin→Channel and Channel→stdout

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    } else if let Some(ref dest) = cli.destination {
        println!("Establishing Link to {}...", dest);
        // Placeholder: establish Link, pipe stdin→Channel and Channel→stdout
    } else {
        eprintln!("Usage: rnlink [OPTIONS] <destination>");
        eprintln!("       rnlink [OPTIONS] -l (listen mode)");
        process::exit(1);
    }
}
