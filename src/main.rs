use std::path::PathBuf;
use std::process;

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};

/// Ferret — Rust implementation of the Reticulum Network Stack.
#[derive(Parser)]
#[command(name = "ferret", version, about)]
struct Cli {
    /// Path to the configuration directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Log level (0-7)
    #[arg(short = 'l', long = "loglevel")]
    loglevel: Option<u8>,

    /// Increase verbosity
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    let config = ReticulumConfig {
        configdir: cli.config,
        loglevel: cli.loglevel,
        verbosity: if cli.verbose { Some(1) } else { None },
        ..Default::default()
    };

    let reticulum = match Reticulum::new(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Fatal: {}", e);
            process::exit(1);
        }
    };

    // Register signal handler — sets the shutdown flag on SIGINT/SIGTERM.
    let shutdown = reticulum.shutdown.clone();
    if let Err(e) = ctrlc::set_handler(move || {
        shutdown.store(true, std::sync::atomic::Ordering::SeqCst);
    }) {
        eprintln!("Warning: failed to register signal handler: {}", e);
    }

    // Block until shutdown is signalled.
    while !reticulum.shutdown.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    reticulum.exit_handler();

    // Force process exit — background threads with blocking socket reads
    // won't notice the shutdown flag until their sockets close. The exit
    // handler has already persisted all state, so it's safe to exit now.
    // This matches the Python reference which calls os._exit(0).
    process::exit(0);
}
