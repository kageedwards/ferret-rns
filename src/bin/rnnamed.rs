//! rnnamed — Reticulum Human-Readable Name Service (ferret-original).
//!
//! Client CLI for looking up and registering names, plus a standalone
//! resolver daemon mode.

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};

/// Reticulum Name Service
#[derive(Parser)]
#[command(name = "rnnamed", version, about = "Reticulum Human-Readable Name Service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config", global = true)]
    config: Option<PathBuf>,

    /// Path to identity to use
    #[arg(short = 'i', global = true)]
    identity: Option<PathBuf>,

    /// Resolver destination hash to query
    #[arg(long = "resolver", global = true)]
    resolver: Option<String>,

    /// Output results as JSON
    #[arg(short = 'j', long = "json", global = true)]
    json: bool,

    /// Start in standalone resolver daemon mode
    #[arg(short = 'l', long = "listen", global = true)]
    listen: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Resolve a name to a destination hash
    Lookup { name: String },
    /// Register a name for a destination hash
    Register { name: String, dest_hash: String },
    /// List all locally cached name records
    List,
}

fn main() {
    let cli = Cli::parse();

    if cli.listen {
        run_resolver(&cli);
        return;
    }

    match &cli.command {
        Some(Commands::Lookup { name }) => {
            println!("Looking up '{}'...", name);
            // Placeholder: connect to resolver via Link, send lookup request
            println!("Name resolution requires a running resolver instance");
        }
        Some(Commands::Register { name, dest_hash }) => {
            println!("Registering '{}' -> {}...", name, dest_hash);
            // Placeholder: compute PoW stamp, sign record, submit to resolver
            println!("Registration requires a running resolver instance and identity (-i)");
        }
        Some(Commands::List) => {
            println!("Locally cached name records:");
            println!("(none)");
        }
        None => {
            if !cli.listen {
                eprintln!("Usage: rnnamed <lookup|register|list> or rnnamed -l (resolver mode)");
                process::exit(1);
            }
        }
    }
}

fn run_resolver(cli: &Cli) {
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

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let shutdown = reticulum.shutdown.clone();
    let _ = ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        shutdown.store(true, Ordering::SeqCst);
    });

    println!("Name resolver running... (Ctrl+C to stop)");
    // Placeholder: register resolver destination, accept Link requests

    while running.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    println!("Resolver stopped.");
}
