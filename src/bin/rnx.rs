//! rnx — Reticulum Remote Execution Utility.
//!
//! Executes commands on a remote Reticulum node via Links.
//! Supports send, listen, and interactive REPL modes.

use std::path::PathBuf;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};

/// Reticulum Remote Execution Utility
#[derive(Parser)]
#[command(name = "rnx", version, about = "Reticulum Remote Execution Utility")]
struct Cli {
    /// Hexadecimal hash of the destination
    destination: Option<String>,

    /// Command to execute remotely
    command: Option<String>,

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

    /// Listen for incoming command execution requests
    #[arg(short = 'l', long = "listen")]
    listen: bool,

    /// Enter interactive mode (REPL)
    #[arg(short = 'x', long = "interactive")]
    interactive: bool,

    /// Allow this identity hash (repeatable)
    #[arg(short = 'a')]
    allowed: Vec<String>,

    /// Accept requests from anyone
    #[arg(short = 'n', long = "noauth")]
    no_auth: bool,

    /// Skip identifying to the listener
    #[arg(short = 'N', long = "noid")]
    no_id: bool,

    /// Show detailed result output
    #[arg(short = 'd', long = "detailed")]
    detailed: bool,

    /// Mirror the exit code of the remote command
    #[arg(short = 'm')]
    mirror_exit: bool,

    /// Connection/request timeout (seconds)
    #[arg(short = 'w', default_value = "15")]
    timeout: f64,

    /// Maximum result download time (seconds)
    #[arg(short = 'W', default_value = "0")]
    max_result_time: f64,

    /// Pass input to remote command's stdin
    #[arg(long = "stdin")]
    stdin_data: Option<String>,

    /// Limit stdout output size (bytes)
    #[arg(long = "stdout")]
    stdout_limit: Option<usize>,

    /// Limit stderr output size (bytes)
    #[arg(long = "stderr")]
    stderr_limit: Option<usize>,

    /// Skip announcing at startup in listener mode
    #[arg(short = 'b', long = "no-announce")]
    no_announce: bool,

    /// Print identity and destination info and exit
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
            println!("rnx listener identity would be displayed here");
            return;
        }

        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        let shutdown = reticulum.shutdown.clone();
        let _ = ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
            shutdown.store(true, Ordering::SeqCst);
        });

        println!("Listening for command execution requests... (Ctrl+C to stop)");

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    } else if cli.interactive {
        println!("Interactive REPL mode: would establish Link and enter command loop");
        // Placeholder: establish Link, loop reading stdin, send as requests
    } else if cli.destination.is_some() && cli.command.is_some() {
        let dest = cli.destination.as_ref().unwrap();
        let cmd = cli.command.as_ref().unwrap();
        println!("Executing '{}' on {}...", cmd, dest);
        // Placeholder: establish Link, identify, send command via request
    } else {
        eprintln!("Usage: rnx [OPTIONS] <destination> <command>");
        eprintln!("       rnx [OPTIONS] -l (listen mode)");
        process::exit(1);
    }
}
