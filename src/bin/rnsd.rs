//! rnsd — Reticulum Network Stack Daemon.
//!
//! This is the primary daemon binary. It initializes a Reticulum shared
//! instance and blocks until interrupted by SIGINT or SIGTERM.

use std::path::PathBuf;
use std::process;

use clap::Parser;
use ferret_rns::reticulum::logging::LogDestination;
use ferret_rns::reticulum::{Reticulum, ReticulumConfig};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reticulum Network Stack Daemon
#[derive(Parser)]
#[command(name = "rnsd", version, about = "Ferret - Reticulum Network Stack Daemon")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (repeatable)
    #[arg(short = 'q', action = clap::ArgAction::Count)]
    quiet: u8,

    /// Run as service (log to file instead of stdout)
    #[arg(short = 's', long = "service")]
    service: bool,

    /// Print verbose example configuration to stdout and exit
    #[arg(long = "exampleconfig")]
    exampleconfig: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.exampleconfig {
        print!("{}", EXAMPLE_CONFIG);
        return;
    }

    let verbosity = cli.verbose as i8 - cli.quiet as i8;

    let log_dest = if cli.service {
        // When running as a service, log to file. The Reticulum init
        // will resolve the actual log file path from the config dir.
        LogDestination::File(PathBuf::from(""))
    } else {
        LogDestination::Stdout
    };

    let config = ReticulumConfig {
        configdir: cli.config,
        loglevel: None,
        verbosity: Some(verbosity),
        log_destination: log_dest,
        require_shared_instance: false,
    };

    let reticulum = match Reticulum::new(config) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Fatal: {}", e);
            process::exit(1);
        }
    };

    if reticulum.is_connected_to_shared_instance {
        ferret_rns::log_warning!(
            "Started Ferret rnsd version {} connected to another shared local instance, \
             this is probably NOT what you want!",
            VERSION
        );
    } else {
        ferret_rns::log_notice!("Started Ferret rnsd version {}", VERSION);
    }

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
    process::exit(0);
}

const EXAMPLE_CONFIG: &str = r#"# This is an example Reticulum config file.
# You should probably edit it to include any additional
# interfaces and settings you might need.

[reticulum]

# If you enable Transport, your system will route traffic
# for other peers, pass announces and serve path requests.

enable_transport = No

# By default, the first program to launch the Reticulum
# Network Stack will create a shared instance, that other
# programs can communicate with.

share_instance = Yes

# If you want to run multiple *different* shared instances
# on the same system, you will need to specify different
# instance names for each.

instance_name = default

# shared_instance_port = 37428
# instance_control_port = 37429

# respond_to_probes = No

[logging]
# Valid log levels are 0 through 7:
#   0: Log only critical information
#   1: Log errors and lower log levels
#   2: Log warnings and lower log levels
#   3: Log notices and lower log levels
#   4: Log info and lower (this is the default)
#   5: Verbose logging
#   6: Debug logging
#   7: Extreme logging

loglevel = 4

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = yes

  [[TCP Server Interface]]
    type = TCPServerInterface
    enabled = no
    listen_ip = 0.0.0.0
    listen_port = 4242

  [[TCP Client Interface]]
    type = TCPClientInterface
    enabled = no
    target_host = 127.0.0.1
    target_port = 4242

  [[UDP Interface]]
    type = UDPInterface
    enabled = no
    listen_ip = 0.0.0.0
    listen_port = 4242
    forward_ip = 255.255.255.255
    forward_port = 4242

  [[RNode LoRa Interface]]
    type = RNodeInterface
    enabled = no
    port = /dev/ttyUSB0
    frequency = 867200000
    bandwidth = 125000
    txpower = 7
    spreadingfactor = 8
    codingrate = 5
"#;
