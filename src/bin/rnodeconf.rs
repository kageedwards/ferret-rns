//! rnodeconf — RNode Hardware Configuration Utility.
//!
//! Configures RNode LoRa transceivers via KISS protocol over serial.
//! Requires the `serial` feature.

use std::path::PathBuf;
use std::process;

use clap::Parser;

/// RNode Hardware Configuration Utility
#[derive(Parser)]
#[command(name = "rnodeconf", version, about = "RNode Hardware Configuration Utility")]
struct Cli {
    /// Serial device path
    port: Option<String>,

    /// Set frequency (Hz)
    #[arg(long = "freq")]
    freq: Option<u64>,

    /// Set bandwidth (Hz)
    #[arg(long = "bw")]
    bw: Option<u32>,

    /// Set TX power (dBm)
    #[arg(long = "txp")]
    txp: Option<i8>,

    /// Set spreading factor
    #[arg(long = "sf")]
    sf: Option<u8>,

    /// Set coding rate
    #[arg(long = "cr")]
    cr: Option<u8>,

    /// Automatically detect and flash firmware
    #[arg(long = "autoinstall")]
    autoinstall: bool,

    /// Display current configuration and firmware version
    #[arg(long = "info")]
    info: bool,

    /// Update firmware on connected RNode
    #[arg(long = "firmware-update")]
    firmware_update: bool,

    /// Erase device EEPROM
    #[arg(long = "eeprom-wipe")]
    eeprom_wipe: bool,

    /// Enable Bluetooth
    #[arg(long = "bluetooth-on")]
    bluetooth_on: bool,

    /// Disable Bluetooth
    #[arg(long = "bluetooth-off")]
    bluetooth_off: bool,

    /// Pair Bluetooth
    #[arg(long = "bluetooth-pair")]
    bluetooth_pair: bool,

    /// Set display intensity
    #[arg(long = "display-intensity")]
    display_intensity: Option<u8>,

    /// Set display rotation
    #[arg(long = "display-rotation")]
    display_rotation: Option<u16>,
}

fn main() {
    let cli = Cli::parse();

    let port = match &cli.port {
        Some(p) => p.clone(),
        None => {
            if !cli.autoinstall {
                eprintln!("Serial port required. Usage: rnodeconf <port> [OPTIONS]");
                process::exit(1);
            }
            String::new()
        }
    };

    if cli.info {
        println!("Querying RNode on {}...", port);
        // Placeholder: open serial, send KISS info command, display response
        println!("RNode info display requires serial connection to device");
        return;
    }

    if cli.autoinstall {
        println!("Auto-installing firmware...");
        // Placeholder: detect device, flash firmware
        println!("Firmware auto-install requires connected RNode device");
        return;
    }

    if cli.firmware_update {
        println!("Updating firmware on {}...", port);
        // Placeholder: flash firmware update
        return;
    }

    if cli.eeprom_wipe {
        println!("Wiping EEPROM on {}...", port);
        // Placeholder: send EEPROM wipe command
        return;
    }

    // Radio parameter configuration
    let has_radio_params = cli.freq.is_some() || cli.bw.is_some()
        || cli.txp.is_some() || cli.sf.is_some() || cli.cr.is_some();

    if has_radio_params {
        println!("Configuring radio parameters on {}...", port);
        if let Some(f) = cli.freq { println!("  Frequency: {} Hz", f); }
        if let Some(b) = cli.bw { println!("  Bandwidth: {} Hz", b); }
        if let Some(t) = cli.txp { println!("  TX Power: {} dBm", t); }
        if let Some(s) = cli.sf { println!("  Spreading Factor: {}", s); }
        if let Some(c) = cli.cr { println!("  Coding Rate: {}", c); }
        // Placeholder: send KISS configuration commands
        return;
    }

    // Bluetooth/display management
    if cli.bluetooth_on { println!("Enabling Bluetooth on {}...", port); return; }
    if cli.bluetooth_off { println!("Disabling Bluetooth on {}...", port); return; }
    if cli.bluetooth_pair { println!("Pairing Bluetooth on {}...", port); return; }
    if let Some(v) = cli.display_intensity { println!("Setting display intensity to {} on {}...", v, port); return; }
    if let Some(v) = cli.display_rotation { println!("Setting display rotation to {} on {}...", v, port); return; }

    println!("No operation specified. Use --info, --autoinstall, or radio parameters.");
}
