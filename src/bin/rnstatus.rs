//! rnstatus — Reticulum Network Status.
//!
//! Connects to the shared instance via RPC and displays interface statistics.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use serde_pickle::value::{HashableValue, Value};

use ferret_rns::rpc_client::RpcClient;
use ferret_rns::util::format::{pretty_hex, size_str, speed_str};

const DEFAULT_CONTROL_PORT: u16 = 37429;

/// Reticulum Network Stack Status
#[derive(Parser)]
#[command(name = "rnstatus", version, about = "Reticulum Network Stack Status")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show all interfaces (including hidden)
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Show announce stats
    #[arg(short = 'A', long = "announce-stats")]
    announce_stats: bool,

    /// Show link stats
    #[arg(short = 'l', long = "link-stats")]
    link_stats: bool,

    /// Output in JSON format
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Sort interfaces by [rate, traffic, rx, tx, announces, held]
    #[arg(short = 's', long = "sort")]
    sort: Option<String>,

    /// Reverse sorting
    #[arg(short = 'r', long = "reverse")]
    reverse: bool,

    /// Display traffic totals
    #[arg(short = 't', long = "totals")]
    totals: bool,

    /// Filter interface names
    filter: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // Derive RPC key from transport identity
    let storage_path = resolve_storage_path(&cli.config);
    let rpc_key = match ferret_rns::rpc_client::derive_rpc_key(&storage_path) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("No shared RNS instance available to get status from");
            process::exit(1);
        }
    };

    let mut client = match RpcClient::connect(DEFAULT_CONTROL_PORT, &rpc_key) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("No shared RNS instance available to get status from");
            process::exit(1);
        }
    };

    // Query interface stats
    let stats = match client.get("interface_stats") {
        Ok(v) => v,
        Err(_) => {
            eprintln!("Could not get RNS status");
            process::exit(2);
        }
    };

    // Query link count if requested
    let link_count = if cli.link_stats {
        client.get("link_count").ok()
    } else {
        None
    };

    let stats_dict = match &stats {
        Value::Dict(d) => d,
        _ => {
            eprintln!("Could not get RNS status");
            process::exit(2);
        }
    };

    // JSON output mode
    if cli.json {
        print_json(&stats);
        return;
    }

    // Extract interfaces list
    let interfaces = match dict_get_list(stats_dict, "interfaces") {
        Some(v) => v,
        None => {
            eprintln!("Could not get RNS status");
            process::exit(2);
        }
    };

    // Sort if requested
    let mut ifaces: Vec<&Value> = interfaces.iter().collect();
    if let Some(ref sort_key) = cli.sort {
        sort_interfaces(&mut ifaces, sort_key, cli.reverse);
    }

    // Display each interface
    for ifstat in &ifaces {
        let d = match ifstat {
            Value::Dict(d) => d,
            _ => continue,
        };

        let name = dict_get_str(d, "name").unwrap_or_default();

        // Filter hidden interfaces unless --all
        if !cli.all && is_hidden_interface(&name) {
            continue;
        }

        // Apply name filter
        if let Some(ref filter) = cli.filter {
            if !name.to_lowercase().contains(&filter.to_lowercase()) {
                continue;
            }
        }

        println!();
        println!(" {}", name);

        // Network name
        if let Some(nn) = dict_get_str(d, "ifac_netname") {
            println!("    Network   : {}", nn);
        }

        // Status
        let status = dict_get_bool(d, "status").unwrap_or(false);
        println!("    Status    : {}", if status { "Up" } else { "Down" });

        // Mode (skip for certain interface types)
        if !name.starts_with("Shared Instance[")
            && !name.starts_with("TCPInterface[Client")
            && !name.starts_with("LocalInterface[")
        {
            let mode = dict_get_i64(d, "mode").unwrap_or(0);
            let mode_str = match mode {
                1 => "Access Point",
                2 => "Point-to-Point",
                3 => "Roaming",
                4 => "Boundary",
                5 => "Gateway",
                _ => "Full",
            };
            println!("    Mode      : {}", mode_str);
        }

        // Bitrate
        if let Some(br) = dict_get_i64(d, "bitrate") {
            println!("    Rate      : {}", speed_str(br as f64));
        }

        // Announce stats
        if cli.announce_stats {
            if let Some(aq) = dict_get_i64(d, "announce_queue") {
                if aq > 0 {
                    let s = if aq == 1 { "announce" } else { "announces" };
                    println!("    Queued    : {} {}", aq, s);
                }
            }
            if let Some(ha) = dict_get_i64(d, "held_announces") {
                if ha > 0 {
                    let s = if ha == 1 { "announce" } else { "announces" };
                    println!("    Held      : {} {}", ha, s);
                }
            }
        }

        // Traffic
        let rxb = dict_get_i64(d, "rxb").unwrap_or(0) as f64;
        let txb = dict_get_i64(d, "txb").unwrap_or(0) as f64;
        let rxs = dict_get_i64(d, "rxs").unwrap_or(0) as f64;
        let txs = dict_get_i64(d, "txs").unwrap_or(0) as f64;

        let rx_str = format!("↓{}  {}", size_str(rxb), speed_str(rxs));
        let tx_str = format!("↑{}  {}", size_str(txb), speed_str(txs));
        println!("    Traffic   : {}", tx_str);
        println!("                {}", rx_str);
    }

    // Traffic totals
    if cli.totals {
        let total_rxb = dict_get_i64(stats_dict, "rxb").unwrap_or(0) as f64;
        let total_txb = dict_get_i64(stats_dict, "txb").unwrap_or(0) as f64;
        let total_rxs = dict_get_i64(stats_dict, "rxs").unwrap_or(0) as f64;
        let total_txs = dict_get_i64(stats_dict, "txs").unwrap_or(0) as f64;

        let rx_str = format!("↓{}  {}", size_str(total_rxb), speed_str(total_rxs));
        let tx_str = format!("↑{}  {}", size_str(total_txb), speed_str(total_txs));
        println!();
        println!(" Totals       : {}", tx_str);
        println!("                {}", rx_str);
    }

    // Link stats and transport info
    let mut lstr = String::new();
    if let Some(Value::I64(lc)) = link_count {
        let ms = if lc == 1 { "y" } else { "ies" };
        lstr = format!("{} entr{} in link table", lc, ms);
    }

    if let Some(tid_bytes) = dict_get_bytes(stats_dict, "transport_id") {
        println!();
        println!(" Transport Instance {} running", pretty_hex(&tid_bytes));
        if let Some(uptime) = dict_get_f64(stats_dict, "transport_uptime") {
            let up_str = ferret_rns::util::format::pretty_time(uptime);
            if !lstr.is_empty() {
                println!(" Uptime is {}, {}", up_str, lstr);
            } else {
                println!(" Uptime is {}", up_str);
            }
        }
    } else if !lstr.is_empty() {
        println!();
        println!(" {}", lstr);
    }

    println!();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_storage_path(configdir: &Option<PathBuf>) -> PathBuf {
    if let Some(ref cd) = configdir {
        cd.join("storage")
    } else {
        dirs_storage_path()
    }
}

fn dirs_storage_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".reticulum").join("storage")
}

fn is_hidden_interface(name: &str) -> bool {
    name.starts_with("LocalInterface[")
        || name.starts_with("TCPInterface[Client")
        || name.starts_with("BackboneInterface[Client on")
        || name.starts_with("AutoInterfacePeer[")
        || name.starts_with("WeaveInterfacePeer[")
        || name.starts_with("I2PInterfacePeer[Connected peer")
}

fn sort_interfaces(ifaces: &mut Vec<&Value>, key: &str, reverse: bool) {
    let key_lower = key.to_lowercase();
    ifaces.sort_by(|a, b| {
        let da = match a { Value::Dict(d) => d, _ => return std::cmp::Ordering::Equal };
        let db = match b { Value::Dict(d) => d, _ => return std::cmp::Ordering::Equal };

        let va = sort_value(da, &key_lower);
        let vb = sort_value(db, &key_lower);

        let ord = va.partial_cmp(&vb).unwrap_or(std::cmp::Ordering::Equal);
        if reverse { ord } else { ord.reverse() }
    });
}

fn sort_value(d: &BTreeMap<HashableValue, Value>, key: &str) -> f64 {
    match key {
        "rate" | "bitrate" => dict_get_i64(d, "bitrate").unwrap_or(0) as f64,
        "rx" => dict_get_i64(d, "rxb").unwrap_or(0) as f64,
        "tx" => dict_get_i64(d, "txb").unwrap_or(0) as f64,
        "traffic" => {
            let rx = dict_get_i64(d, "rxb").unwrap_or(0);
            let tx = dict_get_i64(d, "txb").unwrap_or(0);
            (rx + tx) as f64
        }
        "announces" | "announce" => {
            let i = dict_get_f64(d, "incoming_announce_frequency").unwrap_or(0.0);
            let o = dict_get_f64(d, "outgoing_announce_frequency").unwrap_or(0.0);
            i + o
        }
        "held" => dict_get_i64(d, "held_announces").unwrap_or(0) as f64,
        _ => 0.0,
    }
}

fn print_json(stats: &Value) {
    // Convert bytes to hex strings for JSON output
    let converted = convert_bytes_for_json(stats);
    match serde_json::to_string_pretty(&pickle_to_json(&converted)) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}

fn pickle_to_json(val: &Value) -> serde_json::Value {
    match val {
        Value::None => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::I64(n) => serde_json::json!(*n),
        Value::F64(f) => serde_json::json!(*f),
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        Value::List(items) => {
            serde_json::Value::Array(items.iter().map(pickle_to_json).collect())
        }
        Value::Dict(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    HashableValue::String(s) => s.clone(),
                    HashableValue::I64(n) => n.to_string(),
                    _ => format!("{:?}", k),
                };
                obj.insert(key, pickle_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::Null,
    }
}

fn convert_bytes_for_json(val: &Value) -> Value {
    match val {
        Value::Bytes(b) => Value::String(hex::encode(b)),
        Value::List(items) => Value::List(items.iter().map(convert_bytes_for_json).collect()),
        Value::Dict(map) => {
            let mut new_map = BTreeMap::new();
            for (k, v) in map {
                new_map.insert(k.clone(), convert_bytes_for_json(v));
            }
            Value::Dict(new_map)
        }
        other => other.clone(),
    }
}

// Minimal hex encoding (no external dep needed)
mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

// ---------------------------------------------------------------------------
// Pickle dict accessors
// ---------------------------------------------------------------------------

fn dict_get_str(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<String> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
}

fn dict_get_i64(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<i64> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::I64(n) => Some(*n),
            _ => None,
        })
}

fn dict_get_f64(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<f64> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::F64(f) => Some(*f),
            Value::I64(n) => Some(*n as f64),
            _ => None,
        })
}

fn dict_get_bool(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<bool> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::Bool(b) => Some(*b),
            _ => None,
        })
}

fn dict_get_bytes(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<Vec<u8>> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::Bytes(b) => Some(b.clone()),
            _ => None,
        })
}

fn dict_get_list<'a>(dict: &'a BTreeMap<HashableValue, Value>, key: &str) -> Option<&'a Vec<Value>> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::List(l) => Some(l),
            _ => None,
        })
}
