//! rnpath — Reticulum Path Management Utility.
//!
//! Connects to the shared instance via RPC to query and manage the routing
//! path table and announce rate table.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process;

use clap::Parser;
use serde_pickle::value::{HashableValue, Value};

use ferret_rns::rpc_client::RpcClient;
use ferret_rns::util::format::{pretty_hex, pretty_date, timestamp_str};

const DEFAULT_CONTROL_PORT: u16 = 37429;

/// Reticulum Path Management Utility
#[derive(Parser)]
#[command(name = "rnpath", version, about = "Reticulum Path Management Utility")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Increase verbosity (repeatable)
    #[arg(short = 'v', action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show all known paths
    #[arg(short = 't', long = "table")]
    table: bool,

    /// Show announce rate info
    #[arg(short = 'r', long = "rates")]
    rates: bool,

    /// Remove the path to a destination
    #[arg(short = 'd', long = "drop")]
    drop: bool,

    /// Drop all queued announces
    #[arg(short = 'D', long = "drop-announces")]
    drop_announces: bool,

    /// Drop all paths via specified transport instance
    #[arg(short = 'x', long = "drop-via")]
    drop_via: bool,

    /// Timeout before giving up (seconds)
    #[arg(short = 'w', default_value = "15")]
    timeout: f64,

    /// Maximum hops to filter path table by
    #[arg(short = 'm', long = "max")]
    max_hops: Option<u8>,

    /// Output in JSON format
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Hexadecimal hash of the destination
    destination: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    // If no action specified and no destination, show help
    if !cli.drop_announces && !cli.table && !cli.rates && cli.destination.is_none() && !cli.drop_via {
        println!();
        // Re-parse with --help to show usage
        let _ = Cli::try_parse_from(["rnpath", "--help"]);
        return;
    }

    let storage_path = resolve_storage_path(&cli.config);
    let rpc_key = match ferret_rns::rpc_client::derive_rpc_key(&storage_path) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("No shared RNS instance available");
            process::exit(1);
        }
    };

    let mut client = match RpcClient::connect(DEFAULT_CONTROL_PORT, &rpc_key) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("No shared RNS instance available");
            process::exit(1);
        }
    };

    if cli.table {
        handle_table(&mut client, &cli);
    } else if cli.rates {
        handle_rates(&mut client, &cli);
    } else if cli.drop_announces {
        handle_drop_announces(&mut client);
    } else if cli.drop {
        handle_drop_path(&mut client, &cli);
    } else if cli.drop_via {
        handle_drop_via(&mut client, &cli);
    } else if let Some(ref dest_hex) = cli.destination {
        handle_path_request(&mut client, dest_hex);
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

fn handle_table(client: &mut RpcClient, cli: &Cli) {
    let extras: Vec<(&str, Value)> = if let Some(mh) = cli.max_hops {
        vec![("max_hops", Value::I64(mh as i64))]
    } else {
        vec![("max_hops", Value::None)]
    };

    let resp = match client.get_with("path_table", &extras) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to query path table: {}", e);
            process::exit(1);
        }
    };

    let entries = match &resp {
        Value::List(l) => l,
        _ => {
            eprintln!("Unexpected response format");
            process::exit(1);
        }
    };

    // Sort by interface then hops
    let mut sorted: Vec<&Value> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        let da = as_dict(a);
        let db = as_dict(b);
        let ia = da.and_then(|d| dict_get_str(d, "interface")).unwrap_or_default();
        let ib = db.and_then(|d| dict_get_str(d, "interface")).unwrap_or_default();
        let ha = da.and_then(|d| dict_get_i64(d, "hops")).unwrap_or(0);
        let hb = db.and_then(|d| dict_get_i64(d, "hops")).unwrap_or(0);
        ia.cmp(&ib).then(ha.cmp(&hb))
    });

    // Filter by destination if provided
    let dest_filter = cli.destination.as_ref().and_then(|h| hex_decode(h));

    if cli.json {
        print_json_list(&sorted);
        return;
    }

    let mut displayed = 0;
    for entry in &sorted {
        let d = match as_dict(entry) {
            Some(d) => d,
            None => continue,
        };

        let hash = dict_get_bytes(d, "hash").unwrap_or_default();
        if let Some(ref filter) = dest_filter {
            if hash != *filter {
                continue;
            }
        }

        displayed += 1;
        let hops = dict_get_i64(d, "hops").unwrap_or(0);
        let via = dict_get_bytes(d, "via").unwrap_or_default();
        let iface = dict_get_str(d, "interface").unwrap_or_default();
        let expires = dict_get_f64(d, "expires").unwrap_or(0.0);

        let s = if hops != 1 { "s" } else { " " };
        println!(
            "{} is {} hop{} away via {} on {} expires {}",
            pretty_hex(&hash),
            hops,
            s,
            pretty_hex(&via),
            iface,
            timestamp_str(expires)
        );
    }

    if dest_filter.is_some() && displayed == 0 {
        println!("No path known");
        process::exit(1);
    }
}

fn handle_rates(client: &mut RpcClient, cli: &Cli) {
    let resp = match client.get("rate_table") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to query rate table: {}", e);
            process::exit(1);
        }
    };

    let entries = match &resp {
        Value::List(l) => l,
        _ => {
            eprintln!("Unexpected response format");
            process::exit(1);
        }
    };

    if entries.is_empty() {
        println!("No information available");
        return;
    }

    // Sort by last heard
    let mut sorted: Vec<&Value> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        let la = as_dict(a).and_then(|d| dict_get_f64(d, "last")).unwrap_or(0.0);
        let lb = as_dict(b).and_then(|d| dict_get_f64(d, "last")).unwrap_or(0.0);
        la.partial_cmp(&lb).unwrap_or(std::cmp::Ordering::Equal)
    });

    let dest_filter = cli.destination.as_ref().and_then(|h| hex_decode(h));

    if cli.json {
        print_json_list(&sorted);
        return;
    }

    let mut displayed = 0;
    for entry in &sorted {
        let d = match as_dict(entry) {
            Some(d) => d,
            None => continue,
        };

        let hash = dict_get_bytes(d, "hash").unwrap_or_default();
        if let Some(ref filter) = dest_filter {
            if hash != *filter {
                continue;
            }
        }

        displayed += 1;
        let last = dict_get_f64(d, "last").unwrap_or(0.0);
        let violations = dict_get_i64(d, "rate_violations").unwrap_or(0);
        let timestamps = dict_get_list(d, "timestamps");
        let ts_count = timestamps.map(|l| l.len()).unwrap_or(0);

        // Compute announces per hour
        let hour_rate = if ts_count > 0 {
            if let Some(ts_list) = timestamps {
                let first_ts = ts_list.first().and_then(|v| match v {
                    Value::F64(f) => Some(*f),
                    _ => None,
                }).unwrap_or(last);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs_f64();
                let span = (now - first_ts).max(3600.0);
                ts_count as f64 / (span / 3600.0)
            } else {
                0.0
            }
        } else {
            0.0
        };

        let last_str = pretty_date(last);

        let mut rv_str = String::new();
        if violations > 0 {
            let s = if violations == 1 { "" } else { "s" };
            rv_str = format!(", {} active rate violation{}", violations, s);
        }

        println!(
            "{} last heard {}, {:.1} announces/hour{}",
            pretty_hex(&hash),
            last_str,
            hour_rate,
            rv_str
        );
    }

    if dest_filter.is_some() && displayed == 0 {
        println!("No information available");
        process::exit(1);
    }
}

fn handle_drop_announces(client: &mut RpcClient) {
    println!("Dropping announce queues on all interfaces...");
    match client.drop_cmd("announce_queues") {
        Ok(_) => {}
        Err(e) => {
            eprintln!("Failed to drop announce queues: {}", e);
            process::exit(1);
        }
    }
}

fn handle_drop_path(client: &mut RpcClient, cli: &Cli) {
    let dest_hex = match &cli.destination {
        Some(h) => h,
        None => {
            eprintln!("Destination hash required for --drop");
            process::exit(1);
        }
    };

    let dest_bytes = match hex_decode(dest_hex) {
        Some(b) => b,
        None => {
            eprintln!("Invalid destination entered. Check your input.");
            process::exit(1);
        }
    };

    match client.drop_with("path", &[("destination_hash", Value::Bytes(dest_bytes.clone()))]) {
        Ok(Value::Bool(true)) => {
            println!("Dropped path to {}", pretty_hex(&dest_bytes));
        }
        _ => {
            println!(
                "Unable to drop path to {}. Does it exist?",
                pretty_hex(&dest_bytes)
            );
            process::exit(1);
        }
    }
}

fn handle_drop_via(client: &mut RpcClient, cli: &Cli) {
    let dest_hex = match &cli.destination {
        Some(h) => h,
        None => {
            eprintln!("Transport hash required for --drop-via");
            process::exit(1);
        }
    };

    let dest_bytes = match hex_decode(dest_hex) {
        Some(b) => b,
        None => {
            eprintln!("Invalid destination entered. Check your input.");
            process::exit(1);
        }
    };

    match client.drop_with("all_via", &[("destination_hash", Value::Bytes(dest_bytes.clone()))]) {
        Ok(Value::I64(n)) => {
            println!("Dropped {} paths via {}", n, pretty_hex(&dest_bytes));
        }
        _ => {
            println!(
                "Unable to drop paths via {}. Does the transport instance exist?",
                pretty_hex(&dest_bytes)
            );
            process::exit(1);
        }
    }
}

fn handle_path_request(client: &mut RpcClient, dest_hex: &str) {
    let dest_bytes = match hex_decode(dest_hex) {
        Some(b) => b,
        None => {
            eprintln!("Invalid destination entered. Check your input.");
            process::exit(1);
        }
    };

    // Query next hop info via RPC
    let resp = match client.get_with(
        "next_hop_if_name",
        &[("destination_hash", Value::Bytes(dest_bytes.clone()))],
    ) {
        Ok(v) => v,
        Err(_) => Value::None,
    };

    let next_hop_resp = match client.get_with(
        "next_hop",
        &[("destination_hash", Value::Bytes(dest_bytes.clone()))],
    ) {
        Ok(v) => v,
        Err(_) => Value::None,
    };

    match (&resp, &next_hop_resp) {
        (Value::String(iface_name), Value::Bytes(next_hop)) => {
            // We have a path — query hops
            let _hops_resp = client
                .get_with(
                    "first_hop_timeout",
                    &[("destination_hash", Value::Bytes(dest_bytes.clone()))],
                )
                .ok();

            // For now, display what we have
            println!(
                "Path found, destination {} via {} on {}",
                pretty_hex(&dest_bytes),
                pretty_hex(next_hop),
                iface_name
            );
        }
        _ => {
            println!("Path not found");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_storage_path(configdir: &Option<PathBuf>) -> PathBuf {
    if let Some(ref cd) = configdir {
        cd.join("storage")
    } else {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".reticulum").join("storage")
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn as_dict(val: &Value) -> Option<&BTreeMap<HashableValue, Value>> {
    match val {
        Value::Dict(d) => Some(d),
        _ => None,
    }
}

fn print_json_list(entries: &[&Value]) {
    let json_vals: Vec<serde_json::Value> = entries.iter().map(|v| pickle_to_json(v)).collect();
    match serde_json::to_string_pretty(&json_vals) {
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
        Value::Bytes(b) => {
            serde_json::Value::String(b.iter().map(|x| format!("{:02x}", x)).collect())
        }
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
