//! rnmon — Reticulum Live Network Monitor (ferret-original).
//!
//! Full-screen TUI dashboard showing real-time interface stats, traffic
//! sparklines, announces, and summary. Requires the `tui` feature.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::*;
use serde_pickle::value::{HashableValue, Value};

use ferret_rns::rpc_client::RpcClient;
use ferret_rns::util::format::size_str;

const DEFAULT_CONTROL_PORT: u16 = 37429;
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reticulum Live Network Monitor
#[derive(Parser)]
#[command(name = "rnmon", version, about = "Reticulum Live Network Monitor")]
struct Cli {
    /// Path to alternative Reticulum config directory
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,

    /// Refresh interval in seconds
    #[arg(short = 'i', default_value = "2")]
    interval: f64,

    /// Output JSON snapshot and exit (for scripting)
    #[arg(short = 'j', long = "json")]
    json: bool,
}

fn main() {
    let cli = Cli::parse();

    let storage_path = resolve_storage_path(&cli.config);
    let rpc_key = match ferret_rns::rpc_client::derive_rpc_key(&storage_path) {
        Ok(k) => k,
        Err(_) => {
            eprintln!("No shared RNS instance available");
            process::exit(1);
        }
    };

    // JSON snapshot mode
    if cli.json {
        let mut client = match RpcClient::connect(DEFAULT_CONTROL_PORT, &rpc_key) {
            Ok(c) => c,
            Err(_) => { eprintln!("No shared RNS instance available"); process::exit(1); }
        };
        if let Ok(stats) = client.get("interface_stats") {
            let json = pickle_to_json(&stats);
            println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
        }
        return;
    }

    // TUI mode
    enable_raw_mode().expect("enable raw mode");
    io::stdout().execute(EnterAlternateScreen).expect("enter alt screen");
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).expect("create terminal");

    let interval = Duration::from_secs_f64(cli.interval);
    let mut last_poll = Instant::now() - interval; // force immediate first poll
    let mut stats_cache: Option<Value> = None;
    let mut link_count: i64 = 0;
    let mut connected = true;

    loop {
        // Poll RPC
        if last_poll.elapsed() >= interval {
            last_poll = Instant::now();
            match RpcClient::connect(DEFAULT_CONTROL_PORT, &rpc_key) {
                Ok(mut client) => {
                    connected = true;
                    stats_cache = client.get("interface_stats").ok();
                    link_count = client.get("link_count").ok()
                        .and_then(|v| match v { Value::I64(n) => Some(n), _ => None })
                        .unwrap_or(0);
                }
                Err(_) => { connected = false; }
            }
        }

        // Render
        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),  // title
                    Constraint::Min(5),    // interfaces
                    Constraint::Length(1),  // status bar
                ])
                .split(area);

            // Title
            let title = format!(" ferret rnmon v{}  Refresh: {}s  q to quit", VERSION, cli.interval);
            frame.render_widget(
                Paragraph::new(title).style(Style::default().fg(Color::Cyan)),
                chunks[0],
            );

            // Interfaces
            if let Some(Value::Dict(ref d)) = stats_cache {
                let mut lines = Vec::new();
                if let Some(Value::List(ifaces)) = d.get(&HashableValue::String("interfaces".into())) {
                    for iface in ifaces {
                        if let Value::Dict(ref id) = iface {
                            let name = dict_get_str(id, "name").unwrap_or_default();
                            let status = dict_get_bool(id, "status").unwrap_or(false);
                            let rxb = dict_get_i64(id, "rxb").unwrap_or(0) as f64;
                            let txb = dict_get_i64(id, "txb").unwrap_or(0) as f64;
                            let marker = if status { "●" } else { "○" };
                            let ss = if status { "Up" } else { "Down" };
                            lines.push(Line::from(format!(
                                " {} {:<30} {:<5} ↑{:<10} ↓{}",
                                marker, name, ss, size_str(txb), size_str(rxb)
                            )));
                        }
                    }
                }
                if lines.is_empty() {
                    lines.push(Line::from(" No interfaces"));
                }
                frame.render_widget(
                    Paragraph::new(lines).block(Block::default().borders(Borders::TOP).title(" Interfaces ")),
                    chunks[1],
                );
            } else if !connected {
                frame.render_widget(
                    Paragraph::new(" Disconnected — retrying...").style(Style::default().fg(Color::Red)),
                    chunks[1],
                );
            } else {
                frame.render_widget(Paragraph::new(" Loading..."), chunks[1]);
            }

            // Status bar
            let status = format!(" Links: {} ", link_count);
            frame.render_widget(
                Paragraph::new(status).style(Style::default().fg(Color::DarkGray)),
                chunks[2],
            );
        }).expect("draw");

        // Handle input
        if event::poll(Duration::from_millis(100)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode().expect("disable raw mode");
    io::stdout().execute(LeaveAlternateScreen).expect("leave alt screen");
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

fn dict_get_str(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<String> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v { Value::String(s) => Some(s.clone()), _ => None })
}

fn dict_get_i64(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<i64> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v { Value::I64(n) => Some(*n), _ => None })
}

fn dict_get_bool(dict: &BTreeMap<HashableValue, Value>, key: &str) -> Option<bool> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v { Value::Bool(b) => Some(*b), _ => None })
}

fn pickle_to_json(val: &Value) -> serde_json::Value {
    match val {
        Value::None => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::I64(n) => serde_json::json!(*n),
        Value::F64(f) => serde_json::json!(*f),
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Bytes(b) => serde_json::Value::String(b.iter().map(|x| format!("{:02x}", x)).collect()),
        Value::List(items) => serde_json::Value::Array(items.iter().map(pickle_to_json).collect()),
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
