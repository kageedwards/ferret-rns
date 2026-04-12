//! rnmon — Reticulum Live Network Monitor (ferret-original).
//!
//! Full-screen TUI dashboard showing real-time interface stats, traffic
//! sparklines, recent announces, and summary bar. Requires the `tui` feature.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::process;
use std::time::{Duration, Instant};

use clap::Parser;
use crossterm::event::{self, Event, KeyCode};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::*;
use serde_pickle::value::{HashableValue, Value};

use ferret_rns::rpc_client::RpcClient;
use ferret_rns::util::format::{pretty_hex, size_str, speed_str};

const DEFAULT_CONTROL_PORT: u16 = 37429;
const VERSION: &str = env!("CARGO_PKG_VERSION");
const SPARKLINE_SAMPLES: usize = 60;

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

/// Snapshot of aggregate traffic for sparkline computation.
struct TrafficSnapshot {
    total_rx: u64,
    total_tx: u64,
}

/// Per-poll state used for rendering.
struct MonitorState {
    stats: Option<Value>,
    link_count: i64,
    path_count: usize,
    connected: bool,
    /// Ring buffer of per-second TX rates (bytes/sec).
    tx_history: VecDeque<u64>,
    /// Ring buffer of per-second RX rates (bytes/sec).
    rx_history: VecDeque<u64>,
    /// Previous snapshot for delta computation.
    prev_snapshot: Option<(Instant, TrafficSnapshot)>,
    /// Recent announce entries from the rate table (dest hash hex, last-heard timestamp).
    recent_announces: Vec<(String, f64, usize)>,
}

impl MonitorState {
    fn new() -> Self {
        Self {
            stats: None,
            link_count: 0,
            path_count: 0,
            connected: false,
            tx_history: VecDeque::with_capacity(SPARKLINE_SAMPLES),
            rx_history: VecDeque::with_capacity(SPARKLINE_SAMPLES),
            prev_snapshot: None,
            recent_announces: Vec::new(),
        }
    }

    /// Extract aggregate rx/tx from the stats dict.
    fn aggregate_traffic(&self) -> TrafficSnapshot {
        let (rx, tx) = if let Some(Value::Dict(ref d)) = self.stats {
            let rx = dict_get_i64(d, "rxb").unwrap_or(0) as u64;
            let tx = dict_get_i64(d, "txb").unwrap_or(0) as u64;
            (rx, tx)
        } else {
            (0, 0)
        };
        TrafficSnapshot {
            total_rx: rx,
            total_tx: tx,
        }
    }

    /// Update sparkline ring buffers from the latest poll.
    fn update_sparklines(&mut self) {
        let now = Instant::now();
        let snap = self.aggregate_traffic();

        if let Some((prev_time, ref prev_snap)) = self.prev_snapshot {
            let elapsed = now.duration_since(prev_time).as_secs_f64().max(0.001);
            let rx_rate = ((snap.total_rx.saturating_sub(prev_snap.total_rx)) as f64 / elapsed) as u64;
            let tx_rate = ((snap.total_tx.saturating_sub(prev_snap.total_tx)) as f64 / elapsed) as u64;

            if self.tx_history.len() >= SPARKLINE_SAMPLES {
                self.tx_history.pop_front();
            }
            if self.rx_history.len() >= SPARKLINE_SAMPLES {
                self.rx_history.pop_front();
            }
            self.tx_history.push_back(tx_rate);
            self.rx_history.push_back(rx_rate);
        }

        self.prev_snapshot = Some((now, snap));
    }

    /// Count interfaces and how many are up.
    fn interface_counts(&self) -> (usize, usize) {
        if let Some(Value::Dict(ref d)) = self.stats {
            if let Some(Value::List(ifaces)) = d.get(&HashableValue::String("interfaces".into())) {
                let total = ifaces.len();
                let up = ifaces
                    .iter()
                    .filter(|v| {
                        if let Value::Dict(ref id) = v {
                            dict_get_bool(id, "status").unwrap_or(false)
                        } else {
                            false
                        }
                    })
                    .count();
                return (total, up);
            }
        }
        (0, 0)
    }

    fn total_traffic_str(&self) -> String {
        let snap = self.aggregate_traffic();
        format!(
            "↑↓ {}",
            size_str((snap.total_rx + snap.total_tx) as f64)
        )
    }
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
            Err(_) => {
                eprintln!("No shared RNS instance available");
                process::exit(1);
            }
        };
        if let Ok(stats) = client.get("interface_stats") {
            let json = pickle_to_json(&stats);
            println!("{}", serde_json::to_string_pretty(&json).unwrap_or_default());
        }
        return;
    }

    // TUI mode
    enable_raw_mode().expect("enable raw mode");
    io::stdout()
        .execute(EnterAlternateScreen)
        .expect("enter alt screen");
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend).expect("create terminal");

    let interval = Duration::from_secs_f64(cli.interval);
    let mut last_poll = Instant::now() - interval; // force immediate first poll
    let mut state = MonitorState::new();

    loop {
        // Poll RPC on each tick
        if last_poll.elapsed() >= interval {
            last_poll = Instant::now();
            match RpcClient::connect(DEFAULT_CONTROL_PORT, &rpc_key) {
                Ok(mut client) => {
                    state.connected = true;
                    state.stats = client.get("interface_stats").ok();
                    state.link_count = client
                        .get("link_count")
                        .ok()
                        .and_then(|v| match v {
                            Value::I64(n) => Some(n),
                            _ => None,
                        })
                        .unwrap_or(0);

                    // Path count from path table
                    if let Ok(Value::List(paths)) =
                        client.get_with("path_table", &[("max_hops", Value::None)])
                    {
                        state.path_count = paths.len();
                    }

                    // Recent announces from rate table
                    if let Ok(Value::List(rates)) = client.get("rate_table") {
                        let mut announces: Vec<(String, f64, usize)> = rates
                            .iter()
                            .filter_map(|v| {
                                if let Value::Dict(ref d) = v {
                                    let hash = dict_get_bytes(d, "hash").unwrap_or_default();
                                    let last = dict_get_f64(d, "last").unwrap_or(0.0);
                                    let ts_count = dict_get_list(d, "timestamps")
                                        .map(|l| l.len())
                                        .unwrap_or(0);
                                    let hex: String =
                                        hash.iter().map(|b| format!("{:02x}", b)).collect();
                                    Some((hex, last, ts_count))
                                } else {
                                    None
                                }
                            })
                            .collect();
                        announces.sort_by(|a, b| {
                            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
                        });
                        announces.truncate(10); // keep last 10
                        state.recent_announces = announces;
                    }

                    state.update_sparklines();
                }
                Err(_) => {
                    state.connected = false;
                }
            }
        }

        // Render
        terminal
            .draw(|frame| render_ui(frame, &state, &cli))
            .expect("draw");

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
    io::stdout()
        .execute(LeaveAlternateScreen)
        .expect("leave alt screen");
}

// ---------------------------------------------------------------------------
// TUI rendering
// ---------------------------------------------------------------------------

fn render_ui(frame: &mut Frame, state: &MonitorState, cli: &Cli) {
    let area = frame.area();

    // 4-panel vertical layout: title | interfaces | traffic sparkline | announces | summary bar
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // title bar
            Constraint::Min(4),    // interfaces panel
            Constraint::Length(5), // traffic sparkline panel
            Constraint::Length(6), // recent announces panel
            Constraint::Length(1), // summary bar
        ])
        .split(area);

    // ── Title bar ──
    let title = format!(
        " ferret rnmon v{}          Refresh: {}s    q to quit",
        VERSION, cli.interval
    );
    frame.render_widget(
        Paragraph::new(title).style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        chunks[0],
    );

    // ── Interfaces panel ──
    if !state.connected {
        frame.render_widget(
            Paragraph::new(" Disconnected — retrying...")
                .style(Style::default().fg(Color::Red))
                .block(
                    Block::default()
                        .borders(Borders::TOP)
                        .title(" Interfaces "),
                ),
            chunks[1],
        );
    } else if let Some(Value::Dict(ref d)) = state.stats {
        let mut lines = Vec::new();
        if let Some(Value::List(ifaces)) = d.get(&HashableValue::String("interfaces".into())) {
            for iface in ifaces {
                if let Value::Dict(ref id) = iface {
                    let name = dict_get_str(id, "name").unwrap_or_default();
                    let status = dict_get_bool(id, "status").unwrap_or(false);
                    let rxb = dict_get_i64(id, "rxb").unwrap_or(0) as f64;
                    let txb = dict_get_i64(id, "txb").unwrap_or(0) as f64;
                    let rxs = dict_get_i64(id, "rxs").unwrap_or(0) as f64;
                    let txs = dict_get_i64(id, "txs").unwrap_or(0) as f64;
                    let bitrate = dict_get_i64(id, "bitrate");

                    let marker = if status { "●" } else { "○" };
                    let ss = if status { "Up" } else { "Down" };
                    let rate_str = bitrate
                        .map(|br| speed_str(br as f64))
                        .unwrap_or_default();

                    let line = format!(
                        " {} {:<28} {:<5} ↑{:<10} ↓{:<10} {:<12} {}",
                        marker,
                        truncate_name(&name, 28),
                        ss,
                        size_str(txb),
                        size_str(rxb),
                        if txs > 0.0 || rxs > 0.0 {
                            format!("{}↑ {}↓", speed_str(txs), speed_str(rxs))
                        } else {
                            String::new()
                        },
                        rate_str,
                    );

                    let style = if status {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    lines.push(Line::styled(line, style));
                }
            }
        }
        if lines.is_empty() {
            lines.push(Line::from(" No interfaces"));
        }
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::TOP)
                    .title(" Interfaces "),
            ),
            chunks[1],
        );
    } else {
        frame.render_widget(
            Paragraph::new(" Loading...").block(
                Block::default()
                    .borders(Borders::TOP)
                    .title(" Interfaces "),
            ),
            chunks[1],
        );
    }

    // ── Traffic sparkline panel ──
    let tx_data: Vec<u64> = state.tx_history.iter().copied().collect();
    let rx_data: Vec<u64> = state.rx_history.iter().copied().collect();

    let spark_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(2)])
        .margin(0)
        .split(chunks[2]);

    // TX sparkline
    let tx_label = if let Some(&last) = tx_data.last() {
        format!(" TX {} ", speed_str(last as f64 * 8.0))
    } else {
        " TX ".to_string()
    };
    frame.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::TOP)
                    .title(format!(" Traffic (last {} samples) ", SPARKLINE_SAMPLES)),
            )
            .data(&tx_data)
            .style(Style::default().fg(Color::Cyan)),
        spark_chunks[0],
    );

    // RX sparkline
    frame.render_widget(
        Sparkline::default()
            .block(Block::default())
            .data(&rx_data)
            .style(Style::default().fg(Color::Yellow)),
        spark_chunks[1],
    );

    // ── Recent announces panel ──
    let mut announce_lines = Vec::new();
    if state.recent_announces.is_empty() {
        announce_lines.push(Line::styled(
            " No recent announces",
            Style::default().fg(Color::DarkGray),
        ));
    } else {
        for (hash_hex, last_ts, count) in &state.recent_announces {
            let hash_bytes: Vec<u8> = (0..hash_hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&hash_hex[i..i + 2], 16).ok())
                .collect();
            let time_str = ferret_rns::util::format::pretty_date(*last_ts);
            let line = format!(
                " {}  {} ({} announces)",
                pretty_hex(&hash_bytes),
                time_str,
                count,
            );
            announce_lines.push(Line::from(line));
        }
    }
    frame.render_widget(
        Paragraph::new(announce_lines).block(
            Block::default()
                .borders(Borders::TOP)
                .title(" Recent Announces "),
        ),
        chunks[3],
    );

    // ── Summary bar ──
    let (total_ifaces, up_ifaces) = state.interface_counts();
    let summary = format!(
        " Interfaces: {} ({} up) │ Paths: {} │ Links: {} │ {}",
        total_ifaces,
        up_ifaces,
        state.path_count,
        state.link_count,
        state.total_traffic_str(),
    );
    frame.render_widget(
        Paragraph::new(summary)
            .style(Style::default().fg(Color::White).bg(Color::DarkGray)),
        chunks[4],
    );

    let _ = tx_label; // used for future per-line label
}

fn truncate_name(name: &str, max: usize) -> String {
    if name.len() <= max {
        name.to_string()
    } else {
        format!("{}…", &name[..max - 1])
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

fn dict_get_list<'a>(
    dict: &'a BTreeMap<HashableValue, Value>,
    key: &str,
) -> Option<&'a Vec<Value>> {
    dict.get(&HashableValue::String(key.to_string()))
        .and_then(|v| match v {
            Value::List(l) => Some(l),
            _ => None,
        })
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
