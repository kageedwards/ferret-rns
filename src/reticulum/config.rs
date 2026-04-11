use std::collections::HashMap;
use std::path::PathBuf;

use crate::{FerretError, Result};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// A value parsed from an interface config key.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    String(String),
    Bool(bool),
    Integer(i64),
    Float(f64),
    List(Vec<String>),
}

/// One named interface definition from the `[interfaces]` section.
#[derive(Debug, Clone, PartialEq)]
pub struct InterfaceDefinition {
    pub name: String,
    pub enabled: bool,
    pub interface_type: String,
    pub params: HashMap<String, ConfigValue>,
}

/// The `[reticulum]` section.
#[derive(Debug, Clone, PartialEq)]
pub struct ReticulumSection {
    pub share_instance: bool,
    pub enable_transport: bool,
    pub shared_instance_port: u16,
    pub instance_control_port: u16,
    pub rpc_key: Option<Vec<u8>>,
    pub use_implicit_proof: bool,
    pub panic_on_interface_error: bool,
    pub link_mtu_discovery: bool,
    pub enable_remote_management: bool,
    pub respond_to_probes: bool,
    pub network_identity: Option<PathBuf>,
    pub discover_interfaces: bool,
    pub required_discovery_value: Option<u32>,
    pub publish_blackhole: bool,
    pub blackhole_sources: Vec<[u8; 16]>,
    pub interface_discovery_sources: Vec<[u8; 16]>,
    pub autoconnect_discovered_interfaces: u32,
    pub instance_name: Option<String>,
}

impl Default for ReticulumSection {
    fn default() -> Self {
        Self {
            share_instance: true,
            enable_transport: false,
            shared_instance_port: 37428,
            instance_control_port: 37429,
            rpc_key: None,
            use_implicit_proof: true,
            panic_on_interface_error: false,
            link_mtu_discovery: true,
            enable_remote_management: false,
            respond_to_probes: false,
            network_identity: None,
            discover_interfaces: false,
            required_discovery_value: None,
            publish_blackhole: false,
            blackhole_sources: Vec::new(),
            interface_discovery_sources: Vec::new(),
            autoconnect_discovered_interfaces: 0,
            instance_name: None,
        }
    }
}

/// The `[logging]` section.
#[derive(Debug, Clone, PartialEq)]
pub struct LoggingSection {
    pub loglevel: u8,
}

impl Default for LoggingSection {
    fn default() -> Self {
        Self { loglevel: 4 }
    }
}

/// Top-level parsed configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedConfig {
    pub reticulum: ReticulumSection,
    pub logging: LoggingSection,
    pub interfaces: Vec<InterfaceDefinition>,
}

impl Default for ParsedConfig {
    fn default() -> Self {
        Self {
            reticulum: ReticulumSection::default(),
            logging: LoggingSection::default(),
            interfaces: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

/// Parse an INI-style config string into a `ParsedConfig`.
pub fn parse_config(input: &str) -> Result<ParsedConfig> {
    let mut config = ParsedConfig::default();
    let mut current_section: Option<&str> = None;
    let mut current_iface: Option<InterfaceDefinition> = None;

    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim();

        // Skip blank lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Interface subsection header: [[name]]
        if line.starts_with("[[") && line.ends_with("]]") {
            if current_section != Some("interfaces") {
                return Err(FerretError::Deserialization(format!(
                    "line {}: subsection outside [interfaces]",
                    line_no + 1
                )));
            }
            // Push previous interface if any
            if let Some(iface) = current_iface.take() {
                config.interfaces.push(iface);
            }
            let name = line[2..line.len() - 2].trim().to_string();
            current_iface = Some(InterfaceDefinition {
                name,
                enabled: false,
                interface_type: String::new(),
                params: HashMap::new(),
            });
            continue;
        }

        // Section header: [name]
        if line.starts_with('[') && line.ends_with(']') && !line.starts_with("[[") {
            // Push previous interface if any
            if let Some(iface) = current_iface.take() {
                config.interfaces.push(iface);
            }
            let name = line[1..line.len() - 1].trim();
            match name {
                "reticulum" | "logging" | "interfaces" => {
                    current_section = Some(match name {
                        "reticulum" => "reticulum",
                        "logging" => "logging",
                        _ => "interfaces",
                    });
                }
                _ => {
                    return Err(FerretError::Deserialization(format!(
                        "line {}: unknown section [{}]",
                        line_no + 1,
                        name
                    )));
                }
            }
            continue;
        }

        // Key = value
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim();
            let val = line[eq_pos + 1..].trim();

            match current_section {
                Some("reticulum") => apply_reticulum_kv(&mut config.reticulum, key, val, line_no)?,
                Some("logging") => apply_logging_kv(&mut config.logging, key, val)?,
                Some("interfaces") => {
                    if let Some(ref mut iface) = current_iface {
                        apply_interface_kv(iface, key, val);
                    } else {
                        return Err(FerretError::Deserialization(format!(
                            "line {}: key outside interface subsection",
                            line_no + 1
                        )));
                    }
                }
                _ => {
                    return Err(FerretError::Deserialization(format!(
                        "line {}: key outside any section",
                        line_no + 1
                    )));
                }
            }
            continue;
        }

        // Unrecognised line
        return Err(FerretError::Deserialization(format!(
            "line {}: unrecognised syntax",
            line_no + 1
        )));
    }

    // Push trailing interface
    if let Some(iface) = current_iface.take() {
        config.interfaces.push(iface);
    }

    Ok(config)
}

// ---------------------------------------------------------------------------
// Parser helpers
// ---------------------------------------------------------------------------

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_hex(s: &str) -> std::result::Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

fn parse_bool(val: &str) -> Option<bool> {
    match val.to_lowercase().as_str() {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

fn parse_hex_bytes_16(val: &str) -> Option<[u8; 16]> {
    if val.len() == 32 {
        let mut buf = [0u8; 16];
        for i in 0..16 {
            buf[i] = u8::from_str_radix(&val[i * 2..i * 2 + 2], 16).ok()?;
        }
        Some(buf)
    } else {
        None
    }
}

fn require_bool(val: &str, line_no: usize) -> Result<bool> {
    parse_bool(val).ok_or_else(|| {
        FerretError::Deserialization(format!("line {}: invalid bool '{}'", line_no + 1, val))
    })
}

fn require_int<T: std::str::FromStr>(val: &str, line_no: usize, label: &str) -> Result<T> {
    val.parse::<T>().map_err(|_| {
        FerretError::Deserialization(format!("line {}: invalid {} '{}'", line_no + 1, label, val))
    })
}

fn apply_reticulum_kv(sec: &mut ReticulumSection, key: &str, val: &str, ln: usize) -> Result<()> {
    match key {
        "share_instance" => sec.share_instance = require_bool(val, ln)?,
        "enable_transport" => sec.enable_transport = require_bool(val, ln)?,
        "use_implicit_proof" => sec.use_implicit_proof = require_bool(val, ln)?,
        "panic_on_interface_error" => sec.panic_on_interface_error = require_bool(val, ln)?,
        "link_mtu_discovery" => sec.link_mtu_discovery = require_bool(val, ln)?,
        "enable_remote_management" => sec.enable_remote_management = require_bool(val, ln)?,
        "respond_to_probes" => sec.respond_to_probes = require_bool(val, ln)?,
        "discover_interfaces" => sec.discover_interfaces = require_bool(val, ln)?,
        "publish_blackhole" => sec.publish_blackhole = require_bool(val, ln)?,
        "shared_instance_port" => sec.shared_instance_port = require_int(val, ln, "port")?,
        "instance_control_port" => sec.instance_control_port = require_int(val, ln, "port")?,
        "autoconnect_discovered_interfaces" => {
            sec.autoconnect_discovered_interfaces = require_int(val, ln, "int")?;
        }
        "required_discovery_value" => {
            let v: u32 = require_int(val, ln, "int")?;
            sec.required_discovery_value = if v > 0 { Some(v) } else { None };
        }
        "rpc_key" => {
            sec.rpc_key = Some(decode_hex(val).map_err(|_| {
                FerretError::Deserialization(format!("line {}: invalid hex '{}'", ln + 1, val))
            })?);
        }
        "network_identity" => sec.network_identity = Some(PathBuf::from(val)),
        "instance_name" => sec.instance_name = Some(val.to_string()),
        "blackhole_sources" => sec.blackhole_sources = parse_hash_list(val, ln)?,
        "interface_discovery_sources" => sec.interface_discovery_sources = parse_hash_list(val, ln)?,
        _ => { /* ignore unknown keys for forward compat */ }
    }
    Ok(())
}

fn parse_hash_list(val: &str, line_no: usize) -> Result<Vec<[u8; 16]>> {
    val.split(',')
        .map(|s| {
            let s = s.trim();
            parse_hex_bytes_16(s).ok_or_else(|| {
                FerretError::Deserialization(format!(
                    "line {}: invalid 16-byte hex hash '{}'",
                    line_no + 1,
                    s
                ))
            })
        })
        .collect()
}

fn apply_logging_kv(sec: &mut LoggingSection, key: &str, val: &str) -> Result<()> {
    if key == "loglevel" {
        sec.loglevel = val
            .parse::<u8>()
            .map_err(|_| FerretError::Deserialization(format!("invalid loglevel '{}'", val)))?;
        if sec.loglevel > 7 {
            sec.loglevel = 7;
        }
    }
    Ok(())
}

fn apply_interface_kv(iface: &mut InterfaceDefinition, key: &str, val: &str) {
    match key {
        "enabled" | "interface_enabled" => {
            if let Some(b) = parse_bool(val) {
                iface.enabled = b;
            }
        }
        "type" => {
            iface.interface_type = val.to_string();
        }
        _ => {
            iface.params.insert(key.to_string(), infer_value(val));
        }
    }
}

/// Infer the ConfigValue type from a raw string.
fn infer_value(val: &str) -> ConfigValue {
    // Bool
    if let Some(b) = parse_bool(val) {
        return ConfigValue::Bool(b);
    }
    // Hex bytes (0x prefix)
    if val.starts_with("0x") || val.starts_with("0X") {
        return ConfigValue::String(val.to_string());
    }
    // Integer
    if let Ok(i) = val.parse::<i64>() {
        return ConfigValue::Integer(i);
    }
    // Float
    if val.contains('.') {
        if let Ok(f) = val.parse::<f64>() {
            return ConfigValue::Float(f);
        }
    }
    // List (comma-separated with at least one comma)
    if val.contains(',') {
        let items: Vec<String> = val.split(',').map(|s| s.trim().to_string()).collect();
        return ConfigValue::List(items);
    }
    ConfigValue::String(val.to_string())
}

// ---------------------------------------------------------------------------
// Serializer (pretty printer)
// ---------------------------------------------------------------------------

/// Serialize a `ParsedConfig` back to INI-style text.
pub fn format_config(config: &ParsedConfig) -> String {
    let mut out = String::new();

    // [reticulum]
    out.push_str("[reticulum]\n");
    let r = &config.reticulum;
    push_kv(&mut out, "enable_transport", &fmt_bool(r.enable_transport));
    push_kv(&mut out, "share_instance", &fmt_bool(r.share_instance));
    push_kv(&mut out, "shared_instance_port", &r.shared_instance_port.to_string());
    push_kv(&mut out, "instance_control_port", &r.instance_control_port.to_string());
    push_kv(&mut out, "use_implicit_proof", &fmt_bool(r.use_implicit_proof));
    push_kv(&mut out, "panic_on_interface_error", &fmt_bool(r.panic_on_interface_error));
    push_kv(&mut out, "link_mtu_discovery", &fmt_bool(r.link_mtu_discovery));
    push_kv(&mut out, "enable_remote_management", &fmt_bool(r.enable_remote_management));
    push_kv(&mut out, "respond_to_probes", &fmt_bool(r.respond_to_probes));
    push_kv(&mut out, "discover_interfaces", &fmt_bool(r.discover_interfaces));
    push_kv(&mut out, "publish_blackhole", &fmt_bool(r.publish_blackhole));
    push_kv(
        &mut out,
        "autoconnect_discovered_interfaces",
        &r.autoconnect_discovered_interfaces.to_string(),
    );
    if let Some(ref key) = r.rpc_key {
        push_kv(&mut out, "rpc_key", &encode_hex(key));
    }
    if let Some(ref path) = r.network_identity {
        push_kv(&mut out, "network_identity", &path.display().to_string());
    }
    if let Some(v) = r.required_discovery_value {
        push_kv(&mut out, "required_discovery_value", &v.to_string());
    }
    if !r.blackhole_sources.is_empty() {
        push_kv(&mut out, "blackhole_sources", &fmt_hash_list(&r.blackhole_sources));
    }
    if !r.interface_discovery_sources.is_empty() {
        push_kv(
            &mut out,
            "interface_discovery_sources",
            &fmt_hash_list(&r.interface_discovery_sources),
        );
    }
    if let Some(ref name) = r.instance_name {
        push_kv(&mut out, "instance_name", name);
    }
    out.push('\n');

    // [logging]
    out.push_str("[logging]\n");
    push_kv(&mut out, "loglevel", &config.logging.loglevel.to_string());
    out.push('\n');

    // [interfaces]
    out.push_str("[interfaces]\n");
    for iface in &config.interfaces {
        out.push_str(&format!("\n  [[{}]]\n", iface.name));
        push_iface_kv(&mut out, "type", &iface.interface_type);
        push_iface_kv(&mut out, "enabled", &fmt_bool(iface.enabled));
        // Sort params for deterministic output
        let mut keys: Vec<&String> = iface.params.keys().collect();
        keys.sort();
        for k in keys {
            push_iface_kv(&mut out, k, &fmt_config_value(&iface.params[k]));
        }
    }
    out.push('\n');

    out
}

fn push_kv(out: &mut String, key: &str, val: &str) {
    out.push_str(&format!("{} = {}\n", key, val));
}

fn push_iface_kv(out: &mut String, key: &str, val: &str) {
    out.push_str(&format!("    {} = {}\n", key, val));
}

fn fmt_bool(b: bool) -> &'static str {
    if b { "Yes" } else { "No" }
}

fn fmt_hash_list(list: &[[u8; 16]]) -> String {
    list.iter()
        .map(|h| encode_hex(h))
        .collect::<Vec<_>>()
        .join(", ")
}

fn fmt_config_value(v: &ConfigValue) -> String {
    match v {
        ConfigValue::String(s) => s.clone(),
        ConfigValue::Bool(b) => fmt_bool(*b).to_string(),
        ConfigValue::Integer(i) => i.to_string(),
        ConfigValue::Float(f) => format!("{}", f),
        ConfigValue::List(items) => items.join(", "),
    }
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// The raw default config text matching the Python reference.
pub fn default_config_text() -> &'static str {
    r#"[reticulum]
enable_transport = False
share_instance = Yes
instance_name = default

[logging]
loglevel = 4

[interfaces]

  [[Default Interface]]
    type = AutoInterface
    enabled = Yes
"#
}

/// Generate the default `ParsedConfig`.
pub fn default_config() -> ParsedConfig {
    let mut config = ParsedConfig::default();
    config.reticulum.instance_name = Some("default".to_string());
    config.interfaces.push(InterfaceDefinition {
        name: "Default Interface".to_string(),
        enabled: true,
        interface_type: "AutoInterface".to_string(),
        params: HashMap::new(),
    });
    config
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_default_config() {
        let cfg = parse_config(default_config_text()).expect("default config should parse");
        assert!(!cfg.reticulum.enable_transport);
        assert!(cfg.reticulum.share_instance);
        assert_eq!(cfg.reticulum.instance_name.as_deref(), Some("default"));
        assert_eq!(cfg.logging.loglevel, 4);
        assert_eq!(cfg.interfaces.len(), 1);
        assert_eq!(cfg.interfaces[0].name, "Default Interface");
        assert_eq!(cfg.interfaces[0].interface_type, "AutoInterface");
        assert!(cfg.interfaces[0].enabled);
    }

    #[test]
    fn round_trip_default() {
        let original = default_config();
        let text = format_config(&original);
        let parsed = parse_config(&text).expect("round-trip parse should succeed");
        assert_eq!(original, parsed);
    }

    #[test]
    fn parse_comments_and_blanks() {
        let input = "# comment\n\n[logging]\n# another\nloglevel = 6\n";
        let cfg = parse_config(input).expect("should parse");
        assert_eq!(cfg.logging.loglevel, 6);
    }

    #[test]
    fn parse_error_on_bad_section() {
        let input = "[unknown_section]\nkey = val\n";
        assert!(parse_config(input).is_err());
    }

    #[test]
    fn parse_bool_variants() {
        let input = "[reticulum]\nenable_transport = true\nshare_instance = no\n";
        let cfg = parse_config(input).expect("should parse");
        assert!(cfg.reticulum.enable_transport);
        assert!(!cfg.reticulum.share_instance);
    }

    #[test]
    fn infer_value_types() {
        assert_eq!(infer_value("Yes"), ConfigValue::Bool(true));
        assert_eq!(infer_value("42"), ConfigValue::Integer(42));
        assert_eq!(infer_value("3.14"), ConfigValue::Float(3.14));
        assert_eq!(infer_value("0xDEAD"), ConfigValue::String("0xDEAD".to_string()));
        assert_eq!(
            infer_value("a, b, c"),
            ConfigValue::List(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );
        assert_eq!(infer_value("hello"), ConfigValue::String("hello".to_string()));
    }
}
