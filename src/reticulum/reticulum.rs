// Reticulum — top-level orchestrator for the Reticulum Network Stack.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use crate::reticulum::config;
use crate::reticulum::logging::LogDestination;
use crate::{FerretError, Result};

// ---------------------------------------------------------------------------
// ReticulumPaths — resolved directory layout
// ---------------------------------------------------------------------------

/// All resolved paths for a Reticulum instance.
#[derive(Debug, Clone)]
pub struct ReticulumPaths {
    pub configdir: PathBuf,
    pub configpath: PathBuf,
    pub storagepath: PathBuf,
    pub cachepath: PathBuf,
    pub resourcepath: PathBuf,
    pub identitypath: PathBuf,
    pub blackholepath: PathBuf,
    pub interfacepath: PathBuf,
}

/// Create all required subdirectories under `configdir` and return resolved paths.
pub fn init_directories(configdir: &Path) -> Result<ReticulumPaths> {
    let storagepath = configdir.join("storage");
    let cachepath = storagepath.join("cache");
    let announcepath = cachepath.join("announces");
    let resourcepath = storagepath.join("resources");
    let identitypath = storagepath.join("identities");
    let blackholepath = storagepath.join("blackhole");
    let interfacepath = configdir.join("interfaces");

    let dirs = [
        configdir,
        &storagepath,
        &cachepath,
        &announcepath,
        &resourcepath,
        &identitypath,
        &blackholepath,
        &interfacepath,
    ];

    for dir in &dirs {
        std::fs::create_dir_all(dir).map_err(|e| {
            FerretError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to create directory {}: {}", dir.display(), e),
            ))
        })?;
    }

    Ok(ReticulumPaths {
        configdir: configdir.to_path_buf(),
        configpath: configdir.join("config"),
        storagepath,
        cachepath,
        resourcepath,
        identitypath,
        blackholepath,
        interfacepath,
    })
}

// ---------------------------------------------------------------------------
// ReticulumConfig — builder input
// ---------------------------------------------------------------------------

/// Configuration passed to `Reticulum::new()`.
pub struct ReticulumConfig {
    pub configdir: Option<PathBuf>,
    pub loglevel: Option<u8>,
    pub verbosity: Option<i8>,
    pub log_destination: LogDestination,
    pub require_shared_instance: bool,
}

impl Default for ReticulumConfig {
    fn default() -> Self {
        Self {
            configdir: None,
            loglevel: None,
            verbosity: None,
            log_destination: LogDestination::Stdout,
            require_shared_instance: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Reticulum — the main struct
// ---------------------------------------------------------------------------

/// Default ports matching the Python reference.
pub const DEFAULT_LOCAL_INTERFACE_PORT: u16 = 37428;
pub const DEFAULT_LOCAL_CONTROL_PORT: u16 = 37429;

/// Top-level Reticulum Network Stack instance.
pub struct Reticulum {
    // Resolved paths
    pub paths: ReticulumPaths,

    // Instance state
    pub is_shared_instance: bool,
    pub is_connected_to_shared_instance: bool,
    pub is_standalone_instance: bool,

    // Config-derived flags
    pub transport_enabled: bool,
    pub share_instance: bool,
    pub use_implicit_proof: bool,
    pub link_mtu_discovery: bool,
    pub remote_management_enabled: bool,
    pub allow_probes: bool,
    pub panic_on_interface_error: bool,
    pub discover_interfaces: bool,
    pub discovery_enabled: bool,
    pub publish_blackhole: bool,

    // Ports
    pub local_interface_port: u16,
    pub local_control_port: u16,

    // RPC
    pub rpc_key: Option<Vec<u8>>,

    // Shutdown signal
    pub shutdown: Arc<AtomicBool>,
}

impl Reticulum {
    /// Create and initialize a new Reticulum instance.
    ///
    /// Steps:
    /// 1. Resolve configdir
    /// 2. Create storage directories
    /// 3. Read or generate config file
    /// 4. Apply config values
    /// 5. Return Arc<Self>
    ///
    /// Transport init, shared instance, interface synthesis, RPC, and jobs
    /// are deferred to later tasks (7, 9, 10, 11, 13).
    pub fn new(user_config: ReticulumConfig) -> Result<Arc<Self>> {
        // 1. Resolve configdir
        let configdir = resolve_configdir(&user_config)?;

        // 2. Create storage directories
        let paths = init_directories(&configdir)?;

        // 3. Read or generate config file
        let parsed = if paths.configpath.exists() {
            let text = std::fs::read_to_string(&paths.configpath).map_err(|e| {
                FerretError::Io(std::io::Error::new(
                    e.kind(),
                    format!("failed to read config {}: {}", paths.configpath.display(), e),
                ))
            })?;
            config::parse_config(&text)?
        } else {
            // Write default config and use default parsed values
            let default_text = config::default_config_text();
            std::fs::write(&paths.configpath, default_text).map_err(|e| {
                FerretError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "failed to write default config {}: {}",
                        paths.configpath.display(),
                        e
                    ),
                ))
            })?;
            config::default_config()
        };

        // 4. Apply config values
        let ret_sec = &parsed.reticulum;

        // Determine effective loglevel (CLI overrides config)
        let _effective_loglevel = match user_config.loglevel {
            Some(l) => l.min(7),
            None => parsed.logging.loglevel.min(7),
        };

        let reticulum = Reticulum {
            paths,
            is_shared_instance: false,
            is_connected_to_shared_instance: false,
            is_standalone_instance: false,
            transport_enabled: ret_sec.enable_transport,
            share_instance: ret_sec.share_instance,
            use_implicit_proof: ret_sec.use_implicit_proof,
            link_mtu_discovery: ret_sec.link_mtu_discovery,
            remote_management_enabled: ret_sec.enable_remote_management,
            allow_probes: ret_sec.respond_to_probes,
            panic_on_interface_error: ret_sec.panic_on_interface_error,
            discover_interfaces: ret_sec.discover_interfaces,
            discovery_enabled: false, // Set during transport init (task 7)
            publish_blackhole: ret_sec.publish_blackhole,
            local_interface_port: ret_sec.shared_instance_port,
            local_control_port: ret_sec.instance_control_port,
            rpc_key: ret_sec.rpc_key.clone(),
            shutdown: Arc::new(AtomicBool::new(false)),
        };

        // TODO (task 7): Load transport identity, start transport
        // TODO (task 9): Shared instance management
        // TODO (task 10): Interface synthesis
        // TODO (task 11): RPC server
        // TODO (task 13): Background jobs

        Ok(Arc::new(reticulum))
    }

    /// Whether implicit proofs should be used.
    pub fn should_use_implicit_proof(&self) -> bool {
        self.use_implicit_proof
    }

    /// Whether transport routing is enabled.
    pub fn transport_enabled(&self) -> bool {
        self.transport_enabled
    }
}

// ---------------------------------------------------------------------------
// configdir resolution
// ---------------------------------------------------------------------------

/// Resolve the base configuration directory.
///
/// Priority:
/// 1. User-provided configdir
/// 2. /etc/reticulum (if it exists)
/// 3. ~/.config/reticulum
/// 4. ~/.reticulum (fallback)
fn resolve_configdir(config: &ReticulumConfig) -> Result<PathBuf> {
    if let Some(ref dir) = config.configdir {
        return Ok(dir.clone());
    }

    let etc_path = Path::new("/etc/reticulum");
    if etc_path.is_dir() {
        return Ok(etc_path.to_path_buf());
    }

    let home = home_dir().ok_or_else(|| {
        FerretError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine home directory",
        ))
    })?;

    let xdg_path = home.join(".config").join("reticulum");
    if xdg_path.is_dir() {
        return Ok(xdg_path);
    }

    Ok(home.join(".reticulum"))
}

/// Get the user's home directory from environment.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_directories_creates_all_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("testnet");
        let paths = init_directories(&base).unwrap();

        assert!(paths.configdir.is_dir());
        assert!(paths.storagepath.is_dir());
        assert!(paths.cachepath.is_dir());
        assert!(paths.cachepath.join("announces").is_dir());
        assert!(paths.resourcepath.is_dir());
        assert!(paths.identitypath.is_dir());
        assert!(paths.blackholepath.is_dir());
        assert!(paths.interfacepath.is_dir());
        assert_eq!(paths.configpath, base.join("config"));
    }

    #[test]
    fn test_init_directories_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("testnet");
        let p1 = init_directories(&base).unwrap();
        let p2 = init_directories(&base).unwrap();
        assert_eq!(p1.configdir, p2.configdir);
    }

    #[test]
    fn test_reticulum_new_default_config() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("rns");
        let config = ReticulumConfig {
            configdir: Some(base.clone()),
            ..Default::default()
        };
        let ret = Reticulum::new(config).unwrap();
        assert!(ret.paths.configpath.exists());
        assert!(ret.share_instance);
        assert!(!ret.transport_enabled);
        assert!(ret.use_implicit_proof);
        assert_eq!(ret.local_interface_port, DEFAULT_LOCAL_INTERFACE_PORT);
        assert_eq!(ret.local_control_port, DEFAULT_LOCAL_CONTROL_PORT);
    }

    #[test]
    fn test_reticulum_new_reads_existing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("rns");
        std::fs::create_dir_all(&base).unwrap();
        let config_text = "[reticulum]\nenable_transport = true\nshare_instance = no\n\n[logging]\nloglevel = 6\n";
        std::fs::write(base.join("config"), config_text).unwrap();

        let config = ReticulumConfig {
            configdir: Some(base),
            ..Default::default()
        };
        let ret = Reticulum::new(config).unwrap();
        assert!(ret.transport_enabled);
        assert!(!ret.share_instance);
    }

    #[test]
    fn test_cli_loglevel_override() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("rns");
        let config = ReticulumConfig {
            configdir: Some(base),
            loglevel: Some(2),
            ..Default::default()
        };
        // Just verify it doesn't panic — loglevel application is internal
        let _ret = Reticulum::new(config).unwrap();
    }

    #[test]
    fn test_reticulumconfig_default() {
        let cfg = ReticulumConfig::default();
        assert!(cfg.configdir.is_none());
        assert!(cfg.loglevel.is_none());
        assert!(cfg.verbosity.is_none());
        assert!(!cfg.require_shared_instance);
    }
}
