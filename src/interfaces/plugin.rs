// cdylib Plugin Loader — load interface implementations from shared libraries.
//
// Gated behind the `plugins` feature (mod.rs handles the cfg gate).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use libloading::{Library, Symbol};

use crate::transport::InterfaceHandle;
use crate::{FerretError, Result};

/// C-ABI entry point signature that plugin shared libraries must export.
///
/// The plugin receives a pointer to a UTF-8 config JSON string and its length,
/// and returns a raw pointer to a trait object implementing `InterfaceHandle`.
///
/// Note: `dyn InterfaceHandle` is not truly FFI-safe, but this is the standard
/// pattern for Rust-to-Rust cdylib plugin loading where both sides share the
/// same trait definition and Rust ABI.
#[allow(improper_ctypes_definitions)]
pub type PluginEntryFn =
    unsafe extern "C" fn(config_json: *const u8, config_len: usize) -> *mut dyn InterfaceHandle;

/// The well-known symbol name that every plugin must export.
const ENTRY_SYMBOL: &[u8] = b"ferret_interface_create";

/// A loaded plugin — keeps the shared library alive alongside the interface.
pub struct LoadedPlugin {
    /// Held to prevent the OS from unloading the shared library.
    _library: Library,
    /// The interface trait object returned by the plugin entry point.
    pub interface: Arc<dyn InterfaceHandle>,
}

/// Namespace for plugin loading helpers.
pub struct PluginLoader;

impl PluginLoader {
    /// Load a single plugin from a shared library at `path`.
    ///
    /// Looks for the `ferret_interface_create` entry point, calls it with
    /// `config_json`, and wraps the result into a `LoadedPlugin`.
    pub fn load(path: &Path, config_json: &str) -> Result<LoadedPlugin> {
        let library = unsafe { Library::new(path) }.map_err(|e| {
            FerretError::PluginLoadError(format!("failed to load library {:?}: {}", path, e))
        })?;

        let entry: Symbol<PluginEntryFn> = unsafe { library.get(ENTRY_SYMBOL) }.map_err(|e| {
            FerretError::PluginLoadError(format!(
                "missing entry point `ferret_interface_create` in {:?}: {}",
                path, e
            ))
        })?;

        let raw_ptr = unsafe { entry(config_json.as_ptr(), config_json.len()) };
        if raw_ptr.is_null() {
            return Err(FerretError::PluginLoadError(format!(
                "plugin {:?} returned null",
                path
            )));
        }

        let interface: Arc<dyn InterfaceHandle> = unsafe { Arc::from(Box::from_raw(raw_ptr)) };

        Ok(LoadedPlugin {
            _library: library,
            interface,
        })
    }

    /// Scan `dir` for shared library files and load each as a plugin.
    ///
    /// Config for each plugin is looked up by filename stem in `configs`.
    /// Files that fail to load are silently skipped.
    pub fn load_directory(
        dir: &Path,
        configs: &HashMap<String, String>,
    ) -> Result<Vec<LoadedPlugin>> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            FerretError::PluginLoadError(format!("cannot read directory {:?}: {}", dir, e))
        })?;

        let mut plugins = Vec::new();

        for entry in entries.flatten() {
            let path = entry.path();
            if !is_plugin_file(&path) {
                continue;
            }

            let stem = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };

            let config_json = configs.get(&stem).map(|s| s.as_str()).unwrap_or("{}");

            match Self::load(&path, config_json) {
                Ok(p) => plugins.push(p),
                Err(_) => { /* skip failed plugins */ }
            }
        }

        Ok(plugins)
    }
}

/// Check whether a path has a platform-appropriate shared library extension.
fn is_plugin_file(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("so") | Some("dylib") | Some("dll") => true,
        _ => false,
    }
}
