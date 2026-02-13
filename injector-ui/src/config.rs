//! Application configuration and persistence.

use crate::app::InjectionMethodType;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Recently used DLL paths (max 10)
    pub recent_dlls: Vec<PathBuf>,

    /// Preferred injection method
    pub preferred_method: SerializableMethod,

    /// Process filter text
    pub process_filter: String,

    /// Window state
    pub window_state: WindowState,

    /// Auto-refresh processes interval (seconds, 0 = disabled)
    pub auto_refresh_interval: u32,
}

/// Serializable injection method.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum SerializableMethod {
    CreateRemoteThread,
    ManualMap,
    QueueUserApc,
    NtCreateThreadEx,
}

impl From<InjectionMethodType> for SerializableMethod {
    fn from(method: InjectionMethodType) -> Self {
        match method {
            InjectionMethodType::CreateRemoteThread => Self::CreateRemoteThread,
            InjectionMethodType::ManualMap => Self::ManualMap,
            InjectionMethodType::QueueUserApc => Self::QueueUserApc,
            InjectionMethodType::NtCreateThreadEx => Self::NtCreateThreadEx,
            // New experimental methods default to CreateRemoteThread for config persistence
            InjectionMethodType::SectionMapping
            | InjectionMethodType::ThreadHijacking
            | InjectionMethodType::ReflectiveLoader
            | InjectionMethodType::DllProxying => Self::CreateRemoteThread,
        }
    }
}

impl From<SerializableMethod> for InjectionMethodType {
    fn from(method: SerializableMethod) -> Self {
        match method {
            SerializableMethod::CreateRemoteThread => Self::CreateRemoteThread,
            SerializableMethod::ManualMap => Self::ManualMap,
            SerializableMethod::QueueUserApc => Self::QueueUserApc,
            SerializableMethod::NtCreateThreadEx => Self::NtCreateThreadEx,
        }
    }
}

/// Window state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowState {
    pub width: f32,
    pub height: f32,
    pub maximized: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            recent_dlls: Vec::new(),
            preferred_method: SerializableMethod::CreateRemoteThread,
            process_filter: String::new(),
            window_state: WindowState {
                width: 1200.0,
                height: 800.0,
                maximized: false,
            },
            auto_refresh_interval: 0,
        }
    }
}

impl Config {
    /// Get config file path.
    ///
    /// Returns: %APPDATA%\DllInjector\config.json
    pub fn config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("DllInjector");
        fs::create_dir_all(&path).ok();
        path.push("config.json");
        path
    }

    /// Load configuration from disk.
    pub fn load() -> Self {
        let path = Self::config_path();

        match fs::read_to_string(&path) {
            Ok(contents) => match serde_json::from_str(&contents) {
                Ok(config) => {
                    log::info!("Loaded config from: {}", path.display());
                    config
                }
                Err(e) => {
                    log::warn!("Failed to parse config: {}", e);
                    Self::default()
                }
            },
            Err(_) => {
                log::info!("No config file found, using defaults");
                Self::default()
            }
        }
    }

    /// Save configuration to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::config_path();

        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;

        log::info!("Saved config to: {}", path.display());
        Ok(())
    }

    /// Add a DLL to recent list.
    pub fn add_recent_dll(&mut self, dll_path: PathBuf) {
        // Remove if already exists
        self.recent_dlls.retain(|p| p != &dll_path);

        // Add to front
        self.recent_dlls.insert(0, dll_path);

        // Keep max 10
        self.recent_dlls.truncate(10);
    }

    /// Clear recent DLLs.
    pub fn clear_recent(&mut self) {
        self.recent_dlls.clear();
    }
}
