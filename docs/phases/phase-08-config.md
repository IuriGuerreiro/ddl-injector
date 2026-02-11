# Phase 8: Configuration & Persistence

**Status:** ⏳ Pending
**Estimated Time:** 3-4 hours
**Complexity:** Medium

## Phase Overview

Implement configuration persistence using serde and JSON. Save user preferences like recent DLLs, favorite injection method, window size, and process filters. Configuration is loaded on startup and saved on exit.

## Objectives

- [ ] Create Config struct with serde
- [ ] Implement save/load from JSON file
- [ ] Track recent DLL paths (max 10)
- [ ] Save preferred injection method
- [ ] Persist window state (size, position)
- [ ] Add settings panel in UI
- [ ] Handle config file errors gracefully

## Prerequisites

- ✅ Phase 7: Advanced methods complete
- Understanding of serde serialization
- Knowledge of file I/O in Rust

## Learning Resources

- [Serde Documentation](https://serde.rs/)
- [serde_json Crate](https://docs.rs/serde_json/)
- [eframe Persistence](https://docs.rs/eframe/latest/eframe/trait.App.html#method.save)

## File Structure

```
injector-ui/src/
├── config.rs                  # Configuration ← IMPLEMENT
└── ui/
    └── settings.rs            # Settings panel ← IMPLEMENT
```

## Dependencies

Already added in Phase 1:
- `serde = { version = "1.0", features = ["derive"] }`
- `serde_json = "1.0"`

## Step-by-Step Implementation

### Step 1: Implement Config Struct

**File:** `injector-ui/src/config.rs`

```rust
//! Application configuration and persistence.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::fs;
use crate::app::InjectionMethodType;

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
    ManualMapping,
    QueueUserApc,
    NtCreateThreadEx,
}

impl From<InjectionMethodType> for SerializableMethod {
    fn from(method: InjectionMethodType) -> Self {
        match method {
            InjectionMethodType::CreateRemoteThread => Self::CreateRemoteThread,
            InjectionMethodType::ManualMapping => Self::ManualMapping,
            InjectionMethodType::QueueUserApc => Self::QueueUserApc,
            InjectionMethodType::NtCreateThreadEx => Self::NtCreateThreadEx,
        }
    }
}

impl From<SerializableMethod> for InjectionMethodType {
    fn from(method: SerializableMethod) -> Self {
        match method {
            SerializableMethod::CreateRemoteThread => Self::CreateRemoteThread,
            SerializableMethod::ManualMapping => Self::ManualMapping,
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
        let mut path = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        path.push("DllInjector");
        fs::create_dir_all(&path).ok();
        path.push("config.json");
        path
    }

    /// Load configuration from disk.
    pub fn load() -> Self {
        let path = Self::config_path();

        match fs::read_to_string(&path) {
            Ok(contents) => {
                match serde_json::from_str(&contents) {
                    Ok(config) => {
                        log::info!("Loaded config from: {}", path.display());
                        config
                    }
                    Err(e) => {
                        log::warn!("Failed to parse config: {}", e);
                        Self::default()
                    }
                }
            }
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
```

### Step 2: Add dirs Dependency

**File:** `injector-ui/Cargo.toml` (update dependencies)

```toml
[dependencies]
# ... existing dependencies ...
dirs = "5.0"  # For getting AppData directory
```

### Step 3: Implement Settings Panel

**File:** `injector-ui/src/ui/settings.rs`

```rust
//! Settings panel UI component.

use eframe::egui;
use crate::config::Config;
use crate::app::InjectionMethodType;

pub fn render(
    ui: &mut egui::Ui,
    config: &mut Config,
    current_method: &mut InjectionMethodType,
) {
    ui.heading("Settings");

    ui.add_space(10.0);

    // Preferred injection method
    ui.group(|ui| {
        ui.label("Default Injection Method:");

        let mut method = config.preferred_method;

        egui::ComboBox::from_id_salt("default_method")
            .selected_text(format!("{:?}", method))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::CreateRemoteThread,
                    "CreateRemoteThread"
                );
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::ManualMapping,
                    "Manual Mapping"
                );
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::QueueUserApc,
                    "QueueUserAPC"
                );
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::NtCreateThreadEx,
                    "NtCreateThreadEx"
                );
            });

        if method != config.preferred_method {
            config.preferred_method = method;
            *current_method = method.into();
        }
    });

    ui.add_space(10.0);

    // Auto-refresh interval
    ui.group(|ui| {
        ui.label("Auto-Refresh Process List:");

        ui.horizontal(|ui| {
            ui.add(egui::Slider::new(&mut config.auto_refresh_interval, 0..=60)
                .text("seconds")
                .suffix("s"));

            if config.auto_refresh_interval == 0 {
                ui.label("(disabled)");
            }
        });

        ui.small("Set to 0 to disable automatic refresh");
    });

    ui.add_space(10.0);

    // Recent DLLs
    ui.group(|ui| {
        ui.label("Recent DLLs:");

        ui.horizontal(|ui| {
            ui.label(format!("{} recent DLLs", config.recent_dlls.len()));

            if ui.button("Clear").clicked() {
                config.clear_recent();
            }
        });

        ui.separator();

        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                if config.recent_dlls.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No recent DLLs");
                } else {
                    for dll_path in &config.recent_dlls {
                        ui.small(dll_path.display().to_string());
                    }
                }
            });
    });

    ui.add_space(10.0);

    // Config file location
    ui.group(|ui| {
        ui.label("Configuration:");

        let config_path = Config::config_path();
        ui.small(format!("Location: {}", config_path.display()));

        ui.horizontal(|ui| {
            if ui.button("Save Now").clicked() {
                if let Err(e) = config.save() {
                    log::error!("Failed to save config: {}", e);
                } else {
                    log::info!("Configuration saved");
                }
            }

            if ui.button("Reset to Defaults").clicked() {
                *config = Config::default();
                log::info!("Configuration reset to defaults");
            }
        });
    });
}
```

### Step 4: Update Application State

**File:** `injector-ui/src/app.rs` (update InjectorApp)

Add config field:

```rust
pub struct InjectorApp {
    // ... existing fields ...

    /// Application configuration
    config: Config,
}
```

Update `new()` to load config:

```rust
impl InjectorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load config
        let config = Config::load();

        let mut app = Self {
            // ... existing initialization ...
            config: config.clone(),
            injection_method: config.preferred_method.into(),
            process_filter: config.process_filter.clone(),
            // ...
        };

        app
    }
}
```

Update `update()` to show settings:

```rust
impl eframe::App for InjectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ... existing menu bar ...

        egui::menu::bar(ui, |ui| {
            ui.menu_button("File", |ui| {
                // ... existing items ...

                if ui.button("Settings").clicked() {
                    self.ui_state.show_settings = true;
                    ui.close_menu();
                }
            });
        });

        // Settings window
        if self.ui_state.show_settings {
            egui::Window::new("Settings")
                .open(&mut self.ui_state.show_settings)
                .resizable(false)
                .show(ctx, |ui| {
                    ui::settings::render(
                        ui,
                        &mut self.config,
                        &mut self.injection_method,
                    );
                });
        }

        // ... rest of UI ...
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        // Save config on exit
        if let Err(e) = self.config.save() {
            log::error!("Failed to save config: {}", e);
        }
    }
}
```

Update DLL selection to track recent:

```rust
fn open_dll_file_dialog(&mut self) {
    if let Some(path) = rfd::FileDialog::new()
        .add_filter("DLL Files", &["dll"])
        .pick_file()
    {
        self.config.add_recent_dll(path.clone());
        self.dll_path = Some(path);
        self.last_error = None;
    }
}
```

### Step 5: Add Recent DLLs to UI

**File:** `injector-ui/src/ui/injection_panel.rs` (update)

Add recent DLLs menu:

```rust
pub fn render(
    ui: &mut egui::Ui,
    // ... existing params ...
    recent_dlls: &[PathBuf],
    select_recent_dll: &mut dyn FnMut(PathBuf),
) {
    // ... existing code ...

    ui.horizontal(|ui| {
        if ui.button("📁 Browse...").clicked() {
            open_file_dialog();
        }

        // Recent DLLs dropdown
        if !recent_dlls.is_empty() {
            egui::ComboBox::from_id_salt("recent_dlls")
                .selected_text("Recent...")
                .show_ui(ui, |ui| {
                    for recent_dll in recent_dlls {
                        let file_name = recent_dll
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .to_string();

                        if ui.selectable_label(false, &file_name).clicked() {
                            select_recent_dll(recent_dll.clone());
                        }
                    }
                });
        }
    });

    // ... rest of panel ...
}
```

## Testing Checklist

- [ ] Config saves on application exit
- [ ] Config loads on application start
- [ ] Recent DLLs tracked (max 10)
- [ ] Preferred method persists
- [ ] Window state saves/loads
- [ ] Settings panel accessible from menu
- [ ] Clear recent works
- [ ] Reset to defaults works

## Common Pitfalls

### 1. Config File Permissions
**Problem:** Can't write to AppData folder
**Solution:** Handle permission errors gracefully

### 2. Invalid JSON
**Problem:** Corrupted config file causes crash
**Solution:** Use default config if parse fails

### 3. Path Serialization
**Problem:** Paths with special characters
**Solution:** serde_json handles this automatically

### 4. Recent DLLs Growing Unbounded
**Problem:** List grows forever
**Solution:** Truncate to 10 items

## Completion Criteria

- ✅ Config struct with serde
- ✅ Save/load from JSON
- ✅ Recent DLLs tracking
- ✅ Preferred method persistence
- ✅ Settings panel in UI
- ✅ Graceful error handling

## Git Commit

```bash
git add injector-ui/src/config.rs injector-ui/src/ui/settings.rs
git commit -m "feat: implement configuration persistence

- Add Config struct with serde serialization
- Save/load config from AppData JSON file
- Track recent DLLs (max 10)
- Persist preferred injection method
- Save window state
- Add settings panel to UI
- Include recent DLLs dropdown

Configuration persists across sessions.

Follows docs/phases/phase-08-config.md
"
```

## Next Steps

Proceed to **Phase 9: Logging** (docs/phases/phase-09-logging.md)
