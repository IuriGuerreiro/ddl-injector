# Phase 9: Enhanced Logging System

**Status:** ⏳ Pending
**Estimated Time:** 3-4 hours
**Complexity:** Medium

## Phase Overview

Implement comprehensive logging that writes to both file and UI. Use env_logger for file output and create a custom log sink that captures log messages for the UI viewer. Add log filtering by level and search functionality.

## Objectives

- [ ] Configure env_logger for file output
- [ ] Create custom UI log sink
- [ ] Implement log level filtering in UI
- [ ] Add search/filter in log viewer
- [ ] Include timestamps in logs
- [ ] Add log file rotation
- [ ] Create clear log functionality

## Prerequisites

- ✅ Phase 8: Configuration complete
- Understanding of Rust logging ecosystem
- Knowledge of multi-target logging

## Learning Resources

- [log Crate](https://docs.rs/log/)
- [env_logger](https://docs.rs/env_logger/)
- [Custom Logger Implementation](https://docs.rs/log/latest/log/trait.Log.html)

## File Structure

```
injector-ui/src/
├── logging.rs                 # Custom logger ← NEW
└── ui/
    └── log_viewer.rs          # Enhanced viewer ← UPDATE
```

## Dependencies

Already added in Phase 1:
- `log = "0.4"`
- `env_logger = "0.11"`

## Step-by-Step Implementation

### Step 1: Create Custom UI Logger

**File:** `injector-ui/src/logging.rs`

```rust
//! Custom logging implementation for UI display.

use log::{Level, Metadata, Record};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Log entry with full details.
#[derive(Clone)]
pub struct LogEntry {
    pub level: Level,
    pub message: String,
    pub target: String,
    pub timestamp: SystemTime,
}

/// Logger that sends to both file and UI.
pub struct DualLogger {
    ui_logs: Arc<Mutex<Vec<LogEntry>>>,
    file_logger: env_logger::Logger,
}

impl DualLogger {
    /// Create a new dual logger.
    pub fn new(ui_logs: Arc<Mutex<Vec<LogEntry>>>) -> Self {
        let file_logger = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info")
        )
        .target(env_logger::Target::Stdout)
        .build();

        Self {
            ui_logs,
            file_logger,
        }
    }

    /// Initialize the dual logger as the global logger.
    pub fn init(ui_logs: Arc<Mutex<Vec<LogEntry>>>) -> Result<(), log::SetLoggerError> {
        let logger = Box::new(Self::new(ui_logs));
        let max_level = logger.file_logger.filter();

        log::set_boxed_logger(logger)?;
        log::set_max_level(max_level);

        Ok(())
    }
}

impl log::Log for DualLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.file_logger.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Log to file (via env_logger)
        self.file_logger.log(record);

        // Log to UI
        let entry = LogEntry {
            level: record.level(),
            message: format!("{}", record.args()),
            target: record.target().to_string(),
            timestamp: SystemTime::now(),
        };

        if let Ok(mut logs) = self.ui_logs.lock() {
            logs.push(entry);

            // Keep last 1000 entries
            if logs.len() > 1000 {
                logs.remove(0);
            }
        }
    }

    fn flush(&self) {
        // Nothing to flush for UI logs
    }
}

/// Configure file logging with rotation.
pub fn setup_file_logging() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::path::PathBuf;

    // Create logs directory
    let mut log_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    log_dir.push("DllInjector");
    log_dir.push("logs");
    fs::create_dir_all(&log_dir)?;

    // Generate log filename with timestamp
    let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let log_file = log_dir.join(format!("injector_{}.log", timestamp));

    // Configure env_logger to write to file
    let target = Box::new(fs::File::create(log_file)?);

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    )
    .target(env_logger::Target::Pipe(target))
    .init();

    Ok(())
}

/// Rotate log files, keeping only the last N.
pub fn rotate_logs(keep_count: usize) -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;
    use std::path::PathBuf;

    let mut log_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    log_dir.push("DllInjector");
    log_dir.push("logs");

    if !log_dir.exists() {
        return Ok(());
    }

    // Get all log files
    let mut log_files: Vec<_> = fs::read_dir(&log_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.path()
                .extension()
                .and_then(|s| s.to_str()) == Some("log")
        })
        .collect();

    // Sort by modified time (newest first)
    log_files.sort_by_key(|entry| {
        entry.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    log_files.reverse();

    // Delete old log files
    for old_file in log_files.iter().skip(keep_count) {
        if let Err(e) = fs::remove_file(old_file.path()) {
            log::warn!("Failed to delete old log: {}", e);
        } else {
            log::debug!("Deleted old log: {}", old_file.path().display());
        }
    }

    Ok(())
}
```

### Step 2: Add chrono Dependency

**File:** `injector-ui/Cargo.toml` (update dependencies)

```toml
[dependencies]
# ... existing dependencies ...
chrono = "0.4"  # For timestamp formatting
```

### Step 3: Enhanced Log Viewer

**File:** `injector-ui/src/ui/log_viewer.rs` (replace existing)

```rust
//! Enhanced log viewer UI component.

use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::logging::LogEntry;

/// Log viewer state.
pub struct LogViewerState {
    /// Filter by log level
    show_error: bool,
    show_warn: bool,
    show_info: bool,
    show_debug: bool,
    show_trace: bool,

    /// Search filter
    search_text: String,

    /// Auto-scroll to bottom
    auto_scroll: bool,
}

impl Default for LogViewerState {
    fn default() -> Self {
        Self {
            show_error: true,
            show_warn: true,
            show_info: true,
            show_debug: false,
            show_trace: false,
            search_text: String::new(),
            auto_scroll: true,
        }
    }
}

pub fn render(
    ui: &mut egui::Ui,
    logs: &Arc<Mutex<Vec<LogEntry>>>,
    state: &mut LogViewerState,
) {
    ui.horizontal(|ui| {
        ui.heading("Logs");

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            // Clear button
            if ui.button("🗑 Clear").clicked() {
                if let Ok(mut log_vec) = logs.lock() {
                    log_vec.clear();
                }
            }

            // Auto-scroll toggle
            ui.checkbox(&mut state.auto_scroll, "Auto-scroll");

            // Export logs
            if ui.button("💾 Export").clicked() {
                export_logs_to_file(logs);
            }
        });
    });

    ui.separator();

    // Filter controls
    ui.horizontal(|ui| {
        ui.label("Show:");

        ui.checkbox(&mut state.show_error, "❌ Error");
        ui.checkbox(&mut state.show_warn, "⚠ Warn");
        ui.checkbox(&mut state.show_info, "ℹ Info");
        ui.checkbox(&mut state.show_debug, "🔍 Debug");
        ui.checkbox(&mut state.show_trace, "📝 Trace");

        ui.separator();

        ui.label("Search:");
        ui.text_edit_singleline(&mut state.search_text);

        if ui.button("✖").clicked() {
            state.search_text.clear();
        }
    });

    ui.separator();

    // Log display
    let scroll_area = egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(state.auto_scroll);

    scroll_area.show(ui, |ui| {
        if let Ok(log_vec) = logs.lock() {
            let filtered: Vec<&LogEntry> = log_vec.iter()
                .filter(|entry| {
                    // Filter by level
                    let level_match = match entry.level {
                        log::Level::Error => state.show_error,
                        log::Level::Warn => state.show_warn,
                        log::Level::Info => state.show_info,
                        log::Level::Debug => state.show_debug,
                        log::Level::Trace => state.show_trace,
                    };

                    // Filter by search text
                    let search_match = if state.search_text.is_empty() {
                        true
                    } else {
                        let search_lower = state.search_text.to_lowercase();
                        entry.message.to_lowercase().contains(&search_lower)
                            || entry.target.to_lowercase().contains(&search_lower)
                    };

                    level_match && search_match
                })
                .collect();

            if filtered.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "No log messages");
            } else {
                for entry in filtered {
                    render_log_entry(ui, entry);
                }
            }

            ui.label(format!("Showing {} of {} messages", filtered.len(), log_vec.len()));
        }
    });
}

fn render_log_entry(ui: &mut egui::Ui, entry: &LogEntry) {
    ui.horizontal(|ui| {
        // Timestamp
        let duration = entry.timestamp
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let datetime = chrono::DateTime::<chrono::Local>::from(
            std::time::UNIX_EPOCH + duration
        );
        let time_str = datetime.format("%H:%M:%S").to_string();

        ui.small(time_str);

        // Level with color
        let (color, icon, level_str) = match entry.level {
            log::Level::Error => (egui::Color32::RED, "❌", "ERROR"),
            log::Level::Warn => (egui::Color32::YELLOW, "⚠", "WARN"),
            log::Level::Info => (egui::Color32::GREEN, "ℹ", "INFO"),
            log::Level::Debug => (egui::Color32::GRAY, "🔍", "DEBUG"),
            log::Level::Trace => (egui::Color32::DARK_GRAY, "📝", "TRACE"),
        };

        ui.colored_label(color, format!("{} {}", icon, level_str));

        // Target (module name)
        if !entry.target.is_empty() {
            ui.small(format!("[{}]", entry.target));
        }

        // Message
        ui.label(&entry.message);
    });
}

fn export_logs_to_file(logs: &Arc<Mutex<Vec<LogEntry>>>) {
    use std::fs::File;
    use std::io::Write;

    if let Some(path) = rfd::FileDialog::new()
        .set_file_name("logs.txt")
        .add_filter("Text Files", &["txt"])
        .save_file()
    {
        match File::create(&path) {
            Ok(mut file) => {
                if let Ok(log_vec) = logs.lock() {
                    for entry in log_vec.iter() {
                        let duration = entry.timestamp
                            .duration_since(std::time::SystemTime::UNIX_EPOCH)
                            .unwrap_or_default();
                        let datetime = chrono::DateTime::<chrono::Local>::from(
                            std::time::UNIX_EPOCH + duration
                        );

                        writeln!(
                            file,
                            "[{}] {:5} [{}] {}",
                            datetime.format("%Y-%m-%d %H:%M:%S"),
                            entry.level,
                            entry.target,
                            entry.message
                        ).ok();
                    }

                    log::info!("Exported {} log entries to {}", log_vec.len(), path.display());
                }
            }
            Err(e) => {
                log::error!("Failed to create log file: {}", e);
            }
        }
    }
}
```

### Step 4: Update Application

**File:** `injector-ui/src/app.rs` (update)

Add logging state:

```rust
pub struct InjectorApp {
    // ... existing fields ...

    /// Log viewer state
    log_viewer_state: ui::log_viewer::LogViewerState,
}
```

Initialize logging in `new()`:

```rust
impl InjectorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Initialize logging
        let logs = Arc::new(Mutex::new(Vec::new()));

        if let Err(e) = logging::DualLogger::init(logs.clone()) {
            eprintln!("Failed to initialize logger: {}", e);
        }

        // Rotate old logs (keep last 10)
        if let Err(e) = logging::rotate_logs(10) {
            log::warn!("Failed to rotate logs: {}", e);
        }

        log::info!("DLL Injector v{} starting", env!("CARGO_PKG_VERSION"));

        // ... rest of initialization ...

        Self {
            // ... existing fields ...
            logs,
            log_viewer_state: Default::default(),
        }
    }
}
```

Update log viewer render call:

```rust
// Bottom panel - Logs
egui::TopBottomPanel::bottom("log_panel")
    .resizable(true)
    .default_height(200.0)
    .show(ctx, |ui| {
        ui::log_viewer::render(
            ui,
            &self.logs,
            &mut self.log_viewer_state,
        );
    });
```

### Step 5: Add Logging Module Export

**File:** `injector-ui/src/main.rs` (update)

```rust
mod app;
mod config;
mod ui;
mod logging;  // ← Add this

use app::InjectorApp;
```

## Testing Checklist

- [ ] Logs appear in UI in real-time
- [ ] Log level filtering works
- [ ] Search filter works
- [ ] Timestamps display correctly
- [ ] Auto-scroll toggles properly
- [ ] Clear logs works
- [ ] Export logs creates file
- [ ] Old logs rotate correctly

## Common Pitfalls

### 1. Mutex Deadlock
**Problem:** Holding log lock while rendering
**Solution:** Lock, clone data, unlock quickly

### 2. Unbounded Log Growth
**Problem:** Logs consume all memory
**Solution:** Truncate to last 1000 entries

### 3. File Permissions
**Problem:** Can't write log files
**Solution:** Handle errors gracefully

### 4. Timestamp Format
**Problem:** Times in wrong timezone
**Solution:** Use chrono::Local

## Completion Criteria

- ✅ Dual logging (file + UI) working
- ✅ Log level filtering functional
- ✅ Search filter operational
- ✅ Timestamps display correctly
- ✅ Export logs feature works
- ✅ Log rotation implemented
- ✅ No performance issues

## Git Commit

```bash
git add injector-ui/src/logging.rs injector-ui/src/ui/log_viewer.rs
git commit -m "feat: implement enhanced logging system

- Create dual logger (file + UI)
- Add log level filtering in UI
- Implement search/filter functionality
- Include timestamps with chrono
- Add log export to file
- Implement log file rotation (keep last 10)
- Add auto-scroll toggle

Comprehensive logging complete.

Follows docs/phases/phase-09-logging.md
"
```

## Next Steps

Proceed to **Phase 10: Testing** (docs/phases/phase-10-testing.md)
