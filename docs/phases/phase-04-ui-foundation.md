# Phase 4: UI Foundation

**Status:** ⏳ Pending
**Estimated Time:** 6-8 hours
**Complexity:** Medium

## Phase Overview

Build the graphical user interface using egui/eframe. This phase creates a modern, responsive UI with three main panels: process list (left), injection controls (center), and log viewer (bottom). The UI will display live process information, allow DLL selection via file dialog, and show injection results in real-time.

## Objectives

- [ ] Design main application layout with egui panels
- [ ] Implement process list component with search/filter
- [ ] Create injection control panel with method selection
- [ ] Build log viewer with auto-scroll and level filtering
- [ ] Add file picker for DLL selection
- [ ] Implement process refresh functionality
- [ ] Add UI state management and error display
- [ ] Create custom styling for professional appearance

## Prerequisites

- ✅ Phase 3: Basic injection complete
- ✅ CreateRemoteThread method working
- Understanding of immediate mode GUI concepts
- Familiarity with egui layout system

## Learning Resources

- [egui Documentation](https://docs.rs/egui/latest/egui/)
- [eframe Examples](https://github.com/emilk/egui/tree/master/examples)
- [egui Demo](https://www.egui.rs/)
- [Immediate Mode GUI Pattern](https://caseymuratori.com/blog_0001)

## File Structure

```
injector-ui/src/
├── main.rs                     # Already exists (minimal)
├── app.rs                      # InjectorApp implementation ← UPDATE
├── config.rs                   # Stub for Phase 8
└── ui/
    ├── mod.rs                  # UI component exports ← UPDATE
    ├── process_list.rs         # Process browser ← NEW
    ├── injection_panel.rs      # Injection controls ← NEW
    ├── log_viewer.rs           # Log display ← NEW
    └── settings.rs             # Stub for Phase 8
```

## Dependencies

Already added in Phase 1. Verify `injector-ui/Cargo.toml`:

```toml
[dependencies]
injector-core = { path = "../injector-core" }
egui = "0.30"
eframe = { version = "0.30", default-features = false, features = [
    "default_fonts",
    "glow",
    "persistence",
] }
anyhow = "1.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
rfd = "0.15"  # File picker
env_logger = "0.11"
log = "0.4"
```

## Step-by-Step Implementation

### Step 1: Define Application State

**File:** `injector-ui/src/app.rs`

```rust
//! Main application state and logic.

use eframe::egui;
use injector_core::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

mod ui;

/// Main application state.
pub struct InjectorApp {
    /// All running processes
    processes: Vec<ProcessInfo>,

    /// Currently selected process
    selected_process: Option<usize>,

    /// Search filter for process list
    process_filter: String,

    /// Selected DLL path
    dll_path: Option<PathBuf>,

    /// Selected injection method
    injection_method: InjectionMethodType,

    /// Log messages
    logs: Arc<Mutex<Vec<LogEntry>>>,

    /// Last error message
    last_error: Option<String>,

    /// Is running as administrator
    is_admin: bool,

    /// UI state
    ui_state: UiState,
}

/// Available injection methods.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectionMethodType {
    CreateRemoteThread,
    // Manual mapping will be added in Phase 6
    // QueueUserAPC will be added in Phase 7
    // NtCreateThreadEx will be added in Phase 7
}

impl InjectionMethodType {
    fn name(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "Classic injection via remote thread creation",
        }
    }
}

/// UI state and flags.
#[derive(Default)]
struct UiState {
    /// Process list needs refresh
    refresh_processes: bool,

    /// Injection in progress
    injecting: bool,

    /// Show settings panel
    show_settings: bool,
}

/// Log entry with level and message.
#[derive(Clone)]
pub struct LogEntry {
    pub level: log::Level,
    pub message: String,
    pub timestamp: std::time::SystemTime,
}

impl InjectorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Configure custom fonts if needed
        Self::configure_fonts(&cc.egui_ctx);

        // Set custom style
        Self::configure_style(&cc.egui_ctx);

        // Initialize logger to capture to UI
        let logs = Arc::new(Mutex::new(Vec::new()));
        Self::setup_logger(logs.clone());

        let mut app = Self {
            processes: Vec::new(),
            selected_process: None,
            process_filter: String::new(),
            dll_path: None,
            injection_method: InjectionMethodType::CreateRemoteThread,
            logs,
            last_error: None,
            ui_state: UiState {
                refresh_processes: true, // Refresh on startup
                ..Default::default()
            },
        };

        // Initial process enumeration
        app.refresh_processes();

        app
    }

    fn configure_fonts(ctx: &egui::Context) {
        // Use default fonts for now
        // Custom fonts can be added here if needed
    }

    fn configure_style(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();

        // Customize colors
        style.visuals.window_rounding = 8.0.into();
        style.visuals.widgets.noninteractive.rounding = 4.0.into();
        style.visuals.widgets.inactive.rounding = 4.0.into();
        style.visuals.widgets.hovered.rounding = 4.0.into();
        style.visuals.widgets.active.rounding = 4.0.into();

        ctx.set_style(style);
    }

    fn setup_logger(logs: Arc<Mutex<Vec<LogEntry>>>) {
        // Logger will be properly set up in Phase 9
        // For now, just use env_logger
    }

    fn refresh_processes(&mut self) {
        match ProcessEnumerator::enumerate() {
            Ok(procs) => {
                self.processes = procs;
                self.last_error = None;
                log::info!("Enumerated {} processes", self.processes.len());
            }
            Err(e) => {
                self.last_error = Some(format!("Failed to enumerate processes: {}", e));
                log::error!("{}", self.last_error.as_ref().unwrap());
            }
        }
        self.ui_state.refresh_processes = false;
    }

    fn perform_injection(&mut self) {
        let Some(selected_idx) = self.selected_process else {
            self.last_error = Some("No process selected".into());
            return;
        };

        let Some(dll_path) = &self.dll_path else {
            self.last_error = Some("No DLL selected".into());
            return;
        };

        let process = &self.processes[selected_idx];

        self.ui_state.injecting = true;
        log::info!("Starting injection into {} (PID: {})", process.name, process.pid);

        // Open process with required access
        let injector = CreateRemoteThreadInjector::new();
        let handle = match ProcessHandle::open(process.pid, injector.required_access()) {
            Ok(h) => h,
            Err(e) => {
                self.last_error = Some(format!("Failed to open process: {}", e));
                log::error!("{}", self.last_error.as_ref().unwrap());
                self.ui_state.injecting = false;
                return;
            }
        };

        // Perform injection
        match injector.inject(&handle, dll_path) {
            Ok(_) => {
                log::info!("Injection successful!");
                self.last_error = None;
            }
            Err(e) => {
                self.last_error = Some(format!("Injection failed: {}", e));
                log::error!("{}", self.last_error.as_ref().unwrap());
            }
        }

        self.ui_state.injecting = false;
    }

    fn open_dll_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("DLL Files", &["dll"])
            .pick_file()
        {
            self.dll_path = Some(path);
            self.last_error = None;
        }
    }
}

impl eframe::App for InjectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Refresh processes if flagged
        if self.ui_state.refresh_processes {
            self.refresh_processes();
        }

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Refresh Processes").clicked() {
                        self.ui_state.refresh_processes = true;
                        ui.close_menu();
                    }
                    ui.separator();
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });

                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        // TODO: Show about dialog
                        ui.close_menu();
                    }
                });
            });
        });

        // Left panel - Process list
        egui::SidePanel::left("process_panel")
            .resizable(true)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui::process_list::render(
                    ui,
                    &mut self.processes,
                    &mut self.selected_process,
                    &mut self.process_filter,
                    &mut self.ui_state.refresh_processes,
                );
            });

        // Bottom panel - Logs
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .default_height(200.0)
            .show(ctx, |ui| {
                ui::log_viewer::render(ui, &self.logs);
            });

        // Central panel - Injection controls
        egui::CentralPanel::default().show(ctx, |ui| {
            ui::injection_panel::render(
                ui,
                &self.processes,
                self.selected_process,
                &mut self.dll_path,
                &mut self.injection_method,
                &self.last_error,
                self.ui_state.injecting,
                &mut || self.open_dll_file_dialog(),
                &mut || self.perform_injection(),
            );
        });
    }
}

mod ui {
    pub mod process_list;
    pub mod injection_panel;
    pub mod log_viewer;
}
```

### Step 2: Implement Process List Component

**File:** `injector-ui/src/ui/process_list.rs`

```rust
//! Process list UI component.

use eframe::egui;
use injector_core::ProcessInfo;

pub fn render(
    ui: &mut egui::Ui,
    processes: &mut [ProcessInfo],
    selected: &mut Option<usize>,
    filter: &mut String,
    refresh_flag: &mut bool,
) {
    ui.heading("Processes");

    ui.horizontal(|ui| {
        ui.label("Search:");
        if ui.text_edit_singleline(filter).changed() {
            // Filter changed, clear selection if it doesn't match
        }

        if ui.button("🔄 Refresh").clicked() {
            *refresh_flag = true;
        }
    });

    ui.separator();

    // Filter processes
    let filter_lower = filter.to_lowercase();
    let filtered: Vec<(usize, &ProcessInfo)> = processes
        .iter()
        .enumerate()
        .filter(|(_, p)| {
            filter.is_empty()
                || p.name.to_lowercase().contains(&filter_lower)
                || p.pid.to_string().contains(&filter_lower)
        })
        .collect();

    ui.label(format!("{} processes (showing {})", processes.len(), filtered.len()));

    ui.separator();

    // Scrollable list
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (idx, process) in filtered {
                let is_selected = *selected == Some(idx);

                let response = ui.selectable_label(
                    is_selected,
                    format!("{} (PID: {})", process.name, process.pid),
                );

                if response.clicked() {
                    *selected = Some(idx);
                }

                // Show additional info on hover
                response.on_hover_text(format!(
                    "PID: {}\nParent PID: {}\nThreads: {}",
                    process.pid, process.parent_pid, process.thread_count
                ));
            }
        });
}
```

### Step 3: Implement Injection Panel Component

**File:** `injector-ui/src/ui/injection_panel.rs`

```rust
//! Injection control panel UI component.

use eframe::egui;
use injector_core::ProcessInfo;
use std::path::PathBuf;
use crate::app::InjectionMethodType;

pub fn render(
    ui: &mut egui::Ui,
    processes: &[ProcessInfo],
    selected_idx: Option<usize>,
    dll_path: &mut Option<PathBuf>,
    injection_method: &mut InjectionMethodType,
    last_error: &Option<String>,
    injecting: bool,
    is_admin: bool,
    open_file_dialog: &mut dyn FnMut(),
    perform_injection: &mut dyn FnMut(),
) {
    ui.heading("DLL Injection");

    // Admin warning
    if !is_admin {
        ui.add_space(5.0);
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::RED, "⚠ NOT RUNNING AS ADMINISTRATOR");
            });
            ui.small("Injection into system processes and most games will fail.");
        });
    }

    ui.add_space(10.0);

    // Selected process info
    ui.group(|ui| {
        ui.label("Target Process:");
        if let Some(idx) = selected_idx {
            if let Some(process) = processes.get(idx) {
                ui.horizontal(|ui| {
                    ui.label("📋");
                    ui.label(&process.name);
                });
                ui.horizontal(|ui| {
                    ui.label("🆔");
                    ui.label(format!("PID: {}", process.pid));
                });
                ui.horizontal(|ui| {
                    ui.label("🧵");
                    ui.label(format!("Threads: {}", process.thread_count));
                });
            } else {
                ui.colored_label(egui::Color32::RED, "Invalid selection");
            }
        } else {
            ui.colored_label(egui::Color32::GRAY, "No process selected");
        }
    });

    ui.add_space(10.0);

    // DLL selection
    ui.group(|ui| {
        ui.label("DLL to Inject:");

        ui.horizontal(|ui| {
            if ui.button("📁 Browse...").clicked() {
                open_file_dialog();
            }

            if let Some(path) = dll_path {
                ui.label(path.file_name().unwrap().to_string_lossy().to_string());
            } else {
                ui.colored_label(egui::Color32::GRAY, "No DLL selected");
            }
        });

        if let Some(path) = dll_path {
            ui.small(path.to_string_lossy().to_string());

            // Validate DLL
            if !path.exists() {
                ui.colored_label(egui::Color32::RED, "⚠ File does not exist");
            } else if !path.is_absolute() {
                ui.colored_label(egui::Color32::RED, "⚠ Path must be absolute");
            } else if path.extension().and_then(|s| s.to_str()) != Some("dll") {
                ui.colored_label(egui::Color32::YELLOW, "⚠ File extension is not .dll");
            }
        }
    });

    ui.add_space(10.0);

    // Injection method selection
    ui.group(|ui| {
        ui.label("Injection Method:");

        egui::ComboBox::from_id_salt("method_selector")
            .selected_text(injection_method.name())
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    injection_method,
                    InjectionMethodType::CreateRemoteThread,
                    "CreateRemoteThread",
                );
                // More methods will be added in later phases
            });

        ui.small(injection_method.description());
    });

    ui.add_space(20.0);

    // Inject button
    ui.vertical_centered(|ui| {
        let can_inject = selected_idx.is_some() && dll_path.is_some() && !injecting;

        let button = egui::Button::new(if injecting { "Injecting..." } else { "💉 Inject" })
            .min_size(egui::vec2(200.0, 40.0));

        if ui.add_enabled(can_inject, button).clicked() {
            perform_injection();
        }
    });

    ui.add_space(10.0);

    // Error display
    if let Some(error) = last_error {
        ui.group(|ui| {
            ui.colored_label(egui::Color32::RED, "❌ Error:");
            ui.label(error);
        });
    }

    ui.add_space(10.0);

    // Information panel
    ui.group(|ui| {
        ui.label("ℹ Information:");
        ui.small("1. Select a target process from the list");
        ui.small("2. Choose a DLL file to inject");
        ui.small("3. Select an injection method");
        ui.small("4. Click 'Inject' to start");
        ui.add_space(5.0);
        ui.colored_label(
            egui::Color32::YELLOW,
            "⚠ Administrator privileges may be required"
        );
    });
}
```

### Step 4: Implement Log Viewer Component

**File:** `injector-ui/src/ui/log_viewer.rs`

```rust
//! Log viewer UI component.

use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::app::LogEntry;

pub fn render(ui: &mut egui::Ui, logs: &Arc<Mutex<Vec<LogEntry>>>) {
    ui.heading("Logs");

    ui.horizontal(|ui| {
        if ui.button("Clear").clicked() {
            if let Ok(mut log_vec) = logs.lock() {
                log_vec.clear();
            }
        }

        ui.label("Filter:");
        // TODO: Add log level filter checkboxes
    });

    ui.separator();

    // Scrollable log area
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            if let Ok(log_vec) = logs.lock() {
                for entry in log_vec.iter() {
                    ui.horizontal(|ui| {
                        // Level indicator with color
                        let (color, level_str) = match entry.level {
                            log::Level::Error => (egui::Color32::RED, "ERROR"),
                            log::Level::Warn => (egui::Color32::YELLOW, "WARN "),
                            log::Level::Info => (egui::Color32::GREEN, "INFO "),
                            log::Level::Debug => (egui::Color32::GRAY, "DEBUG"),
                            log::Level::Trace => (egui::Color32::DARK_GRAY, "TRACE"),
                        };

                        ui.colored_label(color, level_str);
                        ui.label(&entry.message);
                    });
                }

                if log_vec.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No log messages");
                }
            }
        });
}
```

### Step 5: Update UI Module Exports

**File:** `injector-ui/src/ui/mod.rs`

```rust
//! UI components.

pub mod process_list;
pub mod injection_panel;
pub mod log_viewer;
```

### Step 6: Update Main Entry Point

**File:** `injector-ui/src/main.rs`

```rust
//! DLL Injector GUI Application

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod config;
mod ui;

use app::InjectorApp;

fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    log::info!("Starting DLL Injector v{}", env!("CARGO_PKG_VERSION"));

    // Configure native options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0])
            .with_title("DLL Injector")
            .with_icon(
                // Load icon if available
                eframe::icon_data::from_png_bytes(&[])
                    .unwrap_or_default()
            ),
        ..Default::default()
    };

    // Run the application
    eframe::run_native(
        "DLL Injector",
        options,
        Box::new(|cc| Ok(Box::new(InjectorApp::new(cc)))),
    )
}
```

### Step 7: Test the UI

```bash
cd F:\Projects\Cheats\dllInjector
cargo run --release -p injector-ui
```

**Expected behavior:**
- Window opens with three panels
- Process list shows all running processes
- Search filter works
- Can select a process
- Can open file dialog to select DLL
- Inject button becomes enabled when process and DLL selected
- Logs appear in bottom panel

## Testing Checklist

- [ ] Application launches without errors
- [ ] Process list populates on startup
- [ ] Search filter narrows process list
- [ ] Can select processes with mouse
- [ ] File dialog opens when clicking Browse
- [ ] Selected DLL path displays correctly
- [ ] Inject button enables/disables appropriately
- [ ] Log messages appear in log viewer
- [ ] Panels are resizable
- [ ] Refresh button updates process list
- [ ] Error messages display when injection fails

## Common Pitfalls

### 1. Log Mutex Deadlock
**Problem:** Holding log lock while rendering causes freeze
**Solution:** Clone logs or use try_lock() with timeout

### 2. Process List Not Updating
**Problem:** Forgetting to set refresh flag
**Solution:** Use flag pattern to trigger refresh from UI

### 3. File Dialog Blocking
**Problem:** rfd blocks UI thread
**Solution:** This is acceptable for now, async version in later phase

### 4. Layout Issues
**Problem:** Panels don't resize correctly
**Solution:** Use auto_shrink([false, false]) on ScrollAreas

### 5. State Management
**Problem:** Losing state between frames
**Solution:** Store all state in InjectorApp struct

## Completion Criteria

Phase 4 is complete when:
- ✅ UI renders with all three panels
- ✅ Process list displays and filters correctly
- ✅ Injection controls work
- ✅ Log viewer shows messages
- ✅ File dialog opens and selects DLL
- ✅ Injection can be triggered from UI
- ✅ Error messages display properly
- ✅ UI is responsive and doesn't freeze

## Git Commit

```bash
git add injector-ui/src/
git commit -m "feat: implement egui UI with process list and injection panel

- Create InjectorApp with full state management
- Implement process list component with search/filter
- Build injection control panel with method selection
- Add log viewer with color-coded levels
- Integrate file picker for DLL selection
- Add custom styling and layout
- Implement process refresh functionality
- Include error display and validation

UI is fully functional and ready for privilege elevation.

Follows docs/phases/phase-04-ui-foundation.md
"
```

## Next Steps

Proceed to **Phase 5: Privilege Elevation** (docs/phases/phase-05-privileges.md)

Phase 5 will implement:
- SeDebugPrivilege elevation
- Administrator detection
- UAC prompt when needed
- Privilege status display in UI
