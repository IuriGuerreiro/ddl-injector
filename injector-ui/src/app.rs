//! Main application state and logic.

use eframe::egui;
use injector_core::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::ui;

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
    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
        }
    }

    pub fn description(&self) -> &'static str {
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
            is_admin: false, // Stub for Phase 5
            ui_state: UiState {
                refresh_processes: true, // Refresh on startup
                ..Default::default()
            },
        };

        // Initial process enumeration
        app.refresh_processes();

        app
    }

    fn configure_fonts(_ctx: &egui::Context) {
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

    fn setup_logger(_logs: Arc<Mutex<Vec<LogEntry>>>) {
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
        let action = egui::CentralPanel::default().show(ctx, |ui| {
            ui::injection_panel::render(
                ui,
                &self.processes,
                self.selected_process,
                &mut self.dll_path,
                &mut self.injection_method,
                &self.last_error,
                self.ui_state.injecting,
                self.is_admin,
            )
        }).inner;

        // Handle injection panel actions
        match action {
            ui::injection_panel::InjectionPanelAction::OpenFileDialog => {
                self.open_dll_file_dialog();
            }
            ui::injection_panel::InjectionPanelAction::PerformInjection => {
                self.perform_injection();
            }
            ui::injection_panel::InjectionPanelAction::None => {}
        }
    }
}
