//! Main application state and logic.

use crate::config::Config;
use crate::logging::LogEntry;
use crate::ui;
use eframe::egui;
use injector_core::PrivilegeManager;
use injector_core::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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

    /// Has SeDebugPrivilege enabled
    has_debug_privilege: bool,

    /// UI state
    ui_state: UiState,

    /// Log viewer state
    log_viewer_state: ui::log_viewer::LogViewerState,

    /// Application configuration
    config: Config,
}

/// Available injection methods.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectionMethodType {
    CreateRemoteThread,
    ManualMap,
    QueueUserApc,
    NtCreateThreadEx,
}

impl InjectionMethodType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
            Self::ManualMap => "Manual Map",
            Self::QueueUserApc => "QueueUserAPC",
            Self::NtCreateThreadEx => "NtCreateThreadEx",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "Classic injection via remote thread creation",
            Self::ManualMap => "Advanced stealth injection - bypasses PEB module list",
            Self::QueueUserApc => "Inject via Asynchronous Procedure Call to alertable threads",
            Self::NtCreateThreadEx => "Inject via undocumented native API (bypasses some hooks)",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::CreateRemoteThread,
            Self::ManualMap,
            Self::QueueUserApc,
            Self::NtCreateThreadEx,
        ]
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

impl InjectorApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Load config
        let config = Config::load();

        // Configure custom fonts if needed
        Self::configure_fonts(&cc.egui_ctx);

        // Set custom style
        Self::configure_style(&cc.egui_ctx);

        // Initialize logger to capture to UI
        let logs = Arc::new(Mutex::new(Vec::new()));
        Self::setup_logger(logs.clone());

        // Check privilege status
        let is_admin = PrivilegeManager::is_administrator().unwrap_or(false);
        let has_debug_privilege = if is_admin {
            PrivilegeManager::try_enable_debug_privilege()
        } else {
            false
        };

        log::info!(
            "Administrator: {}, SeDebugPrivilege: {}",
            is_admin,
            has_debug_privilege
        );

        let mut app = Self {
            processes: Vec::new(),
            selected_process: None,
            process_filter: config.process_filter.clone(),
            dll_path: None,
            injection_method: config.preferred_method.into(),
            logs,
            last_error: None,
            is_admin,
            has_debug_privilege,
            ui_state: UiState {
                refresh_processes: true, // Refresh on startup
                ..Default::default()
            },
            log_viewer_state: Default::default(),
            config,
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
        style.spacing.item_spacing = egui::vec2(10.0, 10.0);
        style.spacing.button_padding = egui::vec2(14.0, 10.0);
        style.spacing.window_margin = egui::Margin::same(14.0);

        // Brutalist cyberpunk inspired theme
        style.visuals.dark_mode = true;
        style.visuals.window_fill = egui::Color32::from_rgb(8, 10, 14);
        style.visuals.faint_bg_color = egui::Color32::from_rgb(16, 19, 28);
        style.visuals.panel_fill = egui::Color32::from_rgb(10, 12, 18);
        style.visuals.extreme_bg_color = egui::Color32::from_rgb(3, 4, 7);
        style.visuals.code_bg_color = egui::Color32::from_rgb(12, 18, 26);
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(0, 238, 255);
        style.visuals.selection.stroke.color = egui::Color32::BLACK;
        style.visuals.hyperlink_color = egui::Color32::from_rgb(255, 92, 246);

        style.visuals.window_rounding = 0.0.into();
        style.visuals.widgets.noninteractive.rounding = 0.0.into();
        style.visuals.widgets.inactive.rounding = 0.0.into();
        style.visuals.widgets.hovered.rounding = 0.0.into();
        style.visuals.widgets.active.rounding = 0.0.into();

        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(14, 18, 26);
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(12, 18, 26);
        style.visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(178, 255, 252);
        style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(255, 92, 246);
        style.visuals.widgets.hovered.fg_stroke.color = egui::Color32::BLACK;
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(0, 238, 255);
        style.visuals.widgets.active.fg_stroke.color = egui::Color32::BLACK;
        style.visuals.widgets.open.bg_fill = egui::Color32::from_rgb(0, 238, 255);

        style.visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 238, 255));
        style.visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 238, 255));
        style.visuals.widgets.inactive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(93, 114, 140));
        style.visuals.widgets.hovered.bg_stroke =
            egui::Stroke::new(2.0, egui::Color32::from_rgb(255, 225, 64));
        style.visuals.widgets.active.bg_stroke =
            egui::Stroke::new(2.0, egui::Color32::from_rgb(255, 225, 64));

        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(26.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(16.0, egui::FontFamily::Monospace),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(15.0, egui::FontFamily::Monospace),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::new(15.0, egui::FontFamily::Monospace),
        );

        ctx.set_style(style);
    }

    fn setup_logger(logs: Arc<Mutex<Vec<LogEntry>>>) {
        use crate::logging;

        // Initialize dual logger (file + UI)
        if let Err(e) = logging::DualLogger::init(logs) {
            eprintln!("Failed to initialize logger: {}", e);
            // Fallback to basic env_logger
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .init();
        }

        // Rotate old logs (keep last 10)
        if let Err(e) = logging::rotate_logs(10) {
            log::warn!("Failed to rotate logs: {}", e);
        }

        log::info!("DLL Injector v{} starting", env!("CARGO_PKG_VERSION"));
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
        log::info!(
            "Starting {} injection into {} (PID: {})",
            self.injection_method.name(),
            process.name,
            process.pid
        );

        // Perform injection based on selected method
        let result = match self.injection_method {
            InjectionMethodType::CreateRemoteThread => {
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
                injector.inject(&handle, dll_path)
            }
            InjectionMethodType::ManualMap => {
                let injector = ManualMapInjector;
                let handle = match ProcessHandle::open(process.pid, injector.required_access()) {
                    Ok(h) => h,
                    Err(e) => {
                        self.last_error = Some(format!("Failed to open process: {}", e));
                        log::error!("{}", self.last_error.as_ref().unwrap());
                        self.ui_state.injecting = false;
                        return;
                    }
                };
                injector.inject(&handle, dll_path)
            }
            InjectionMethodType::QueueUserApc => {
                let injector = QueueUserApcInjector::new();
                let handle = match ProcessHandle::open(process.pid, injector.required_access()) {
                    Ok(h) => h,
                    Err(e) => {
                        self.last_error = Some(format!("Failed to open process: {}", e));
                        log::error!("{}", self.last_error.as_ref().unwrap());
                        self.ui_state.injecting = false;
                        return;
                    }
                };
                injector.inject(&handle, dll_path)
            }
            InjectionMethodType::NtCreateThreadEx => {
                let injector = NtCreateThreadExInjector::new();
                let handle = match ProcessHandle::open(process.pid, injector.required_access()) {
                    Ok(h) => h,
                    Err(e) => {
                        self.last_error = Some(format!("Failed to open process: {}", e));
                        log::error!("{}", self.last_error.as_ref().unwrap());
                        self.ui_state.injecting = false;
                        return;
                    }
                };
                injector.inject(&handle, dll_path)
            }
        };

        // Handle result
        match result {
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
            self.config.add_recent_dll(path.clone());
            self.dll_path = Some(path);
            self.last_error = None;
        }
    }
}

impl eframe::App for InjectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update window state in config
        let size = ctx.screen_rect().size();
        self.config.window_state.width = size.x;
        self.config.window_state.height = size.y;

        // Refresh processes if flagged
        if self.ui_state.refresh_processes {
            self.refresh_processes();
        }

        // Top menu bar
        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("DDL INJECTOR // OPS CONSOLE")
                        .strong()
                        .color(egui::Color32::from_rgb(0, 238, 255)),
                );
                ui.separator();
                ui.small(
                    egui::RichText::new("Neon Brutalist Control Deck")
                        .color(egui::Color32::from_rgb(255, 225, 64)),
                );
            });

            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Refresh Processes").clicked() {
                        self.ui_state.refresh_processes = true;
                        ui.close_menu();
                    }
                    if ui.button("Settings").clicked() {
                        self.ui_state.show_settings = true;
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

        // Settings window
        if self.ui_state.show_settings {
            egui::Window::new("Settings")
                .open(&mut self.ui_state.show_settings)
                .resizable(false)
                .show(ctx, |ui| {
                    ui::settings::render(ui, &mut self.config, &mut self.injection_method);
                });
        }

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
                self.config.process_filter = self.process_filter.clone();
            });

        // Bottom panel - Logs
        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .default_height(200.0)
            .show(ctx, |ui| {
                ui::log_viewer::render(ui, &self.logs, &mut self.log_viewer_state);
            });

        // Central panel - Injection controls
        let action = egui::CentralPanel::default()
            .show(ctx, |ui| {
                ui::injection_panel::render(
                    ui,
                    &self.processes,
                    self.selected_process,
                    &mut self.dll_path,
                    &mut self.injection_method,
                    &self.last_error,
                    self.ui_state.injecting,
                    self.is_admin,
                    self.has_debug_privilege,
                    &self.config.recent_dlls,
                )
            })
            .inner;

        // Handle injection panel actions
        match action {
            ui::injection_panel::InjectionPanelAction::OpenFileDialog => {
                self.open_dll_file_dialog();
            }
            ui::injection_panel::InjectionPanelAction::PerformInjection => {
                self.perform_injection();
            }
            ui::injection_panel::InjectionPanelAction::SelectRecentDll(path) => {
                self.dll_path = Some(path);
                self.last_error = None;
            }
            ui::injection_panel::InjectionPanelAction::None => {}
        }
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        // Save config on exit
        if let Err(e) = self.config.save() {
            log::error!("Failed to save config: {}", e);
        }
    }
}
