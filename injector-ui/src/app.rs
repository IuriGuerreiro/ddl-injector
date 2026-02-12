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
        let config = Config::load();

        Self::configure_fonts(&cc.egui_ctx);
        Self::configure_style(&cc.egui_ctx);

        let logs = Arc::new(Mutex::new(Vec::new()));
        Self::setup_logger(logs.clone());

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
                refresh_processes: true,
                ..Default::default()
            },
            log_viewer_state: Default::default(),
            config,
        };

        app.refresh_processes();
        app
    }

    fn configure_fonts(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();
        style.override_text_style = Some(egui::TextStyle::Body);
        ctx.set_style(style);
    }

    fn configure_style(ctx: &egui::Context) {
        let mut style = (*ctx.style()).clone();

        style.visuals = egui::Visuals::dark();
        style.visuals.override_text_color = Some(egui::Color32::from_rgb(220, 255, 245));
        style.visuals.panel_fill = egui::Color32::from_rgb(4, 9, 14);
        style.visuals.window_fill = egui::Color32::from_rgb(8, 16, 22);
        style.visuals.faint_bg_color = egui::Color32::from_rgb(14, 24, 30);
        style.visuals.extreme_bg_color = egui::Color32::from_rgb(2, 5, 8);
        style.visuals.code_bg_color = egui::Color32::from_rgb(7, 30, 33);
        style.visuals.window_stroke = egui::Stroke::new(1.2, egui::Color32::from_rgb(50, 219, 201));
        style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(11, 18, 27);
        style.visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(28, 53, 75));
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(9, 28, 38);
        style.visuals.widgets.inactive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(0, 170, 170));
        style.visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(15, 42, 50);
        style.visuals.widgets.hovered.bg_stroke =
            egui::Stroke::new(1.5, egui::Color32::from_rgb(240, 246, 99));
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(21, 59, 57);
        style.visuals.widgets.active.bg_stroke =
            egui::Stroke::new(1.6, egui::Color32::from_rgb(0, 255, 201));
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(17, 81, 71);
        style.visuals.selection.stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(252, 255, 140));

        style.visuals.window_rounding = 2.0.into();
        style.visuals.menu_rounding = 0.0.into();
        style.visuals.widgets.noninteractive.rounding = 0.0.into();
        style.visuals.widgets.inactive.rounding = 0.0.into();
        style.visuals.widgets.hovered.rounding = 0.0.into();
        style.visuals.widgets.active.rounding = 0.0.into();

        style.spacing.button_padding = egui::vec2(10.0, 8.0);
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.window_margin = egui::Margin::same(10.0);

        style.text_styles = [
            (
                egui::TextStyle::Heading,
                egui::FontId::new(26.0, egui::FontFamily::Proportional),
            ),
            (
                egui::TextStyle::Name("Hero".into()),
                egui::FontId::new(34.0, egui::FontFamily::Monospace),
            ),
            (
                egui::TextStyle::Body,
                egui::FontId::new(15.5, egui::FontFamily::Monospace),
            ),
            (
                egui::TextStyle::Button,
                egui::FontId::new(15.0, egui::FontFamily::Monospace),
            ),
            (
                egui::TextStyle::Monospace,
                egui::FontId::new(15.0, egui::FontFamily::Monospace),
            ),
            (
                egui::TextStyle::Small,
                egui::FontId::new(12.5, egui::FontFamily::Monospace),
            ),
        ]
        .into();

        ctx.set_style(style);
    }

    fn setup_logger(logs: Arc<Mutex<Vec<LogEntry>>>) {
        use crate::logging;

        if let Err(e) = logging::DualLogger::init(logs) {
            eprintln!("Failed to initialize logger: {}", e);
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
                .init();
        }

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
        let size = ctx.screen_rect().size();
        self.config.window_state.width = size.x;
        self.config.window_state.height = size.y;

        if self.ui_state.refresh_processes {
            self.refresh_processes();
        }

        egui::TopBottomPanel::top("menu_bar").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("◢ BLACKSITE // DLL INJECTOR ◣")
                        .text_style(egui::TextStyle::Name("Hero".into()))
                        .color(egui::Color32::from_rgb(243, 255, 125)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("SETTINGS").clicked() {
                        self.ui_state.show_settings = true;
                    }
                    if ui.button("REFRESH").clicked() {
                        self.ui_state.refresh_processes = true;
                    }
                    if ui.button("EXIT").clicked() {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                });
            });
            ui.label(
                egui::RichText::new(
                    "Tactical runtime injector console · neon brutalism mode · all systems live",
                )
                .small()
                .color(egui::Color32::from_rgb(101, 220, 190)),
            );
            ui.add_space(3.0);
        });

        if self.ui_state.show_settings {
            egui::Window::new("Control Room Settings")
                .open(&mut self.ui_state.show_settings)
                .resizable(false)
                .show(ctx, |ui| {
                    ui::settings::render(ui, &mut self.config, &mut self.injection_method);
                });
        }

        egui::SidePanel::left("process_panel")
            .resizable(true)
            .default_width(325.0)
            .show(ctx, |ui| {
                egui::Frame::group(ui.style())
                    .fill(egui::Color32::from_rgb(10, 20, 27))
                    .inner_margin(egui::Margin::same(12.0))
                    .show(ui, |ui| {
                        ui::process_list::render(
                            ui,
                            &mut self.processes,
                            &mut self.selected_process,
                            &mut self.process_filter,
                            &mut self.ui_state.refresh_processes,
                        );
                        self.config.process_filter = self.process_filter.clone();
                    });
            });

        egui::TopBottomPanel::bottom("log_panel")
            .resizable(true)
            .default_height(210.0)
            .show(ctx, |ui| {
                egui::Frame::group(ui.style())
                    .fill(egui::Color32::from_rgb(8, 13, 24))
                    .inner_margin(egui::Margin::same(10.0))
                    .show(ui, |ui| {
                        ui::log_viewer::render(ui, &self.logs, &mut self.log_viewer_state);
                    });
            });

        let action = egui::CentralPanel::default()
            .show(ctx, |ui| {
                egui::Frame::group(ui.style())
                    .fill(egui::Color32::from_rgb(9, 22, 28))
                    .inner_margin(egui::Margin::same(16.0))
                    .show(ui, |ui| {
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
                    .inner
            })
            .inner;

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
        if let Err(e) = self.config.save() {
            log::error!("Failed to save config: {}", e);
        }
    }
}
