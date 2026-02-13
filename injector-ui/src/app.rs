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

    /// [DLL Proxy] Target executable path
    proxy_target_exe: Option<PathBuf>,

    /// [DLL Proxy] System DLL name to proxy
    proxy_system_dll: String,

    /// [DLL Proxy] Backup original DLL before replacing
    proxy_backup_original: bool,

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
    SectionMapping,
    ThreadHijacking,
    ReflectiveLoader,
    DllProxying,
}

impl InjectionMethodType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
            Self::ManualMap => "Manual Map",
            Self::QueueUserApc => "QueueUserAPC",
            Self::NtCreateThreadEx => "NtCreateThreadEx",
            Self::SectionMapping => "Section Mapping",
            Self::ThreadHijacking => "Thread Hijacking",
            Self::ReflectiveLoader => "Reflective Loader",
            Self::DllProxying => "DLL Proxying",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::CreateRemoteThread => "Classic injection via remote thread creation",
            Self::ManualMap => "Advanced stealth injection - bypasses PEB module list",
            Self::QueueUserApc => "Inject via Asynchronous Procedure Call to alertable threads",
            Self::NtCreateThreadEx => "Inject via undocumented native API (bypasses some hooks)",
            Self::SectionMapping => "Memory-efficient injection using section objects (STABLE)",
            Self::ThreadHijacking => "Hijack existing thread to execute injection (EXPERIMENTAL)",
            Self::ReflectiveLoader => "Advanced PIC loader - no LoadLibrary calls (RESEARCH)",
            Self::DllProxying => {
                "File-based hijacking - loads before anti-cheat initialization (STEALTH)"
            }
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::CreateRemoteThread,
            Self::ManualMap,
            Self::QueueUserApc,
            Self::NtCreateThreadEx,
            Self::SectionMapping,
            Self::ThreadHijacking,
            Self::ReflectiveLoader,
            Self::DllProxying,
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
            proxy_target_exe: None,
            proxy_system_dll: "version.dll".to_string(),
            proxy_backup_original: true,
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

        // Customize colors
        style.visuals.window_rounding = 8.0.into();
        style.visuals.widgets.noninteractive.rounding = 4.0.into();
        style.visuals.widgets.inactive.rounding = 4.0.into();
        style.visuals.widgets.hovered.rounding = 4.0.into();
        style.visuals.widgets.active.rounding = 4.0.into();

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
        let Some(dll_path) = &self.dll_path else {
            self.last_error = Some("No DLL selected".into());
            log::error!("{}", self.last_error.as_ref().unwrap());
            return;
        };

        let process = if matches!(self.injection_method, InjectionMethodType::DllProxying) {
            None
        } else {
            let Some(selected_idx) = self.selected_process else {
                self.last_error = Some("No process selected".into());
                log::error!("{}", self.last_error.as_ref().unwrap());
                return;
            };

            Some(&self.processes[selected_idx])
        };

        self.ui_state.injecting = true;
        if let Some(process) = process {
            log::info!(
                "Starting {} injection into {} (PID: {})",
                self.injection_method.name(),
                process.name,
                process.pid
            );
        } else {
            log::info!("Starting {} preparation", self.injection_method.name());
        }

        // Perform injection based on selected method
        let result = match self.injection_method {
            InjectionMethodType::CreateRemoteThread => {
                let process = process.expect("process required for runtime injection");
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
                let process = process.expect("process required for runtime injection");
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
                let process = process.expect("process required for runtime injection");
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
                let process = process.expect("process required for runtime injection");
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
            InjectionMethodType::SectionMapping => {
                let process = process.expect("process required for runtime injection");
                let injector = SectionMappingInjector::new();
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
            InjectionMethodType::ThreadHijacking => {
                let process = process.expect("process required for runtime injection");
                let injector = ThreadHijackingInjector::new();
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
            InjectionMethodType::ReflectiveLoader => {
                let process = process.expect("process required for runtime injection");
                let injector = ReflectiveLoaderInjector::new();
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
            InjectionMethodType::DllProxying => {
                let Some(target_exe) = &self.proxy_target_exe else {
                    self.last_error = Some("DLL Proxying requires a target executable path".into());
                    log::error!("{}", self.last_error.as_ref().unwrap());
                    self.ui_state.injecting = false;
                    return;
                };

                let system_dll_name = self.proxy_system_dll.trim();
                if system_dll_name.is_empty() {
                    self.last_error = Some("System DLL name is required for DLL Proxying".into());
                    log::error!("{}", self.last_error.as_ref().unwrap());
                    self.ui_state.injecting = false;
                    return;
                }

                let injector = DllProxyInjector::new();
                let options = PreparationOptions::new(system_dll_name.to_string())
                    .with_backup(self.proxy_backup_original);

                log::info!(
                    "Preparing DLL proxy: payload={}, target_exe={}, system_dll={}, backup={}",
                    dll_path.display(),
                    target_exe.display(),
                    system_dll_name,
                    self.proxy_backup_original
                );

                match injector.prepare(target_exe, dll_path, &options) {
                    Ok(prep_result) => {
                        log::info!("DLL proxy preparation complete");
                        log::info!("{}", prep_result.instructions);
                        self.last_error = None;
                    }
                    Err(e) => {
                        self.last_error = Some(format!("DLL proxy preparation failed: {}", e));
                        log::error!("{}", self.last_error.as_ref().unwrap());
                    }
                }

                self.ui_state.injecting = false;
                return;
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

    fn open_target_exe_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Executable Files", &["exe"])
            .pick_file()
        {
            self.proxy_target_exe = Some(path);
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
                    &mut self.proxy_target_exe,
                    &mut self.proxy_system_dll,
                    &mut self.proxy_backup_original,
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
            ui::injection_panel::InjectionPanelAction::OpenTargetExeDialog => {
                self.open_target_exe_file_dialog();
            }
            ui::injection_panel::InjectionPanelAction::SelectRecentDll(path) => {
                self.dll_path = Some(path);
                self.last_error = None;
            }
            ui::injection_panel::InjectionPanelAction::CleanupDllProxy => {
                let Some(target_exe) = &self.proxy_target_exe else {
                    self.last_error = Some("No target executable selected for cleanup".into());
                    log::error!("{}", self.last_error.as_ref().unwrap());
                    return;
                };

                let injector = DllProxyInjector::new();
                log::info!("Starting DLL proxy cleanup for {}", target_exe.display());
                match injector.cleanup(target_exe) {
                    Ok(()) => {
                        self.last_error = None;
                        log::info!("DLL proxy cleanup completed for {}", target_exe.display());
                    }
                    Err(e) => {
                        self.last_error = Some(format!("DLL proxy cleanup failed: {}", e));
                        log::error!("{}", self.last_error.as_ref().unwrap());
                    }
                }
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
