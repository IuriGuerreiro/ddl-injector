//! Injection control panel UI component.

use crate::app::InjectionMethodType;
use eframe::egui;
use injector_core::ProcessInfo;
use std::path::PathBuf;

/// Actions that can be triggered from the injection panel
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionPanelAction {
    None,
    OpenFileDialog,
    PerformInjection,
    SelectRecentDll(PathBuf),
}

#[allow(clippy::too_many_arguments)]
pub fn render(
    ui: &mut egui::Ui,
    processes: &[ProcessInfo],
    selected_idx: Option<usize>,
    dll_path: &mut Option<PathBuf>,
    injection_method: &mut InjectionMethodType,
    last_error: &Option<String>,
    injecting: bool,
    is_admin: bool,
    has_debug_privilege: bool,
    recent_dlls: &[PathBuf],
) -> InjectionPanelAction {
    let mut action = InjectionPanelAction::None;
    ui.heading("DLL Injection");

    // Privilege status display
    ui.add_space(5.0);
    ui.group(|ui| {
        ui.label("Privilege Status:");

        ui.horizontal(|ui| {
            if is_admin {
                ui.colored_label(egui::Color32::GREEN, "✓ Administrator");
            } else {
                ui.colored_label(egui::Color32::RED, "✗ Not Administrator");
            }
        });

        ui.horizontal(|ui| {
            if has_debug_privilege {
                ui.colored_label(egui::Color32::GREEN, "✓ SeDebugPrivilege");
            } else if is_admin {
                ui.colored_label(egui::Color32::YELLOW, "⚠ SeDebugPrivilege failed to enable");
            } else {
                ui.colored_label(egui::Color32::YELLOW, "⚠ SeDebugPrivilege not available");
            }
        });

        if !is_admin {
            ui.add_space(5.0);
            ui.small("Run as administrator to inject into protected processes");
        }
    });

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
                action = InjectionPanelAction::OpenFileDialog;
            }

            // Recent DLLs dropdown
            if !recent_dlls.is_empty() {
                egui::ComboBox::from_id_salt("recent_dlls")
                    .selected_text("Recent...")
                    .show_ui(ui, |ui| {
                        for recent_dll in recent_dlls {
                            let file_name = recent_dll
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "Unknown".to_string());

                            if ui.selectable_label(false, &file_name).clicked() {
                                action = InjectionPanelAction::SelectRecentDll(recent_dll.clone());
                            }
                        }
                    });
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
                for method in InjectionMethodType::all() {
                    ui.selectable_value(injection_method, *method, method.name());
                }
            });

        ui.small(injection_method.description());

        // Show additional info for specific methods
        match injection_method {
            InjectionMethodType::ManualMap => {
                ui.add_space(5.0);
                ui.colored_label(
                    egui::Color32::from_rgb(100, 200, 255),
                    "🔒 Stealth Features:",
                );
                ui.small("• Bypasses PEB module list");
                ui.small("• Not visible in most module enumerators");
            }
            InjectionMethodType::QueueUserApc => {
                ui.add_space(5.0);
                ui.colored_label(egui::Color32::YELLOW, "⚠ Note:");
                ui.small("• Requires alertable threads to execute");
                ui.small("• Injection may be delayed until a thread sleeps");
            }
            InjectionMethodType::NtCreateThreadEx => {
                ui.add_space(5.0);
                ui.colored_label(egui::Color32::from_rgb(100, 255, 150), "🚀 Advanced:");
                ui.small("• Uses undocumented native ntdll API");
                ui.small("• Bypasses some CreateRemoteThread hooks");
            }
            _ => {}
        }
    });

    ui.add_space(20.0);

    // Inject button
    ui.vertical_centered(|ui| {
        let has_process = selected_idx.is_some();
        let has_dll = dll_path.is_some();
        let can_inject = has_process && has_dll && !injecting;

        // Debug info for troubleshooting
        if !can_inject {
            ui.add_space(5.0);
            ui.label("Button disabled because:");
            if !has_process {
                ui.small("  ❌ No process selected");
            }
            if !has_dll {
                ui.small("  ❌ No DLL selected");
            }
            if injecting {
                ui.small("  ⏳ Injection in progress");
            }
            ui.add_space(5.0);
        }

        let button = egui::Button::new(if injecting {
            "Injecting..."
        } else {
            "💉 Inject"
        })
        .min_size(egui::vec2(200.0, 40.0));

        if ui.add_enabled(can_inject, button).clicked() {
            action = InjectionPanelAction::PerformInjection;
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
            "⚠ Administrator privileges may be required",
        );
    });

    action
}
