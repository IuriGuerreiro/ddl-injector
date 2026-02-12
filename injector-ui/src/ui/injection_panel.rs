//! Injection control panel UI component.

use crate::app::InjectionMethodType;
use eframe::egui;
use injector_core::ProcessInfo;
use std::path::PathBuf;

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

    ui.label(
        egui::RichText::new("OPERATION / PAYLOAD EXECUTION")
            .heading()
            .color(egui::Color32::from_rgb(243, 255, 115)),
    );
    ui.label(
        egui::RichText::new("Inject with precision. Leave no footprint.")
            .small()
            .color(egui::Color32::from_rgb(114, 196, 176)),
    );

    ui.add_space(10.0);

    ui.columns(2, |columns| {
        columns[0].group(|ui| {
            ui.label(egui::RichText::new("PRIVILEGE GRID").strong());
            ui.separator();

            ui.colored_label(
                if is_admin {
                    egui::Color32::from_rgb(120, 255, 145)
                } else {
                    egui::Color32::from_rgb(255, 95, 95)
                },
                if is_admin {
                    "● Administrator Access: YES"
                } else {
                    "● Administrator Access: NO"
                },
            );

            let debug_text = if has_debug_privilege {
                "● SeDebugPrivilege: ENABLED"
            } else if is_admin {
                "● SeDebugPrivilege: FAILED"
            } else {
                "● SeDebugPrivilege: LOCKED"
            };

            ui.colored_label(
                if has_debug_privilege {
                    egui::Color32::from_rgb(120, 255, 145)
                } else {
                    egui::Color32::from_rgb(255, 203, 109)
                },
                debug_text,
            );

            if !is_admin {
                ui.add_space(4.0);
                ui.small("Elevate process to target protected sessions.");
            }
        });

        columns[1].group(|ui| {
            ui.label(egui::RichText::new("TARGET LOCK").strong());
            ui.separator();

            if let Some(idx) = selected_idx {
                if let Some(process) = processes.get(idx) {
                    ui.label(format!("Name    : {}", process.name));
                    ui.label(format!("PID     : {}", process.pid));
                    ui.label(format!("Threads : {}", process.thread_count));
                } else {
                    ui.colored_label(egui::Color32::from_rgb(255, 70, 70), "Selection invalid");
                }
            } else {
                ui.colored_label(egui::Color32::from_rgb(140, 140, 140), "No target selected");
            }
        });
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(egui::RichText::new("PAYLOAD SOURCE").strong());
        ui.separator();

        ui.horizontal(|ui| {
            if ui
                .add_sized([120.0, 28.0], egui::Button::new("BROWSE DLL"))
                .clicked()
            {
                action = InjectionPanelAction::OpenFileDialog;
            }

            if !recent_dlls.is_empty() {
                egui::ComboBox::from_id_salt("recent_dlls")
                    .selected_text("Recent payloads")
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
        });

        ui.add_space(4.0);
        if let Some(path) = dll_path {
            ui.monospace(path.to_string_lossy().to_string());

            if !path.exists() {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 95, 95),
                    "! File does not exist",
                );
            } else if !path.is_absolute() {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 95, 95),
                    "! Path must be absolute",
                );
            } else if path.extension().and_then(|s| s.to_str()) != Some("dll") {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 190, 120),
                    "! Non-.dll extension detected",
                );
            }
        } else {
            ui.colored_label(
                egui::Color32::from_rgb(130, 145, 145),
                "No payload selected",
            );
        }
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(egui::RichText::new("DELIVERY METHOD").strong());
        ui.separator();

        egui::ComboBox::from_id_salt("method_selector")
            .selected_text(injection_method.name())
            .show_ui(ui, |ui| {
                for method in InjectionMethodType::all() {
                    ui.selectable_value(injection_method, *method, method.name());
                }
            });

        ui.small(injection_method.description());
    });

    ui.add_space(14.0);

    ui.horizontal(|ui| {
        let has_process = selected_idx.is_some();
        let has_dll = dll_path.is_some();
        let can_inject = has_process && has_dll && !injecting;

        if ui
            .add_enabled(
                can_inject,
                egui::Button::new(if injecting {
                    "TRANSMITTING..."
                } else {
                    "EXECUTE INJECTION"
                })
                .min_size(egui::vec2(260.0, 42.0)),
            )
            .clicked()
        {
            action = InjectionPanelAction::PerformInjection;
        }

        if !can_inject {
            ui.vertical(|ui| {
                if !has_process {
                    ui.small("Select target process");
                }
                if !has_dll {
                    ui.small("Select payload DLL");
                }
                if injecting {
                    ui.small("Injection already running");
                }
            });
        }
    });

    if let Some(error) = last_error {
        ui.add_space(10.0);
        ui.group(|ui| {
            ui.colored_label(egui::Color32::from_rgb(255, 87, 87), "ERROR CHANNEL");
            ui.separator();
            ui.label(error);
        });
    }

    action
}
