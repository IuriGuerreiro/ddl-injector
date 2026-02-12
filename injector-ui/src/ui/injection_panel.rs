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

    ui.heading(
        egui::RichText::new("PAYLOAD ORCHESTRATION")
            .color(egui::Color32::from_rgb(255, 225, 64))
            .strong(),
    );
    ui.label(
        egui::RichText::new("Neon Brutalist execution lane for precision injection")
            .color(egui::Color32::from_rgb(132, 171, 194))
            .italics(),
    );

    ui.add_space(10.0);

    ui.columns(2, |columns| {
        columns[0].group(|ui| {
            ui.label(
                egui::RichText::new("PRIVILEGE GRID")
                    .strong()
                    .color(egui::Color32::from_rgb(255, 92, 246)),
            );

            let (admin_color, admin_text) = if is_admin {
                (egui::Color32::from_rgb(0, 238, 255), "ROOT ACCESS: GRANTED")
            } else {
                (egui::Color32::from_rgb(255, 74, 74), "ROOT ACCESS: DENIED")
            };
            ui.colored_label(admin_color, admin_text);

            let (debug_color, debug_text) = if has_debug_privilege {
                (egui::Color32::from_rgb(0, 238, 255), "SEDEBUG: ENABLED")
            } else if is_admin {
                (
                    egui::Color32::from_rgb(255, 225, 64),
                    "SEDEBUG: ELEVATION FAILED",
                )
            } else {
                (
                    egui::Color32::from_rgb(255, 225, 64),
                    "SEDEBUG: LOCKED (NON-ADMIN)",
                )
            };
            ui.colored_label(debug_color, debug_text);

            if !is_admin {
                ui.small("Launch with administrator rights for protected targets.");
            }
        });

        columns[1].group(|ui| {
            ui.label(
                egui::RichText::new("TARGET LOCK")
                    .strong()
                    .color(egui::Color32::from_rgb(255, 92, 246)),
            );

            if let Some(idx) = selected_idx {
                if let Some(process) = processes.get(idx) {
                    ui.label(
                        egui::RichText::new(format!("{}", process.name))
                            .color(egui::Color32::from_rgb(178, 255, 252))
                            .strong(),
                    );
                    ui.monospace(format!("PID      {:>8}", process.pid));
                    ui.monospace(format!("PPID     {:>8}", process.parent_pid));
                    ui.monospace(format!("THREADS  {:>8}", process.thread_count));
                } else {
                    ui.colored_label(egui::Color32::from_rgb(255, 74, 74), "INVALID SELECTION");
                }
            } else {
                ui.colored_label(egui::Color32::from_rgb(105, 122, 142), "NO TARGET ARMED");
            }
        });
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(
            egui::RichText::new("PAYLOAD FILE")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );

        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("SELECT DLL")
                            .strong()
                            .color(egui::Color32::BLACK),
                    )
                    .fill(egui::Color32::from_rgb(0, 238, 255)),
                )
                .clicked()
            {
                action = InjectionPanelAction::OpenFileDialog;
            }

            if !recent_dlls.is_empty() {
                egui::ComboBox::from_id_salt("recent_dlls")
                    .selected_text("RECENT PAYLOADS")
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
                ui.label(
                    egui::RichText::new(
                        path.file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                    )
                    .monospace()
                    .color(egui::Color32::from_rgb(178, 255, 252)),
                );
            } else {
                ui.colored_label(egui::Color32::from_rgb(105, 122, 142), "No DLL selected");
            }
        });

        if let Some(path) = dll_path {
            ui.small(egui::RichText::new(path.to_string_lossy()).monospace());

            if !path.exists() {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 74, 74),
                    "⚠ File does not exist",
                );
            } else if !path.is_absolute() {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 74, 74),
                    "⚠ Path must be absolute",
                );
            } else if path.extension().and_then(|s| s.to_str()) != Some("dll") {
                ui.colored_label(
                    egui::Color32::from_rgb(255, 225, 64),
                    "⚠ Extension is not .dll",
                );
            } else {
                ui.colored_label(egui::Color32::from_rgb(0, 238, 255), "PAYLOAD VERIFIED");
            }
        }
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(
            egui::RichText::new("DELIVERY VECTOR")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );

        egui::ComboBox::from_id_salt("method_selector")
            .selected_text(injection_method.name())
            .show_ui(ui, |ui| {
                for method in InjectionMethodType::all() {
                    ui.selectable_value(injection_method, *method, method.name());
                }
            });

        ui.small(
            egui::RichText::new(injection_method.description())
                .color(egui::Color32::from_rgb(130, 166, 195)),
        );
    });

    ui.add_space(16.0);

    ui.vertical_centered(|ui| {
        let has_process = selected_idx.is_some();
        let has_dll = dll_path.is_some();
        let can_inject = has_process && has_dll && !injecting;

        if !can_inject {
            ui.label(
                egui::RichText::new("ARMING CONDITIONS")
                    .strong()
                    .color(egui::Color32::from_rgb(255, 225, 64)),
            );
            if !has_process {
                ui.small("• Missing target process lock");
            }
            if !has_dll {
                ui.small("• Missing payload file");
            }
            if injecting {
                ui.small("• Injector currently executing");
            }
            ui.add_space(6.0);
        }

        let button = egui::Button::new(
            egui::RichText::new(if injecting {
                "EXECUTING..."
            } else {
                "LAUNCH INJECTION"
            })
            .strong(),
        )
        .fill(if injecting {
            egui::Color32::from_rgb(120, 120, 120)
        } else {
            egui::Color32::from_rgb(255, 92, 246)
        })
        .min_size(egui::vec2(280.0, 54.0));

        if ui.add_enabled(can_inject, button).clicked() {
            action = InjectionPanelAction::PerformInjection;
        }
    });

    if let Some(error) = last_error {
        ui.add_space(12.0);
        ui.group(|ui| {
            ui.colored_label(egui::Color32::from_rgb(255, 74, 74), "ERROR SIGNAL");
            ui.label(error);
        });
    }

    ui.add_space(10.0);
    ui.group(|ui| {
        ui.label(
            egui::RichText::new("RUNBOOK")
                .strong()
                .color(egui::Color32::from_rgb(255, 225, 64)),
        );
        ui.small("01 → Select target from PROCESS TARGET MATRIX");
        ui.small("02 → Attach payload DLL");
        ui.small("03 → Choose delivery vector");
        ui.small("04 → Launch injection");
    });

    action
}
