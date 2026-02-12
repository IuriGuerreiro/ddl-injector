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

    ui.vertical(|ui| {
        ui.heading("INJECTION DECK");
        ui.label(
            egui::RichText::new("Precision payload deployment console")
                .size(12.0)
                .color(egui::Color32::from_rgb(186, 193, 210)),
        );

        ui.add_space(8.0);

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(17, 27, 35))
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(53, 74, 92)))
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new("PRIVILEGE CHANNEL")
                        .monospace()
                        .size(11.0),
                );
                ui.horizontal_wrapped(|ui| {
                    privilege_pill(
                        ui,
                        if is_admin {
                            "ADMIN ONLINE"
                        } else {
                            "ADMIN OFFLINE"
                        },
                        if is_admin {
                            egui::Color32::from_rgb(66, 173, 120)
                        } else {
                            egui::Color32::from_rgb(190, 83, 72)
                        },
                    );

                    let debug_label = if has_debug_privilege {
                        "SeDebug READY"
                    } else if is_admin {
                        "SeDebug FAILED"
                    } else {
                        "SeDebug LOCKED"
                    };
                    let debug_color = if has_debug_privilege {
                        egui::Color32::from_rgb(84, 176, 229)
                    } else {
                        egui::Color32::from_rgb(228, 170, 71)
                    };
                    privilege_pill(ui, debug_label, debug_color);
                });
            });

        ui.add_space(10.0);

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(20, 24, 41))
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("TARGET LOCK").monospace().size(11.0));
                if let Some(idx) = selected_idx {
                    if let Some(process) = processes.get(idx) {
                        ui.label(
                            egui::RichText::new(format!("{} [{}]", process.name, process.pid))
                                .strong()
                                .size(16.0),
                        );
                        ui.small(format!(
                            "Parent PID: {} · Threads: {}",
                            process.parent_pid, process.thread_count
                        ));
                    } else {
                        ui.colored_label(egui::Color32::from_rgb(190, 83, 72), "Invalid selection");
                    }
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(228, 170, 71),
                        "No target selected from process matrix",
                    );
                }
            });

        ui.add_space(10.0);

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(20, 24, 41))
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("PAYLOAD").monospace().size(11.0));
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new("BROWSE DLL")
                                .fill(egui::Color32::from_rgb(64, 87, 129))
                                .rounding(8.0),
                        )
                        .clicked()
                    {
                        action = InjectionPanelAction::OpenFileDialog;
                    }

                    if !recent_dlls.is_empty() {
                        egui::ComboBox::from_id_salt("recent_dlls")
                            .selected_text("RECENT")
                            .show_ui(ui, |ui| {
                                for recent_dll in recent_dlls {
                                    let file_name = recent_dll
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "Unknown".to_string());

                                    if ui.selectable_label(false, &file_name).clicked() {
                                        action = InjectionPanelAction::SelectRecentDll(
                                            recent_dll.clone(),
                                        );
                                    }
                                }
                            });
                    }
                });

                ui.add_space(6.0);
                if let Some(path) = dll_path {
                    ui.label(path.display().to_string());

                    if !path.exists() {
                        ui.colored_label(
                            egui::Color32::from_rgb(190, 83, 72),
                            "File does not exist",
                        );
                    } else if !path.is_absolute() {
                        ui.colored_label(
                            egui::Color32::from_rgb(190, 83, 72),
                            "Path must be absolute",
                        );
                    } else if path.extension().and_then(|s| s.to_str()) != Some("dll") {
                        ui.colored_label(
                            egui::Color32::from_rgb(228, 170, 71),
                            "Expected .dll extension",
                        );
                    }
                } else {
                    ui.colored_label(
                        egui::Color32::from_rgb(137, 146, 168),
                        "No payload selected",
                    );
                }
            });

        ui.add_space(10.0);

        egui::Frame::default()
            .fill(egui::Color32::from_rgb(20, 24, 41))
            .rounding(12.0)
            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
            .show(ui, |ui| {
                ui.label(egui::RichText::new("VECTOR").monospace().size(11.0));
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

        let has_process = selected_idx.is_some();
        let has_dll = dll_path.is_some();
        let can_inject = has_process && has_dll && !injecting;

        let inject_text = if injecting {
            "INJECTING..."
        } else {
            "EXECUTE INJECTION"
        };
        let button = egui::Button::new(egui::RichText::new(inject_text).size(18.0).strong())
            .fill(if can_inject {
                egui::Color32::from_rgb(219, 91, 74)
            } else {
                egui::Color32::from_rgb(63, 68, 79)
            })
            .rounding(12.0)
            .min_size(egui::vec2(ui.available_width(), 46.0));

        if ui.add_enabled(can_inject, button).clicked() {
            action = InjectionPanelAction::PerformInjection;
        }

        if !can_inject {
            ui.add_space(6.0);
            ui.small("Need target process + DLL payload + idle injector state.");
        }

        if let Some(error) = last_error {
            ui.add_space(10.0);
            egui::Frame::default()
                .fill(egui::Color32::from_rgb(60, 28, 31))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(190, 83, 72)))
                .rounding(10.0)
                .inner_margin(egui::Margin::same(10.0))
                .show(ui, |ui| {
                    ui.colored_label(egui::Color32::from_rgb(255, 176, 169), "TRANSMISSION ERROR");
                    ui.label(error);
                });
        }
    });

    action
}

fn privilege_pill(ui: &mut egui::Ui, label: &str, color: egui::Color32) {
    egui::Frame::default()
        .fill(color.gamma_multiply(0.20))
        .stroke(egui::Stroke::new(1.0, color))
        .rounding(99.0)
        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.colored_label(color, label);
        });
}
