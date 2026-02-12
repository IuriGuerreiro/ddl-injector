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

    let frame = egui::Frame::new()
        .fill(egui::Color32::from_rgb(11, 16, 27))
        .inner_margin(egui::Margin::same(18))
        .corner_radius(egui::CornerRadius::same(16));

    frame.show(ui, |ui| {
        ui.vertical(|ui| {
            ui.heading(egui::RichText::new("PAYLOAD ORCHESTRATOR").size(24.0));
            ui.label(
                egui::RichText::new("Neon tactical injection suite for live process manipulation")
                    .color(egui::Color32::from_rgb(144, 172, 232)),
            );
            ui.add_space(12.0);

            ui.columns(2, |columns| {
                columns[0].group(|ui| {
                    ui.label(egui::RichText::new("Privileges").strong());
                    status_chip(ui, "ADMIN", is_admin);
                    status_chip(ui, "SeDebugPrivilege", has_debug_privilege);
                    if !is_admin {
                        ui.small(
                            egui::RichText::new("Elevation required for hardened targets")
                                .color(egui::Color32::from_rgb(248, 181, 97)),
                        );
                    }
                });

                columns[1].group(|ui| {
                    ui.label(egui::RichText::new("Target").strong());
                    if let Some(idx) = selected_idx {
                        if let Some(process) = processes.get(idx) {
                            ui.label(
                                egui::RichText::new(&process.name)
                                    .size(20.0)
                                    .color(egui::Color32::from_rgb(112, 208, 255)),
                            );
                            ui.small(format!("PID {}", process.pid));
                            ui.small(format!("{} threads", process.thread_count));
                        } else {
                            ui.colored_label(egui::Color32::RED, "Invalid process selection");
                        }
                    } else {
                        ui.colored_label(egui::Color32::from_gray(140), "No process selected");
                    }
                });
            });

            ui.add_space(12.0);
            ui.group(|ui| {
                ui.label(egui::RichText::new("Payload Path").strong());
                ui.horizontal(|ui| {
                    if ui.button("BROWSE FILE").clicked() {
                        action = InjectionPanelAction::OpenFileDialog;
                    }
                    if !recent_dlls.is_empty() {
                        egui::ComboBox::from_id_salt("recent_dlls")
                            .selected_text("LOAD RECENT")
                            .show_ui(ui, |ui| {
                                for recent_dll in recent_dlls {
                                    let file_name = recent_dll
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "Unknown".to_string());

                                    if ui.button(file_name).clicked() {
                                        action = InjectionPanelAction::SelectRecentDll(
                                            recent_dll.clone(),
                                        );
                                    }
                                }
                            });
                    }
                });

                if let Some(path) = dll_path {
                    ui.label(path.display().to_string());
                    if !path.exists() {
                        ui.colored_label(egui::Color32::RED, "Path does not exist");
                    } else if path.extension().and_then(|s| s.to_str()) != Some("dll") {
                        ui.colored_label(egui::Color32::YELLOW, "Extension is not .dll");
                    }
                } else {
                    ui.colored_label(egui::Color32::from_gray(130), "No DLL selected yet");
                }
            });

            ui.add_space(12.0);
            ui.group(|ui| {
                ui.label(egui::RichText::new("Injection Vector").strong());
                egui::ComboBox::from_id_salt("method_selector")
                    .selected_text(injection_method.name())
                    .show_ui(ui, |ui| {
                        for method in InjectionMethodType::all() {
                            ui.selectable_value(injection_method, *method, method.name());
                        }
                    });
                ui.small(
                    egui::RichText::new(injection_method.description())
                        .color(egui::Color32::from_rgb(143, 170, 221)),
                );
            });

            ui.add_space(18.0);
            ui.horizontal(|ui| {
                let can_inject = selected_idx.is_some() && dll_path.is_some() && !injecting;
                let pulse = ui
                    .ctx()
                    .animate_bool(egui::Id::new("inject_button_pulse"), injecting);
                let pulse_tint = (120.0 + pulse * 90.0) as u8;

                let inject_btn = egui::Button::new(if injecting {
                    egui::RichText::new("INJECTING...").strong()
                } else {
                    egui::RichText::new("EXECUTE INJECTION").strong()
                })
                .fill(egui::Color32::from_rgb(40, pulse_tint, 255))
                .min_size(egui::vec2(260.0, 48.0));

                if ui.add_enabled(can_inject, inject_btn).clicked() {
                    action = InjectionPanelAction::PerformInjection;
                }

                if !can_inject {
                    ui.small(
                        egui::RichText::new(
                            "Waiting for process + payload selection before deployment",
                        )
                        .color(egui::Color32::from_gray(145)),
                    );
                }
            });

            if let Some(error) = last_error {
                ui.add_space(12.0);
                let warning_frame = egui::Frame::new()
                    .fill(egui::Color32::from_rgb(64, 18, 24))
                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(214, 72, 98)))
                    .inner_margin(egui::Margin::same(10))
                    .corner_radius(egui::CornerRadius::same(10));
                warning_frame.show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("INJECTION FAULT")
                            .strong()
                            .color(egui::Color32::from_rgb(255, 129, 145)),
                    );
                    ui.label(error);
                });
            }
        });
    });

    action
}

fn status_chip(ui: &mut egui::Ui, label: &str, active: bool) {
    let (fill, text) = if active {
        (
            egui::Color32::from_rgb(20, 99, 70),
            egui::RichText::new(format!("{}: ACTIVE", label)).color(egui::Color32::LIGHT_GREEN),
        )
    } else {
        (
            egui::Color32::from_rgb(76, 38, 24),
            egui::RichText::new(format!("{}: OFFLINE", label))
                .color(egui::Color32::from_rgb(255, 177, 139)),
        )
    };

    egui::Frame::new()
        .fill(fill)
        .inner_margin(egui::Margin::symmetric(8, 4))
        .corner_radius(egui::CornerRadius::same(6))
        .show(ui, |ui| {
            ui.label(text);
        });
}
