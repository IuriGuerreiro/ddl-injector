//! Injection control panel UI component.

use eframe::egui;
use injector_core::ProcessInfo;
use std::path::PathBuf;
use crate::app::InjectionMethodType;

/// Actions that can be triggered from the injection panel
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InjectionPanelAction {
    None,
    OpenFileDialog,
    PerformInjection,
}

pub fn render(
    ui: &mut egui::Ui,
    processes: &[ProcessInfo],
    selected_idx: Option<usize>,
    dll_path: &mut Option<PathBuf>,
    injection_method: &mut InjectionMethodType,
    last_error: &Option<String>,
    injecting: bool,
    is_admin: bool,
) -> InjectionPanelAction {
    let mut action = InjectionPanelAction::None;
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
                action = InjectionPanelAction::OpenFileDialog;
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
            "⚠ Administrator privileges may be required"
        );
    });

    action
}
