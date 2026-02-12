//! Settings panel UI component.

use crate::app::InjectionMethodType;
use crate::config::Config;
use eframe::egui;

pub fn render(ui: &mut egui::Ui, config: &mut Config, current_method: &mut InjectionMethodType) {
    ui.heading("Control Room Settings");
    ui.label(
        egui::RichText::new("Persistence, defaults, and operator convenience controls")
            .color(egui::Color32::from_rgb(136, 171, 226)),
    );
    ui.add_space(12.0);

    ui.group(|ui| {
        ui.label(egui::RichText::new("Default Injection Method").strong());

        let mut method = config.preferred_method;
        egui::ComboBox::from_id_salt("default_method")
            .selected_text(format!("{:?}", method))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::CreateRemoteThread,
                    "CreateRemoteThread",
                );
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::ManualMap,
                    "Manual Map",
                );
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::QueueUserApc,
                    "QueueUserAPC",
                );
                ui.selectable_value(
                    &mut method,
                    crate::config::SerializableMethod::NtCreateThreadEx,
                    "NtCreateThreadEx",
                );
            });

        if method != config.preferred_method {
            config.preferred_method = method;
            *current_method = method.into();
        }
    });

    ui.add_space(10.0);
    ui.group(|ui| {
        ui.label(egui::RichText::new("Auto-Refresh Interval").strong());
        ui.horizontal(|ui| {
            ui.add(
                egui::Slider::new(&mut config.auto_refresh_interval, 0..=60)
                    .text("seconds")
                    .suffix("s"),
            );
            if config.auto_refresh_interval == 0 {
                ui.colored_label(egui::Color32::from_rgb(255, 206, 124), "disabled");
            }
        });
    });

    ui.add_space(10.0);
    ui.group(|ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new("Recent DLL Arsenal").strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Clear").clicked() {
                    config.clear_recent();
                }
                ui.label(format!("{} entries", config.recent_dlls.len()));
            });
        });

        egui::ScrollArea::vertical()
            .max_height(160.0)
            .show(ui, |ui| {
                if config.recent_dlls.is_empty() {
                    ui.colored_label(egui::Color32::from_gray(130), "No recently used payloads");
                } else {
                    for dll_path in &config.recent_dlls {
                        ui.small(dll_path.display().to_string());
                    }
                }
            });
    });

    ui.add_space(10.0);
    ui.group(|ui| {
        ui.label(egui::RichText::new("Configuration File").strong());
        let config_path = Config::config_path();
        ui.small(format!("Location: {}", config_path.display()));

        ui.horizontal(|ui| {
            if ui.button("Save now").clicked() {
                if let Err(e) = config.save() {
                    log::error!("Failed to save config: {}", e);
                } else {
                    log::info!("Configuration saved");
                }
            }

            if ui.button("Reset defaults").clicked() {
                *config = Config::default();
                log::info!("Configuration reset to defaults");
            }
        });
    });
}
