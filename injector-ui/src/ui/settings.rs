//! Settings panel UI component.

use crate::app::InjectionMethodType;
use crate::config::Config;
use eframe::egui;

pub fn render(ui: &mut egui::Ui, config: &mut Config, current_method: &mut InjectionMethodType) {
    ui.heading(
        egui::RichText::new("CONTROL TUNING")
            .color(egui::Color32::from_rgb(255, 225, 64))
            .strong(),
    );

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(
            egui::RichText::new("DEFAULT DELIVERY VECTOR")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );

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
        ui.label(
            egui::RichText::new("AUTO RESCAN CLOCK")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );

        ui.horizontal(|ui| {
            ui.add(
                egui::Slider::new(&mut config.auto_refresh_interval, 0..=60)
                    .text("seconds")
                    .suffix("s"),
            );

            if config.auto_refresh_interval == 0 {
                ui.colored_label(egui::Color32::from_rgb(255, 225, 64), "DISABLED");
            }
        });
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(
            egui::RichText::new("RECENT PAYLOADS")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );

        ui.horizontal(|ui| {
            ui.label(format!("{} tracked", config.recent_dlls.len()));
            if ui.button("Clear").clicked() {
                config.clear_recent();
            }
        });

        ui.separator();

        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                if config.recent_dlls.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(105, 122, 142), "No payload history");
                } else {
                    for dll_path in &config.recent_dlls {
                        ui.small(egui::RichText::new(dll_path.display().to_string()).monospace());
                    }
                }
            });
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label(
            egui::RichText::new("CONFIG ARTIFACT")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );

        let config_path = Config::config_path();
        ui.small(egui::RichText::new(format!("Path: {}", config_path.display())).monospace());

        ui.horizontal(|ui| {
            if ui.button("Save Now").clicked() {
                if let Err(e) = config.save() {
                    log::error!("Failed to save config: {}", e);
                } else {
                    log::info!("Configuration saved");
                }
            }

            if ui.button("Reset Defaults").clicked() {
                *config = Config::default();
                log::info!("Configuration reset to defaults");
            }
        });
    });
}
