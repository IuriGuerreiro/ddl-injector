//! Settings panel UI component.

use crate::app::InjectionMethodType;
use crate::config::Config;
use eframe::egui;

pub fn render(ui: &mut egui::Ui, config: &mut Config, current_method: &mut InjectionMethodType) {
    ui.label(
        egui::RichText::new("CONTROL ROOM SETTINGS")
            .heading()
            .color(egui::Color32::from_rgb(243, 255, 115)),
    );

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.label("Default injection profile");

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

    ui.add_space(8.0);

    ui.group(|ui| {
        ui.label("Auto refresh frequency");

        ui.horizontal(|ui| {
            ui.add(
                egui::Slider::new(&mut config.auto_refresh_interval, 0..=60)
                    .text("seconds")
                    .suffix("s"),
            );

            if config.auto_refresh_interval == 0 {
                ui.label("disabled");
            }
        });
    });

    ui.add_space(8.0);

    ui.group(|ui| {
        ui.label("Recent payload history");

        ui.horizontal(|ui| {
            ui.label(format!("{} entries", config.recent_dlls.len()));

            if ui.button("Clear list").clicked() {
                config.clear_recent();
            }
        });

        ui.separator();

        egui::ScrollArea::vertical()
            .max_height(200.0)
            .show(ui, |ui| {
                if config.recent_dlls.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No recent DLLs");
                } else {
                    for dll_path in &config.recent_dlls {
                        ui.small(dll_path.display().to_string());
                    }
                }
            });
    });

    ui.add_space(8.0);

    ui.group(|ui| {
        ui.label("Configuration storage");

        let config_path = Config::config_path();
        ui.small(format!("Path: {}", config_path.display()));

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
