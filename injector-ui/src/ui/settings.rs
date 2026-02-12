//! Settings panel UI component.

use crate::app::InjectionMethodType;
use crate::config::Config;
use eframe::egui;

pub fn render(ui: &mut egui::Ui, config: &mut Config, current_method: &mut InjectionMethodType) {
    ui.heading("CONTROL ROOM SETTINGS");
    ui.label(
        egui::RichText::new("Tune behavior and persistence")
            .size(12.0)
            .color(egui::Color32::from_rgb(186, 193, 210)),
    );

    ui.add_space(10.0);

    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 24, 41))
        .rounding(10.0)
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.label("Default Injection Method");

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

    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 24, 41))
        .rounding(10.0)
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.label("Auto-Refresh Process List");
            ui.add(
                egui::Slider::new(&mut config.auto_refresh_interval, 0..=60)
                    .text("seconds")
                    .suffix("s"),
            );
            if config.auto_refresh_interval == 0 {
                ui.small("Disabled");
            }
        });

    ui.add_space(10.0);

    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 24, 41))
        .rounding(10.0)
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Recent DLLs ({})", config.recent_dlls.len()));
                if ui.button("Clear").clicked() {
                    config.clear_recent();
                }
            });
            ui.separator();
            egui::ScrollArea::vertical()
                .max_height(160.0)
                .show(ui, |ui| {
                    if config.recent_dlls.is_empty() {
                        ui.colored_label(egui::Color32::from_rgb(137, 146, 168), "No recent DLLs");
                    } else {
                        for dll_path in &config.recent_dlls {
                            ui.small(dll_path.display().to_string());
                        }
                    }
                });
        });

    ui.add_space(10.0);

    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 24, 41))
        .rounding(10.0)
        .inner_margin(egui::Margin::same(10.0))
        .show(ui, |ui| {
            ui.label("Configuration");
            ui.small(format!("Location: {}", Config::config_path().display()));
            ui.horizontal(|ui| {
                if ui.button("Save Now").clicked() {
                    if let Err(e) = config.save() {
                        log::error!("Failed to save config: {}", e);
                    } else {
                        log::info!("Configuration saved");
                    }
                }

                if ui.button("Reset to Defaults").clicked() {
                    *config = Config::default();
                    log::info!("Configuration reset to defaults");
                }
            });
        });
}
