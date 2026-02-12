//! Log viewer UI component.

use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::app::LogEntry;

pub fn render(ui: &mut egui::Ui, logs: &Arc<Mutex<Vec<LogEntry>>>) {
    ui.heading("Logs");

    ui.horizontal(|ui| {
        if ui.button("Clear").clicked() {
            if let Ok(mut log_vec) = logs.lock() {
                log_vec.clear();
            }
        }

        ui.label("Filter:");
        // TODO: Add log level filter checkboxes
    });

    ui.separator();

    // Scrollable log area
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            if let Ok(log_vec) = logs.lock() {
                for entry in log_vec.iter() {
                    ui.horizontal(|ui| {
                        // Level indicator with color
                        let (color, level_str) = match entry.level {
                            log::Level::Error => (egui::Color32::RED, "ERROR"),
                            log::Level::Warn => (egui::Color32::YELLOW, "WARN "),
                            log::Level::Info => (egui::Color32::GREEN, "INFO "),
                            log::Level::Debug => (egui::Color32::GRAY, "DEBUG"),
                            log::Level::Trace => (egui::Color32::DARK_GRAY, "TRACE"),
                        };

                        ui.colored_label(color, level_str);
                        ui.label(&entry.message);
                    });
                }

                if log_vec.is_empty() {
                    ui.colored_label(egui::Color32::GRAY, "No log messages");
                }
            }
        });
}
