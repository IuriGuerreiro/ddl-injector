//! Enhanced log viewer UI component with filtering and search.

use crate::logging::LogEntry;
use chrono::{DateTime, Local};
use eframe::egui;
use std::sync::{Arc, Mutex};

/// State for the log viewer UI.
#[derive(Default)]
pub struct LogViewerState {
    /// Filter by log level
    pub filter_error: bool,
    pub filter_warn: bool,
    pub filter_info: bool,
    pub filter_debug: bool,
    pub filter_trace: bool,

    /// Search text
    pub search_text: String,

    /// Auto-scroll enabled
    pub auto_scroll: bool,
}

impl LogViewerState {
    /// Check if a log entry passes the level filter.
    fn passes_level_filter(&self, level: log::Level) -> bool {
        if !self.filter_error
            && !self.filter_warn
            && !self.filter_info
            && !self.filter_debug
            && !self.filter_trace
        {
            return true;
        }

        match level {
            log::Level::Error => self.filter_error,
            log::Level::Warn => self.filter_warn,
            log::Level::Info => self.filter_info,
            log::Level::Debug => self.filter_debug,
            log::Level::Trace => self.filter_trace,
        }
    }

    /// Check if a log entry passes the search filter.
    fn passes_search_filter(&self, entry: &LogEntry) -> bool {
        if self.search_text.is_empty() {
            return true;
        }

        let search_lower = self.search_text.to_lowercase();
        entry.message.to_lowercase().contains(&search_lower)
            || entry.target.to_lowercase().contains(&search_lower)
    }

    /// Check if a log entry passes all filters.
    pub fn passes_filters(&self, entry: &LogEntry) -> bool {
        self.passes_level_filter(entry.level) && self.passes_search_filter(entry)
    }
}

/// Render the log viewer UI.
pub fn render(ui: &mut egui::Ui, logs: &Arc<Mutex<Vec<LogEntry>>>, state: &mut LogViewerState) {
    ui.horizontal(|ui| {
        ui.heading("TELEMETRY");
        ui.label(
            egui::RichText::new("Live instrumentation stream")
                .size(12.0)
                .color(egui::Color32::from_rgb(186, 193, 210)),
        );
    });

    egui::Frame::default()
        .fill(egui::Color32::from_rgb(17, 22, 36))
        .corner_radius(12.0)
        .inner_margin(egui::Margin::symmetric(10, 10))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("CLEAR").clicked() {
                    if let Ok(mut log_vec) = logs.lock() {
                        log_vec.clear();
                    }
                }

                if ui.button("EXPORT").clicked() {
                    export_logs(logs);
                }

                ui.separator();
                ui.checkbox(&mut state.filter_error, "ERR");
                ui.checkbox(&mut state.filter_warn, "WRN");
                ui.checkbox(&mut state.filter_info, "INF");
                ui.checkbox(&mut state.filter_debug, "DBG");
                ui.checkbox(&mut state.filter_trace, "TRC");

                ui.separator();
                ui.label("SEARCH");
                ui.add(egui::TextEdit::singleline(&mut state.search_text).desired_width(160.0));

                ui.separator();
                ui.checkbox(&mut state.auto_scroll, "FOLLOW");
            });

            ui.add_space(6.0);

            if let Ok(log_vec) = logs.lock() {
                let filtered_count = log_vec.iter().filter(|e| state.passes_filters(e)).count();
                ui.label(
                    egui::RichText::new(format!(
                        "{} packets visible · {} total",
                        filtered_count,
                        log_vec.len()
                    ))
                    .monospace()
                    .size(11.0)
                    .color(egui::Color32::from_rgb(228, 170, 71)),
                );
            }

            ui.add_space(8.0);

            let scroll_area = egui::ScrollArea::vertical().auto_shrink([false, false]);
            let scroll_area = if state.auto_scroll {
                scroll_area.stick_to_bottom(true)
            } else {
                scroll_area
            };

            scroll_area.show(ui, |ui| {
                if let Ok(log_vec) = logs.lock() {
                    let filtered_logs: Vec<&LogEntry> =
                        log_vec.iter().filter(|e| state.passes_filters(e)).collect();

                    for entry in &filtered_logs {
                        let (level_color, level_str) = match entry.level {
                            log::Level::Error => (egui::Color32::from_rgb(239, 112, 102), "ERROR"),
                            log::Level::Warn => (egui::Color32::from_rgb(231, 188, 92), "WARN "),
                            log::Level::Info => (egui::Color32::from_rgb(89, 206, 144), "INFO "),
                            log::Level::Debug => (egui::Color32::from_rgb(144, 158, 186), "DEBUG"),
                            log::Level::Trace => (egui::Color32::from_rgb(108, 117, 141), "TRACE"),
                        };

                        egui::Frame::default()
                            .fill(egui::Color32::from_rgb(24, 31, 46))
                            .corner_radius(8.0)
                            .inner_margin(egui::Margin::symmetric(8, 6))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    let datetime: DateTime<Local> = entry.timestamp.into();
                                    let time_str = datetime.format("%H:%M:%S").to_string();
                                    ui.label(
                                        egui::RichText::new(time_str)
                                            .monospace()
                                            .color(egui::Color32::from_rgb(131, 139, 161)),
                                    );

                                    ui.colored_label(
                                        level_color,
                                        egui::RichText::new(level_str).monospace().strong(),
                                    );

                                    if !entry.target.is_empty() {
                                        ui.label(
                                            egui::RichText::new(format!("[{}]", entry.target))
                                                .color(egui::Color32::from_rgb(120, 172, 255)),
                                        );
                                    }

                                    ui.label(&entry.message);
                                });
                            });

                        ui.add_space(4.0);
                    }

                    if filtered_logs.is_empty() && log_vec.is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(137, 146, 168),
                            "No telemetry yet",
                        );
                    } else if filtered_logs.is_empty() {
                        ui.colored_label(
                            egui::Color32::from_rgb(137, 146, 168),
                            "No telemetry matches current filters",
                        );
                    }
                }
            });
        });
}

/// Export logs to a file.
fn export_logs(logs: &Arc<Mutex<Vec<LogEntry>>>) {
    let file_path = rfd::FileDialog::new()
        .set_file_name("injector_logs.txt")
        .add_filter("Text Files", &["txt"])
        .add_filter("Log Files", &["log"])
        .save_file();

    if let Some(path) = file_path {
        if let Ok(log_vec) = logs.lock() {
            let mut content = String::new();

            for entry in log_vec.iter() {
                let datetime: DateTime<Local> = entry.timestamp.into();
                let timestamp = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                let level = format!("{:5}", entry.level.to_string());

                if entry.target.is_empty() {
                    content.push_str(&format!("[{}] {} {}\n", timestamp, level, entry.message));
                } else {
                    content.push_str(&format!(
                        "[{}] {} [{}] {}\n",
                        timestamp, level, entry.target, entry.message
                    ));
                }
            }

            if let Err(e) = std::fs::write(&path, content) {
                log::error!("Failed to export logs: {}", e);
            } else {
                log::info!("Logs exported to {}", path.display());
            }
        }
    }
}
