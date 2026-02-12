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

    fn passes_search_filter(&self, entry: &LogEntry) -> bool {
        if self.search_text.is_empty() {
            return true;
        }

        let search_lower = self.search_text.to_lowercase();
        entry.message.to_lowercase().contains(&search_lower)
            || entry.target.to_lowercase().contains(&search_lower)
    }

    pub fn passes_filters(&self, entry: &LogEntry) -> bool {
        self.passes_level_filter(entry.level) && self.passes_search_filter(entry)
    }
}

pub fn render(ui: &mut egui::Ui, logs: &Arc<Mutex<Vec<LogEntry>>>, state: &mut LogViewerState) {
    egui::Frame::new()
        .fill(egui::Color32::from_rgb(9, 14, 22))
        .inner_margin(egui::Margin::same(12))
        .corner_radius(egui::CornerRadius::same(12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TELEMETRY FEED");
                ui.label(
                    egui::RichText::new("live runtime diagnostics")
                        .color(egui::Color32::from_rgb(136, 172, 227)),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.checkbox(&mut state.auto_scroll, "FOLLOW");
                    if ui.button("EXPORT").clicked() {
                        export_logs(logs);
                    }
                    if ui.button("CLEAR").clicked() {
                        if let Ok(mut log_vec) = logs.lock() {
                            log_vec.clear();
                        }
                    }
                });
            });

            ui.add_space(8.0);
            ui.horizontal_wrapped(|ui| {
                ui.label("LEVELS");
                ui.checkbox(&mut state.filter_error, "ERR");
                ui.checkbox(&mut state.filter_warn, "WRN");
                ui.checkbox(&mut state.filter_info, "INF");
                ui.checkbox(&mut state.filter_debug, "DBG");
                ui.checkbox(&mut state.filter_trace, "TRC");
                ui.separator();
                ui.label("SEARCH");
                ui.add(egui::TextEdit::singleline(&mut state.search_text).desired_width(180.0));
            });

            if let Ok(log_vec) = logs.lock() {
                let filtered_count = log_vec.iter().filter(|e| state.passes_filters(e)).count();
                ui.small(format!(
                    "{} shown / {} total",
                    filtered_count,
                    log_vec.len()
                ));
            }

            ui.separator();

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
                        let (tag_bg, tag_fg, label) = match entry.level {
                            log::Level::Error => (
                                egui::Color32::from_rgb(87, 24, 35),
                                egui::Color32::from_rgb(255, 146, 163),
                                "ERR",
                            ),
                            log::Level::Warn => (
                                egui::Color32::from_rgb(90, 66, 14),
                                egui::Color32::from_rgb(255, 226, 134),
                                "WRN",
                            ),
                            log::Level::Info => (
                                egui::Color32::from_rgb(14, 80, 55),
                                egui::Color32::from_rgb(136, 255, 202),
                                "INF",
                            ),
                            log::Level::Debug => (
                                egui::Color32::from_rgb(32, 52, 84),
                                egui::Color32::from_rgb(170, 200, 255),
                                "DBG",
                            ),
                            log::Level::Trace => (
                                egui::Color32::from_rgb(44, 40, 66),
                                egui::Color32::from_rgb(188, 168, 255),
                                "TRC",
                            ),
                        };

                        egui::Frame::new()
                            .fill(egui::Color32::from_rgb(16, 20, 31))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(33, 43, 64)))
                            .inner_margin(egui::Margin::same(8))
                            .corner_radius(egui::CornerRadius::same(8))
                            .show(ui, |ui| {
                                ui.horizontal_wrapped(|ui| {
                                    let datetime: DateTime<Local> = entry.timestamp.into();
                                    ui.small(
                                        egui::RichText::new(
                                            datetime.format("%H:%M:%S").to_string(),
                                        )
                                        .color(egui::Color32::from_gray(160)),
                                    );
                                    egui::Frame::new()
                                        .fill(tag_bg)
                                        .inner_margin(egui::Margin::symmetric(6, 2))
                                        .corner_radius(egui::CornerRadius::same(4))
                                        .show(ui, |ui| {
                                            ui.small(
                                                egui::RichText::new(label).color(tag_fg).strong(),
                                            );
                                        });
                                    if !entry.target.is_empty() {
                                        ui.small(
                                            egui::RichText::new(format!("@{}", entry.target))
                                                .color(egui::Color32::from_rgb(121, 175, 255)),
                                        );
                                    }
                                    ui.label(&entry.message);
                                });
                            });
                        ui.add_space(5.0);
                    }

                    if filtered_logs.is_empty() && log_vec.is_empty() {
                        ui.colored_label(egui::Color32::from_gray(130), "No telemetry yet");
                    } else if filtered_logs.is_empty() {
                        ui.colored_label(egui::Color32::from_gray(130), "No entries match filters");
                    }
                }
            });
        });
}

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
