//! Enhanced log viewer UI component with filtering and search.

use eframe::egui;
use std::sync::{Arc, Mutex};
use crate::logging::LogEntry;
use chrono::{DateTime, Local};

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
        // If no filters are enabled, show all
        if !self.filter_error && !self.filter_warn && !self.filter_info
            && !self.filter_debug && !self.filter_trace {
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
    ui.heading("Logs");

    // Control bar
    ui.horizontal(|ui| {
        // Clear button
        if ui.button("Clear").clicked() {
            if let Ok(mut log_vec) = logs.lock() {
                log_vec.clear();
            }
        }

        // Export button
        if ui.button("Export...").clicked() {
            export_logs(logs);
        }

        ui.separator();

        // Level filter checkboxes
        ui.label("Filters:");
        ui.checkbox(&mut state.filter_error, "Error");
        ui.checkbox(&mut state.filter_warn, "Warn");
        ui.checkbox(&mut state.filter_info, "Info");
        ui.checkbox(&mut state.filter_debug, "Debug");
        ui.checkbox(&mut state.filter_trace, "Trace");

        ui.separator();

        // Search box
        ui.label("Search:");
        ui.text_edit_singleline(&mut state.search_text);

        ui.separator();

        // Auto-scroll toggle
        ui.checkbox(&mut state.auto_scroll, "Auto-scroll");
    });

    // Stats display
    if let Ok(log_vec) = logs.lock() {
        let filtered_count = log_vec.iter()
            .filter(|e| state.passes_filters(e))
            .count();
        let total_count = log_vec.len();

        ui.horizontal(|ui| {
            ui.label(format!("Showing {} of {} messages", filtered_count, total_count));
        });
    }

    ui.separator();

    // Scrollable log area
    let scroll_area = egui::ScrollArea::vertical()
        .auto_shrink([false, false]);

    let scroll_area = if state.auto_scroll {
        scroll_area.stick_to_bottom(true)
    } else {
        scroll_area
    };

    scroll_area.show(ui, |ui| {
        if let Ok(log_vec) = logs.lock() {
            let filtered_logs: Vec<&LogEntry> = log_vec.iter()
                .filter(|e| state.passes_filters(e))
                .collect();

            for entry in &filtered_logs {
                ui.horizontal(|ui| {
                    // Timestamp
                    let datetime: DateTime<Local> = entry.timestamp.into();
                    let time_str = datetime.format("%H:%M:%S").to_string();
                    ui.label(egui::RichText::new(time_str).color(egui::Color32::DARK_GRAY));

                    // Level indicator with color
                    let (color, level_str) = match entry.level {
                        log::Level::Error => (egui::Color32::RED, "ERROR"),
                        log::Level::Warn => (egui::Color32::YELLOW, "WARN "),
                        log::Level::Info => (egui::Color32::GREEN, "INFO "),
                        log::Level::Debug => (egui::Color32::GRAY, "DEBUG"),
                        log::Level::Trace => (egui::Color32::DARK_GRAY, "TRACE"),
                    };

                    ui.colored_label(color, level_str);

                    // Target (if not empty)
                    if !entry.target.is_empty() {
                        ui.label(egui::RichText::new(format!("[{}]", entry.target))
                            .color(egui::Color32::LIGHT_BLUE));
                    }

                    // Message
                    ui.label(&entry.message);
                });
            }

            if filtered_logs.is_empty() && log_vec.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "No log messages");
            } else if filtered_logs.is_empty() {
                ui.colored_label(egui::Color32::GRAY, "No messages match current filters");
            }
        }
    });
}

/// Export logs to a file.
fn export_logs(logs: &Arc<Mutex<Vec<LogEntry>>>) {
    // Open file dialog
    let file_path = rfd::FileDialog::new()
        .set_file_name("injector_logs.txt")
        .add_filter("Text Files", &["txt"])
        .add_filter("Log Files", &["log"])
        .save_file();

    if let Some(path) = file_path {
        // Collect all logs
        if let Ok(log_vec) = logs.lock() {
            let mut content = String::new();

            for entry in log_vec.iter() {
                let datetime: DateTime<Local> = entry.timestamp.into();
                let timestamp = datetime.format("%Y-%m-%d %H:%M:%S").to_string();
                let level = format!("{:5}", entry.level.to_string());

                if entry.target.is_empty() {
                    content.push_str(&format!("[{}] {} {}\n",
                        timestamp, level, entry.message));
                } else {
                    content.push_str(&format!("[{}] {} [{}] {}\n",
                        timestamp, level, entry.target, entry.message));
                }
            }

            // Write to file
            if let Err(e) = std::fs::write(&path, content) {
                log::error!("Failed to export logs: {}", e);
            } else {
                log::info!("Logs exported to {}", path.display());
            }
        }
    }
}
