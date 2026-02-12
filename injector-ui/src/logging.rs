//! Custom logging implementation for UI display and file output.

use log::{Level, Metadata, Record};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use std::fs;
use std::path::PathBuf;

/// Log entry with full details.
#[derive(Clone)]
pub struct LogEntry {
    pub level: Level,
    pub message: String,
    pub target: String,
    pub timestamp: SystemTime,
}

/// Logger that sends to both file and UI.
pub struct DualLogger {
    ui_logs: Arc<Mutex<Vec<LogEntry>>>,
    file_logger: env_logger::Logger,
}

impl DualLogger {
    /// Create a new dual logger.
    pub fn new(ui_logs: Arc<Mutex<Vec<LogEntry>>>) -> anyhow::Result<Self> {
        // Create logs directory
        let mut log_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."));
        log_dir.push("DllInjector");
        log_dir.push("logs");
        fs::create_dir_all(&log_dir)?;

        // Generate log filename with timestamp
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        let log_file = log_dir.join(format!("injector_{}.log", timestamp));

        // Create log file
        let file = fs::File::create(log_file)?;

        // Build the internal env_logger
        let file_logger = env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or("info")
        )
        .target(env_logger::Target::Pipe(Box::new(file)))
        .build();

        Ok(Self {
            ui_logs,
            file_logger,
        })
    }

    /// Initialize the dual logger as the global logger.
    pub fn init(ui_logs: Arc<Mutex<Vec<LogEntry>>>) -> anyhow::Result<()> {
        let logger = Self::new(ui_logs)?;
        let max_level = logger.file_logger.filter();

        log::set_boxed_logger(Box::new(logger))
            .map_err(|e| anyhow::anyhow!("Failed to set logger: {}", e))?;
        log::set_max_level(max_level);

        Ok(())
    }
}

impl log::Log for DualLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.file_logger.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // Log to file (via internal env_logger)
        self.file_logger.log(record);

        // Log to UI
        let entry = LogEntry {
            level: record.level(),
            message: format!("{}", record.args()),
            target: record.target().to_string(),
            timestamp: SystemTime::now(),
        };

        if let Ok(mut logs) = self.ui_logs.lock() {
            logs.push(entry);

            // Keep last 1000 entries
            if logs.len() > 1000 {
                logs.remove(0);
            }
        }
    }

    fn flush(&self) {
        self.file_logger.flush();
    }
}

/// Rotate log files, keeping only the last N.
pub fn rotate_logs(keep_count: usize) -> anyhow::Result<()> {
    let mut log_dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    log_dir.push("DllInjector");
    log_dir.push("logs");

    if !log_dir.exists() {
        return Ok(());
    }

    // Get all log files
    let mut log_files: Vec<_> = fs::read_dir(&log_dir)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry.path()
                .extension()
                .and_then(|s| s.to_str()) == Some("log")
        })
        .collect();

    // Sort by modified time (newest first)
    log_files.sort_by_key(|entry| {
        entry.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH)
    });
    log_files.reverse();

    // Delete old log files
    for old_file in log_files.iter().skip(keep_count) {
        if let Err(e) = fs::remove_file(old_file.path()) {
            log::warn!("Failed to delete old log: {}", e);
        } else {
            log::debug!("Deleted old log: {}", old_file.path().display());
        }
    }

    Ok(())
}
