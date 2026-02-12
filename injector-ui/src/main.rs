//! DLL Injector GUI Application

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod config;
mod logging;
mod ui;

use app::InjectorApp;
use config::Config;

fn main() -> Result<(), eframe::Error> {
    // Load config to get window size
    let config = Config::load();

    // Configure native options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([config.window_state.width, config.window_state.height])
            .with_min_inner_size([800.0, 600.0])
            .with_title("DLL Injector"),
        ..Default::default()
    };

    // Run the application
    eframe::run_native(
        "DLL Injector",
        options,
        Box::new(|cc| Ok(Box::new(InjectorApp::new(cc)))),
    )
}
