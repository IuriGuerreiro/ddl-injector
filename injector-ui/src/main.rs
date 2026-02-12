//! DLL Injector GUI Application

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;

mod app;
mod config;
mod ui;

use app::InjectorApp;

fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .init();

    log::info!("Starting DLL Injector v{}", env!("CARGO_PKG_VERSION"));

    // Configure native options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
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
