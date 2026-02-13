//! Injection control panel UI component.

use crate::app::InjectionMethodType;
use eframe::egui;
use injector_core::ProcessInfo;
use std::path::PathBuf;

/// Actions that can be triggered from the injection panel
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionPanelAction {
    None,
    OpenFileDialog,
    OpenTargetExeDialog,
    PerformInjection,
    CleanupDllProxy,
    SelectRecentDll(PathBuf),
}

#[allow(clippy::too_many_arguments)]
pub fn render(
    ui: &mut egui::Ui,
    processes: &[ProcessInfo],
    selected_idx: Option<usize>,
    dll_path: &mut Option<PathBuf>,
    proxy_target_exe: &mut Option<PathBuf>,
    proxy_system_dll: &mut String,
    proxy_backup_original: &mut bool,
    injection_method: &mut InjectionMethodType,
    last_error: &Option<String>,
    injecting: bool,
    is_admin: bool,
    has_debug_privilege: bool,
    recent_dlls: &[PathBuf],
) -> InjectionPanelAction {
    let mut action = InjectionPanelAction::None;

    ui.vertical(|ui| {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading(egui::RichText::new("INJECTION CONTROL").strong().size(22.0));
            if injecting {
                ui.add_space(8.0);
                ui.add(egui::Spinner::new().size(16.0));
            }
        });
        ui.label(
            egui::RichText::new("Configure and deploy payloads to target processes")
                .color(egui::Color32::from_gray(160)),
        );
        ui.add_space(12.0);

        // --- SECTION 1: SYSTEM PRIVILEGES ---
        egui::Frame::none()
            .fill(ui.visuals().faint_bg_color)
            .rounding(8.0)
            .inner_margin(10.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("SYSTEM STATUS").strong().size(11.0));
                    ui.add_space(ui.available_width() - 200.0); // Simple alignment

                    // Admin Badge
                    let (admin_text, admin_color) = if is_admin {
                        ("ADMIN", egui::Color32::from_rgb(46, 204, 113))
                    } else {
                        ("USER", egui::Color32::from_rgb(231, 76, 60))
                    };
                    render_badge(ui, admin_text, admin_color);

                    // SeDebug Badge
                    let (debug_text, debug_color) = if has_debug_privilege {
                        ("DEBUG ENABLED", egui::Color32::from_rgb(52, 152, 219))
                    } else {
                        ("DEBUG DISABLED", egui::Color32::from_rgb(243, 156, 18))
                    };
                    render_badge(ui, debug_text, debug_color);
                });
            });

        ui.add_space(16.0);

        let is_dll_proxy = matches!(injection_method, InjectionMethodType::DllProxying);

        // --- SECTION 2: TARGET/PROXY & PAYLOAD ---
        ui.columns(2, |cols| {
            cols[0].vertical(|ui| {
                if is_dll_proxy {
                    ui.label(
                        egui::RichText::new("DLL PROXY CONFIGURATION")
                            .strong()
                            .size(13.0),
                    );
                    ui.add_space(4.0);
                    egui::Frame::none()
                        .fill(ui.visuals().widgets.noninteractive.bg_fill)
                        .rounding(8.0)
                        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                if ui.button("🎯 SELECT TARGET EXE").clicked() {
                                    action = InjectionPanelAction::OpenTargetExeDialog;
                                }

                                if ui.button("🧹 CLEANUP").clicked() {
                                    action = InjectionPanelAction::CleanupDllProxy;
                                }
                            });

                            ui.add_space(6.0);
                            if let Some(path) = proxy_target_exe {
                                ui.label(egui::RichText::new("Target executable").strong());
                                ui.add(egui::Label::new(path.to_string_lossy()).truncate());
                            } else {
                                ui.label(
                                    egui::RichText::new("No target executable selected")
                                        .italics()
                                        .color(egui::Color32::from_gray(100)),
                                );
                            }

                            ui.add_space(8.0);
                            ui.label(egui::RichText::new("System DLL to proxy").strong());
                            ui.text_edit_singleline(proxy_system_dll);

                            ui.checkbox(
                                proxy_backup_original,
                                "Backup original DLL before replacement",
                            );
                        });
                } else {
                    ui.label(egui::RichText::new("TARGET PROCESS").strong().size(13.0));
                    ui.add_space(4.0);
                    egui::Frame::none()
                        .fill(ui.visuals().widgets.noninteractive.bg_fill)
                        .rounding(8.0)
                        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                        .inner_margin(12.0)
                        .show(ui, |ui| {
                            ui.set_min_height(80.0);
                            if let Some(idx) = selected_idx {
                                if let Some(process) = processes.get(idx) {
                                    ui.label(
                                        egui::RichText::new(&process.name).strong().size(16.0),
                                    );
                                    ui.monospace(format!("PID: {}", process.pid));
                                    ui.small(format!("Threads: {}", process.thread_count));
                                } else {
                                    ui.colored_label(egui::Color32::RED, "Selection Error");
                                }
                            } else {
                                ui.vertical_centered(|ui| {
                                    ui.add_space(20.0);
                                    ui.label(
                                        egui::RichText::new("No Target Selected")
                                            .italics()
                                            .color(egui::Color32::from_gray(100)),
                                    );
                                });
                            }
                        });
                }
            });

            cols[1].vertical(|ui| {
                ui.label(egui::RichText::new("PAYLOAD DLL").strong().size(13.0));
                ui.add_space(4.0);
                egui::Frame::none()
                    .fill(ui.visuals().widgets.noninteractive.bg_fill)
                    .rounding(8.0)
                    .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                    .inner_margin(12.0)
                    .show(ui, |ui| {
                        ui.set_min_height(80.0);
                        ui.horizontal(|ui| {
                            if ui.button("📁 BROWSE").clicked() {
                                action = InjectionPanelAction::OpenFileDialog;
                            }

                            if !recent_dlls.is_empty() {
                                egui::ComboBox::from_id_salt("recent_dlls")
                                    .selected_text("RECENT")
                                    .show_ui(ui, |ui| {
                                        for recent_dll in recent_dlls {
                                            let file_name = recent_dll
                                                .file_name()
                                                .map(|n| n.to_string_lossy().to_string())
                                                .unwrap_or_default();
                                            if ui.selectable_label(false, &file_name).clicked() {
                                                action = InjectionPanelAction::SelectRecentDll(
                                                    recent_dll.clone(),
                                                );
                                            }
                                        }
                                    });
                            }
                        });

                        ui.add_space(4.0);
                        if let Some(path) = dll_path {
                            let file_name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();
                            ui.label(egui::RichText::new(file_name).strong());
                            ui.add(
                                egui::Label::new(
                                    egui::RichText::new(path.to_string_lossy())
                                        .small()
                                        .color(egui::Color32::from_gray(120)),
                                )
                                .truncate(),
                            );
                        } else {
                            ui.label(
                                egui::RichText::new("Select payload...")
                                    .italics()
                                    .color(egui::Color32::from_gray(100)),
                            );
                        }
                    });
            });
        });

        ui.add_space(16.0);

        // --- SECTION 3: INJECTION METHOD ---
        ui.label(
            egui::RichText::new("INJECTION STRATEGY")
                .strong()
                .size(13.0),
        );
        ui.add_space(4.0);
        egui::Frame::none()
            .fill(ui.visuals().widgets.noninteractive.bg_fill)
            .rounding(8.0)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
            .inner_margin(12.0)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("method_selector")
                        .selected_text(injection_method.name())
                        .width(200.0)
                        .show_ui(ui, |ui| {
                            for method in InjectionMethodType::all() {
                                ui.selectable_value(injection_method, *method, method.name());
                            }
                        });

                    ui.add_space(12.0);
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(injection_method.description()).small());
                        match injection_method {
                            InjectionMethodType::ManualMap => {
                                ui.label(
                                    egui::RichText::new(
                                        "• Bypasses PEB module list (High Stealth)",
                                    )
                                    .size(10.0)
                                    .color(egui::Color32::from_rgb(100, 200, 255)),
                                );
                            }
                            InjectionMethodType::QueueUserApc => {
                                ui.label(
                                    egui::RichText::new("• Requires alertable threads")
                                        .size(10.0)
                                        .color(egui::Color32::YELLOW),
                                );
                            }
                            _ => {}
                        }
                    });
                });
            });

        ui.add_space(24.0);

        // --- SECTION 4: EXECUTION ---
        let has_process = selected_idx.is_some();
        let has_dll = dll_path.is_some();
        let dll_proxy_ready = proxy_target_exe.is_some() && !proxy_system_dll.trim().is_empty();
        let can_inject = if is_dll_proxy {
            has_dll && dll_proxy_ready && !injecting
        } else {
            has_process && has_dll && !injecting
        };

        ui.vertical_centered(|ui| {
            let btn_text = if injecting {
                "INJECTION IN PROGRESS..."
            } else {
                "EXECUTE DEPLOYMENT"
            };
            let btn_color = if can_inject {
                egui::Color32::from_rgb(46, 204, 113)
            } else {
                ui.visuals().widgets.inactive.bg_fill
            };

            let button = egui::Button::new(egui::RichText::new(btn_text).strong().size(18.0))
                .min_size(egui::vec2(300.0, 50.0))
                .rounding(12.0)
                .fill(btn_color);

            if ui.add_enabled(can_inject, button).clicked() {
                action = InjectionPanelAction::PerformInjection;
            }

            if !can_inject && !injecting {
                ui.add_space(8.0);
                let wait_text = if is_dll_proxy {
                    "Waiting for payload, target exe, and system DLL name..."
                } else {
                    "Waiting for target and payload locks..."
                };
                ui.label(
                    egui::RichText::new(wait_text)
                        .small()
                        .color(egui::Color32::from_gray(100)),
                );
            }
        });

        // Error display
        if let Some(error) = last_error {
            ui.add_space(16.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgba_unmultiplied(231, 76, 60, 20))
                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(231, 76, 60)))
                .rounding(8.0)
                .inner_margin(12.0)
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("✖")
                                .color(egui::Color32::from_rgb(231, 76, 60))
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new(format!("Error: {}", error))
                                .color(egui::Color32::from_rgb(231, 76, 60)),
                        );
                    });
                });
        }
    });

    action
}

fn render_badge(ui: &mut egui::Ui, text: &str, color: egui::Color32) {
    egui::Frame::none()
        .fill(color.gamma_multiply(0.15))
        .stroke(egui::Stroke::new(1.0, color))
        .rounding(4.0)
        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).color(color).strong().size(10.0));
        });
    ui.add_space(4.0);
}
