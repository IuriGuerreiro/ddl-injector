//! Process list UI component.

use eframe::egui;
use injector_core::ProcessInfo;

pub fn render(
    ui: &mut egui::Ui,
    processes: &mut [ProcessInfo],
    selected: &mut Option<usize>,
    filter: &mut String,
    refresh_flag: &mut bool,
) {
    let frame = egui::Frame::none()
        .fill(egui::Color32::from_rgb(11, 16, 27))
        .inner_margin(egui::Margin::same(14.0))
        .rounding(14.0);

    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading(egui::RichText::new("PROCESS RADAR").size(22.0));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("↻ SCAN").clicked() {
                    *refresh_flag = true;
                }
            });
        });
        ui.label(
            egui::RichText::new(
                "Target discovery grid • Select a host process for payload execution",
            )
            .color(egui::Color32::from_rgb(130, 160, 225)),
        );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("FILTER");
            ui.add(
                egui::TextEdit::singleline(filter)
                    .desired_width(f32::INFINITY)
                    .hint_text("name, pid"),
            );
        });

        let filter_lower = filter.to_lowercase();
        let filtered: Vec<(usize, &ProcessInfo)> = processes
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                filter.is_empty()
                    || p.name.to_lowercase().contains(&filter_lower)
                    || p.pid.to_string().contains(&filter_lower)
            })
            .collect();

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!("{} online", processes.len()))
                    .color(egui::Color32::from_rgb(101, 220, 154)),
            );
            ui.label("•");
            ui.label(
                egui::RichText::new(format!("{} matching", filtered.len()))
                    .color(egui::Color32::from_rgb(104, 188, 255)),
            );
        });

        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (idx, process) in filtered {
                    let is_selected = *selected == Some(idx);
                    let item_frame = egui::Frame::none()
                        .fill(if is_selected {
                            egui::Color32::from_rgb(29, 68, 133)
                        } else {
                            egui::Color32::from_rgb(16, 23, 36)
                        })
                        .stroke(egui::Stroke::new(
                            1.0,
                            if is_selected {
                                egui::Color32::from_rgb(93, 205, 255)
                            } else {
                                egui::Color32::from_rgb(36, 45, 64)
                            },
                        ))
                        .inner_margin(egui::Margin::same(10.0))
                        .rounding(10.0);

                    let response = item_frame
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    egui::RichText::new("◉").color(egui::Color32::LIGHT_GREEN),
                                );
                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new(&process.name).strong());
                                    ui.small(format!(
                                        "PID {}  •  PPID {}  •  {} threads",
                                        process.pid, process.parent_pid, process.thread_count
                                    ));
                                });
                            });
                        })
                        .response;

                    if response.clicked() {
                        *selected = Some(idx);
                    }

                    response.on_hover_text(format!(
                        "Executable process\nPID: {}\nParent PID: {}\nThread Count: {}",
                        process.pid, process.parent_pid, process.thread_count
                    ));
                    ui.add_space(6.0);
                }
            });
    });
}
