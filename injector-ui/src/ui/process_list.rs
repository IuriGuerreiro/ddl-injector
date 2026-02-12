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
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.heading("PROCESS MATRIX");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let refresh = egui::Button::new("⟳ SYNC")
                    .rounding(10.0)
                    .fill(egui::Color32::from_rgb(219, 91, 74));
                if ui.add(refresh).clicked() {
                    *refresh_flag = true;
                }
            });
        });

        ui.label(
            egui::RichText::new("Search by image name or PID")
                .size(12.0)
                .color(egui::Color32::from_rgb(186, 193, 210)),
        );

        ui.add(
            egui::TextEdit::singleline(filter)
                .hint_text("chrome, 1337...")
                .desired_width(f32::INFINITY),
        );

        ui.add_space(8.0);

        // Filter processes
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

        ui.label(
            egui::RichText::new(format!(
                "{} ONLINE TARGETS · {} VISIBLE",
                processes.len(),
                filtered.len()
            ))
            .monospace()
            .size(11.0)
            .color(egui::Color32::from_rgb(228, 170, 71)),
        );

        ui.add_space(6.0);

        egui::Frame::none()
            .fill(egui::Color32::from_rgb(18, 23, 33))
            .rounding(14.0)
            .inner_margin(egui::Margin::symmetric(8.0, 8.0))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (idx, process) in filtered {
                            let is_selected = *selected == Some(idx);

                            let text = if is_selected {
                                egui::RichText::new(format!(
                                    "▶ {}   [{}]  •  {} threads",
                                    process.name, process.pid, process.thread_count
                                ))
                                .color(egui::Color32::from_rgb(252, 243, 221))
                                .strong()
                            } else {
                                egui::RichText::new(format!(
                                    "{}   [{}]  •  {} threads",
                                    process.name, process.pid, process.thread_count
                                ))
                                .color(egui::Color32::from_rgb(199, 207, 224))
                            };

                            let row = egui::Button::new(text)
                                .fill(if is_selected {
                                    egui::Color32::from_rgb(179, 70, 56)
                                } else {
                                    egui::Color32::from_rgb(24, 31, 46)
                                })
                                .rounding(8.0)
                                .min_size(egui::vec2(ui.available_width(), 28.0));

                            let response = ui.add(row);

                            if response.clicked() {
                                *selected = Some(idx);
                            }

                            response.on_hover_text(format!(
                                "PID: {}\nParent PID: {}\nThreads: {}",
                                process.pid, process.parent_pid, process.thread_count
                            ));

                            ui.add_space(4.0);
                        }
                    });
            });
    });
}
