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
    ui.label(
        egui::RichText::new("TARGET CATALOG")
            .heading()
            .color(egui::Color32::from_rgb(128, 255, 232)),
    );

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new("Filter").color(egui::Color32::from_rgb(226, 233, 166)));
        ui.add_sized(
            [180.0, 24.0],
            egui::TextEdit::singleline(filter).hint_text("process / pid"),
        );

        if ui.button("SCAN").clicked() {
            *refresh_flag = true;
        }
    });

    ui.separator();

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
            "{} online targets · {} visible in current query",
            processes.len(),
            filtered.len()
        ))
        .small()
        .color(egui::Color32::from_rgb(140, 178, 168)),
    );

    ui.add_space(6.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (idx, process) in filtered {
                let is_selected = *selected == Some(idx);
                let tint = if is_selected {
                    egui::Color32::from_rgb(40, 79, 74)
                } else {
                    egui::Color32::from_rgb(10, 18, 24)
                };

                egui::Frame::none()
                    .fill(tint)
                    .stroke(egui::Stroke::new(
                        1.0,
                        egui::Color32::from_rgb(41, 112, 113),
                    ))
                    .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                    .show(ui, |ui| {
                        let response = ui.selectable_label(
                            is_selected,
                            egui::RichText::new(format!("{} · PID {}", process.name, process.pid))
                                .color(egui::Color32::from_rgb(217, 255, 231)),
                        );

                        if response.clicked() {
                            *selected = Some(idx);
                        }

                        response.on_hover_text(format!(
                            "PID: {}\nParent PID: {}\nThreads: {}",
                            process.pid, process.parent_pid, process.thread_count
                        ));
                    });

                ui.add_space(4.0);
            }
        });
}
