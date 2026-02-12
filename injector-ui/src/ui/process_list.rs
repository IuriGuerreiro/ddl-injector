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
    ui.heading(
        egui::RichText::new("PROCESS TARGET MATRIX")
            .color(egui::Color32::from_rgb(255, 225, 64))
            .strong(),
    );
    ui.small(
        egui::RichText::new("Acquire host process and lock target for payload delivery")
            .color(egui::Color32::from_rgb(130, 166, 195)),
    );

    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("FILTER")
                .strong()
                .color(egui::Color32::from_rgb(255, 92, 246)),
        );
        let edit = egui::TextEdit::singleline(filter)
            .desired_width(170.0)
            .hint_text("name / pid");
        ui.add(edit);

        if ui
            .add(
                egui::Button::new(
                    egui::RichText::new("⟳ RESCAN")
                        .strong()
                        .color(egui::Color32::BLACK),
                )
                .fill(egui::Color32::from_rgb(0, 238, 255)),
            )
            .clicked()
        {
            *refresh_flag = true;
        }
    });

    ui.add_space(4.0);

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
            "VISIBLE NODES: {} / {}",
            filtered.len(),
            processes.len()
        ))
        .monospace()
        .color(egui::Color32::from_rgb(178, 255, 252)),
    );

    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (idx, process) in filtered {
                let is_selected = *selected == Some(idx);
                let threads_heat = if process.thread_count > 20 {
                    egui::Color32::from_rgb(255, 92, 246)
                } else {
                    egui::Color32::from_rgb(0, 238, 255)
                };

                let label = format!(
                    "{}  //  PID:{:>6}  //  THR:{:>3}",
                    process.name, process.pid, process.thread_count
                );

                let response = ui.add(egui::SelectableLabel::new(
                    is_selected,
                    egui::RichText::new(label).monospace(),
                ));

                if response.clicked() {
                    *selected = Some(idx);
                }

                response.on_hover_ui(|ui| {
                    ui.label(
                        egui::RichText::new("TARGET TELEMETRY")
                            .strong()
                            .color(egui::Color32::from_rgb(255, 225, 64)),
                    );
                    ui.label(format!("PID: {}", process.pid));
                    ui.label(format!("Parent PID: {}", process.parent_pid));
                    ui.colored_label(
                        threads_heat,
                        format!("Thread count: {}", process.thread_count),
                    );
                });
            }
        });
}
