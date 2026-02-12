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
    ui.heading("Processes");

    ui.horizontal(|ui| {
        ui.label("Search:");
        if ui.text_edit_singleline(filter).changed() {
            // Filter changed, clear selection if it doesn't match
        }

        if ui.button("🔄 Refresh").clicked() {
            *refresh_flag = true;
        }
    });

    ui.separator();

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

    ui.label(format!(
        "{} processes (showing {})",
        processes.len(),
        filtered.len()
    ));

    ui.separator();

    // Scrollable list
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (idx, process) in filtered {
                let is_selected = *selected == Some(idx);

                let response = ui.selectable_label(
                    is_selected,
                    format!("{} (PID: {})", process.name, process.pid),
                );

                if response.clicked() {
                    *selected = Some(idx);
                }

                // Show additional info on hover
                response.on_hover_text(format!(
                    "PID: {}\nParent PID: {}\nThreads: {}",
                    process.pid, process.parent_pid, process.thread_count
                ));
            }
        });
}
