//! Native egui GUI — the default frontend (three-pane Lancer layout).

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use sf_core::{ApiKeyStore, Config, EventSink, Policy, Scan, ScanEngine, SfEvent, Target};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

const POLICIES: [&str; 4] = ["passive", "footprint", "investigate", "all"];

struct GuiScan {
    id: String,
    target: String,
    status: Arc<Mutex<String>>,
    events: Arc<Mutex<Vec<SfEvent>>>,
    cancel: CancellationToken,
}

struct GuiSink {
    status: Arc<Mutex<String>>,
    events: Arc<Mutex<Vec<SfEvent>>>,
    ctx: egui::Context,
}

impl EventSink for GuiSink {
    fn on_event(&self, evt: &SfEvent) {
        if let Ok(mut e) = self.events.lock() {
            e.push(evt.clone());
        }
        self.ctx.request_repaint();
    }
    fn on_finish(&self, scan: &Scan) {
        if let Ok(mut s) = self.status.lock() {
            *s = scan.status.as_str().to_string();
        }
        self.ctx.request_repaint();
    }
}

pub struct GuiApp {
    rt: Arc<Runtime>,
    target: String,
    policy_idx: usize,
    scans: Vec<GuiScan>,
    selected: Option<usize>,
    selected_event: Option<usize>,
    status: String,
}

impl GuiApp {
    pub fn new(rt: Arc<Runtime>, _cc: &eframe::CreationContext<'_>) -> Self {
        GuiApp {
            rt,
            target: String::new(),
            policy_idx: 0,
            scans: Vec::new(),
            selected: None,
            selected_event: None,
            status: format!("Ready — {} modules registered", sf_modules::module_count()),
        }
    }

    fn start(&mut self, ctx: &egui::Context) {
        let target = match Target::detect(self.target.trim()) {
            Ok(t) => t,
            Err(e) => {
                self.status = format!("Invalid target: {e}");
                return;
            }
        };
        let cfg = Config::load_default();
        let keys = ApiKeyStore::from_config(&cfg);
        let all = sf_modules::all_modules();
        let policy = Policy::from_name(POLICIES[self.policy_idx]).unwrap_or(Policy::Passive);
        let selected = policy.select(all, |n| keys.has_key(n));
        let engine = match ScanEngine::new(selected, cfg) {
            Ok(e) => e,
            Err(e) => {
                self.status = e.to_string();
                return;
            }
        };
        let status = Arc::new(Mutex::new("RUNNING".to_string()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let cancel = CancellationToken::new();
        let gscan = GuiScan {
            id: format!("scan-{}", self.scans.len() + 1),
            target: target.value.clone(),
            status: status.clone(),
            events: events.clone(),
            cancel: cancel.clone(),
        };
        self.scans.push(gscan);
        self.selected = Some(self.scans.len() - 1);
        self.selected_event = None;
        self.status = format!("Scanning {}", target.value);
        let sink: Arc<dyn EventSink> = Arc::new(GuiSink {
            status,
            events,
            ctx: ctx.clone(),
        });
        self.rt.spawn(async move {
            let _ = engine.run(target, cancel, Some(sink)).await;
        });
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top menu bar.
        egui::TopBottomPanel::top("menu").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Quit").clicked() {
                        std::process::exit(0);
                    }
                });
                ui.menu_button("Tools", |ui| {
                    let _ = ui.button("Modules…");
                });
                ui.menu_button("Help", |ui| {
                    if ui.button("About").clicked() {
                        self.status =
                            "lancer-spiderfoot — Rust OSINT recon (Lancer ecosystem)".to_string();
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("{} modules", sf_modules::module_count()));
                });
            });
        });

        // Bottom status bar.
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let items = self
                    .selected
                    .and_then(|i| self.scans.get(i))
                    .map(|s| s.events.lock().map(|e| e.len()).unwrap_or(0))
                    .unwrap_or(0);
                ui.label(&self.status);
                ui.separator();
                ui.label(format!("Items: {items}"));
                if let Some(s) = self.selected.and_then(|i| self.scans.get(i)) {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("⏹ Stop").clicked() {
                            s.cancel.cancel();
                        }
                    });
                }
            });
        });

        // Left sidebar: new scan + scan list.
        let mut start_clicked = false;
        let mut new_sel = self.selected;
        egui::SidePanel::left("left")
            .min_width(230.0)
            .show(ctx, |ui| {
                ui.heading("New Scan");
                ui.add_space(4.0);
                ui.label("Target");
                ui.text_edit_singleline(&mut self.target);
                egui::ComboBox::from_label("Policy")
                    .selected_text(POLICIES[self.policy_idx])
                    .show_ui(ui, |ui| {
                        for (i, p) in POLICIES.iter().enumerate() {
                            ui.selectable_value(&mut self.policy_idx, i, *p);
                        }
                    });
                if ui.button("▶ Run scan").clicked() {
                    start_clicked = true;
                }
                ui.separator();
                ui.heading("Scans");
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, s) in self.scans.iter().enumerate() {
                        let st = s.status.lock().map(|x| x.clone()).unwrap_or_default();
                        let label = format!("{} · {} [{}]", s.id, s.target, st);
                        if ui
                            .selectable_label(self.selected == Some(i), label)
                            .clicked()
                        {
                            new_sel = Some(i);
                        }
                    }
                });
            });
        if new_sel != self.selected {
            self.selected = new_sel;
            self.selected_event = None;
        }
        if start_clicked {
            self.start(ctx);
        }

        // Right detail pane.
        egui::SidePanel::right("right")
            .min_width(320.0)
            .show(ctx, |ui| {
                ui.heading("Detail");
                ui.separator();
                let detail = self.selected.and_then(|si| self.scans.get(si)).and_then(|s| {
                    let ev = s.events.lock().ok()?;
                    let i = self.selected_event?;
                    ev.get(i).cloned()
                });
                match detail {
                    Some(e) => {
                        ui.label(format!("Type: {}", e.type_.as_str()));
                        ui.label(format!("Module: {}", e.module));
                        ui.label(format!("Risk: {}", e.risk.as_str()));
                        ui.label(format!("Confidence: {}", e.confidence));
                        ui.separator();
                        ui.label("Data:");
                        egui::ScrollArea::vertical().show(ui, |ui| {
                            ui.monospace(&e.data);
                        });
                    }
                    None => {
                        ui.label("Select an event to see details.");
                    }
                }
            });

        // Center: events table.
        let rows: Vec<SfEvent> = self
            .selected
            .and_then(|i| self.scans.get(i))
            .map(|s| s.events.lock().map(|e| e.clone()).unwrap_or_default())
            .unwrap_or_default();
        let mut clicked_row = None;
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Events");
            TableBuilder::new(ui)
                .striped(true)
                .column(Column::auto().at_least(140.0))
                .column(Column::remainder())
                .column(Column::auto().at_least(120.0))
                .column(Column::auto().at_least(70.0))
                .header(20.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Type");
                    });
                    header.col(|ui| {
                        ui.strong("Data");
                    });
                    header.col(|ui| {
                        ui.strong("Module");
                    });
                    header.col(|ui| {
                        ui.strong("Risk");
                    });
                })
                .body(|body| {
                    body.rows(18.0, rows.len(), |mut row| {
                        let i = row.index();
                        let e = &rows[i];
                        row.col(|ui| {
                            if ui.selectable_label(false, e.type_.as_str()).clicked() {
                                clicked_row = Some(i);
                            }
                        });
                        row.col(|ui| {
                            let d: String = e.data.chars().take(120).collect();
                            ui.label(d);
                        });
                        row.col(|ui| {
                            ui.label(&e.module);
                        });
                        row.col(|ui| {
                            ui.label(e.risk.as_str());
                        });
                    });
                });
        });
        if clicked_row.is_some() {
            self.selected_event = clicked_row;
        }

        ctx.request_repaint_after(Duration::from_millis(750));
    }
}

/// Launch the GUI (blocks on the main thread).
pub fn run(rt: Arc<Runtime>) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1200.0, 760.0]),
        ..Default::default()
    };
    eframe::run_native(
        "lancer-spiderfoot",
        options,
        Box::new(move |cc| Ok(Box::new(GuiApp::new(rt, cc)))),
    )
}
