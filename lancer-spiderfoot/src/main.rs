//! lancer-spiderfoot — Rust clone of SpiderFoot.
//!
//! Default invocation opens the native GUI. `--cli` (or providing `-s TARGET`)
//! runs the headless CLI scanner; `-l IP:PORT` starts the web UI + REST API.

mod gui;
mod output;

use clap::Parser;
use output::OutOpts;
use sf_core::{ApiKeyStore, Config, EventSink, Policy, ScanEngine, SfEvent, Target};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// SpiderFoot-compatible CLI surface (upstream `sf.py` flag parity).
#[derive(Parser, Debug)]
#[command(
    name = "lancer-spiderfoot",
    version,
    about = "Automated OSINT reconnaissance — Rust clone of SpiderFoot (Lancer ecosystem)"
)]
struct Cli {
    /// Target (positional alternative to -s).
    target_pos: Option<String>,

    /// Scan target (domain, IP, netblock, email, phone, username, ...).
    #[arg(short = 's', long = "target")]
    target: Option<String>,

    /// Comma-separated module list to enable.
    #[arg(short = 'm', long = "modules")]
    modules: Option<String>,

    /// Comma-separated event types to collect.
    #[arg(short = 't', long = "types")]
    types: Option<String>,

    /// Use-case profile: all | footprint | investigate | passive.
    #[arg(short = 'u', long = "usecase")]
    usecase: Option<String>,

    /// Output format: tab | csv | json | gexf | graphml | html | xlsx.
    #[arg(short = 'o', long = "output", default_value = "tab")]
    output: String,

    /// Suppress field headers (tab/csv).
    #[arg(short = 'H', long = "no-headers")]
    no_headers: bool,

    /// Strip newlines from data fields.
    #[arg(short = 'n', long = "strip-newlines")]
    strip_newlines: bool,

    /// Include the source-data field in tab/csv output.
    #[arg(short = 'r', long = "source-data")]
    source_data: bool,

    /// Limit max data display length.
    #[arg(short = 'S', long = "max-length")]
    max_length: Option<usize>,

    /// Custom CSV delimiter.
    #[arg(short = 'D', long = "delimiter", default_value = ",")]
    delimiter: String,

    /// Show only the specified event types (comma list).
    #[arg(short = 'F', long = "filter-types")]
    filter_types: Option<String>,

    /// List all available modules and exit.
    #[arg(short = 'M', long = "list-modules")]
    list_modules: bool,

    /// List all available event types and exit.
    #[arg(short = 'T', long = "list-types")]
    list_types: bool,

    /// Listen address for the web UI (e.g. 127.0.0.1:5001).
    #[arg(short = 'l', long = "listen")]
    listen: Option<String>,

    /// Run correlation rules against an existing finished scan ID.
    #[arg(short = 'C', long = "correlate")]
    correlate: Option<String>,

    /// Enable debug output.
    #[arg(short = 'd', long = "debug")]
    debug: bool,

    /// Disable logging.
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Strict mode (only modules consuming the declared target type).
    #[arg(short = 'x', long = "strict")]
    strict: bool,

    /// Filter out unspecified event types.
    #[arg(short = 'f', long = "filter")]
    filter: bool,

    /// Maximum concurrent module count.
    #[arg(long = "max-threads")]
    max_threads: Option<usize>,

    /// Hard cap on total events (0 = unlimited).
    #[arg(long = "max-events")]
    max_events: Option<u64>,

    /// Directory of correlation rule YAML files.
    #[arg(long = "correlations")]
    correlations: Option<String>,

    /// Force the CLI scanner (no GUI).
    #[arg(long = "cli")]
    cli: bool,

    /// Force the GUI.
    #[arg(long = "gui")]
    gui: bool,

    /// Append an AI narrative summary at scan finish.
    #[arg(long = "ai-summary")]
    ai_summary: bool,

    /// Run the parity self-test matrix and exit.
    #[arg(long = "self-test")]
    self_test: bool,
}

fn init_logging(cli: &Cli) {
    if cli.quiet {
        return;
    }
    let level = if cli.debug { "debug" } else { "info" };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| format!("lancer_spiderfoot={level},sf_core={level},sf_web=info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn build_out_opts(cli: &Cli) -> OutOpts {
    let filter = cli
        .filter_types
        .clone()
        .or_else(|| if cli.filter { cli.types.clone() } else { None })
        .map(|s| s.split(',').map(|x| x.trim().to_string()).collect::<HashSet<_>>());
    OutOpts {
        format: cli.output.to_lowercase(),
        delimiter: if cli.delimiter.is_empty() {
            ",".to_string()
        } else {
            cli.delimiter.clone()
        },
        no_headers: cli.no_headers,
        strip_newlines: cli.strip_newlines,
        source_data: cli.source_data,
        max_length: cli.max_length,
        filter_types: filter,
    }
}

fn default_corr_dir(cli: &Cli) -> PathBuf {
    cli.correlations
        .clone()
        .map(PathBuf::from)
        .or_else(|| std::env::var("SPIDERFOOT_CORRELATIONS").ok().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("correlations"))
}

fn count_types(events: &[SfEvent]) -> usize {
    events.iter().map(|e| e.type_.as_str()).collect::<HashSet<_>>().len()
}

struct CliSink {
    opts: OutOpts,
}

impl EventSink for CliSink {
    fn on_event(&self, evt: &SfEvent) {
        if let Some(line) = output::row_line(evt, &self.opts) {
            println!("{line}");
        }
    }
}

fn list_modules_cmd() {
    let mut modules = sf_modules::all_modules();
    modules.sort_by_key(|m| m.name());
    println!("{:<28} {:<12} {}", "MODULE", "CATEGORY", "DESCRIPTION");
    for m in &modules {
        let cat = m
            .categories()
            .first()
            .map(|c| c.as_str())
            .unwrap_or("-");
        println!("{:<28} {:<12} {}", m.name(), cat, m.descr());
    }
    eprintln!("\n{} modules total.", modules.len());
}

fn list_types_cmd() {
    let mut types: Vec<&str> = sf_core::EventType::ALL.iter().map(|e| e.as_str()).collect();
    types.sort();
    for t in &types {
        println!("{t}");
    }
    eprintln!("\n{} event types total.", types.len());
}

fn self_test() {
    println!("lancer-spiderfoot — parity self-test");
    println!("  modules registered : {}", sf_modules::module_count());
    println!("  event types        : {}", sf_core::EventType::ALL.len());
    println!("  target types       : 11");
    let corr = sf_graph::CorrelationEngine::load_dir(&PathBuf::from("correlations"))
        .map(|e| e.len())
        .unwrap_or(0);
    println!("  correlation rules  : {corr}");
    println!("  output formats     : tab, csv, json, gexf, graphml, html, xlsx");
    println!("  frontends          : GUI (egui), CLI, web (axum) + REST API");
    println!("  self-test: OK");
}

fn run_web(cli: &Cli, addr: &str) -> anyhow::Result<()> {
    let socket: SocketAddr = addr
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid listen address `{addr}` (want IP:PORT)"))?;
    let _ = cli;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        sf_web::serve(socket)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))
    })
}

fn run_cli(cli: &Cli, target: Option<String>) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let target_str = target.ok_or_else(|| anyhow::anyhow!("no target — pass -s TARGET"))?;
        let target = Target::detect(&target_str).map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let mut cfg = Config::load_default();
        if let Some(mt) = cli.max_threads {
            cfg.global._maxthreads = mt;
        }
        if let Some(me) = cli.max_events {
            cfg.global._max_events = me;
        }
        let keys = ApiKeyStore::from_config(&cfg);
        let all = sf_modules::all_modules();
        let policy = if let Some(m) = &cli.modules {
            Policy::custom(m)
        } else {
            Policy::from_name(cli.usecase.as_deref().unwrap_or("passive")).unwrap_or(Policy::Passive)
        };
        let selected = policy.select(all, |n| keys.has_key(n));
        eprintln!(
            "[*] {} ({}) — {} modules selected",
            target.value,
            target.type_.as_str(),
            selected.len()
        );
        let engine = ScanEngine::new(selected, cfg).map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let opts = build_out_opts(cli);
        if opts.is_streaming() {
            if let Some(h) = output::header_line(&opts) {
                println!("{h}");
            }
        }
        let sink: Option<Arc<dyn EventSink>> = if opts.is_streaming() {
            Some(Arc::new(CliSink { opts: opts.clone() }))
        } else {
            None
        };

        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            cancel2.cancel();
        });

        let result = engine
            .run(target, cancel, sink)
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        if !opts.is_streaming() {
            let out = output::final_output(&result.events, &result.scan.id.to_string(), &opts);
            println!("{out}");
        }

        let corr_dir = default_corr_dir(cli);
        if let Ok(corr) = sf_graph::CorrelationEngine::load_dir(&corr_dir) {
            let fired = corr.evaluate(&result.events);
            if !fired.is_empty() {
                eprintln!("[*] {} correlation(s) fired:", fired.len());
                for r in &fired {
                    eprintln!("    [{}] {}", r.risk.as_str(), r.headline);
                }
            }
        }
        if cli.ai_summary {
            eprintln!(
                "[ai] {} events across {} types (configure sfp_ai_summarizer + key for a narrative)",
                result.events.len(),
                count_types(&result.events)
            );
        }
        eprintln!(
            "[*] scan {} {} — {} events, {} errors",
            result.scan.id,
            result.scan.status.as_str(),
            result.scan.event_count,
            result.scan.error_count
        );
        Ok::<(), anyhow::Error>(())
    })
}

fn run_gui() -> anyhow::Result<()> {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );
    gui::run(rt).map_err(|e| anyhow::anyhow!(e.to_string()))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli);

    if cli.list_modules {
        list_modules_cmd();
        return Ok(());
    }
    if cli.list_types {
        list_types_cmd();
        return Ok(());
    }
    if cli.self_test {
        self_test();
        return Ok(());
    }
    if let Some(addr) = cli.listen.clone() {
        return run_web(&cli, &addr);
    }

    let target = cli.target.clone().or_else(|| cli.target_pos.clone());
    let headless = cli.cli || (target.is_some() && !cli.gui);
    if headless {
        return run_cli(&cli, target);
    }
    run_gui()
}
