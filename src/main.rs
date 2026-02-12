//! lancer-spiderfoot
//! Rust clone of spiderfoot. See plan.md (local, gitignored) for the spec.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "lancer-spiderfoot", version, about = "Rust clone of spiderfoot")]
struct Cli {}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let _cli = Cli::parse();
    println!("lancer-spiderfoot - scaffold ready. Implement per plan.md.");
    Ok(())
}
