//! `loom`: see `loom_daemon::cli`.

use clap::Parser;

fn main() {
    let cli = loom_daemon::cli::Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("loom: cannot start the async runtime: {e}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(loom_daemon::cli::run(cli));
    std::process::exit(code);
}
