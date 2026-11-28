//! The scripted evaluation suite, for a person to run before and after a harness change:
//!
//! ```text
//! cargo run -p ferret-agent --example eval                    # every scenario, as a table
//! cargo run -p ferret-agent --example eval -- direct delegates # only these
//! cargo run -p ferret-agent --example eval -- --json           # the outcomes as JSON, lead and mission cards
//! ```
//!
//! Each scenario is a fixed model behaviour (`ferret_agent::evalkit`) played against the real runtime in a
//! temporary directory; no model server is needed and nothing outside that directory is touched. The
//! table has one row per scenario with the mission's scorecard. Run it on two versions of the harness
//! and compare the rows: the scripted model does the same thing in both, so a difference is the harness's.
//! Exits 1 when a scenario could not be played or a name is not a scenario.
//!
//! Before it starts any thread, it writes the kit's fake `depscan` (`evalkit::install_fake_depscan`) to a
//! temporary directory and puts that directory first on its own PATH, so a scenario that scans plays the
//! same on every host; the directory is removed when it exits.

use ferret_agent::evalkit::{self, Outcome, Scenario};

async fn play(scenario: &Scenario) -> Result<Outcome, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("Could not create a temporary directory: {e}"))?;
    evalkit::run(scenario, dir.path()).await
}

async fn all(wanted: &[String]) -> Result<Vec<Outcome>, String> {
    let suite = evalkit::suite();
    if let Some(unknown) = wanted.iter().find(|w| !suite.iter().any(|s| s.name == w.as_str())) {
        let names: Vec<&str> = suite.iter().map(|s| s.name).collect();
        return Err(format!("`{unknown}` is not a scenario. The scenarios: {}.", names.join(", ")));
    }
    let mut outcomes = Vec::new();
    for scenario in suite.iter().filter(|s| wanted.is_empty() || wanted.iter().any(|w| w == s.name)) {
        eprintln!("{}: a model that {}", scenario.name, scenario.plays);
        outcomes.push(play(scenario).await?);
    }
    Ok(outcomes)
}

async fn run_all() -> i32 {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--json");
    let text = match all(&args).await {
        Ok(outcomes) if json => serde_json::to_string_pretty(&outcomes).map_err(|e| e.to_string()),
        Ok(outcomes) => Ok(evalkit::table(&outcomes).trim_end().to_string()),
        Err(e) => Err(e),
    };
    match text {
        Ok(text) => {
            println!("{text}");
            0
        }
        Err(e) => {
            eprintln!("eval: {e}");
            1
        }
    }
}

fn main() {
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("eval: Could not create a temporary directory: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = evalkit::install_fake_depscan(dir.path()) {
        eprintln!("eval: {e}");
        std::process::exit(1);
    }
    let mut paths = vec![dir.path().to_path_buf()];
    paths.extend(std::env::var_os("PATH").iter().flat_map(std::env::split_paths));
    let path = match std::env::join_paths(paths) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("eval: Could not put the fake depscan on the PATH: {e}");
            std::process::exit(1);
        }
    };
    // The process is single-threaded here: no runtime or other thread exists yet, so changing the
    // environment cannot race with a reader.
    std::env::set_var("PATH", path);
    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => {
            let code = rt.block_on(run_all());
            // The directory holding the fake is removed before the process exits.
            drop(dir);
            std::process::exit(code);
        }
        Err(e) => {
            eprintln!("eval: Could not start the runtime: {e}");
            std::process::exit(1);
        }
    }
}
