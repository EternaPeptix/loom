//! The scripted evaluation suite, for a person to run before and after a harness change:
//!
//! ```text
//! cargo run -p loom-agent --example eval                    # every scenario, as a table
//! cargo run -p loom-agent --example eval -- direct delegates # only these
//! cargo run -p loom-agent --example eval -- --json           # the outcomes as JSON, lead and mission cards
//! ```
//!
//! Each scenario is a fixed model behaviour (`loom_agent::evalkit`) played against the real runtime in a
//! temporary directory; no model server is needed and nothing outside that directory is touched. The
//! table has one row per scenario with the mission's scorecard. Run it on two versions of the harness
//! and compare the rows: the scripted model does the same thing in both, so a difference is the harness's.
//! Exits 1 when a scenario could not be played or a name is not a scenario.

use loom_agent::evalkit::{self, Outcome, Scenario};

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

#[tokio::main]
async fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = args.iter().any(|a| a == "--json");
    args.retain(|a| a != "--json");
    let text = match all(&args).await {
        Ok(outcomes) if json => serde_json::to_string_pretty(&outcomes).map_err(|e| e.to_string()),
        Ok(outcomes) => Ok(evalkit::table(&outcomes).trim_end().to_string()),
        Err(e) => Err(e),
    };
    match text {
        Ok(text) => println!("{text}"),
        Err(e) => {
            eprintln!("eval: {e}");
            std::process::exit(1);
        }
    }
}
