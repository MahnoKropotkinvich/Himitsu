//! himitsu-trace: standalone CLI tool for traitor tracing.
//!
//! This binary is intentionally separated from the main Himitsu application
//! so that regular users never have access to the fingerprint extraction
//! and traitor identification logic.
//!
//! Usage:
//!   himitsu-trace extract  --input leaked_file.bin --session session.json
//!   himitsu-trace identify --extracted fp.json --db /path/to/himitsu/db

use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod extract;
mod identify;

#[derive(Parser)]
#[command(name = "himitsu-trace")]
#[command(about = "Traitor tracing tool for Himitsu broadcast encryption")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extract a fingerprint value from a leaked plaintext file.
    Extract {
        /// Path to the leaked plaintext file.
        #[arg(short, long)]
        input: PathBuf,

        /// Path to the session metadata JSON (contains r_vector and modulus).
        #[arg(short, long)]
        session: PathBuf,

        /// Output file for the extracted fingerprint data.
        #[arg(short, long, default_value = "extracted_fp.json")]
        output: PathBuf,
    },

    /// Identify which user's fingerprint matches the extracted value.
    Identify {
        /// Path to the extracted fingerprint JSON.
        #[arg(short = 'f', long)]
        extracted: PathBuf,

        /// Path to the Himitsu database directory.
        #[arg(short, long)]
        db: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Extract { input, session, output } => {
            extract::run(&input, &session, &output)
        }
        Commands::Identify { extracted, db } => {
            identify::run(&extracted, &db)
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
