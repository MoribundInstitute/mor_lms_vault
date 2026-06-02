use clap::{Parser, Subcommand};
use lms_core::progress::log_review;
use lms_core::schema::Card;
use serde::Deserialize;

#[derive(Parser)]
#[command(name = "mor-lms")]
#[command(about = "Moribund Knowledge Vault - Terminal Interface")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mine a topic from Wikipedia and format as an mflash card
    Mine {
        #[arg(help = "Page title / wiki topic, e.g. 'Spaced repetition'")]
        topic: String,
    },
    /// Log a spaced repetition review directly to the JSONL file
    Review {
        #[arg(help = "The ID of the flashcard")]
        card_id: String,
        #[arg(help = "Memory quality score (1.0 to 5.0)")]
        quality: f32,
        #[arg(help = "Next interval in days")]
        interval: u32,
    },
}

// Serde tags added so the compiler can read the Wikipedia API
#[derive(Deserialize)]
struct WikiResponse {
    query: Query,
}

#[derive(Deserialize)]
struct Query {
    pages: std::collections::HashMap<String, Page>,
}

#[derive(Deserialize)]
struct Page {
    title: String,
    extract: Option<String>,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Mine { topic } => {
            let url = format!("https://en.wikipedia.org/w/api.php?action=query&prop=extracts&exsentences=2&explaintext=1&format=json&titles={}", topic);
            
            let res: WikiResponse = reqwest::blocking::get(&url)
                .expect("Network failed")
                .json()
                .expect("Failed to parse JSON");

            for (_, page) in res.query.pages {
                // Instantiating the new literal schema you built
                let card = Card {
                    id: page.title.to_lowercase().replace(" ", "_"),
                    term: page.title,
                    definition: page.extract.unwrap_or_else(|| "No definition found.".to_string()).trim().replace("\n", " "),
                    term_lang: Some("en".to_string()),
                    def_lang: Some("en".to_string()),
                    tags: vec!["mined".to_string()],
                };

                let json = serde_json::to_string_pretty(&card).unwrap();
                println!("Mined Card Payload:\n{}", json);
            }
        }
        Commands::Review { card_id, quality, interval } => {
            log_review(card_id, *quality, *interval);
            println!("Logged review for {} to my_brain_progress.jsonl", card_id);
        }
    }
}