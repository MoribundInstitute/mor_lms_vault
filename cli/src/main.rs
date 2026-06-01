use clap::{Parser, Subcommand};
use lms_core::{NodeType, SrsData, TrackedNode, VaultProvider};
use lms_crypto::LocalCryptoProvider;
use rpassword::prompt_password;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "mor-lms")]
#[command(about = "Moribund Knowledge Vault - Terminal Interface", long_about = None)]
struct Cli {
    /// Path to your encrypted vault file
    #[arg(short, long, default_value = "my_brain.enc")]
    vault: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// View the current status of your knowledge vault
    Status,
    
    /// Start tracking a new lesson, article, or flashcard
    Track {
        #[arg(help = "The unique ID/URL of the content (e.g., 'scarcity-101')")]
        node_id: String,
        #[arg(short, long, help = "Type: 'article', 'lexicon', or 'lesson'", default_value = "article")]
        node_type: String,
    },

    /// Mark an existing node as completed
    Complete {
        #[arg(help = "The ID of the node to complete")]
        node_id: String,
    },

    /// Grade your memory of an SRS item (0.0 to 5.0)
    Review {
        #[arg(help = "The ID of the lexicon/flashcard node")]
        node_id: String,
        #[arg(help = "Your memory quality score (0 to 5)")]
        score: f32,
    },
}

fn main() {
    let cli = Cli::parse();

    // 1. Securely prompt for the Master Password
    let password = match prompt_password("Unlock Vault (Password): ") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to read password: {}", e);
            return;
        }
    };

    // 2. Initialize the Cryptography Adapter
    let provider = LocalCryptoProvider::new(&cli.vault);

    // 3. Authenticate and load the Vault into memory
    let mut vault = match provider.authenticate_and_load(&password) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Authentication Failed: {}", e);
            return;
        }
    };

    // 4. Handle the specific command
    let mut state_changed = false;

    match cli.command {
        Commands::Status => {
            println!("\n=== VAULT STATUS ===");
            println!("Nodes Tracked: {}", vault.nodes.len());
            let completed = vault.nodes.values().filter(|n| n.is_completed).count();
            println!("Nodes Completed: {}", completed);
            println!("====================\n");
        }

        Commands::Track { node_id, node_type } => {
            let parsed_type = match node_type.to_lowercase().as_str() {
                "lesson" => NodeType::Lesson,
                "lexicon" => NodeType::Lexicon,
                _ => NodeType::Article,
            };

            let srs_data = if parsed_type == NodeType::Lexicon || parsed_type == NodeType::Lesson {
                Some(SrsData::new())
            } else {
                None
            };

            let node = TrackedNode {
                id: node_id.clone(),
                parent_id: None,
                node_type: parsed_type,
                is_completed: false,
                srs: srs_data,
            };

            vault.insert_node(node);
            println!("Now tracking: {}", node_id);
            state_changed = true;
        }

        Commands::Complete { node_id } => {
            match vault.mark_completed(&node_id) {
                Ok(_) => {
                    println!("Marked '{}' as Complete!", node_id);
                    state_changed = true;
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }

        Commands::Review { node_id, score } => {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            match vault.process_review(&node_id, score, now) {
                Ok(_) => {
                    let node = vault.get_node(&node_id).unwrap();
                    let srs = node.srs.as_ref().unwrap();
                    println!("Review recorded. Next review in {} days.", srs.interval_days);
                    state_changed = true;
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }

    // 5. If data was modified, encrypt it and save it back to the hard drive
    if state_changed {
        match provider.save_state(&vault) {
            Ok(_) => println!("Vault encrypted and saved successfully."),
            Err(e) => eprintln!("Critical Error saving vault: {}", e),
        }
    }
}
