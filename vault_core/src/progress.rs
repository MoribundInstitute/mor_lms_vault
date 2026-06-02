use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Debug)]
pub struct ReviewEvent {
    pub card_id: String,
    pub timestamp: u64,
    pub ease_factor: f32,
    pub interval: u32,
}

pub fn log_review(card_id: &str, ease_factor: f32, interval: u32) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let event = ReviewEvent {
        card_id: card_id.to_string(),
        timestamp: ts,
        ease_factor,
        interval,
    };

    // Serialize to tight JSON string
    let mut json_line = serde_json::to_string(&event).expect("Failed to serialize event");
    json_line.push('\n'); // Critical for .jsonl format

    // Open file in append mode. Create if missing.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("my_brain_progress.jsonl")
        .expect("Failed to open progress log");

    // Write bytes to bottom of file
    file.write_all(json_line.as_bytes())
        .expect("Failed to write to log");
}