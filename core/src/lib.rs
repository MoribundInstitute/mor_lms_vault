pub mod auth;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ==========================================
// NODE ARCHITECTURE
// ==========================================

/// Defines the nature of the Blogger content being tracked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// A standard post (Read/Unread only)
    Article,
    /// A dictionary entry (Pure SRS memorization)
    Lexicon,
    /// A course module (Requires completion, optional SRS)
    Lesson,
    /// Time-based media (video, podcast, audiobook) — tracks watch/listen progress
    Media,
}

/// The Spaced Repetition (SM-2) engine data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrsData {
    pub repetitions: u32,
    pub ease_factor: f32,
    pub interval_days: u32,
    pub next_review_ts: i64,
}

impl SrsData {
    pub fn new() -> Self {
        Self {
            repetitions: 0,
            ease_factor: 2.5,
            interval_days: 0,
            next_review_ts: 0,
        }
    }

    /// SuperMemo-2 Algorithm: Grades from 0 (Blackout) to 5 (Perfect)
    pub fn process_review(&mut self, quality: f32, current_time_ts: i64) {
        if quality < 3.0 {
            self.repetitions = 0;
            self.interval_days = 1;
        } else {
            self.repetitions += 1;
            self.interval_days = match self.repetitions {
                1 => 1,
                2 => 6,
                _ => (self.interval_days as f32 * self.ease_factor).round() as u32,
            };
        }
        
        self.ease_factor += 0.1 - (5.0 - quality) * (0.08 + (5.0 - quality) * 0.02);
        if self.ease_factor < 1.3 { self.ease_factor = 1.3; }

        self.next_review_ts = current_time_ts + (self.interval_days as i64 * 86_400);
    }
}

impl Default for SrsData {
    fn default() -> Self {
        Self::new()
    }
}

/// Progress tracking for time-based media (video, podcast, audiobook).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaData {
    /// Total length in seconds. 0 if unknown.
    pub duration_seconds: u32,
    /// Current playback position in seconds.
    pub progress_seconds: u32,
    /// Unix timestamp of the most recent progress update.
    pub last_viewed_ts: i64,
}

impl MediaData {
    pub fn new(duration_seconds: u32) -> Self {
        Self {
            duration_seconds,
            progress_seconds: 0,
            last_viewed_ts: 0,
        }
    }

    /// Record a new playback position.
    pub fn update_progress(&mut self, position_seconds: u32, current_time_ts: i64) {
        self.progress_seconds = position_seconds;
        self.last_viewed_ts = current_time_ts;
    }

    /// Fraction of the media consumed, 0.0–1.0. Returns 0.0 when duration is unknown.
    pub fn completion_ratio(&self) -> f32 {
        if self.duration_seconds == 0 {
            0.0
        } else {
            (self.progress_seconds as f32 / self.duration_seconds as f32).min(1.0)
        }
    }

    /// Conventional "finished" threshold: 95% consumed.
    pub fn is_finished(&self) -> bool {
        self.completion_ratio() >= 0.95
    }
}

impl Default for MediaData {
    fn default() -> Self {
        Self::new(0)
    }
}

/// The universal tracking object saved in the JSON database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedNode {
    pub id: String,                 
    pub parent_id: Option<String>,  
    pub node_type: NodeType,
    pub is_completed: bool,
    #[serde(default)]
    pub srs: Option<SrsData>,       
    #[serde(default)]
    pub media: Option<MediaData>,
}

impl TrackedNode {
    /// Marks an article or lesson as complete
    pub fn mark_complete(&mut self) {
        self.is_completed = true;
    }
}

// ==========================================
// VAULT ARCHITECTURE
// ==========================================

/// The master database. Holds all tracked progress across the entire ecosystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub nodes: HashMap<String, TrackedNode>,
}

impl Vault {
    /// Initialize a brand new, empty vault.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn insert_node(&mut self, node: TrackedNode) {
        self.nodes.insert(node.id.clone(), node);
    }

    pub fn get_node(&self, id: &str) -> Option<&TrackedNode> {
        self.nodes.get(id)
    }

    pub fn mark_completed(&mut self, id: &str) -> Result<(), String> {
        if let Some(node) = self.nodes.get_mut(id) {
            node.mark_complete();
            Ok(())
        } else {
            Err(format!("Node ID '{}' not found in Vault.", id))
        }
    }

    pub fn process_review(&mut self, id: &str, quality: f32, current_time_ts: i64) -> Result<(), String> {
        let node = self.nodes.get_mut(id)
            .ok_or_else(|| format!("Node ID '{}' not found.", id))?;

        if let Some(ref mut srs) = node.srs {
            srs.process_review(quality, current_time_ts);
            Ok(())
        } else {
            Err(format!("Node ID '{}' does not have SRS data attached.", id))
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

impl Default for Vault {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================
// INFRASTRUCTURE CONTRACT
// ==========================================

/// The universal contract for saving and loading the Vault.
/// Infrastructure plugins (Crypto, Cloud, LocalStorage) MUST implement this trait.
pub trait VaultProvider {
    /// Load the vault (Authentication logic handled by the adapter internally)
    fn authenticate_and_load(&self, credentials: &str) -> Result<Vault, String>;
    
    /// Securely save the vault state
    fn save_state(&self, vault: &Vault) -> Result<(), String>;
}