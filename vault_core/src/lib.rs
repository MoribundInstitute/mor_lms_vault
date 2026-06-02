pub mod auth;
pub mod progress;
pub mod schema; 

use serde::{Deserialize, Serialize};

/// The 4-button review grade exposed to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Grade {
    Again,
    Hard,
    Good,
    Easy,
}

impl Grade {
    /// Maps UI button to SM-2 quality value (0.0–5.0)
    pub fn quality(self) -> f32 {
        match self {
            Grade::Again => 1.0,
            Grade::Hard => 3.0, 
            Grade::Good => 4.0, 
            Grade::Easy => 5.0, 
        }
    }
}

/// The Spaced Repetition (SM-2) engine math.
/// Pure logic. State is saved by progress.rs appending to JSONL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SrsData {
    pub repetitions: u32,
    pub ease_factor: f32,
    pub interval_days: u32,
}

impl SrsData {
    pub fn new() -> Self {
        Self {
            repetitions: 0,
            ease_factor: 2.5,
            interval_days: 0,
        }
    }

    pub fn process_review(&mut self, quality: f32) {
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
    }

    pub fn review(&mut self, grade: Grade) {
        self.process_review(grade.quality());
    }
}

impl Default for SrsData {
    fn default() -> Self {
        Self::new()
    }
}