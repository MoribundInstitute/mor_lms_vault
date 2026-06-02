use serde::{Deserialize, Serialize};

/// The textbook. Static. Readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deck {
    pub id: String,
    pub title: String,
    pub format: String, // Always "mflash_v5_json"
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub cards: Vec<Card>,
}

/// The page. Holds facts, not progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub id: String,
    pub term: String,
    pub definition: String,
    pub term_lang: Option<String>,
    pub def_lang: Option<String>,
    pub tags: Vec<String>,
}

impl Deck {
    /// Bootstraps an empty deck ready for cards
    pub fn new(id: &str, title: &str) -> Self {
        Self {
            id: id.to_string(),
            title: title.to_string(),
            format: "mflash_v5_json".to_string(),
            description: None,
            tags: Vec::new(),
            cards: Vec::new(),
        }
    }

    /// Appends a new card to the static array
    pub fn add_card(&mut self, card: Card) {
        self.cards.push(card);
    }
}
