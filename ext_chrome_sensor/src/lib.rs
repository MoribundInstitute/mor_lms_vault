use wasm_bindgen::prelude::*;

// The extension lives in the browser sandbox. 
// It cannot write to the local filesystem directly.
// It will format JSON payloads and pass them to the native bridge.

#[wasm_bindgen]
pub fn initialize_sensor() -> String {
    "Sensor WASM module loaded. Ready to track content.".to_string()
}

#[wasm_bindgen]
pub fn build_review_payload(card_id: &str, quality: f32, interval: u32) -> String {
    // This JSON will eventually be sent to bridge_linux_fs
    format!(
        "{{\"action\": \"log_review\", \"card_id\": \"{}\", \"quality\": {}, \"interval\": {}}}",
        card_id, quality, interval
    )
}

#[wasm_bindgen]
pub fn build_mine_payload(topic: &str) -> String {
    format!(
        "{{\"action\": \"mine_topic\", \"topic\": \"{}\"}}",
        topic
    )
}