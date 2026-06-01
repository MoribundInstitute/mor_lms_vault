use std::io::{self, Read, Write};
use std::fs;

fn main() {
    let mut len_bytes = [0u8; 4];
    if io::stdin().read_exact(&mut len_bytes).is_err() { return; }
    let len = u32::from_ne_bytes(len_bytes) as usize;

    let mut buffer = vec![0u8; len];
    if io::stdin().read_exact(&mut buffer).is_err() { return; }

    if let Ok(json) = String::from_utf8(buffer) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&json) {
            let home = std::env::var("HOME").unwrap();

            // 1. Process the Encrypted Vault
            if let Some(b64_data) = parsed.get("vault_data").and_then(|v| v.as_str()) {
                let path = format!("{}/my_brain.enc", home);
                let _ = fs::write(path, b64_data);
            }

            // 2. Process the Scraped Content
            if let Some(scraped_content) = parsed.get("scraped_content") {
                let lib_path = format!("{}/library.json", home);

                // Read existing library (or create new empty array)
                let mut library_array = fs::read_to_string(&lib_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<Vec<serde_json::Value>>(&s).ok())
                    .unwrap_or_else(Vec::new);

                // Add the new scraped item and save
                library_array.push(scraped_content.clone());
                if let Ok(new_lib_json) = serde_json::to_string_pretty(&library_array) {
                    let _ = fs::write(lib_path, new_lib_json);
                }
            }

            send_response("{\"status\":\"success\"}");
        }
    }
}

fn send_response(msg: &str) {
    let len = msg.len() as u32;
    io::stdout().write_all(&len.to_ne_bytes()).unwrap();
    io::stdout().write_all(msg.as_bytes()).unwrap();
    io::stdout().flush().unwrap();
}