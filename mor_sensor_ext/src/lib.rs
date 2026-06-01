use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{window, Document, Element, HtmlElement, Event};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STD};

// Bind chrome.runtime.sendMessage so we can pass payloads to the background service worker.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["chrome", "runtime"])]
    fn sendMessage(message: JsValue);
}

#[wasm_bindgen(start)]
pub fn run() -> Result<(), JsValue> {
    let window = window().expect("No global `window` exists");
    let document = window.document().expect("Should have a document on window");

    // Scan for our Blogger Tracker Hooks
    let nodes = document.query_selector_all("[data-mor-type]")?;
    
    for i in 0..nodes.length() {
        if let Some(node) = nodes.item(i) {
            let element = node.dyn_into::<Element>()?;
            inject_tracker_ui(&document, &element)?;
        }
    }

    Ok(())
}

fn inject_tracker_ui(doc: &Document, target: &Element) -> Result<(), JsValue> {
    let node_type = target.get_attribute("data-mor-type").unwrap_or_else(|| "unknown".to_string());
    
    // We try to grab the ID, fallback to 'generic' if missing
    let node_id = target.get_attribute("data-mor-id").unwrap_or_else(|| "generic_node".to_string());
    let btn_id = format!("mor-btn-{}", node_id);
    
    // Create our UI container
    let container = doc.create_element("div")?;
    
    // Build the raw HTML string, giving the button a unique ID
    let html_content = format!(
        "<div style='margin-top: 20px; padding: 15px; background-color: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; border-radius: 8px; font-family: monospace; display: flex; justify-content: space-between; align-items: center;'>
            <div>
                <strong style='color: #58a6ff;'>Moribund WASM Sensor</strong>
                <div style='font-size: 0.85rem; color: #8b949e;'>Type: {} | ID: {}</div>
            </div>
            <button id='{}' style='background: #238636; color: white; border: none; padding: 8px 16px; border-radius: 6px; cursor: pointer; font-weight: bold;'>
                Mark via Rust
            </button>
        </div>",
        node_type.to_uppercase(), node_id, btn_id
    );

    container.set_inner_html(&html_content);
    target.append_child(&container)?;
    
    // --- NEW: THE RUST EVENT LISTENER ---
    
    // 1. Find the button we just injected
    let button = doc.get_element_by_id(&btn_id).expect("Button should exist");
    
    // 2. Clone the button reference so we can move it into the closure
    let button_clone = button.clone();
    
    // 3. Create the Rust closure that fires on click
    let node_id_clone = node_id.clone();
    let node_type_clone = node_type.clone();
    let target_clone = target.clone();
    
    let closure = Closure::wrap(Box::new(move |_event: Event| {
        let window = web_sys::window().expect("Window missing");
        let storage = window.local_storage().unwrap().unwrap();

        // Step A: Prompt Password
        let password = match window.prompt_with_message("Enter Moribund Vault Password:") {
            Ok(Some(p)) if !p.is_empty() => p,
            _ => {
                web_sys::console::log_1(&"Action cancelled.".into());
                return;
            }
        };

        // Step B: Hydrate Vault from LocalStorage
        let mut vault = lms_core::Vault::new(); 
        if let Ok(Some(b64_data)) = storage.get_item("my_brain_enc") {
            if let Ok(encrypted_bytes) = BASE64_STD.decode(&b64_data) {
                // Route bytes through your crypto adapter
                if let Ok(decrypted_json) = lms_crypto::decrypt_vault(&encrypted_bytes, &password) {
                    vault = lms_core::Vault::from_json(&decrypted_json).unwrap_or_default();
                } else {
                    web_sys::window().unwrap().alert_with_message("Wrong password. Vault locked.").unwrap();
                    return;
                }
            }
        }

        // Step C: Mutate State
        let node_type_enum = match node_type_clone.as_str() {
            "media" => lms_core::NodeType::Media,
            "lexicon" => lms_core::NodeType::Lexicon,
            _ => lms_core::NodeType::Article,
        };

        // If node exists, update it. If not, create it.
        // (Simplified for example. Expand to handle episodes if needed).
        let node = lms_core::TrackedNode {
            id: node_id_clone.clone(),
            parent_id: None,
            node_type: node_type_enum,
            is_completed: true,
            srs: None,
            media: None,
        };
        
        vault.insert_node(node);

        // Step D: Encrypt, Scrape, and Save
        let new_json = vault.to_json().unwrap();
        if let Ok(new_encrypted_bytes) = lms_crypto::encrypt_vault(&new_json, &password) {
            let new_b64 = BASE64_STD.encode(new_encrypted_bytes);
            let _ = storage.set_item("my_brain_enc", &new_b64);

            // -- NEW: MAXIMAL RUST SCRAPER --
            // Grab the raw text from the HTML element we are attached to
            let scraped_text = target_clone.dyn_ref::<HtmlElement>()
                .map(|el| el.inner_text())
                .unwrap_or_default();

            // Build the Scrape Object
            let scrape_data = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&scrape_data, &JsValue::from_str("id"), &JsValue::from_str(&node_id_clone));
            let _ = js_sys::Reflect::set(&scrape_data, &JsValue::from_str("type"), &JsValue::from_str(&node_type_clone));
            let _ = js_sys::Reflect::set(&scrape_data, &JsValue::from_str("content"), &JsValue::from_str(&scraped_text));

            // Build the Final Pipeline Payload
            let payload = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&payload, &JsValue::from_str("vault_data"), &JsValue::from_str(&new_b64));
            let _ = js_sys::Reflect::set(&payload, &JsValue::from_str("scraped_content"), &scrape_data);

            // Toss the payload over the wall!
            sendMessage(payload.into());

            web_sys::console::log_1(&"Rust says: Vault encrypted and content scraped.".into());

            if let Ok(html_btn) = button_clone.clone().dyn_into::<HtmlElement>() {
                html_btn.set_inner_text("Completed ✓");
                let _ = html_btn.style().set_property("background", "#2ea043");
            }
        }

    }) as Box<dyn FnMut(_)>);

    // 4. Attach the closure to the button's "click" event
    button.add_event_listener_with_callback("click", closure.as_ref().unchecked_ref())?;

    // 5. "Forget" the closure so Rust doesn't clean it up from memory after this function ends
    closure.forget();

    Ok(())
}