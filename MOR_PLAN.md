# 🧠 Moribund Vault (The Anti-LMS)

**Project State:** Paused / Cryo-sleep. 
**Objective:** A decentralized, local-first Spaced Repetition System (SRS) and web clipper. The browser acts merely as a dumb terminal; the local OS holds the data, encryption, and SM-2 memory math.

## 🏗️ Architecture Layout

This workspace is divided into 7 distinct Rust crates and a Chrome Extension.

### 1. The Core Engine
* **`vault_core`**: Contains the mathematical heartbeat. `lib.rs` holds the SM-2 algorithm (`SrsData`). `schema.rs` defines the flashcard structure. `progress.rs` handles appending review logs to a local JSONL file.
* **`vault_crypto`**: Handles the local encryption/decryption of the vault files (`my_brain.enc`).
* **`vault_auth`**: Modular authentication. Currently configured for OIDC (Rauthy) in `oidc.rs`. Contains stubs for `steam.rs` and `web3.rs`.

### 2. The OS Bridge (Native Messaging)
* **`bridge_linux_fs`**: The Native Messaging host. The Chrome extension talks to `run_bridge.sh`, which pipes standard I/O JSON payloads to this Rust binary. It executes file system reads/writes and returns the encrypted/decrypted data.
* **`bridge_wasm_idb`**: A fallback/alternative bridge compiled to WASM for interacting with browser IndexedDB.

### 3. The Visual Terminal
* **`ext_chrome_sensor`**: The Chrome Extension. 
  * `background.js` keeps the Native Messaging channel open.
  * `content.js` listens for `window.postMessage` from the DOM (specifically looking for our custom `<mor-vocab-quiz>` web components or the `{{MOR_LMS_HOOKS}}` on Blogger pages).

### 4. The CLI Miner
* **`vault_cli`**: A terminal application (`main.rs`). Can be used to run `mor-lms mine "Topic"` to pull Wikipedia API data, decompress Brotli data, and convert it into the `mflash` schema. Also handles manual terminal-based review logging.

## 🛑 Where We Stopped & Why
We successfully built the pipeline. However, we attempted to inject `{{MOR_LMS_HOOKS}}` directly into a generalized Blogger XML template (`mor_blogger_theme_editor`). This made the Blogger template too brittle for standard users. We decoupled the LMS from the standard Blogger theme editor. The "mutant" XML template is archived on the `MorXML` blog.

## 🚀 Next Steps (For the Next AI)
1. **The Infinite Scroll Feed:** The frontend Web Component needs to be upgraded from single-card testing to a "social media style" infinite scroll feed. The Rust backend should send batches of 10 cards (mixed vocab and Wikipedia extracts) to the browser.
2. **Dynamic Distractors:** Update `vault_core` so that when a vocabulary card is requested, Rust dynamically pulls 3 random definitions from the vault to serve as multiple-choice distractors for the web component.
3. **Image Occlusion:** Implement simple SVG polygon overlays for anatomical images. Keep it lightweight (HTML/CSS), no heavy canvas drawing.
