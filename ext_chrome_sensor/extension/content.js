// Listen for shouts from the webpage
window.addEventListener("message", (event) => {
    // Ignore noise. Only trust our own window.
    if (event.source !== window || !event.data || !event.data.type) return;

    // --- 1. UNLOCK THE VAULT ---
    if (event.data.type === "MOR_LOGIN") {
        chrome.runtime.sendMessage({ command: "unlock" }, (response) => {
            console.log("Vault Unlock Response:", response);
            if (response && (response.status === "unlocked" || response.status === "provisioned")) {
                // Chain reaction: Once unlocked, tell the UI to fetch data!
                window.postMessage({ type: "MOR_FETCH_FEED" }, "*");
            }
        });
    }

    // --- 2. READ DATA (Fetch Feed) ---
    if (event.data.type === "MOR_FETCH_FEED") {
        chrome.runtime.sendMessage({ command: "fetch_feed" }, (vaultArray) => {
            // Hand the decrypted array BACK to the <mor-study> CRT screen
            window.postMessage({ type: "MOR_FEED_DATA", payload: vaultArray || [] }, "*");
        });
    }

    // --- 3. WRITE DATA (Save Card) ---
    if (event.data.type === "MOR_SAVE_CARD") {
        const newCard = event.data.payload;

        // Step A: Fetch current vault so we don't overwrite it
        chrome.runtime.sendMessage({ command: "fetch_feed" }, (currentVault) => {
            let vault = Array.isArray(currentVault) ? currentVault : [];

            // Step B: Put the newest card at the top of the stack
            vault.unshift(newCard);

            // Step C: Send the updated stack back to Rust to be encrypted
            chrome.runtime.sendMessage({
                command: "save_vault",
                payload: vault
            }, (res) => {
                console.log("Vault sealed with new card:", res);
                // Optional: Tell the UI it succeeded so it can update the button
                window.postMessage({ type: "MOR_SAVE_SUCCESS" }, "*");
            });
        });
    }
});