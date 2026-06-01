chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("Background worker forwarding Rust payload to OS...");
    
    chrome.runtime.sendNativeMessage(
        "moribund.native.bridge",
        request, // <-- Just forward the exact object Rust built
        function(response) {
            if (chrome.runtime.lastError) {
                console.error("Bridge Error:", chrome.runtime.lastError.message);
            } else {
                console.log("Arch Linux Replied:", response);
            }
        }
    );
});