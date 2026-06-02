chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    chrome.runtime.sendNativeMessage("moribund.native.bridge", request, (response) => {
        if (chrome.runtime.lastError) {
            console.error("Bridge Error:", chrome.runtime.lastError);
            sendResponse(null);
        } else {
            sendResponse(response);
        }
    });
    return true; // Required. Keeps async channel open.
});