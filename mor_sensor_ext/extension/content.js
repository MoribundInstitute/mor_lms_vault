(async () => {
    try {
        // 1. Get the secure internal URL for the generated Rust/JS bridge
        const jsUrl = chrome.runtime.getURL("pkg/sensor_ext.js");
        
        // 2. Dynamically import the bridge
        const { default: init } = await import(jsUrl);

        // 3. Get the secure internal URL for the raw WASM binary
        const wasmUrl = chrome.runtime.getURL("pkg/sensor_ext_bg.wasm");
        
        // 4. Boot the Rust engine
        await init(wasmUrl);

        console.log("Moribund Rust Engine Booted.");
        // Note: Your Rust run() function executes automatically 
        // because of the #[wasm_bindgen(start)] macro!
        
    } catch (e) {
        console.error("Critical Failure: Moribund WASM Sensor failed to boot.", e);
    }
})();
