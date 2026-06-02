#![allow(non_snake_case)]
use dioxus::prelude::*;
use dioxus_logger::tracing::{Level, info};

// --- MOCK SYNC MANAGER (From previous architecture) ---
#[derive(Clone, Copy, PartialEq)]
enum SyncMode {
    AppBound,
    Daemon,
}

// --- MAIN ENTRY POINT ---
fn main() {
    dioxus_logger::init(Level::INFO).expect("failed to init logger");
    info!("Booting Moribund Vault Desktop...");

    let cfg = dioxus::desktop::Config::new()
        .with_window(dioxus::desktop::WindowBuilder::new()
            .with_title("Moribund Vault [LMS]")
            .with_inner_size(dioxus::desktop::LogicalSize::new(1200.0, 800.0)));

    LaunchBuilder::desktop().with_cfg(cfg).launch(App);
}

// --- ROOT COMPONENT ---
#[component]
fn App() -> Element {
    // Global state for current view and sync mode
    let mut current_view = use_signal(|| "study");
    let mut sync_mode = use_signal(|| SyncMode::AppBound);

    rsx! {
        // Inject minimal CSS directly for the prototype
        style { {include_str!("../assets/base.css")} }

        div { class: "app-container",
            // SIDEBAR NAV
            div { class: "sidebar",
                h2 { class: "brand", "MORIBUND" }
                ul { class: "nav-links",
                    li { 
                        class: if *current_view.read() == "study" { "active" } else { "" },
                        onclick: move |_| current_view.set("study"),
                        "🧠 Study Queue" 
                    }
                    li { 
                        class: if *current_view.read() == "vault" { "active" } else { "" },
                        onclick: move |_| current_view.set("vault"),
                        "🗄️ The Vault" 
                    }
                    li { 
                        class: if *current_view.read() == "sync" { "active" } else { "" },
                        onclick: move |_| current_view.set("sync"),
                        "⚙️ Engine & Sync" 
                    }
                }
                
                div { class: "sync-status",
                    if *sync_mode.read() == SyncMode::Daemon {
                        "🟢 Sync: 24/7 (Daemon)"
                    } else {
                        "🟡 Sync: Active (App-bound)"
                    }
                }
            }

            // MAIN WORKSPACE ROUTER
            div { class: "workspace",
                match *current_view.read() {
                    "study" => rsx! { StudyView {} },
                    "vault" => rsx! { VaultView {} },
                    "sync" => rsx! { SyncSettingsView { sync_mode } },
                    _ => rsx! { div { "404 - View Not Found" } }
                }
            }
        }
    }
}

// --- VIEWS ---

#[component]
fn StudyView() -> Element {
    rsx! {
        div { class: "view-study",
            h1 { "Daily Review" }
            div { class: "flashcard",
                div { class: "card-term", "Spaced Repetition" }
                div { class: "card-actions",
                    button { class: "btn-fail", "Again (1)" }
                    button { class: "btn-hard", "Hard (3)" }
                    button { class: "btn-good", "Good (6)" }
                    button { class: "btn-easy", "Easy (12)" }
                }
            }
        }
    }
}

#[component]
fn VaultView() -> Element {
    rsx! {
        div { class: "view-vault",
            h1 { "Vault Explorer" }
            p { "Your offline Xikipedia shards and vocabulary reside here." }
            // Future: Implement a table or grid of parsed JSONL files
        }
    }
}

#[component]
fn SyncSettingsView(sync_mode: Signal<SyncMode>) -> Element {
    rsx! {
        div { class: "view-sync",
            h1 { "Engine & Telemetry" }
            div { class: "settings-card",
                h3 { "Consent-Driven Sync" }
                p { "Syncthing currently runs only when this app is open. Do you want to install it as a background daemon to sync 24/7?" }
                
                div { class: "toggle-group",
                    button {
                        class: if *sync_mode.read() == SyncMode::AppBound { "active" } else { "" },
                        onclick: move |_| {
                            // Call SyncManager::opt_out_of_background() here
                            sync_mode.set(SyncMode::AppBound);
                        },
                        "App-Bound (Polite)"
                    }
                    button {
                        class: if *sync_mode.read() == SyncMode::Daemon { "active" } else { "" },
                        onclick: move |_| {
                            // Call SyncManager::opt_in_to_background() here
                            sync_mode.set(SyncMode::Daemon);
                        },
                        "24/7 Background Daemon"
                    }
                }
            }
        }
    }
}