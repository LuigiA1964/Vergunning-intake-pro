#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use serde::Serialize;

#[derive(Serialize)]
struct AppInfo {
    version: String,
    platform: String,
    is_tauri: bool,
    app_data_dir: String,
}

#[tauri::command]
fn get_app_info(app_handle: tauri::AppHandle) -> Result<AppInfo, String> {
    let app_data_dir = app_handle
        .path_resolver()
        .app_data_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|| "Kon app data directory niet bepalen".to_string());

    Ok(AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
        is_tauri: true,
        app_data_dir,
    })
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_app_info])
        .run(tauri::generate_context!())
        .expect("Fout bij het starten van de applicatie");
}
