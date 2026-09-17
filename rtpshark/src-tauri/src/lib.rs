// RTPShark 桌面版：分析逻辑全部在前端 Web Worker 内完成，
// Rust 侧仅负责窗口与插件生命周期。
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
