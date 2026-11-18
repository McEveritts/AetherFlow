fn main() {
    #[cfg(target_arch = "wasm32")]
    leptos::mount::mount_to_body(af_web_app::App);
}
