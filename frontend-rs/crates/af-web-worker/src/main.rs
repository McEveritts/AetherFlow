//! Trunk emits a module worker loader; no DOM or Leptos is linked into this binary.
#[cfg(target_arch = "wasm32")]
fn main() {
    af_web_worker::start();
}
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    eprintln!("af-web-worker is a wasm32 Dedicated Web Worker");
}
