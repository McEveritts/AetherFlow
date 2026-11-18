use std::{
    fs,
    io::{self, Write},
    path::Path,
};
fn compress_dir(directory: &Path) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.is_dir() {
            compress_dir(&path)?;
            continue;
        }
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("wasm" | "js" | "css" | "json" | "svg")
        ) {
            continue;
        }
        let input = fs::read(&path)?;
        let mut compressed = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut compressed, 64 * 1024, 11, 22);
            writer.write_all(&input)?;
        }
        let sidecar = format!("{}.br", path.display());
        if compressed.len() < input.len() {
            fs::write(&sidecar, &compressed)?;
        } else {
            let _ = fs::remove_file(&sidecar);
        }
        println!(
            "{} {} bytes -> {} bytes Brotli",
            path.display(),
            input.len(),
            compressed.len()
        );
    }
    Ok(())
}
fn main() -> io::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| io::Error::other("usage: compress-assets DIST"))?;
    compress_dir(Path::new(&path))
}
