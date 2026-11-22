use rand::Rng;
use std::fs;
use std::path::{Path, PathBuf};

mod core_tests;
mod internal_links_tests;
mod mutation_upload_tests;

pub(super) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub(super) fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let path = std::env::temp_dir().join(format!("af-files-test-{token:032x}"));
            if fs::create_dir(&path).is_ok() {
                return Self { path };
            }
        }
        panic!("failed to create test tempdir");
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
