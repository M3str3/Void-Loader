//! PE binary in-memory execution techniques

use anyhow::Result;

#[cfg(feature = "execution-local-pe")]
pub mod local_pe;

#[cfg(feature = "execution-process-hollowing")]
pub mod process_hollowing;

#[cfg(feature = "execution-thread-hijack")]
pub mod thread_hijack;

/// Execute PE using process hollowing
#[cfg(feature = "execution-process-hollowing")]
pub fn execute_with_process_hollowing(pe_data: &[u8], target_path: &str, verbose: bool) -> Result<()> {
    process_hollowing::inject_and_execute(pe_data, target_path, verbose)
}

/// Result of a PE execution operation
#[derive(Debug)]
pub struct ExecutionResult {
    pub success: bool,
    pub error: Option<String>,
    pub method: String,
}

/// Trait for implementing custom execution methods
pub trait Executor {
    fn execute(&self, pe_data: &[u8], args: &[String]) -> Result<ExecutionResult>;
    fn method_name(&self) -> &str;
}

/// Validate PE format before execution
pub fn validate_pe_before_execution(data: &[u8]) -> Result<()> {
    use crate::validation;
    validation::validate_pe_format(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pe_basic() {
        let mut pe_data = vec![0u8; 256];
        pe_data[0] = b'M';
        pe_data[1] = b'Z';
        pe_data[60] = 128;
        pe_data[128] = b'P';
        pe_data[129] = b'E';

        assert!(validate_pe_before_execution(&pe_data).is_ok());
    }

    #[test]
    fn test_validate_pe_invalid() {
        let invalid_data = vec![0u8; 64];
        assert!(validate_pe_before_execution(&invalid_data).is_err());
    }
}
