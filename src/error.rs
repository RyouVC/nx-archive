use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
    #[error("Invalid data: {0}")]
    InvalidData(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Not supported: {0}")]
    NotSupported(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Timeout: {0}")]
    Timeout(String),
    #[error("Other error: {0}")]
    Other(String),
}