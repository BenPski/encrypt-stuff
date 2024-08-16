use boring_derive::From;
use thiserror::Error;

#[derive(Debug, Error, From)]
pub enum EncryptionError {
    #[error("Serialization error: `{0}`")]
    Serialization(bitcode::Error),
    #[error("Encryption error: `{0}`")]
    Encryption(aead::Error),
}
