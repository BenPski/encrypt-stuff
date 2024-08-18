use ciphers::Aes256Gcm;
use schemes::bitcode::Bitcode;

pub mod ciphers;
pub mod decode;
pub mod encode;
pub mod encryption;
pub mod schemes;

#[cfg(feature = "default")]
pub type DefaultScheme = Aes256Gcm<Bitcode>;

pub use aead::Key;
