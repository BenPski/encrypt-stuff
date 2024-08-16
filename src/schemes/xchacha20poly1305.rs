use crate::encryption::Encryption;

pub struct XChaCha20Poly1305;
impl Encryption for XChaCha20Poly1305 {
    type Cipher = chacha20poly1305::XChaCha20Poly1305;
}
