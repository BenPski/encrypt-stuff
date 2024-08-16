use crate::encryption::Encryption;

pub struct ChaCha20Poly1305;
impl Encryption for ChaCha20Poly1305 {
    type Cipher = chacha20poly1305::ChaCha20Poly1305;
}
