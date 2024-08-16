use crate::encryption::Encryption;

pub struct ChaCha8Poly1305;
impl Encryption for ChaCha8Poly1305 {
    type Cipher = chacha20poly1305::ChaCha8Poly1305;
}
