use crate::encryption::Encryption;

pub struct ChaCha12Poly1305;
impl Encryption for ChaCha12Poly1305 {
    type Cipher = chacha20poly1305::ChaCha12Poly1305;
}
