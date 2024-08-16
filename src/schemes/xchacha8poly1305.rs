use crate::encryption::Encryption;

pub struct XChaCha8Poly1305;
impl Encryption for XChaCha8Poly1305 {
    type Cipher = chacha20poly1305::XChaCha8Poly1305;
}
