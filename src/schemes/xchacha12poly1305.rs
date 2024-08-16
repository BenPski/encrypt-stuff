use crate::encryption::Encryption;

pub struct XChaCha12Poly1305;
impl Encryption for XChaCha12Poly1305 {
    type Cipher = chacha20poly1305::XChaCha12Poly1305;
}
