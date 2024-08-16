use crate::encryption::Encryption;

pub struct Aes128Gcm;
impl Encryption for Aes128Gcm {
    type Cipher = aes_gcm::Aes128Gcm;
}
