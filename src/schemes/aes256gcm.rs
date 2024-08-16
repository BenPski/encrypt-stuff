use crate::encryption::Encryption;

pub struct Aes256Gcm;
impl Encryption for Aes256Gcm {
    type Cipher = aes_gcm::Aes256Gcm;
}
