use crate::encryption::Encryption;

pub struct Aes256GcmSiv;
impl Encryption for Aes256GcmSiv {
    type Cipher = aes_gcm_siv::Aes256GcmSiv;
}
