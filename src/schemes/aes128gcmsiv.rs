use crate::encryption::Encryption;

pub struct Aes128GcmSiv;
impl Encryption for Aes128GcmSiv {
    type Cipher = aes_gcm_siv::Aes128GcmSiv;
}
