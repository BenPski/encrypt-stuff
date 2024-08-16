use serde::Serialize;

pub trait Encoder {
    fn encode<T: Serialize + ?Sized>(t: &T) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
}
