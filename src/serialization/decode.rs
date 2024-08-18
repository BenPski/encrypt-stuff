use serde::Deserialize;

pub trait Decoder {
    fn decode<'de, T: Deserialize<'de>>(input: &'de [u8]) -> Result<T, Box<dyn std::error::Error>>;
}
