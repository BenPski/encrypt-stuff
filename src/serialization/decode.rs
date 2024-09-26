use serde::{de::DeserializeOwned, Deserialize};

pub trait Decoder {
    fn decode<'de, T: Deserialize<'de>>(input: &'de [u8]) -> Result<T, Box<dyn std::error::Error>>;
    fn decode_owned<T: DeserializeOwned>(input: Vec<u8>) -> Result<T, Box<dyn std::error::Error>>;
}
