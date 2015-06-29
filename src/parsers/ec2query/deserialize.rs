use xml::reader::EventReader;
use xml::reader::events::*;

#[derive(Debug)]
pub enum DeserializeError {
    SerializationError
}

pub type DeserializationResult = Result<T, DeserializeError>;


