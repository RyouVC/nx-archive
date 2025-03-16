use std::io::{Read, Seek};

pub mod formats;
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}
