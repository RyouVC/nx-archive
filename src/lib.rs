use std::io::{Read, Seek};

pub mod formats;
pub mod io;
impl<T: Read + Seek> ReadSeek for T {}
pub trait ReadSeek: Read + Seek {}


