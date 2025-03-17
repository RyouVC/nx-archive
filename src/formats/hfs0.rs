//! The Nintendo Hashed filesystem (HFS0) is a filesystem used by the Nintendo Switch to store data in a hashed format.
//! This filesystem is used in the Nintendo Switch's game cards (the little bitter carts that you insert physically into the console).
//!
//! This module doesn't allow you to eat the game itself, but lets you dump data
//! from the game card.
//!
//! You still require the XCI module to read the game card image format, which in turn contains this filesystem.
//! For the game card image format, see [xci](crate::formats::xci).

use binrw::prelude::*;
use std::io::{Read, Seek, SeekFrom};
