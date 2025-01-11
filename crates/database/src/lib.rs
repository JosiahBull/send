#![doc = include_str!("../README.md")]
#![warn(clippy::all, clippy::pedantic)]

mod error;
mod migrate;
mod upload;

pub use error::DatabaseError;
pub use migrate::migrate;
pub use upload::*;
