#[macro_use] extern crate log;
extern crate byteorder;
extern crate flate2;
#[cfg(feature = "apple-auth")]
extern crate num_bigint;
#[cfg(feature = "apple-auth")]
extern crate octavo;
#[cfg(feature = "apple-auth")]
extern crate crypto;

use std::io::Write;
use byteorder::{BigEndian, WriteBytesExt};

mod protocol;
mod zrle;
mod security;

pub mod client;
pub mod proxy;
pub mod server;

pub use protocol::{PixelFormat, Colour, Encoding};
pub use client::Client;
pub use proxy::Proxy;
pub use server::Server;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Rect {
    pub left:   u16,
    pub top:    u16,
    pub width:  u16,
    pub height: u16
}

impl Rect {
    /// Constructs new `Rect`.
    pub fn new(left: u16, top: u16, width: u16, height: u16) -> Self {
        Rect {
            left: left,
            top: top,
            width: width,
            height: height,
        }
    }

    /// Constructs new zero-sized `Rect` placed at (0, 0).
    pub fn new_empty() -> Self {
        Rect {
            left: 0,
            top: 0,
            width: 0,
            height: 0,
        }
    }

    /// Writes `Rect` to given stream.
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        try!(writer.write_u16::<BigEndian>(self.left));
        try!(writer.write_u16::<BigEndian>(self.top));
        try!(writer.write_u16::<BigEndian>(self.width));
        try!(writer.write_u16::<BigEndian>(self.height));
        Ok(())
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Unexpected(&'static str),
    Server(String),
    AuthenticationUnavailable,
    AuthenticationFailure(String),
    Disconnected
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match self {
            &Error::Io(ref inner) => inner.fmt(f),
            &Error::Unexpected(ref descr) =>
                write!(f, "unexpected {}", descr),
            &Error::Server(ref descr) =>
                write!(f, "server error: {}", descr),
            &Error::AuthenticationFailure(ref descr) =>
                write!(f, "authentication failure: {}", descr),
            _ => f.write_str(std::error::Error::description(self))
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::Io(ref inner) => inner.description(),
            &Error::Unexpected(_) => "unexpected value",
            &Error::Server(_) => "server error",
            &Error::AuthenticationUnavailable => "authentication unavailable",
            &Error::AuthenticationFailure(_) => "authentication failure",
            &Error::Disconnected => "peer disconnected",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            &Error::Io(ref inner) => Some(inner),
            _ => None
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Error { Error::Io(error) }
}

pub type Result<T> = std::result::Result<T, Error>;
