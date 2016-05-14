/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//!
//! `rshark`, the Rusty Shark library, is a library for deep inspection
//! of malicious packets.
//!
//! # Background
//!
//! [Wireshark](https://www.wireshark.org) is a very useful tool for network
//! debugging, but it's had its
//! [fair share of security vulnerabilities](https://www.wireshark.org/security).
//! It's generally accepted that, to succeed at Capture the Flag, one should fuzz
//! Wireshark for awhile before the competition to find a few new vulnerabilities
//! (don't worry, they're there, you'll find some) and use those offensively to
//! blind one's opponents.
//! This speaks to both the indispensability of packet capture/dissection tools
//! and the fundamental difficulty of ``just making Wireshark secure''.
//! Wireshark has a *lot* of dissectors, which are written using a
//! [complex C API](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html)
//! (although some are now written in Lua).
//!
//! `rshark` uses the type safety of Rust to enable the dissection of
//! malicious packets without worry of buffer overflows or other common memory errors.
//! Rusty Shark dissectors can make mistakes, but those logical errors should only
//! affect the interpretation of the *current* data, rather than *all* data.
//! That is to say, Rusty Shark is compartmentalized to minimize the damage that
//! can be done by a successful adversary. The submarine metaphors write themselves.
//!
//! # Usage
//!
//! *note: for help on the `rshark` command-line client,
//! run `man rshark` or `rshark --help`.*
//!
//! The `rshark` library provides packet dissection functions such as
//! `rshark::ethernet::dissect()`. Every such dissection function, which should
//! conform to the `rshark::Dissector` function type, takes as input a slice of bytes
//! and returns an `rshark::Result` (which defaults to
//! `Result<rshark::Val, rshark::Error>`).
//! Usage is pretty simple:
//!
//! ```
//! let data = vec![];
//!
//! match rshark::ethernet::dissect(&data) {
//!     Err(e) => println!["Error: {}", e],
//!     Ok(val) => print!["{}", val.pretty_print(0)],
//! }
//! ```
//!
//! A `Val` can represent an arbitrary tree of structured data
//! (useful in graphical displays) and can be pretty-printed with indentation for
//! sub-objects.

#![doc(html_logo_url = "https://raw.githubusercontent.com/musec/rusty-shark/master/artwork/wordmark.png")]

extern crate byteorder;

use byteorder::ReadBytesExt;
use std::fmt;
use std::io;
use std::ops::Index;

/// A value parsed from a packet.
///
/// # TODO
/// This value type isn't as expressive as would be required for a real
/// Wireshark replacement just yet. Additional needs include:
///
///  * tracking original bytes (by reference or by index?)
///  * supporting error metadata (e.g., "parsed ok but checksum doesn't match")
///  * supporting asynchronous sub-object parsing (some sort of promises?)
///
#[derive(Debug, PartialEq)]
pub enum Val {
    /// A signed integer, in machine-native representation.
    Signed(i64),

    /// An unsigned integer, in machine-native representation.
    Unsigned(u64),

    /// A UTF-8–encoded string.
    String(String),

    /// A UTF-8-encoded static string.
    Symbol(&'static str),

    /// A network address, which can have its own special encoding.
    Address { bytes: Vec<u8>, encoded: String },

    /// A sub-object is an ordered set of name, value pairs.
    Object(NamedValues),

    /// A payload, which can be dissected and fail
    Payload(Result<Box<Val>>),

    /// Raw bytes, e.g., a checksum or just unparsed data.
    Bytes(Vec<u8>),
}

impl Val {
    pub fn pretty_print(&self, indent:usize) -> String {
        match self {
            &Val::Object(ref values) => {
                let mut s = "\n".to_string();
                let prefix =
                    ::std::iter::repeat(" ").take(2 * indent).collect::<String>();

                for &(ref k, ref v) in values {
                    s = s + &format!["{}{}: {}\n", prefix, k, v.pretty_print(indent + 1)]
                }
                s
            }
            &Val::Payload(Ok(ref v)) => format!["-> {}", v.pretty_print(indent + 1)],
            &Val::Payload(Err(ref e)) => format!["<< Error: {} >>", e],
            _ => format!["{}", self]
        }
    }

    /// Returns true if the `Val` is a Signed. Returns false otherwise.
    pub fn is_signed(&self) -> bool {
        self.as_signed().is_some()
    }

    /// If the `Val` is a Signed, returns the associated i64.
    /// Returns None otherwise.
    pub fn as_signed(&self) -> Option<i64> {
        match self {
            &Val::Signed(val) => Some(val),
            _ => None
        }
    }

    /// Returns true if the `Val` is an Unsigned. Returns false otherwise.
    pub fn is_unsigned(&self) -> bool {
        self.as_unsigned().is_some()
    }

    /// If the `Val` is an Unsigned, returns the associated u64.
    /// Returns None otherwise.
    pub fn as_unsigned(&self) -> Option<u64> {
        match self {
            &Val::Unsigned(val) => Some(val),
            _ => None
        }
    }

    /// Returns true if the `Val` is a String. Returns false otherwise.
    pub fn is_string(&self) -> bool {
        self.as_string().is_some()
    }

    /// If the `Val` is a String, returns the associated String.
    /// Returns None otherwise.
    pub fn as_string<'a>(&'a self) -> Option<&'a str> {
        match self {
            &Val::String(ref val) => Some(&val),
            _ => None
        }
    }

    /// Returns true if the `Val` is a Symbol. Returns false otherwise.
    pub fn is_symbol(&self) -> bool {
        self.as_symbol().is_some()
    }

    /// If the `Val` is a Symbol, returns the associated &str.
    /// Returns None otherwise.
    pub fn as_symbol(&self) -> Option<&'static str> {
        match self {
            &Val::Symbol(ref val) => Some(val),
            _ => None
        }
    }

    /// Returns true if the `Val` is a Address. Returns false otherwise.
    pub fn is_address(&self) -> bool {
        self.as_address_bytes().is_some()
    }

    /// If the `Val` is a Address, returns the associated bytes field as Vec<u8>.
    /// Returns None otherwise.
    pub fn as_address_bytes<'a>(&'a self) -> Option<&'a [u8]> {
        match self {
            &Val::Address{ref bytes, ..} => Some(bytes.as_slice()),
            _ => None
        }
    }

    /// If the `Val` is a Address, returns the associated encoded field as String.
    /// Returns None otherwise.
    pub fn as_address_encoded<'a>(&'a self) -> Option<&'a str> {
        match self {
            &Val::Address{ref encoded, ..} => Some(&encoded),
            _ => None
        }
    }

    /// Returns true if the `Val` is a Object. Returns false otherwise.
    pub fn is_object(&self) -> bool {
        self.as_object().is_some()
    }

    /// If the `Val` is a Object, returns the associated NamedValues.
    /// Returns None otherwise.
    pub fn as_object<'a>(&'a self) -> Option<&'a NamedValues> {
        match self {
            &Val::Object(ref val) => Some(val),
            _ => None
        }
    }

    /// Returns true if the `Val` is a Payload. Returns false otherwise.
    pub fn is_payload(&self) -> bool {
        self.as_payload().is_some()
    }

    /// If the `Val` is a Payload, returns the associated Box<Result<Val>>.
    /// Returns None otherwise.
    pub fn as_payload<'a>(&'a self) -> Option<&'a Result> {
        match self {
            &Val::Payload(ref val) => Some(val),
            _ => None
        }
    }

    /// Returns true if the `Val` is a Bytes. Returns false otherwise.
    pub fn is_bytes(&self) -> bool {
        self.as_bytes().is_some()
    }

    /// If the `Val` is a Bytes, returns the associated Vec<u8>.
    /// Returns None otherwise.
    pub fn as_bytes<'a>(&'a self) -> Option<&'a [u8]> {
        match self {
            &Val::Bytes(ref val) => Some(val.as_slice()),
            _ => None
        }
    }
}

impl Index<&'static str> for Val {
    type Output = Val;

    // TODO: also need to provide .get() -> Option<&Val> variant
    fn index<'a>(&'a self, index: &'static str) -> &'a Val {
        match self {
            &Val::Object(ref values) => &values.iter().find(|&&(ref k, ref _v)| k == &index).expect(&format!["no value for index '{}' found in: {:?}", index, self]).1,
            &Val::Payload(Ok(ref val)) => &val[index],
            &Val::Payload(Err(ref e)) => panic!(format!["Val::Payload under index '{}' contains error: {}", index, e]),
            _ => panic!(format!["index on non Val::Object variant: {:?}", self]),
        }
    }
}

impl fmt::Display for Val {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Val::Signed(ref i) => write![f, "{}", i],
            &Val::Unsigned(ref i) => write![f, "{}", i],
            &Val::String(ref s) => write![f, "\"{}\"", s],
            &Val::Symbol(ref s) => write![f, "{}", s],
            &Val::Address { ref encoded, .. } => write![f, "{}", encoded],
            &Val::Object(ref values) => {
                try![write![f, "{{ "]];

                //TODO: map().join()
                for &(ref k, ref v) in values {
                    try![write![f, "{}: {}", k, v]];
                    try![write![f, ", "]];
                }

                write![f, "}}"]
            },
            &Val::Payload(Ok(ref val)) => write![f, "({})", val],
            &Val::Payload(Err(ref e)) => write![f, "<<{}>>", e],
            &Val::Bytes(ref bytes) => {
                try![write![f, "{} B [", bytes.len()]];

                let to_print:&[u8] =
                    if bytes.len() < 16 { bytes }
                    else { &bytes[..16] }
                    ;

                for b in to_print {
                    try![write![f, " {:02x}", b]];
                }

                if bytes.len() > 16 {
                    try![write![f, " ..."]];
                }

                write![f, " ]"]
            }
        }
    }
}


/// An error related to packet dissection (underflow, bad value, etc.).
#[derive(Debug, PartialEq)]
pub enum Error {
    Underflow { expected: usize, have: usize, message: String, },
    InvalidData(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::Underflow { expected, have, ref message } =>
                write![f, "underflow (expected {}, have {}): {}",
                    expected, have, message],

            &Error::InvalidData(ref msg) => write![f, "invalid data: {}", msg],
        }
    }
}

/// The result of a dissection function.
pub type Result<T=Box<Val>> = ::std::result::Result<T,Error>;

/// A named value-or-error.
pub type NamedValues = Vec<(&'static str, Val)>;

/// Type of dissection functions.
pub type Dissector = fn(&[u8]) -> Result<Box<Val>>;

/// Little- or big-endian integer representations.
pub enum Endianness {
    BigEndian,
    LittleEndian,
}

/// Parse a signed integer of a given endianness from a byte buffer.
///
/// The size of the buffer will be used to determine the size of the integer
/// that should be parsed (i8, i16, i32 or i64), but the result will be stored
/// in an i64.
pub fn signed(buffer: &[u8], endianness: Endianness) -> Result<i64> {
    let mut reader = io::Cursor::new(buffer);

    match endianness {
        Endianness::BigEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as i64),
                2 => Ok(reader.read_i16::<byteorder::BigEndian>().unwrap() as i64),
                4 => Ok(reader.read_i32::<byteorder::BigEndian>().unwrap() as i64),
                8 => Ok(reader.read_i64::<byteorder::BigEndian>().unwrap()),
                x => Err(Error::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }

        Endianness::LittleEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as i64),
                2 => Ok(reader.read_i16::<byteorder::LittleEndian>().unwrap() as i64),
                4 => Ok(reader.read_i32::<byteorder::LittleEndian>().unwrap() as i64),
                8 => Ok(reader.read_i64::<byteorder::LittleEndian>().unwrap()),
                x => Err(Error::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }
    }
}

/// Parse a signed integer of a given endianness from a byte buffer.
///
/// The size of the buffer will be used to determine the size of the integer
/// that should be parsed (u8, u16, u32 or u64), but the result will be stored
/// in a u64.
pub fn unsigned(buffer: &[u8], endianness: Endianness) -> Result<u64> {
    let mut reader = io::Cursor::new(buffer);

    match endianness {
        Endianness::BigEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as u64),
                2 => Ok(reader.read_u16::<byteorder::BigEndian>().unwrap() as u64),
                4 => Ok(reader.read_u32::<byteorder::BigEndian>().unwrap() as u64),
                8 => Ok(reader.read_u64::<byteorder::BigEndian>().unwrap()),
                x => Err(Error::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }

        Endianness::LittleEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as u64),
                2 => Ok(reader.read_u16::<byteorder::LittleEndian>().unwrap() as u64),
                4 => Ok(reader.read_u32::<byteorder::LittleEndian>().unwrap() as u64),
                8 => Ok(reader.read_u64::<byteorder::LittleEndian>().unwrap()),
                x => Err(Error::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }
    }
}

/// Dissector of last resort: store raw bytes without interpretation.
pub fn raw(data: &[u8]) -> Result {
    let mut obj = NamedValues::new();
    obj.push(("raw data", Val::Bytes(data.to_vec())));
    Ok(Box::new(Val::Object(obj)))
}

pub mod ethernet;
pub mod ip;

#[cfg(test)]
mod test {
    use super::*;

    fn test_object() -> Val {
        let mut obj = NamedValues::new();
        let mut payload = NamedValues::new();

        payload.push(("bar", Val::Unsigned(42)));
        obj.push(("foo", Val::Payload(Ok(Box::new(Val::Object(payload))))));

        Val::Object(obj)
    }

    fn test_object_err_payload() -> Val {
        let mut obj = NamedValues::new();
        let mut payload = NamedValues::new();

        payload.push(("bar", Val::Unsigned(42)));
        obj.push(("foo", Val::Payload(Err(Error::InvalidData("error".to_string())))));

        Val::Object(obj)
    }

    #[test]
    fn val_index_access() {
        let _ = test_object()["foo"]["bar"];
    }

    #[test]
    #[should_panic(expected = "no value for index 'baz' found in: Object([(\"foo\", Payload(Ok(Object([(\"bar\", Unsigned(42))]))))])")]
    fn val_index_access_not_found() {
        let _ = test_object()["baz"]["bar"];
    }

    #[test]
    #[should_panic(expected = "no value for index 'baz' found in: Object([(\"bar\", Unsigned(42))])")]
    fn val_index_access_not_found2() {
        let _ = test_object()["foo"]["baz"];
    }

    #[test]
    #[should_panic(expected = "Val::Payload under index 'bar' contains error: invalid data: error")]
    fn val_index_access_err_payload() {
        let _ = test_object_err_payload()["foo"]["bar"];
    }

    #[test]
    #[should_panic(expected = "index on non Val::Object variant: Unsigned(42)")]
    fn val_index_access_non_object() {
        let _ = Val::Unsigned(42)["baz"];
    }
}
