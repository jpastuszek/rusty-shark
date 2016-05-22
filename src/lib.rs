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
//! and returns an `rshark::DissectResult` (which defaults to
//! `DissectResult<rshark::Val, rshark::Error>`).
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
#[macro_use]
extern crate itertools;

use byteorder::ReadBytesExt;
use std::fmt;
use std::io;
use std::ops::Index;
use std::error::Error;

use itertools::Itertools;

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
pub enum Val<'data> {
    /// A signed integer, in machine-native representation.
    Signed(i64),

    /// An unsigned integer, in machine-native representation.
    Unsigned(u64),

    /// A UTF-8–encoded string.
    String(String),

    /// A UTF-8-encoded static string.
    Symbol(&'static str),

    /// A network address, which can have its own special encoding.
    Address { bytes: &'data [u8], encoded: String },

    /// Single byte bit flags.
    BitFlags8(u8, [Option<&'static str>; 8]),

    /// A sub-object is an ordered set of name, value pairs.
    Object(NamedValues<'data>),

    /// A payload, which can be dissected and fail
    Payload(DissectResult<'data, Box<Val<'data>>>),

    /// Raw bytes, e.g., a checksum or just unparsed data.
    Bytes(&'data [u8]),

    // TODO: labeled or enum variant for enumerations like protocols: 6 (tcp), 17 (udp)
    // try avoid Boxing (allocations) - perhaps pointer to detail dissect function
    // Signed(i64, Option<Dissector>)
}

impl<'data> Val<'data> {
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
    pub fn as_string<'val>(&'val self) -> Option<&'val str> {
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
    pub fn as_address_bytes(&self) -> Option<&'data [u8]> {
        match self {
            &Val::Address{ref bytes, ..} => Some(bytes),
            _ => None
        }
    }

    /// If the `Val` is a Address, returns the associated encoded field as String.
    /// Returns None otherwise.
    pub fn as_address_encoded<'val>(&'val self) -> Option<&'val str> {
        match self {
            &Val::Address{ref encoded, ..} => Some(&encoded),
            _ => None
        }
    }

    pub fn is_bitflags8(&self) -> bool {
        match self {
            &Val::BitFlags8(_, _) => true,
            _ => false
        }
    }

    pub fn as_bitflags8_bit_no(&self, bit: u8) -> Option<bool> {
        assert!(bit < 8, "cannot access bit higher than 8'th");
        match self {
            &Val::BitFlags8(flag, _) => Some(1 << bit & flag > 0),
            _ => None
        }
    }

    pub fn as_bitflags8_bit_name(&self, name: &str) -> Option<bool> {
        match self {
            &Val::BitFlags8(_, ref names) => {
                if let Some(pos) = names.into_iter().position(|&n| n == Some(name)) {
                    return self.as_bitflags8_bit_no(pos as u8);
                }
                None
            },
            _ => None
        }
    }

    /// Returns true if the `Val` is a Object. Returns false otherwise.
    pub fn is_object(&self) -> bool {
        self.as_object().is_some()
    }

    /// If the `Val` is a Object, returns the associated NamedValues.
    /// Returns None otherwise.
    pub fn as_object(&self) -> Option<&'data NamedValues> {
        match self {
            &Val::Object(ref val) => Some(val),
            _ => None
        }
    }

    /// Returns true if the `Val` is a Payload. Returns false otherwise.
    pub fn is_payload(&self) -> bool {
        self.as_payload().is_some()
    }

    /// If the `Val` is a Payload, returns the associated Box<DissectResult<Val>>.
    /// Returns None otherwise.
    pub fn as_payload(&self) -> Option<&'data DissectResult> {
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
    pub fn as_bytes(&self) -> Option<&'data [u8]> {
        match self {
            &Val::Bytes(ref val) => Some(val),
            _ => None
        }
    }

    pub fn get<'val>(&'val self, index: &str) -> Result<&'val Val<'data>, AccessError> {
        match self {
            &Val::Object(ref values) => values.iter().find(|&&(ref k, ref _v)| k == &index)
                .ok_or(AccessError::not_found(index, self)).map(|v| &v.1),
            &Val::Payload(Ok(ref val)) => val.get(index),
            &Val::Payload(Err(ref e)) => Err(AccessError::dissect_error(index, e)),
            _ => Err(AccessError::leaf_variant(self))
        }
    }

    pub fn get_path(&self, keys: &[&str]) -> Result<&'data Val, AccessError> {
        keys.iter().fold(Ok(self), |val, index| {
            match val {
                Ok(val) => val.get(index),
                Err(_) => return val
            }
        })
    }

    pub fn lookup(&self, path: &str) -> Option<&'data Val> {
        path.split('.').fold(Some(self), |val, index| {
            match val {
                Some(val) => val.get(index).ok(),
                None => return None
            }
        })
    }
}

#[derive(Debug, PartialEq)]
pub enum AccessError {
    NotFound(String),
    DissectError(String),
    LeafVariant(String),
}

impl AccessError {
    fn not_found(index: &str, val: &Val) -> AccessError {
        AccessError::NotFound(format!["no value for index '{}' found in: {:?}", index, val])
    }

    fn dissect_error(index: &str, error: &DissectError) -> AccessError {
        AccessError::DissectError(format!["Val::Payload under index '{}' contains error: {}", index, error])
    }

    fn leaf_variant(val: &Val) -> AccessError {
        AccessError::LeafVariant(format!["index on non Val::Object variant: {:?}", val])
    }
}

impl Error for AccessError {
    fn description(&self) -> &str {
        match self {
            &AccessError::NotFound(ref desc) => desc,
            &AccessError::DissectError(ref desc) => desc,
            &AccessError::LeafVariant(ref desc) => desc,
        }
    }
}

impl fmt::Display for AccessError {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
        match self {
            &AccessError::NotFound(ref desc) => write![f, "access error: {}", desc],
            &AccessError::DissectError(ref desc) => write![f, "access error: {}", desc],
            &AccessError::LeafVariant(ref desc) => write![f, "access error: {}", desc],
        }
    }
}

impl<'data> Index<&'static str> for Val<'data> {
    type Output = Val<'data>;

    fn index(&self, index: &str) -> &Val<'data> {
        match self.get(index) {
            Err(err) => panic!(format!["indexing error: {}", err]),
            Ok(val) => val
        }
    }
}

impl<'data> fmt::Display for Val<'data> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Val::Signed(ref i) => write![f, "{}", i],
            &Val::Unsigned(ref i) => write![f, "{}", i],
            &Val::String(ref s) => write![f, "\"{}\"", s],
            &Val::Symbol(ref s) => write![f, "{}", s],
            &Val::Address { ref encoded, .. } => write![f, "{}", encoded],
            &Val::BitFlags8(ref flags, ref desc) => {
                let mut bit = 1u8;
                write![f, "{:08b} ({})", flags, (0..8).into_iter().filter_map(move |i| {
                    let val = if let Some(desc) = desc[i] {
                        if flags & bit > 0 {
                            Some(desc)
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    bit = bit << 1;
                    val
                }).format("+", |val, f| f(&format_args!("{}", val)))]
            },
            &Val::Object(ref values) => {
                write![f, "{{ {} }}", values.iter()
                    .format(", ", |kv, f| f(&format_args!("{}: {}", kv.0, kv.1)))]
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
pub enum DissectError {
    Underflow { expected: usize, have: usize, message: String, },
    InvalidData(String),
}

impl fmt::Display for DissectError {
    fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DissectError::Underflow { expected, have, ref message } =>
                write![f, "underflow (expected {}, have {}): {}",
                    expected, have, message],

            &DissectError::InvalidData(ref msg) => write![f, "invalid data: {}", msg],
        }
    }
}

/// The result of a dissection function.
pub type DissectResult<'data, T = Box<Val<'data>>> = Result<T, DissectError>;

/// A named value-or-error.
pub type NamedValues<'data> = Vec<(&'static str, Val<'data>)>;

/// Type of dissection functions.
pub type Dissector<'data> = fn(&'data [u8]) -> DissectResult<Box<Val<'data>>>;

/// Little- or big-endian integer representations.
pub enum Endianness {
    BigEndian,
    LittleEndian,
}

/// Parse a signed integer of a given endianness from a byte buffer.
///
/// The size of the buffer will be used to determine the size of the integer
/// that should be parsed (i8, i16, i32 or i64), but the DissectResult will be stored
/// in an i64.
pub fn signed(buffer: &[u8], endianness: Endianness) -> DissectResult<i64> {
    let mut reader = io::Cursor::new(buffer);

    match endianness {
        Endianness::BigEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as i64),
                2 => Ok(reader.read_i16::<byteorder::BigEndian>().unwrap() as i64),
                4 => Ok(reader.read_i32::<byteorder::BigEndian>().unwrap() as i64),
                8 => Ok(reader.read_i64::<byteorder::BigEndian>().unwrap()),
                x => Err(DissectError::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }

        Endianness::LittleEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as i64),
                2 => Ok(reader.read_i16::<byteorder::LittleEndian>().unwrap() as i64),
                4 => Ok(reader.read_i32::<byteorder::LittleEndian>().unwrap() as i64),
                8 => Ok(reader.read_i64::<byteorder::LittleEndian>().unwrap()),
                x => Err(DissectError::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }
    }
}

/// Parse a signed integer of a given endianness from a byte buffer.
///
/// The size of the buffer will be used to determine the size of the integer
/// that should be parsed (u8, u16, u32 or u64), but the DissectResult will be stored
/// in a u64.
pub fn unsigned(buffer: &[u8], endianness: Endianness) -> DissectResult<u64> {
    let mut reader = io::Cursor::new(buffer);

    match endianness {
        Endianness::BigEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as u64),
                2 => Ok(reader.read_u16::<byteorder::BigEndian>().unwrap() as u64),
                4 => Ok(reader.read_u32::<byteorder::BigEndian>().unwrap() as u64),
                8 => Ok(reader.read_u64::<byteorder::BigEndian>().unwrap()),
                x => Err(DissectError::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }

        Endianness::LittleEndian => {
            match buffer.len() {
                1 => Ok(buffer[0] as u64),
                2 => Ok(reader.read_u16::<byteorder::LittleEndian>().unwrap() as u64),
                4 => Ok(reader.read_u32::<byteorder::LittleEndian>().unwrap() as u64),
                8 => Ok(reader.read_u64::<byteorder::LittleEndian>().unwrap()),
                x => Err(DissectError::InvalidData(format!["Invalid integer size: {} B", x])),
            }
        }
    }
}

/// Dissector of last resort: store raw bytes without interpretation.
pub fn raw<'data>(data: &'data [u8]) -> DissectResult<'data> {
    let mut obj = NamedValues::new();
    obj.push(("raw data", Val::Bytes(data)));
    Ok(Box::new(Val::Object(obj)))
}

pub mod ethernet;
pub mod ip;

#[cfg(test)]
mod test {
    use super::*;

    fn test_object() -> Val<'static> {
        let mut obj = NamedValues::new();
        let mut payload = NamedValues::new();

        payload.push(("bar", Val::Unsigned(42)));
        obj.push(("foo", Val::Payload(Ok(Box::new(Val::Object(payload))))));

        Val::Object(obj)
    }

    fn test_object_err_payload() -> Val<'static> {
        let mut obj = NamedValues::new();
        let mut payload = NamedValues::new();

        payload.push(("bar", Val::Unsigned(42)));
        obj.push(("foo", Val::Payload(Err(DissectError::InvalidData("error".to_string())))));

        Val::Object(obj)
    }

    fn flags_test_object() -> Val<'static> {
        let mut obj = NamedValues::new();

        obj.push(("flags", Val::BitFlags8(0b01011100, [
                                          Some("foo"), None, Some("bar"), None,
                                          None, None, Some("baz"), None])));

        Val::Object(obj)
    }

    #[test]
    fn val_index() {
        assert_eq!(test_object()["foo"]["bar"], Val::Unsigned(42));
    }

    #[test]
    #[should_panic(expected = "indexing error: access error: no value for index 'baz' found in: Object([(\"foo\", Payload(Ok(Object([(\"bar\", Unsigned(42))]))))])")]
    fn val_index_not_found() {
        let _ = test_object()["baz"]["bar"];
    }

    #[test]
    #[should_panic(expected = "indexing error: access error: no value for index 'baz' found in: Object([(\"bar\", Unsigned(42))])")]
    fn val_index_not_found2() {
        let _ = test_object()["foo"]["baz"];
    }

    #[test]
    #[should_panic(expected = "indexing error: access error: Val::Payload under index 'bar' contains error: invalid data: error")]
    fn val_index_dissect_err() {
        let _ = test_object_err_payload()["foo"]["bar"];
    }

    #[test]
    #[should_panic(expected = "indexing error: access error: index on non Val::Object variant: Unsigned(42)")]
    fn val_index_non_object() {
        let _ = Val::Unsigned(42)["baz"];
    }

    #[test]
    fn val_get() {
        assert_eq!(test_object().get("foo").unwrap().get("bar").unwrap(), &Val::Unsigned(42));
    }

    #[test]
    fn val_get_not_found() {
        match test_object().get("baz").unwrap_err() {
            AccessError::NotFound(ref desc) => assert_eq!(desc, "no value for index 'baz' found in: Object([(\"foo\", Payload(Ok(Object([(\"bar\", Unsigned(42))]))))])"),
            _ => panic!("wrong error")
        }
    }

    #[test]
    fn val_get_dissect_err() {
        match test_object_err_payload()["foo"].get("bar").unwrap_err() {
            AccessError::DissectError(ref desc) => assert_eq!(desc, "Val::Payload under index 'bar' contains error: invalid data: error"),
            _ => panic!("wrong error")
        }
    }

    #[test]
    fn val_get_non_object() {
        match Val::Unsigned(42).get("baz").unwrap_err() {
            AccessError::LeafVariant(ref desc) => assert_eq!(desc, "index on non Val::Object variant: Unsigned(42)"),
            _ => panic!("wrong error")
        }
    }

    #[test]
    fn val_get_path() {
        assert_eq!(test_object().get_path(&["foo", "bar"]).unwrap(), &Val::Unsigned(42));
    }

    #[test]
    fn val_lookup() {
        assert_eq!(test_object().lookup("foo.bar"), Some(&Val::Unsigned(42)));
    }

    #[test]
    fn val_lookup_none() {
        assert_eq!(test_object().lookup("foo.bar.baz"), None);
    }

    #[test]
    fn flags_access_by_bit_no() {
        let ref flags = flags_test_object()["flags"];
        assert_eq!(flags.as_bitflags8_bit_no(0), Some(false));
        assert_eq!(flags.as_bitflags8_bit_no(1), Some(false));
        assert_eq!(flags.as_bitflags8_bit_no(2), Some(true));
        assert_eq!(flags.as_bitflags8_bit_no(3), Some(true));
        assert_eq!(flags.as_bitflags8_bit_no(4), Some(true));
        assert_eq!(flags.as_bitflags8_bit_no(5), Some(false));
        assert_eq!(flags.as_bitflags8_bit_no(6), Some(true));
        assert_eq!(flags.as_bitflags8_bit_no(7), Some(false));
    }

    #[test]
    #[should_panic(expected = "cannot access bit higher than 8'th")]
    fn flags_access_by_bit_no_overflow() {
        let ref flags = flags_test_object()["flags"];
        assert_eq!(flags.as_bitflags8_bit_no(9), Some(false));
    }

    #[test]
    fn flags_access_by_bit_name() {
        let ref flags = flags_test_object()["flags"];
        assert_eq!(flags.as_bitflags8_bit_name("foo"), Some(false));
        assert_eq!(flags.as_bitflags8_bit_name("bar"), Some(true));
        assert_eq!(flags.as_bitflags8_bit_name("baz"), Some(true));
        assert_eq!(flags.as_bitflags8_bit_name("quix"), None);
    }
}
