/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of Ethernet (IEEE 802.3) frames.

use {
    Dissector,
    Endianness,
    Error,
    NamedValue,
    Result,
    Val,
    ip,
    raw,
    unsigned,
};


pub fn dissect(data : &[u8]) -> Result {
    if data.len() < 14 {
        return Err(Error::Underflow { expected: 14, have: data.len(),
            message: "An Ethernet frame must be at least 14 B".to_string() })
    }

    let mut values:Vec<NamedValue> = vec![];
    values.push(("Destination", Ok(Val::Bytes(data[0..6].to_vec()))));
    values.push(("Source", Ok(Val::Bytes(data[6..12].to_vec()))));

    // The type/length field might be either a type or a length.
    let tlen = unsigned(&data[12..14], Endianness::BigEndian);
    let remainder = &data[14..];

    match tlen {
        Ok(i) if i <= 1500 => {
            values.push(("Length", Ok(Val::Unsigned(i))));
        },

        Ok(i) => {
            let (protocol, dissector): (Result<(&str, &str)>, Dissector) = match i {
                0x800 => (Ok(("IP", "IP data")), ip::dissect),
                0x806 => (Ok(("ARP", "ARB data")), raw),
                0x8138 => (Ok(("IPX", "IPX data")), raw),
                0x86dd => (Ok(("IPv6", "IPVv6 data")), raw),
                _ => (
                    Err(Error::InvalidData(format!["unknown protocol: {:x}", i])),
                    raw
                ),
            };

            let (ty, subname):(Result, &str) = match protocol {
                Ok((name, val_name)) =>
                    (
                        Ok(Val::String(name.to_string())),
                        val_name
                    ),

                Err(e) => (Err(e), "Unknown protocol data"),
            };

            values.push(("Type", ty));
            values.push((subname, dissector(remainder)));
        },
        Err(e) => {
            values.push(("Type/length", Err(e)));
        },
    };

    Ok(Val::Object(values))
}
