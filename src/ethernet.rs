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
                        Ok(Val::Symbol(name)),
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

#[cfg(test)]
mod test {
    use super::*;
    use Val;
    use Error;

    #[test]
    fn dissect_ethernet() {
        let data = [132, 56, 53, 69, 73, 136, 156, 32, 123, 233, 26, 2, 8, 0];

        let val = dissect(&data).unwrap();

        /*
           Destination: 6 B [ 84 38 35 45 49 88 ]
           Source: 6 B [ 9c 20 7b e9 1a 02 ]
           Type: IP
        */

        let mut values = vec![];

        values.push(("Destination", Ok(Val::Bytes(vec![0x84, 0x38, 0x35, 0x45, 0x49, 0x88]))));
        values.push(("Source", Ok(Val::Bytes(vec![0x9c, 0x20, 0x7b, 0xe9, 0x1a, 0x02]))));
        values.push(("Type", Ok(Val::Symbol("IP"))));
        values.push(("IP data", Err(Error::Underflow { expected: 20, have: 0, message: "An IP packet must be at least 20 B".to_string() })));

        let expected_val = Val::Object(values);

        println!("{}", &val.pretty_print(0));
        println!("{}", &expected_val.pretty_print(0));

        assert_eq!(val, expected_val);
    }
}
