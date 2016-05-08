/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of Internet Protocol (IP) packets.
//!
//! This module will eventually contain dissectors for protocols in the IP suite,
//! e.g., `rshark::ip::icmp` and `rshark::ip::tcp`.
//! For now, it only handles IP headers.
//!
//! See [RFC 791](https://tools.ietf.org/html/rfc791).

use {
    Endianness,
    Error,
    NamedValue,
    Result,
    Val,
    raw,
    unsigned,
};


pub fn dissect(data : &[u8]) -> Result {
    if data.len() < 20 {
        return Err(Error::Underflow { expected: 20, have: data.len(),
            message: "An IP packet must be at least 20 B".to_string() })
    }

    let mut values:Vec<NamedValue> = vec![];

    // IP version (should be "4")
    let version = data[0] >> 4;
    values.push(("Version", Ok(Val::Unsigned(version as u64))));

    // Internet Header Length (IHL): number of 32b words in header
    let words = data[0] & 0x0f;
    values.push(("IHL", Ok(Val::Unsigned(words as u64))));

    // Differentiated Services Code Point (DSCP): RFC 2474
    let dscp = data[1] >> 2;
    values.push(("DSCP", Ok(Val::Unsigned(dscp as u64))));

    // Explicit Congestion Notification (ECN): RFC 3168
    let ecn = data[1] & 0x03;
    values.push(("ECN", Ok(Val::Unsigned(ecn as u64))));

    // Total length (including header)
    let length = unsigned(&data[2..4], Endianness::BigEndian);
    values.push(("Length", length.map(|v| Val::Unsigned(v))));

    // Identification (of datagraph fragments): RFC 6864
    values.push(("Identification", Ok(Val::Unsigned(data[8] as u64))));

    // Protocol number (assigned by IANA)
    let protocol = data[9];
    values.push(("Protocol", Ok(Val::Unsigned(protocol as u64))));

    // Header checksum
    values.push(("Checksum", Ok(Val::Bytes(data[10..12].to_vec()))));

    // Source and destination addresses
    let source = &data[12..16];
    values.push(("Source", Ok(Val::Address {
        bytes: source.to_vec(),
        encoded: source.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
    })));

    let dest = &data[16..20];
    values.push(("Destination", Ok(Val::Address {
        bytes: dest.to_vec(),
        encoded: dest.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
    })));

    // Parse the remainder according to the specified protocol.
    let remainder = &data[20..];
    let dissect_pdu = match protocol {
        // TODO: UDP, TCP, etc.
        _ => raw,
    };

    values.push(("Protocol Data", dissect_pdu(remainder)));

    Ok(Val::Object(values))
}

#[cfg(test)]
mod test {
    use super::*;
    use Val;
    use raw;

    #[test]
    fn dissect_ip() {
        let data = [69, 0, 0, 60, 0, 0, 64, 0, 46, 6, 161, 36, 46, 137, 186, 243, 192, 168, 1, 115, 1, 187, 252, 235, 74, 97, 130, 175, 50, 220, 74, 238, 160, 18, 56, 144, 237, 13, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 15, 68, 221, 156, 29, 26, 35, 62, 1, 3, 3, 6];

        let val = dissect(&data).unwrap();

        /*
          Version: 4
          IHL: 5
          DSCP: 0
          ECN: 0
          Length: 60
          Identification: 46
          Protocol: 6
          Checksum: 2 B [ a1 24 ]
          Source: 46.137.186.243
          Destination: 192.168.1.115
        */

        let mut values = vec![];

        values.push(("Version", Ok(Val::Unsigned(4))));
        values.push(("IHL", Ok(Val::Unsigned(5))));
        values.push(("DSCP", Ok(Val::Unsigned(0))));
        values.push(("ECN", Ok(Val::Unsigned(0))));
        values.push(("Length", Ok(Val::Unsigned(60))));
        values.push(("Identification", Ok(Val::Unsigned(46))));
        values.push(("Protocol", Ok(Val::Unsigned(6))));
        values.push(("Checksum", Ok(Val::Bytes(vec![0xa1u8, 0x24]))));
        values.push(("Source", Ok(Val::Address{bytes: vec![46, 137, 186, 243], encoded: "46.137.186.243".to_string()})));
        values.push(("Destination", Ok(Val::Address{bytes: vec![192, 168, 1, 115], encoded: "192.168.1.115".to_string()})));
        values.push(("Protocol Data", raw(&data[20..])));

        let expected_val = Val::Object(values);

        println!("{}", &val.pretty_print(0));
        println!("{}", &expected_val.pretty_print(0));

        assert_eq!(val, expected_val);
    }
}
