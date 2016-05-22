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

use Endianness;
use DissectError;
use DissectResult;
use Val;
use NamedValues;
use raw;
use unsigned;

pub fn dissect(data : &[u8]) -> DissectResult {
    if data.len() < 20 {
        return Err(DissectError::Underflow { expected: Some(20), have: data.len(),
            message: "An IP packet must be at least 20 B".to_string() })
    }

    let mut values = NamedValues::new();

    // IP version (should be "4")
    let version = data[0] >> 4;
    values.push(("Version", Val::Unsigned(version as u64)));

    // Internet Header Length (IHL): number of 32b words in header
    let ihl = data[0] & 0x0f;
    values.push(("IHL", Val::Unsigned(ihl as u64)));

    let header_lenght = ihl as usize * 4;
    if header_lenght > data.len() {
        return Err(DissectError::Underflow { expected: Some(header_lenght), have: data.len(),
            message: "IP packet IHL (header length) greater than available data".to_string() });
    }

    // Differentiated Services Code Point (DSCP): RFC 2474
    let dscp = data[1] >> 2;
    values.push(("DSCP", Val::Unsigned(dscp as u64)));

    // Explicit Congestion Notification (ECN): RFC 3168
    let ecn = data[1] & 0x03;
    values.push(("ECN", Val::Unsigned(ecn as u64)));

    // Total length (including header)
    let length = unsigned(&data[2..4], Endianness::BigEndian);
    values.push(("Length", Val::Unsigned(length.unwrap())));

    // Identification (of datagraph fragments): RFC 6864
    values.push(("Identification", Val::Unsigned(data[8] as u64)));

    // Protocol number (assigned by IANA)
    let protocol = data[9];
    values.push(("Protocol", Val::Unsigned(protocol as u64)));

    // Header checksum
    values.push(("Checksum", Val::Bytes(&data[10..12])));

    // Source and destination addresses
    let source = &data[12..16];
    values.push(("Source", Val::Address {
        bytes: source,
        encoded: source.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
    }));

    let dest = &data[16..20];
    values.push(("Destination", Val::Address {
        bytes: dest,
        encoded: dest.iter().map(|b| b.to_string()).collect::<Vec<_>>().join("."),
    }));

    if header_lenght > 20 {
        let options = &data[20..header_lenght];
        values.push(("Options", Val::Bytes(options)));
    }

    // Parse the remainder according to the specified protocol.
    let remainder = &data[header_lenght..];
    match protocol {
        6 => values.push(("TCP", Val::Payload(tcp::dissect(remainder)))),
        // TODO: UDP, TCP, etc.
        _ => values.push(("Unknown", Val::Payload(raw(remainder))))
    };

    Ok(Box::new(Val::Object(values)))
}

mod tcp;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dissect_ip() {
        let data = [69, 0, 0, 60, 0, 0, 64, 0, 46, 6, 161, 36, 46, 137, 186, 243, 192, 168, 1, 115, 1, 187, 252, 235, 74, 97, 130, 175, 50, 220, 74, 238, 5, 18, 56, 144, 237, 13, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 15, 68, 221, 156, 29, 26, 35, 62, 1, 3, 3, 6];

        let val = *dissect(&data).unwrap();
        println!("{}", &val);
        println!("{}", &val.pretty_print(0));

        assert_eq!(val["Version"].as_unsigned().unwrap(), 4);
        assert_eq!(val["IHL"].as_unsigned().unwrap(), 5);
        assert_eq!(val["DSCP"].as_unsigned().unwrap(), 0);
        assert_eq!(val["ECN"].as_unsigned().unwrap(), 0);
        assert_eq!(val["Length"].as_unsigned().unwrap(), 60);
        assert_eq!(val["Identification"].as_unsigned().unwrap(), 46);
        assert_eq!(val["Protocol"].as_unsigned().unwrap(), 6);
        assert_eq!(val["Checksum"].as_bytes().unwrap(), &[0xa1u8, 0x24]);
        assert_eq!(val["Source"].as_address_encoded().unwrap(), "46.137.186.243");
        assert_eq!(val["Destination"].as_address_encoded().unwrap(), "192.168.1.115");
        assert!(val["TCP"].is_payload());
    }
}
