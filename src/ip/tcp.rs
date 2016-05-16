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
        return Err(DissectError::Underflow { expected: 20, have: data.len(),
            message: "An TCP packet must be at least 20 B".to_string() })
    }

    let mut values = NamedValues::new();

    let source_port = unsigned(&data[0..2], Endianness::BigEndian);
    values.push(("Source Port", Val::Unsigned(source_port.unwrap())));

    let destination_port = unsigned(&data[2..4], Endianness::BigEndian);
    values.push(("Destination Port", Val::Unsigned(destination_port.unwrap())));

    let sequence_number = unsigned(&data[4..8], Endianness::BigEndian);
    values.push(("Sequence Number", Val::Unsigned(sequence_number.unwrap())));

    let acknowledgement_number = unsigned(&data[8..12], Endianness::BigEndian);
    values.push(("Acknowledgement Number", Val::Unsigned(acknowledgement_number.unwrap())));

    //TODO: need better Val for this
    let offset = data[12];
    values.push(("Offset", Val::Unsigned(offset as u64)));

    let header_lenght = offset as usize * 4;
    if header_lenght > data.len() {
        return Err(DissectError::Underflow { expected: header_lenght, have: data.len(),
            message: "TCP packet offset (header length) greater than available data".to_string() });
    }

    let flags = data[14];
    values.push(("Flags", Val::BitFlags8(flags, [
                                         Some("CWR"), Some("ECE"), Some("URG"), Some("ACK"),
                                         Some("PSH"), Some("RST"), Some("SYN"), Some("FIN")])));

    let window = unsigned(&data[14..16], Endianness::BigEndian);
    values.push(("Window", Val::Unsigned(window.unwrap())));

    //TODO: Val::Checksum ? need parts of IP header?!
    let checksum = &data[16..18];
    values.push(("Checksum", Val::Bytes(checksum.to_vec())));

    let urgent_pointer = unsigned(&data[18..20], Endianness::BigEndian);
    values.push(("Urgent Pointer", Val::Unsigned(urgent_pointer.unwrap() as u64)));

    if header_lenght > 20 {
        let options = &data[20..header_lenght];
        values.push(("Options", Val::Bytes(options.to_vec())));
    }

    let remainder = &data[header_lenght..];
    values.push(("Payload", Val::Payload(raw(remainder))));

    Ok(Box::new(Val::Object(values)))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dissect_tcp() {
        let data = [1, 187, 252, 235, 74, 97, 130, 175, 50, 220, 74, 238, 5, 18, 56, 144, 237, 13, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 15, 68, 221, 156, 29, 26, 35, 62, 1, 3, 3, 6];

        let val = *dissect(&data).unwrap();
        println!("{}", &val);
        println!("{}", &val.pretty_print(0));

        assert_eq!(val["Source Port"].as_unsigned().unwrap(), 443);
        assert_eq!(val["Destination Port"].as_unsigned().unwrap(), 64747);
    }
}
