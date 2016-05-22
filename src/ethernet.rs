/*
 * Copyright 2015 Jonathan Anderson
 *
 * Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
 * http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
 * http://opensource.org/licenses/MIT>, at your option. This file may not be
 * copied, modified, or distributed except according to those terms.
 */

//! Dissection of Ethernet (IEEE 802.3) frames.

use DissectError;
use DissectResult;
use Val;
use NamedValues;
use ip;
use raw;
use nom::{IResult, Needed, be_u16};

pub fn dissect(data : &[u8]) -> DissectResult {
    let mut values = NamedValues::new();

    //TODO: beter parsing: 802.1Q tag, minimum payload size, CRC
    match tuple!(data, take!(6), take!(6), be_u16) {
        IResult::Done(remainder, (dest, src, tlen)) => {
            values.push(("Destination", Val::Bytes(dest)));
            values.push(("Source", Val::Bytes(src)));

            if tlen <= 1500 {
                values.push(("Length", Val::Unsigned(tlen as u64)));
            } else {
                match tlen {
                    0x800 => values.push(("IP", Val::Payload(ip::dissect(remainder)))),
                    0x806 => values.push(("ARP", Val::Payload(raw(remainder)))),
                    0x8138 => values.push(("IPX", Val::Payload(raw(remainder)))),
                    0x86dd => values.push(("IPv6", Val::Payload(raw(remainder)))),
                    _ => values.push(("Unknown Type", Val::Payload(Err(DissectError::InvalidData(format!["unknown protocol: {:x}", tlen]))))),
                };
            };
        },
        IResult::Incomplete(Needed::Size(needed)) =>
            return Err(DissectError::Underflow { expected: needed, have: data.len(),
                message: format!("An Ethernet frame must be at least {} B", needed) }),
        //TODO: anything I can do here?
        _ => panic!("failed to parse Ethernet packet!")
    }

    Ok(Box::new(Val::Object(values)))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dissect_ethernet() {
        let data = [132, 56, 53, 69, 73, 136, 156, 32, 123, 233, 26, 2, 8, 0];

        let val = *dissect(&data).unwrap();
        println!("{}", &val.pretty_print(0));

        assert_eq!(val["Destination"].as_bytes().unwrap(), &[0x84, 0x38, 0x35, 0x45, 0x49, 0x88]);
        assert_eq!(val["Source"].as_bytes().unwrap(), &[0x9c, 0x20, 0x7b, 0xe9, 0x1a, 0x02]);
        assert!(val["IP"].as_payload().unwrap().is_err())
    }

    #[test]
    #[should_panic(expected = "Underflow { expected: 12, have: 10, message: \"An Ethernet frame must be at least 12 B\" }")]
    fn dissect_ethernet_underflow() {
        let data = [132, 56, 53, 69, 73, 136, 156, 32, 123, 233];
        let _ = dissect(&data).unwrap();
    }
}
