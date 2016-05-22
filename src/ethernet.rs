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
use IntoDissectResult;
use Val;
use NamedValues;
use ip;
use raw;
use nom::{be_u16, rest};

pub fn dissect(data : &[u8]) -> DissectResult {

    //TODO: beter parsing: 802.1Q tag, minimum payload size, CRC
    chain!(data,
           dest: take!(6) ~
           src: take!(6) ~
           tlen: be_u16 ~
           remainder: rest,
           || {
               let mut values = NamedValues::new();

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

               values
           }).into_dissect_result("Ethernet packet", data)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn dissect_ethernet() {
        let data = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa0, 0x0b, 0xba, 0x84, 0x2d, 0x0e, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01, 0xa0, 0x0b, 0xba, 0x84, 0x2d, 0x0e, 0xc0, 0xa8, 0x01, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

        let val = *dissect(&data).unwrap();
        println!("{}", &val.pretty_print(0));

        assert_eq!(val["Destination"].as_bytes().unwrap(), &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(val["Source"].as_bytes().unwrap(), &[0xa0, 0x0b, 0xba, 0x84, 0x2d, 0x0e]);
        assert!(val["ARP"].is_payload());
    }

    #[test]
    #[should_panic(expected = "Underflow { expected: Some(12), have: 10, message: \"Need 12 B of data to dissect Ethernet packet, have 10 B\" }")]
    fn dissect_ethernet_underflow() {
        let data = [132, 56, 53, 69, 73, 136, 156, 32, 123, 233];
        let _ = dissect(&data).unwrap();
    }
}
