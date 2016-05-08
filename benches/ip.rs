#![feature(test)]

extern crate rshark;
extern crate test;

use test::Bencher;
use rshark::ip::dissect;

#[bench]
fn dissect_ip_bench(b: &mut Bencher) {
    let data = [69, 0, 0, 60, 0, 0, 64, 0, 46, 6, 161, 36, 46, 137, 186, 243, 192, 168, 1, 115, 1, 187, 252, 235, 74, 97, 130, 175, 50, 220, 74, 238, 160, 18, 56, 144, 237, 13, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 15, 68, 221, 156, 29, 26, 35, 62, 1, 3, 3, 6];

    b.iter(|| dissect(&data).unwrap());
}
