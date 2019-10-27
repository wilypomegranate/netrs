extern crate netrs;

use netrs::handler::l2::{DefaultHandler, EthernetHandler, EthernetReceiver};
use netrs::hw::pcap::{PacketRecord, PcapReader};
use netrs::hw::socket::RawSocket;
use netrs::hw::Interface;
use std::env;

pub fn main() {
    // let socket: RawSocket = RawSocket::new().expect("Socket error.");
    // const MTU: usize = 1500;
    // let mut buffer: [u8; MTU] = [0; MTU];
    // socket.recv(&mut buffer);

    let args: Vec<String> = env::args().collect();

    let mut pcap: PcapReader = PcapReader::new(&args[1]).expect("Pcap reader error.");
    let mut handler = DefaultHandler {};
    let eth_processor = EthernetReceiver::new(&mut handler);

    let mut count: usize = 0;
    while let Ok(record) = pcap.read_packet() {
        eth_processor.handle(&record);
        // println!(
        //     "sec: {}, usec: {}, incl_len: {}, orig_len: {}",
        //     record.ts_sec(), record.ts_usec(), record.incl_len(), record.orig_len()
        // );
        count += 1;
    }
    println!("Count {}", count);

    // println!("Magic number: {} snaplen: {}.", pcap.header.magic_number, pcap.header.snaplen);
}
