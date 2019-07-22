extern crate netrs;

use netrs::hw::socket::RawSocket;
use netrs::hw::Interface;

pub fn main() {
    let socket: RawSocket = RawSocket::new().expect("Socket error.");
    const MTU: usize = 1500;
    let mut buffer: [u8; MTU] = [0; MTU];
    socket.recv(&mut buffer);
}
