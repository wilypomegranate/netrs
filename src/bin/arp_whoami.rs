extern crate netrs;

use netrs::hw::Interface;
use netrs::hw::socket::RawSocket;

pub fn main() {
    let socket: RawSocket = RawSocket{};
    const MTU: usize = 1500;
    let mut buffer: [u8;MTU] = [0;MTU];
    socket.recv(&mut buffer);
}
