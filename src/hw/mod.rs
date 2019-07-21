extern crate libc;

pub trait Interface {
    fn recv(&self, data: &mut [u8]);
    // fn send(data: &[u8]);
}

pub type Result<T> = std::result::Result<T, HwError>;
#[derive(Debug, Clone)]
struct HwError;

#[cfg(target_os = "linux")]
pub mod socket {

    use libc::{c_int, c_void, ssize_t};

    pub struct RawSocket {
        socket: i32
    }

    // impl RawSocket {
    //     pub fn new() -> Result<RawSocket, super::HwError> {
    //     }
    // }

    impl super::Interface for RawSocket {
        fn recv(&self, data: &mut [u8]) {
            let sock: c_int = -1;
            let eth: u16 = libc::ETH_P_ALL as u16;
            let bytes_received: ssize_t = 0;
            unsafe {
                let sock: c_int = libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth.to_be() as i32);
                const SOCK_FLAGS: c_int = 0;
                if sock != -1 {
                    // let buf: *mut c_void = data as *mut c_void;
                    let bytes_received: ssize_t = libc::recv(
                        sock,
                        data.as_mut_ptr() as *mut c_void,
                        data.len(),
                        SOCK_FLAGS,
                    );
                    if bytes_received > 0 {
                        println!("Received {}.", bytes_received);
                    } else {
                        println!("Error2");
                    }
                } else {
                    println!("Error");
                }
            }
        }
    }

}
