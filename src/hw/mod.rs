extern crate libc;
use libc::c_int;

pub trait Interface {
    fn recv(&self, data: &mut [u8]);
    // fn send(data: &[u8]);
}

pub type Result<T> = std::result::Result<T, HwError>;

#[derive(Debug, Clone)]
pub struct HwError {
    errno: c_int,
}

// impl std::error::Error for HwError {
//     fn description(&self) -> &str {}
// }

#[cfg(target_os = "linux")]
pub mod socket {

    use libc::{c_int, c_void, ssize_t};

    pub struct RawSocket {
        socket: i32,
    }

    impl RawSocket {
        pub fn new() -> Result<Self, super::HwError> {
            let eth: u16 = libc::ETH_P_ALL as u16;
            unsafe {
                let socket: c_int =
                    libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth.to_be() as i32);
                if socket != -1 {
                    return Ok(RawSocket { socket });
                } else {
                    Err(super::HwError {
                        errno: *libc::__errno_location(),
                    })
                }
            }
        }
    }

    impl super::Interface for RawSocket {
        fn recv(&self, data: &mut [u8]) {
            let bytes_received: ssize_t = 0;
            unsafe {
                const SOCK_FLAGS: c_int = 0;
                if self.socket != -1 {
                    // let buf: *mut c_void = data as *mut c_void;
                    let bytes_received: ssize_t = libc::recv(
                        self.socket,
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
