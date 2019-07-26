extern crate libc;
use libc::c_int;

pub trait Interface {
    fn recv(&self, data: &mut [u8]) -> usize;
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
        fn recv(&self, data: &mut [u8]) -> usize {
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
                        bytes_received as usize
                    } else {
                        println!("Error2");
                        0
                    }
                } else {
                    println!("Error");
                    0
                }
            }
        }
    }

}

pub mod pcap {

    use byteorder::{BigEndian, ByteOrder, LittleEndian, NativeEndian, ReadBytesExt};
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

    const PCAP_MAGIC: u32 = 0xa1b2c3d4;

    pub struct PcapHeader {
        pub magic_number: u32,
        version_major: u16,
        version_minor: u16,
        thiszone: i32,
        sigfigs: u32,
        pub snaplen: u32,
        network: u32,
    }

    pub struct PcapRecord {
        pub ts_sec: u32,
        pub ts_usec: u32,
        pub incl_len: u32,
        pub orig_len: u32,
    }

    pub struct PacketRecord<'a> {
        pub data: &'a [u8],
    }

    impl<'a> PacketRecord<'a> {
        pub fn ts_sec(&self) -> u32 {
            NativeEndian::read_u32(&self.data[0..4])
        }

        pub fn ts_usec(&self) -> u32 {
            NativeEndian::read_u32(&self.data[4..8])
        }

        pub fn incl_len(&self) -> u32 {
            NativeEndian::read_u32(&self.data[8..12])
        }

        pub fn orig_len(&self) -> u32 {
            NativeEndian::read_u32(&self.data[12..16])
        }
    }

    pub struct PcapReader {
        pub header: PcapHeader,
        reader: BufReader<File>,
        swap: bool,
        record: Vec<u8>,
        data: Vec<u8>,
        // packet_record: PacketRecord<'a>,
    }

    impl PcapReader {
        pub fn new(file: &str) -> std::io::Result<Self> {
            // let file = File::open(file);
            let mut reader = BufReader::new(File::open(file)?);
            let (header, swap) = PcapReader::read_header(&mut reader)?;
            // let mut record = Vec::with_capacity(header.snaplen as usize);
            // record = [0; header.snaplen];
            let record = vec![0; 16];
            let data = vec![0; header.snaplen as usize];
            // let packet_record = PacketRecord { data: &record };
            let pcap_reader = PcapReader {
                header,
                reader,
                swap,
                record,
                data,
                // packet_record
            };
            Ok(pcap_reader)
        }

        fn parse_header(
            reader: &mut BufReader<File>,
            magic_number: u32,
            swap: bool,
        ) -> std::io::Result<(PcapHeader, bool)> {
            match swap {
                false => Ok((
                    PcapHeader {
                        magic_number: magic_number,
                        version_major: reader.read_u16::<NativeEndian>()?,
                        version_minor: reader.read_u16::<NativeEndian>()?,
                        thiszone: reader.read_i32::<NativeEndian>()?,
                        sigfigs: reader.read_u32::<NativeEndian>()?,
                        snaplen: reader.read_u32::<NativeEndian>()?,
                        network: reader.read_u32::<NativeEndian>()?,
                    },
                    swap,
                )),

                true => Ok((
                    PcapHeader {
                        magic_number: u32::swap_bytes(magic_number),
                        version_major: u16::swap_bytes(reader.read_u16::<NativeEndian>()?),
                        version_minor: u16::swap_bytes(reader.read_u16::<NativeEndian>()?),
                        thiszone: i32::swap_bytes(reader.read_i32::<NativeEndian>()?),
                        sigfigs: u32::swap_bytes(reader.read_u32::<NativeEndian>()?),
                        snaplen: u32::swap_bytes(reader.read_u32::<NativeEndian>()?),
                        network: u32::swap_bytes(reader.read_u32::<NativeEndian>()?),
                    },
                    swap,
                )),
            }
        }

        fn read_header(reader: &mut BufReader<File>) -> std::io::Result<(PcapHeader, bool)> {
            let magic_number = reader.read_u32::<NativeEndian>().unwrap();

            // Correct endianness.
            if magic_number == PCAP_MAGIC {
                PcapReader::parse_header(reader, magic_number, false)
            }
            // Wrong endianess.
            else if u32::swap_bytes(magic_number) == PCAP_MAGIC {
                PcapReader::parse_header(reader, magic_number, true)
            }
            // Bad magic number.
            else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Bad pcap magic number.",
                ))
            }
        }

        pub fn read_record(&mut self) -> std::io::Result<PcapRecord> {
            match self.swap {
                false => Ok(PcapRecord {
                    ts_sec: self.reader.read_u32::<NativeEndian>()?,
                    ts_usec: self.reader.read_u32::<NativeEndian>()?,
                    incl_len: self.reader.read_u32::<NativeEndian>()?,
                    orig_len: self.reader.read_u32::<NativeEndian>()?,
                }),

                true => Ok(PcapRecord {
                    ts_sec: u32::swap_bytes(self.reader.read_u32::<NativeEndian>()?),
                    ts_usec: u32::swap_bytes(self.reader.read_u32::<NativeEndian>()?),
                    incl_len: u32::swap_bytes(self.reader.read_u32::<NativeEndian>()?),
                    orig_len: u32::swap_bytes(self.reader.read_u32::<NativeEndian>()?),
                }),
            }
        }

        pub fn read_data(&mut self, record: &PcapRecord) -> std::io::Result<()> {
            self.reader
                .read_exact(&mut self.record[0..record.incl_len as usize])
        }

        pub fn read_packet(&mut self) -> std::io::Result<PacketRecord> {
            match self.reader.read_exact(&mut self.record[0..16]) {
                Ok(_) => {
                    let record = PacketRecord{data: &self.record[0..16]};
                    self.reader.read_exact(&mut self.data[0..record.incl_len() as usize]).unwrap();
                    Ok(record)
                }
                Err(x) => Err(x)
            }
        }
    }

    // impl super::Interface for PcapReader {
    //     fn recv(&self, data: &mut [u8]) -> usize {
    //         0
    //     }
    // }
}
