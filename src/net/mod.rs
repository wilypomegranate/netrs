pub mod ethernet {
    use byteorder::{ByteOrder, NativeEndian};

    pub enum EtherType {
        Arp,
        Ipv4,
        Unknown(u16),
    }

    pub struct Ethernet<'a> {
        data: &'a [u8],
    }

    impl<'a> Ethernet<'a> {
        pub fn dst_mac(&self) -> u64 {
            0
        }
        pub fn src_mac(&self) -> u64 {
            0
        }
        pub fn vlan(&self) -> Option<u16> {
            let vlan_ethertype: u16 = NativeEndian::read_u16(&self.data[20..22]);
            if vlan_ethertype == 0x8100 {
                Some(NativeEndian::read_u16(&self.data[22..24]))
            } else {
                None
            }
        }
        pub fn ethertype(&self) -> EtherType {
            // TODO Does not handle Q-in-Q vlan.
            // See https://en.wikipedia.org/wiki/IEEE_802.1ad
            // for more details.
            let ethertype = match self.vlan() {
                None => NativeEndian::read_u16(&self.data[20..22]),
                Some(_x) => NativeEndian::read_u16(&self.data[24..26]),
            };

            match ethertype {
                0x0800 => EtherType::Ipv4,
                0x0806 => EtherType::Arp,
                _ => EtherType::Unknown(ethertype),
            }
        }
    }
}

pub mod mac {

    use std::fmt;

    pub struct MacAddress<'a> {
        addr: &'a [u8],
    }

    impl<'a> MacAddress<'a> {
        pub fn new(data: &'a [u8]) -> MacAddress<'a> {
            MacAddress { addr: data }
        }
    }

    impl<'a> fmt::Display for MacAddress<'a> {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "{}:{}:{}:{}:{}:{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3], self.addr[4], self.addr[5]
            )
        }
    }
}

pub mod arp {
    use crate::net::mac::MacAddress;
    use byteorder::{ByteOrder, NativeEndian};

    pub struct Arp<'a> {
        data: &'a [u8],
    }

    impl<'a> Arp<'a> {
        pub fn htype(&self) -> u16 {
            NativeEndian::read_u16(&self.data[0..2])
        }

        pub fn ptype(&self) -> u16 {
            NativeEndian::read_u16(&self.data[2..4])
        }

        pub fn hlen(&self) -> u8 {
            self.data[4]
        }

        pub fn plen(&self) -> u8 {
            self.data[5]
        }

        pub fn oper(&self) -> u16 {
            NativeEndian::read_u16(&self.data[6..8])
        }

        pub fn sha(&self) -> MacAddress<'a> {
            MacAddress::new(&self.data[8..14])
        }

        // pub fn spa(&self) -> Ipv4Address<'a> {
        // }

        pub fn tha(&self) -> MacAddress<'a> {
            MacAddress::new(&self.data[18..24])
        }

        // pub fn tpa(&self) -> Ipv4Address<'a> {}
    }
}
