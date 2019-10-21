pub mod ethernet {
    use byteorder::{ByteOrder, NativeEndian};

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
            }
            else {
                None
            }
        }
        pub fn ethertype(&self) -> u16 {
            // TODO Does not handle Q-in-Q vlan.
            // See https://en.wikipedia.org/wiki/IEEE_802.1ad
            // for more details.
            match self.vlan() {
                None => NativeEndian::read_u16(&self.data[20..22]),
                Some(_x) => NativeEndian::read_u16(&self.data[24..26])
            }
        }
    }
}
