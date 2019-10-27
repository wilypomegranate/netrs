pub mod l2 {
    use crate::net::ethernet::{EtherType};

    pub trait EthernetHandler {
        fn handle_arp(&self, _record: &crate::hw::pcap::PacketRecord) {}
        fn handle_ipv4(&self, _record: &crate::hw::pcap::PacketRecord) {}
    }

    pub struct DefaultHandler {}

    impl DefaultHandler {
    }

    impl EthernetHandler for DefaultHandler {}

    pub struct EthernetReceiver<'a, Handler = DefaultHandler> {
        handler: &'a mut Handler,
    }

    impl<'a, Handler: EthernetHandler> EthernetReceiver<'a, Handler> {
        pub fn new(handler: &'a mut Handler) -> Self {
            Self { handler }
        }

        pub fn handle(&self, record: &crate::hw::pcap::PacketRecord) {
            // TODO Parse ethernet frame from payload.

            // TODO Handle known ethertypes.

            // TODO Handle arp messages for arp table.
            self.handler.handle_arp(record);
            self.handler.handle_ipv4(record);
        }
    }
}
