pub mod l2 {
    pub trait ArpHandler {
        fn handle_arp(&self, record: &crate::hw::pcap::PacketRecord) {}
    }

    pub trait Ipv4Handler {
        fn handle_ipv4(&self, record: &crate::hw::pcap::PacketRecord) {}
    }

    pub struct DefaultHandler {}

    impl DefaultHandler {
    }

    impl ArpHandler for DefaultHandler {}
    impl Ipv4Handler for DefaultHandler {}

    pub struct EthernetHandler<'a, Handler = DefaultHandler> {
        handler: &'a mut Handler,
    }

    impl<'a, Handler: ArpHandler + Ipv4Handler> EthernetHandler<'a, Handler> {
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
