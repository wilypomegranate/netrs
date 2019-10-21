pub mod l2 {
    pub trait Layer2Handler {
        fn handle(&self, record: &crate::hw::pcap::PacketRecord);
    }

    pub struct DefaultHandler {}

    impl DefaultHandler {
        pub fn handle(&self, _record: &crate::hw::pcap::PacketRecord) {}
    }

    pub struct EthernetHandler<'a, ArpHandler = DefaultHandler, Ipv4Handler = DefaultHandler> {
        arp_handler: &'a mut ArpHandler,
        ipv4_handler: &'a mut Ipv4Handler,
    }

    impl<'a, ArpHandler: Layer2Handler, Ipv4Handler: Layer2Handler>
        EthernetHandler<'a, ArpHandler, Ipv4Handler>
    {
        fn new(arp_handler: &'a mut ArpHandler, ipv4_handler: &'a mut Ipv4Handler) -> Self {
            Self {
                arp_handler,
                ipv4_handler,
            }
        }

        fn handle(&self, record: &crate::hw::pcap::PacketRecord) {
            // TODO Parse ethernet frame from payload.

            // TODO Handle known ethertypes.

            // TODO Handle arp messages for arp table.
            self.arp_handler.handle(record);
        }
    }
}
