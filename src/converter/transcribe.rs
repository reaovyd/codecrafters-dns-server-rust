use std::{cell::RefCell, collections::HashMap, net::SocketAddr, rc::Rc};

use crate::section::SectionGroup;

use super::packet::{PendingPacket, UdpPacket};

#[derive(Debug, Default)]
pub struct Transcriber {
    txid_to_pending: HashMap<u16, Rc<RefCell<PendingPacket>>>,
    txid: u16,
}

impl Transcriber {
    pub fn insert(&mut self, pending_packet: Rc<RefCell<PendingPacket>>) {
        if self.txid == u16::MAX {
            self.txid = 0;
        }
        self.txid_to_pending.insert(self.txid, pending_packet);
        self.txid += 1;
    }

    pub fn txid(&self) -> u16 {
        self.txid
    }

    pub fn receive_and_delete(
        &mut self,
        txid: u16,
        section_group: SectionGroup,
    ) -> Option<(UdpPacket, SocketAddr)> {
        let pending_packet = self
            .txid_to_pending
            .remove(&txid)
            .expect("should've been inserted since we're single threaded?");
        let full = pending_packet
            .borrow_mut()
            .insert_section_group(section_group);
        if full {
            let opt = Rc::into_inner(pending_packet)
                .expect("Somehow there was another strong reference?");
            let pending_packet = opt.into_inner();
            Some(pending_packet.into_packet())
        } else {
            None
        }
        // if pending_packet.get_mut().insert_section_group(section_group) {
        //     Some(pending_packet.into_inner().into_packet())
        // } else {
        //     None
        // }
    }
}
