use std::net::SocketAddr;

use crate::{
    header::{
        AuthAnswer, DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, OpCode,
        QueryResponse, RecursionAvailablity, RecursionDesired, ResponseCode, SectionCount,
        Truncation,
    },
    section::{Section, SectionGroup},
};

pub type PendingHeaderPacket = (SocketAddr, u16, OpCode, RecursionDesired);

#[derive(Debug, Clone)]
pub struct PendingPacket {
    addr_hdr: PendingHeaderPacket,
    rcode: ResponseCode,
    capacity: usize,
    qsection: Section,
    a_section_groups: Vec<SectionGroup>,
}

#[derive(Debug, Clone)]
pub struct UdpPacket {
    raw: Vec<u8>,
}

impl UdpPacket {
    pub fn new(
        addr_hdr: (SocketAddr, DnsHeader),
        qsection: Section,
        a_section_groups: Vec<SectionGroup>,
    ) -> (Self, SocketAddr) {
        let (addr, hdr) = (addr_hdr.0, addr_hdr.1);
        let mut raw = <[u8; 12]>::from(hdr).to_vec();
        raw.extend(Vec::<u8>::from(qsection));
        a_section_groups.into_iter().for_each(|group| {
            raw.extend(Vec::<u8>::try_from(group).expect("Conversion failed for some reason..."));
        });
        (UdpPacket { raw }, addr)
    }
}

impl From<UdpPacket> for Vec<u8> {
    fn from(value: UdpPacket) -> Self {
        value.raw
    }
}

impl PendingPacket {
    pub fn new(addr_hdr: PendingHeaderPacket, capacity: usize, qsection: Section) -> Self {
        let rcode = match addr_hdr.2 {
            OpCode::Query => ResponseCode::None,
            _ => ResponseCode::NotImplemented,
        };
        PendingPacket {
            addr_hdr,
            rcode,
            capacity,
            qsection,
            a_section_groups: Vec::new(),
        }
    }

    pub fn into_packet(self) -> (UdpPacket, SocketAddr) {
        let (socket_addr, txid, opcode, rd) = self.addr_hdr;
        let rcode = self.rcode;
        let qsection = self.qsection;
        let a_section_groups = self.a_section_groups;
        let hdr_sr_fh = HeaderSecondRowFirstHalf::new(
            QueryResponse::Response,
            opcode,
            AuthAnswer::NotAuthoritative,
            Truncation::NotTruncated,
            rd,
        );
        let hdr_sr_sh =
            HeaderSecondRowSecondHalf::new(RecursionAvailablity::NoRecursionAvailable, 0, rcode)
                .expect("Should work anyways");
        let counts = SectionCount::new(
            qsection.groups.len() as u16,
            a_section_groups.len() as u16,
            0,
            0,
        );
        let hdr = DnsHeader::new(txid, hdr_sr_fh, hdr_sr_sh, counts);
        UdpPacket::new((socket_addr, hdr), qsection, a_section_groups)
    }

    pub fn insert_section_group(&mut self, section_group: SectionGroup) -> bool {
        self.a_section_groups.push(section_group);
        self.a_section_groups.len() == self.capacity
    }
}
