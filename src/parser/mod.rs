use self::header_types::{
    AuthAnswer, OpCode, QrIndicator, RecursionDesired, RecursionStatus, ResponseCode, Truncation,
};
use anyhow::anyhow;
pub mod header_types;
pub mod section;

#[derive(Debug, PartialEq, Clone)]
pub struct DnsHeader {
    id: u16,
    qr: QrIndicator,
    opcode: OpCode,
    aa: AuthAnswer,
    tc: Truncation,
    rd: RecursionDesired,
    rs: RecursionStatus,
    reserved: u8,
    rcode: ResponseCode,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DnsHeader {
    #![allow(clippy::too_many_arguments)]
    pub fn new(
        id: u16,
        qr: QrIndicator,
        opcode: OpCode,
        aa: AuthAnswer,
        tc: Truncation,
        rd: RecursionDesired,
        rs: RecursionStatus,
        reserved: u8,
        rcode: ResponseCode,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Self {
        Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            rs,
            reserved,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    pub fn id(&self) -> &u16 {
        &self.id
    }

    pub fn qr(&self) -> &QrIndicator {
        &self.qr
    }

    pub fn opcode(&self) -> &OpCode {
        &self.opcode
    }

    pub fn auth_answer(&self) -> &AuthAnswer {
        &self.aa
    }

    pub fn truncation(&self) -> &Truncation {
        &self.tc
    }

    pub fn recursion_desired(&self) -> &RecursionDesired {
        &self.rd
    }

    pub fn recursion_status(&self) -> &RecursionStatus {
        &self.rs
    }

    pub fn reserved(&self) -> &u8 {
        &self.reserved
    }

    pub fn rcode(&self) -> &ResponseCode {
        &self.rcode
    }

    pub fn qdcount(&self) -> &u16 {
        &self.qdcount
    }

    pub fn ancount(&self) -> &u16 {
        &self.ancount
    }

    pub fn nscount(&self) -> &u16 {
        &self.nscount
    }

    pub fn arcount(&self) -> &u16 {
        &self.arcount
    }
}

impl TryFrom<&[u8]> for DnsHeader {
    type Error = anyhow::Error;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 12 {
            Err(anyhow!("Not enough bytes to create a header"))
        } else {
            let id = {
                let id = &value[0..2];
                ((id[0] as u16) << 8) | (id[1] as u16)
            };
            let (qr, opcode, aa, tc, rd, rs, reserved, rcode) = {
                let qoatrrrr = &value[2..4];
                let first = qoatrrrr[0];
                let second = qoatrrrr[1];

                let rd = RecursionDesired::try_from(first & 0b00000001)?;
                let tc = Truncation::try_from((first & 0b00000010) >> 1)?;
                let aa = AuthAnswer::try_from((first & 0b00000100) >> 2)?;
                let opcode = OpCode::try_from((first & 0b01111000) >> 3)?;
                let qr = QrIndicator::try_from((first & 0b10000000) >> 7)?;

                let rcode = ResponseCode::try_from(second & 0b00001111)?;
                let reserved = (second & 0b01110000) >> 4;
                let ra = RecursionStatus::try_from((second & 0b10000000) >> 7)?;

                (qr, opcode, aa, tc, rd, ra, reserved, rcode)
            };

            let (qdcount, ancount, nscount, arcount) = {
                let counts = [&value[4..6], &value[6..8], &value[8..10], &value[10..12]]
                    .map(|val| ((val[0] as u16) << 8) | (val[1] as u16));
                (counts[0], counts[1], counts[2], counts[3])
            };
            Ok(DnsHeader {
                id,
                qr,
                opcode,
                aa,
                tc,
                rd,
                rs,
                reserved,
                rcode,
                qdcount,
                ancount,
                nscount,
                arcount,
            })
        }
    }
}

impl From<DnsHeader> for [u8; 12] {
    fn from(value: DnsHeader) -> Self {
        let mut res = [0u8; 12];
        res[11] = (value.arcount & 0xFF) as u8;
        res[10] = ((value.arcount >> 8) & 0xFF) as u8;

        res[9] = (value.nscount & 0xFF) as u8;
        res[8] = ((value.nscount >> 8) & 0xFF) as u8;

        res[7] = (value.ancount & 0xFF) as u8;
        res[6] = ((value.ancount >> 8) & 0xFF) as u8;

        res[5] = (value.qdcount & 0xFF) as u8;
        res[4] = ((value.qdcount >> 8) & 0xFF) as u8;

        res[3] = (u8::from(value.rcode))
            | ((value.reserved << 4) & 0b01110000)
            | ((u8::from(value.rs) << 7) & 0b10000000);

        res[2] = (u8::from(value.rd))
            | ((u8::from(value.tc) << 1) & 0b00000010)
            | ((u8::from(value.aa) << 2) & 0b00000100)
            | ((u8::from(value.opcode) << 3) & 0b01111000)
            | ((u8::from(value.qr) << 7) & 0b10000000);

        res[1] = (value.id & 0xFF) as u8;
        res[0] = ((value.id >> 8) & 0xFF) as u8;
        res
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::header_types::*;
    use crate::DnsHeader;

    #[test]
    pub fn test_header_id_is_correct_number() {
        let hdr: [u8; 12] = [0x7F, 0xAC, 0x97, 0x80, 0, 0, 0, 0, 0, 0, 0, 0];
        let hdr = DnsHeader::try_from(&hdr[..]).unwrap();
        assert_eq!(0x7FAC, hdr.id);
    }

    #[test]
    pub fn test_header_second_row_is_correct_bits() {
        let hdr = [
            0x7F, 0xAC, 0x97, 0x80, 0x54, 0x12, 0x34, 0x64, 0x55, 0x20, 0x01, 0x00,
        ];
        let hdr = DnsHeader::try_from(&hdr[..]).unwrap();
        assert_eq!(QrIndicator::Reply, hdr.qr);
        assert_eq!(OpCode::Status, hdr.opcode);
        assert_eq!(AuthAnswer::Authoritative, hdr.aa);
        assert_eq!(Truncation::Truncated, hdr.tc);
        assert_eq!(RecursionDesired::Recursion, hdr.rd);
        assert_eq!(RecursionStatus::Available, hdr.rs);
        assert_eq!(0, hdr.reserved);
        assert_eq!(ResponseCode::NoError, hdr.rcode);
    }

    #[test]
    pub fn test_header_counts() {
        let hdr = [
            0x7F, 0xAC, 0x97, 0x80, 0x54, 0x12, 0x34, 0x64, 0x55, 0x20, 0x01, 0x00,
        ];
        let hdr = DnsHeader::try_from(&hdr[..]).unwrap();

        assert_eq!(0x5412, hdr.qdcount);
        assert_eq!(0x3464, hdr.ancount);
        assert_eq!(0x5520, hdr.nscount);
        assert_eq!(0x0100, hdr.arcount);
    }

    #[test]
    pub fn header_same() {
        let actual = [
            0x7F, 0xAC, 0x97, 0x80, 0x54, 0x12, 0x34, 0x64, 0x55, 0x20, 0x01, 0x00,
        ];
        let hdr = DnsHeader::try_from(&actual[..]).unwrap();
        let bytes = <[u8; 12]>::from(hdr);
        assert_eq!(actual, bytes);
    }

    #[test]
    pub fn create_header() {}
}
