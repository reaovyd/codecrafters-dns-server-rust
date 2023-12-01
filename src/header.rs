use crate::error::ParseError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    txid: u16,
    hdr_sr_fh: HeaderSecondRowFirstHalf,
    hdr_sr_sh: HeaderSecondRowSecondHalf,
    counts: SectionCount,
}

impl DnsHeader {
    pub fn new(
        txid: u16,
        hdr_sr_fh: HeaderSecondRowFirstHalf,
        hdr_sr_sh: HeaderSecondRowSecondHalf,
        counts: SectionCount,
    ) -> Self {
        DnsHeader {
            txid,
            hdr_sr_fh,
            hdr_sr_sh,
            counts,
        }
    }

    pub fn txid(&self) -> u16 {
        self.txid
    }

    pub fn header_first_half(&self) -> &HeaderSecondRowFirstHalf {
        &self.hdr_sr_fh
    }

    pub fn header_second_half(&self) -> &HeaderSecondRowSecondHalf {
        &self.hdr_sr_sh
    }

    pub fn counts(&self) -> &SectionCount {
        &self.counts
    }
}

impl From<DnsHeader> for [u8; 12] {
    fn from(value: DnsHeader) -> Self {
        let mut res = [0u8; 12];
        res[1] = (value.txid & 0xFF) as u8;
        res[0] = ((value.txid >> 8) & 0xFF) as u8;
        res[2] = u8::from(value.hdr_sr_fh);
        res[3] = u8::from(value.hdr_sr_sh);
        <[u8; 8]>::from(value.counts)
            .into_iter()
            .enumerate()
            .for_each(|(idx, byte)| {
                res[4 + idx] = byte;
            });
        res
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSecondRowSecondHalf {
    ra: RecursionAvailablity,
    reserved: u8,
    rcode: ResponseCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSecondRowFirstHalf {
    qr: QueryResponse,
    opcode: OpCode,
    aa: AuthAnswer,
    tc: Truncation,
    rd: RecursionDesired,
}

impl HeaderSecondRowSecondHalf {
    pub fn new(
        ra: RecursionAvailablity,
        reserved: u8,
        rcode: ResponseCode,
    ) -> Result<Self, ParseError> {
        if reserved >= 8 {
            Err(ParseError::OverflowError { found: reserved })
        } else {
            Ok(Self {
                ra,
                reserved,
                rcode,
            })
        }
    }

    pub fn ra(&self) -> &RecursionAvailablity {
        &self.ra
    }

    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    pub fn rcode(&self) -> &ResponseCode {
        &self.rcode
    }
}

impl From<HeaderSecondRowSecondHalf> for u8 {
    fn from(value: HeaderSecondRowSecondHalf) -> Self {
        let ra = (value.ra as u8) << 7;
        let reserved = value.reserved << 4;
        let rcode = value.rcode as u8;
        ra | reserved | rcode
    }
}

impl TryFrom<u8> for HeaderSecondRowSecondHalf {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let ra = (value & 0b1000_0000) >> 7;
        let reserved = (value & 0b0111_0000) >> 4;
        let rcode = value & 0b0000_1111;
        let res = HeaderSecondRowSecondHalf::new(
            RecursionAvailablity::try_from(ra)?,
            reserved,
            ResponseCode::try_from(rcode)?,
        )?;
        Ok(res)
    }
}

impl HeaderSecondRowFirstHalf {
    pub fn new(
        qr: QueryResponse,
        opcode: OpCode,
        aa: AuthAnswer,
        tc: Truncation,
        rd: RecursionDesired,
    ) -> Self {
        Self {
            qr,
            opcode,
            aa,
            tc,
            rd,
        }
    }

    pub fn qr(&self) -> &QueryResponse {
        &self.qr
    }

    pub fn opcode(&self) -> &OpCode {
        &self.opcode
    }

    pub fn aa(&self) -> &AuthAnswer {
        &self.aa
    }

    pub fn tc(&self) -> &Truncation {
        &self.tc
    }

    pub fn rd(&self) -> &RecursionDesired {
        &self.rd
    }
}

impl From<HeaderSecondRowFirstHalf> for u8 {
    fn from(value: HeaderSecondRowFirstHalf) -> Self {
        let qr = value.qr as u8;
        let opcode = value.opcode as u8;
        let aa = value.aa as u8;
        let tc = value.tc as u8;
        let rd = value.rd as u8;
        qr << 7 | opcode << 3 | aa << 2 | tc << 1 | rd
    }
}

impl TryFrom<u8> for HeaderSecondRowFirstHalf {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let qr = (value & 0b1000_0000) >> 7;
        let opcode = (value & 0b0111_1000) >> 3;
        let aa = (value & 0b0000_0100) >> 2;
        let tc = (value & 0b0000_0010) >> 1;
        let rd = value & 0b0000_0001;

        Ok(HeaderSecondRowFirstHalf::new(
            QueryResponse::try_from(qr)?,
            OpCode::try_from(opcode)?,
            AuthAnswer::try_from(aa)?,
            Truncation::try_from(tc)?,
            RecursionDesired::try_from(rd)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionCount {
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl SectionCount {
    pub fn new(qdcount: u16, ancount: u16, nscount: u16, arcount: u16) -> Self {
        Self {
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }

    pub fn qdcount(&self) -> u16 {
        self.qdcount
    }

    pub fn ancount(&self) -> u16 {
        self.ancount
    }

    pub fn nscount(&self) -> u16 {
        self.nscount
    }

    pub fn arcount(&self) -> u16 {
        self.arcount
    }
}

impl From<SectionCount> for [u8; 8] {
    fn from(value: SectionCount) -> Self {
        let SectionCount {
            qdcount,
            ancount,
            nscount,
            arcount,
        } = value;
        let mut res = [0u8; 8];
        [qdcount, ancount, nscount, arcount]
            .into_iter()
            .enumerate()
            .for_each(|(idx, val)| {
                let rht = (val & 0xFF) as u8;
                let lft = ((val >> 8) & 0xFF) as u8;
                res[2 * idx] = lft;
                res[2 * idx + 1] = rht;
            });
        res
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResponse {
    Query = 0,
    Response = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthAnswer {
    NotAuthoritative = 0,
    Authoritative = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Truncation {
    NotTruncated = 0,
    Truncated = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursionDesired {
    DontWantRecursion = 0,
    IWantRecursion = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecursionAvailablity {
    NoRecursionAvailable = 0,
    RecursionAvailable = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpCode {
    Query = 0,
    IQuery = 1,
    Status = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseCode {
    None = 0,
    Format = 1,
    ServerFailure = 2,
    Name = 3,
    NotImplemented = 4,
    Refused = 5,
}

impl TryFrom<u8> for ResponseCode {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::Format),
            2 => Ok(Self::ServerFailure),
            3 => Ok(Self::Name),
            4 => Ok(Self::NotImplemented),
            5 => Ok(Self::Refused),
            _ => {
                if (6..=15).contains(&value) {
                    Err(ParseError::UnimplementedError)
                } else {
                    Err(ParseError::ConversionError)
                }
            }
        }
    }
}

impl TryFrom<u8> for OpCode {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Query),
            1 => Ok(Self::IQuery),
            2 => Ok(Self::Status),
            _ => {
                if (3..=15).contains(&value) {
                    Err(ParseError::UnimplementedError)
                } else {
                    Err(ParseError::ConversionError)
                }
            }
        }
    }
}

impl TryFrom<u8> for RecursionAvailablity {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoRecursionAvailable),
            1 => Ok(Self::RecursionAvailable),
            _ => Err(ParseError::ConversionError),
        }
    }
}

impl TryFrom<u8> for RecursionDesired {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RecursionDesired::DontWantRecursion),
            1 => Ok(RecursionDesired::IWantRecursion),
            _ => Err(ParseError::ConversionError),
        }
    }
}

impl TryFrom<u8> for QueryResponse {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(QueryResponse::Query),
            1 => Ok(QueryResponse::Response),
            _ => Err(ParseError::ConversionError),
        }
    }
}

impl TryFrom<u8> for AuthAnswer {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(AuthAnswer::NotAuthoritative),
            1 => Ok(AuthAnswer::Authoritative),
            _ => Err(ParseError::ConversionError),
        }
    }
}

impl TryFrom<u8> for Truncation {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Truncation::NotTruncated),
            1 => Ok(Truncation::Truncated),
            _ => Err(ParseError::ConversionError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, SectionCount, Truncation,
    };
    use anyhow::Result;

    #[test]
    fn test_conversion() {
        let a = Truncation::NotTruncated as u8;
        let trunc = Truncation::try_from(a).unwrap();
        assert_eq!(Truncation::NotTruncated, trunc);
    }

    #[test]
    fn test_conversion_section_count() {
        let a = <[u8; 8]>::from(SectionCount::new(0x7FAB, 0x33AB, 0xFFFF, 0xFFFF));
        assert_eq!(a, [0x7F, 0xAB, 0x33, 0xAB, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    #[test]
    fn test_dns_header_conversion() -> Result<()> {
        let hdr = DnsHeader::new(
            0x7f3b,
            HeaderSecondRowFirstHalf::new(
                super::QueryResponse::Query,
                super::OpCode::Query,
                super::AuthAnswer::NotAuthoritative,
                Truncation::Truncated,
                super::RecursionDesired::IWantRecursion,
            ),
            HeaderSecondRowSecondHalf::new(
                super::RecursionAvailablity::RecursionAvailable,
                2,
                super::ResponseCode::None,
            )?,
            SectionCount::new(1, 0, 0, 0),
        );
        let hdr = <[u8; 12]>::from(hdr);
        assert_eq!(
            hdr,
            [
                0x7f,
                0x3b,
                0b00000011,
                0b1010_0000,
                0x0,
                0x1,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0
            ]
        );
        Ok(())
    }
}
