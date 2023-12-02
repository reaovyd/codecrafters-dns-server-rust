use std::str;

use crate::{
    error::{ParseError, UdpBufferError},
    header::{DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, SectionCount},
    section::{Class, Section, SectionGroup, Type},
};
pub const MAX_UDP_PACKET_SIZE: usize = 512;
pub const DNS_HEADER_SIZE: usize = 12;

#[derive(Debug)]
pub struct UdpBuffer {
    inner: [u8; MAX_UDP_PACKET_SIZE],
    pos: usize,
}

use anyhow;

impl UdpBuffer {
    pub fn new(inner: [u8; MAX_UDP_PACKET_SIZE]) -> Self {
        UdpBuffer { inner, pos: 0 }
    }

    fn unpack_domain(&mut self, is_asection: bool) -> anyhow::Result<SectionGroup> {
        let mut jumps = 0u8;
        let mut reset_pos = None;
        let mut domain = Vec::new();

        loop {
            let len = self.peek()?;
            if len == 0 {
                if jumps > 0 {
                    self.seek(reset_pos.ok_or(ParseError::JumpError)?)?;
                } else {
                    self.read()?;
                }
                break;
            }
            if len & 0xC0 == 0xC0 {
                jumps += 1;
                let len = self.get_u16()?;
                // so it doesn't reset_pos again
                if reset_pos.is_none() {
                    reset_pos = Some(self.pos);
                }
                self.seek(usize::try_from(len & 0b0011_1111_1111_1111)?)?;
            } else {
                let len = usize::try_from(self.get_u8()?)?;
                let label = str::from_utf8(
                    self.inner
                        .get(self.pos..(self.pos + len))
                        .ok_or(ParseError::SectionError)?,
                )?
                .to_owned();
                self.seek(self.pos + len)?;
                domain.push(label);
            }
        }
        let t_type = Type::try_from(self.get_u16()?)?;
        let class = Class::try_from(self.get_u16()?)?;
        Ok(SectionGroup::new(
            domain,
            t_type,
            class,
            match is_asection {
                true => {
                    let (ttl, length) = (self.get_u32()?, self.get_u16()?);
                    let end = self.pos + usize::try_from(length)?;
                    let data = self
                        .inner
                        .get(self.pos..end)
                        .ok_or(ParseError::SectionError)?
                        .to_vec();

                    self.seek(end)?;
                    Some((ttl, length, data))
                }
                false => None,
            },
        ))
    }

    fn unpack_section(&mut self, count: u16, is_asection: bool) -> anyhow::Result<Section> {
        let start_pos = self.pos;
        let mut groups = Vec::new();
        for _ in 0..count {
            groups.push(self.unpack_domain(is_asection)?);
        }
        let end_pos = self.pos;
        Ok(Section::new(
            groups,
            self.inner
                .get(start_pos..end_pos)
                .ok_or(ParseError::SectionError)?
                .to_vec(),
        ))
    }

    pub fn unpack(mut self) -> anyhow::Result<(DnsHeader, [Option<Section>; 4])> {
        let hdr = self.unpack_dns_header()?;
        let counts = hdr.counts();
        let (qdcount, ancount, nscount, arcount) = (
            counts.qdcount(),
            counts.ancount(),
            counts.nscount(),
            counts.arcount(),
        );
        let mut sections = [None, None, None, None];
        if qdcount > 0 {
            sections[0] = Some(self.unpack_section(qdcount, false)?);
        }

        println!("{:?}", nscount);
        if ancount > 0 {
            sections[1] = Some(self.unpack_section(ancount, true)?);
        }

        if nscount > 0 {
            sections[2] = Some(self.unpack_section(nscount, true)?);
        }

        if arcount > 0 {
            sections[3] = Some(self.unpack_section(arcount, true)?);
        }
        Ok((hdr, sections))
    }

    fn unpack_dns_header(&mut self) -> anyhow::Result<DnsHeader> {
        let txid = self.get_u16()?;
        let first_half = self.get_u8()?;
        let second_half = self.get_u8()?;
        let qdcount = self.get_u16()?;
        let ancount = self.get_u16()?;
        let nscount = self.get_u16()?;
        let arcount = self.get_u16()?;
        Ok(DnsHeader::new(
            txid,
            HeaderSecondRowFirstHalf::try_from(first_half)?,
            HeaderSecondRowSecondHalf::try_from(second_half)?,
            SectionCount::new(qdcount, ancount, nscount, arcount),
        ))
    }

    fn read(&mut self) -> Result<u8, UdpBufferError> {
        if self.pos >= MAX_UDP_PACKET_SIZE {
            Err(UdpBufferError::EndOfBuffer)
        } else {
            let res = self.inner[self.pos];
            self.pos += 1;
            Ok(res)
        }
    }

    fn seek(&mut self, index: usize) -> Result<(), UdpBufferError> {
        if index >= MAX_UDP_PACKET_SIZE {
            Err(UdpBufferError::Seek { index })
        } else {
            self.pos = index;
            Ok(())
        }
    }

    #[allow(dead_code)]
    fn has_remaining(&mut self) -> bool {
        self.pos >= MAX_UDP_PACKET_SIZE
    }

    fn peek(&self) -> Result<u8, UdpBufferError> {
        if self.pos >= MAX_UDP_PACKET_SIZE {
            Err(UdpBufferError::EndOfBuffer)
        } else {
            Ok(self.inner[self.pos])
        }
    }

    fn get_u8(&mut self) -> Result<u8, UdpBufferError> {
        self.read()
    }

    fn get_u16(&mut self) -> Result<u16, UdpBufferError> {
        let mut res = (self.read()? as u16) << 8;
        res |= self.read()? as u16;
        Ok(res)
    }

    fn get_u32(&mut self) -> Result<u32, UdpBufferError> {
        let mut res = (self.get_u16()? as u32) << 8;
        res |= self.get_u16()? as u32;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use crate::header::{
        AuthAnswer, DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, OpCode,
        QueryResponse, RecursionAvailablity, RecursionDesired, ResponseCode, SectionCount,
        Truncation,
    };

    use super::UdpBuffer;

    #[test]
    fn test_parse_domain_2() {
        let buf = [
            250, 44, 1, 0, 0, 2, 0, 0, 0, 0, 0, 0, 3, 97, 98, 99, 17, 108, 111, 110, 103, 97, 115,
            115, 100, 111, 109, 97, 105, 110, 110, 97, 109, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3,
            100, 101, 102, 192, 16, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0u8,
        ];
        let buf = UdpBuffer::new(buf);
        let _hdr = buf.unpack().unwrap();
    }

    #[test]
    #[allow(clippy::char_lit_as_u8)]
    fn test_parse_domain() {
        let mut buf = [0u8; 512];
        [32, 75, 1, 0, 0, 5, 0, 0, 0, 0, 0, 0]
            .into_iter()
            .enumerate()
            .for_each(|(idx, elem)| {
                buf[idx] = elem;
            });
        [
            6, 'g' as u8, 'o' as u8, 'o' as u8, 'g' as u8, 'l' as u8, 'e' as u8, 3, 'c' as u8,
            'o' as u8, 'm' as u8, 0, 0, 1, 0, 1, 6, 'p' as u8, 'h' as u8, 'o' as u8, 't' as u8,
            'o' as u8, 's' as u8, 0xC0, 12, 0, 1, 0, 1, 6, 'i' as u8, 'm' as u8, 'a' as u8,
            'g' as u8, 'e' as u8, 's' as u8, 0xC0, 12, 0, 1, 0, 1, 3, 'd' as u8, 'b' as u8,
            '1' as u8, 0xC0, 28, 0, 1, 0, 1, 3, 'd' as u8, 'b' as u8, '2' as u8, 0xC0, 28, 0, 1, 0,
            1,
        ]
        .into_iter()
        .enumerate()
        .for_each(|(idx, elem)| {
            buf[12 + idx] = elem;
        });
        let mut buf = UdpBuffer::new(buf);
        let _hdr = buf.unpack_dns_header().unwrap();
        // buf.unpack_section(hdr.counts().qdcount()).unwrap();
        // buf[12] = 6;
        // "google"
        //     .as_bytes()
        //     .iter()
        //     .enumerate()
        //     .for_each(|(idx, elem)| {
        //         buf[13 + idx] = elem.to_owned();
        //     });
        // buf[19] = 3;
        // "com".as_bytes().iter().enumerate().for_each(|(idx, elem)| {
        //     buf[19 + idx] = elem.to_owned();
        // });
    }

    #[test]
    fn test_parse_header_udp_buffer() {
        let mut buf = [0u8; 512];
        let buf2 = [127u8, 59, 131, 160, 0, 1, 0, 0, 0, 0, 0, 0];
        buf2.into_iter().enumerate().for_each(|(idx, byte)| {
            buf[idx] = byte;
        });
        let hdr_actual = UdpBuffer::new(buf).unpack_dns_header().unwrap();
        let hdr = DnsHeader::new(
            0x7f3b,
            HeaderSecondRowFirstHalf::new(
                QueryResponse::Response,
                OpCode::Query,
                AuthAnswer::NotAuthoritative,
                Truncation::Truncated,
                RecursionDesired::IWantRecursion,
            ),
            HeaderSecondRowSecondHalf::new(
                RecursionAvailablity::RecursionAvailable,
                2,
                ResponseCode::None,
            )
            .unwrap(),
            SectionCount::new(1, 0, 0, 0),
        );
        assert_eq!(hdr_actual, hdr);
        assert_eq!(<[u8; 12]>::from(hdr_actual), buf2);
    }
}
