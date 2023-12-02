use std::collections::BTreeMap;

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

    fn unpack_asection(&mut self, count: u16) -> anyhow::Result<Section> {
        let mut cache = BTreeMap::new();
        let start_of_section = self.pos;
        for _ in 0..count {
            let st = self.pos as u16;
            let domain = self.unpack_domain(&mut cache)?;
            let t_type = Type::try_from(self.get_u16()?)?;
            let class = Class::try_from(self.get_u16()?)?;
            let ttl = self.get_u32()?;
            let length = self.get_u16()?;
            let mut data_section = Vec::new();
            for _ in 0..length {
                data_section.push(self.get_u8()?);
            }
            cache.insert(
                st,
                SectionGroup::new(domain, t_type, class, Some((ttl, length, data_section))),
            );
        }
        let end_of_section = self.pos;
        Ok(Section::new(
            cache.into_values().collect(),
            self.inner[start_of_section..end_of_section].to_vec(),
        ))
    }

    fn unpack_qsection(&mut self, count: u16) -> anyhow::Result<Section> {
        let mut cache = BTreeMap::new();
        let start_of_section = self.pos;
        for _ in 0..count {
            let st = self.pos as u16;
            let domain = self.unpack_domain(&mut cache)?;
            let t_type = Type::try_from(self.get_u16()?)?;
            let class = Class::try_from(self.get_u16()?)?;
            cache.insert(st, SectionGroup::new(domain, t_type, class, None));
        }
        let end_of_section = self.pos;
        Ok(Section::new(
            cache.into_values().collect(),
            self.inner[start_of_section..end_of_section].to_vec(),
        ))
    }

    pub fn unpack(mut self) -> anyhow::Result<(DnsHeader, [Option<Section>; 4])> {
        let dns_header = self.unpack_dns_header()?;
        let (qdcount, ancount, nscount, arcount) = (
            dns_header.counts().qdcount(),
            dns_header.counts().ancount(),
            dns_header.counts().nscount(),
            dns_header.counts().arcount(),
        );
        println!("1. PARSING QSECTION HELLO WORLD!!!!");
        let mut sections: [Option<Section>; 4] = [None, None, None, None];
        if qdcount > 0 {
            sections[0] = match self.unpack_qsection(qdcount) {
                Ok(ans) => Some(ans),
                Err(_) => {
                    eprintln!("{:?}", self.inner);
                    None
                }
            }
        }

        if ancount > 0 {
            sections[1] = Some(self.unpack_asection(ancount)?);
        }

        if nscount > 0 {
            sections[2] = Some(self.unpack_asection(nscount)?);
        }

        if arcount > 0 {
            sections[3] = Some(self.unpack_asection(arcount)?);
        }
        Ok((dns_header, sections))
    }

    fn unpack_domain(
        &mut self,
        cache: &mut BTreeMap<u16, SectionGroup>,
    ) -> anyhow::Result<Vec<String>> {
        let mut res: Vec<String> = Vec::new();
        loop {
            let mut len = self.peek()?;
            if len == 0 {
                self.read()?;
                break;
            }
            if len & 0xC0 == 0xC0 {
                let len = self.get_u16()? & 0b0011_1111_1111_1111;
                let cached = cache.get(&len).ok_or(ParseError::SectionError)?;
                for lbl in cached.domain().iter() {
                    res.push(lbl.clone());
                }
                break;
            } else {
                self.seek(self.pos + 1)?;
                let mut s = String::new();
                while len != 0 {
                    let byte = char::try_from(self.get_u8()?)?;
                    if !byte.is_alphanumeric() && byte != '-' {
                        return Err(anyhow::anyhow!(ParseError::SectionError));
                    } else {
                        s.push(byte);
                    }

                    len -= 1;
                }

                res.push(s);
            }
        }
        Ok(res)
    }

    // fn unpack_section(&mut self, count: u16) -> anyhow::Result<Section> {
    //     let mut cache = BTreeMap::new();
    //     let start_of_section = self.pos;
    //     for _ in 0..count {
    //         let st = self.pos as u16;
    //         let domain = self.unpack_domain(&mut cache)?;
    //         let t_type = Type::try_from(self.get_u16()?)?;
    //         let class = Class::try_from(self.get_u16()?)?;
    //         cache.insert(st, SectionGroup::new(domain, t_type, class));
    //     }
    //     let end_of_section = self.pos;
    //     Ok(Section::new(
    //         cache.into_values().collect(),
    //         self.inner[start_of_section..end_of_section].to_vec(),
    //     ))
    // }

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
