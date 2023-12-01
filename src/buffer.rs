use std::collections::HashMap;

use crate::{
    error::{ParseError, UdpBufferError},
    header::{DnsHeader, HeaderSecondRowFirstHalf, HeaderSecondRowSecondHalf, SectionCount},
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

    pub fn read_asection(&self) -> anyhow::Result<()> {
        todo!()
    }

    pub fn read_qsection(&self) -> anyhow::Result<()> {
        todo!()
    }

    // fn is_pointer_byte(&self) -> anyhow::Result<bool> {
    //     Ok(self.peek()? & 0xC0 == 0xC0)
    // }

    // fn unpack_pointer_domain(&mut self) -> anyhow::Result<()> {
    //     if self.is_pointer_byte()? {
    //         let offset = self.get_u16()? as usize;
    //         self.seek(offset)?;
    //         Ok(())
    //     } else {
    //         Ok(())
    //     }
    // }
    fn parse_domain(
        &mut self,
        cache: &mut HashMap<u16, Vec<String>>,
    ) -> anyhow::Result<Vec<String>> {
        let mut res: Vec<String> = Vec::new();
        loop {
            let mut len = self.peek()?;
            if len & 0x3c == 0x3c {
                let len = self.get_u16()? & 0b0011_1111_1111_1111;
                let cached = cache.get(&len).ok_or(ParseError::SectionError)?;
                for lbl in cached {
                    res.push(lbl.clone())
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
            }
        }
        Ok(res)
    }

    pub fn read_section(&mut self, count: u16) -> anyhow::Result<()> {
        let mut cache = HashMap::new();
        for _ in 0..count {
            let st = self.pos as u16;
            let domain = self.parse_domain(&mut cache)?;
            let _type_class = self.get_u16()?;
            cache.insert(st, domain);
        }
        println!("{:?}", cache);
        Ok(())
        // loop {
        //     if !self.has_remaining() || qdcount == 0 {
        //         break;
        //     }
        //     let len = self.get_u8()?;
        //     if len & 0xC0 == 0xC0 {
        //         let len = len & 0x3F;
        //         let next_byte = self.get_u8()?;
        //         let left_off_pos = self.pos;
        //         let seek_pos = ((len as u16) << 8) | next_byte as u16;
        //         self.seek(seek_pos as usize)?;

        //     } else {
        //     }
        //     qdcount -= 1;
        // }
        // if qdcount + ancount + nscount + arcount != 0 {
        //     Err(anyhow::anyhow!(ParseError::SectionError))
        // } else {
        //     Ok(())
        // }
    }

    pub fn unpack_dns_header(&mut self) -> anyhow::Result<DnsHeader> {
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

    pub fn seek(&mut self, index: usize) -> Result<(), UdpBufferError> {
        if index >= MAX_UDP_PACKET_SIZE {
            Err(UdpBufferError::Seek { index })
        } else {
            self.pos = index;
            Ok(())
        }
    }

    pub fn has_remaining(&mut self) -> bool {
        self.pos >= MAX_UDP_PACKET_SIZE
    }

    pub fn peek(&self) -> Result<u8, UdpBufferError> {
        if self.pos >= MAX_UDP_PACKET_SIZE {
            Err(UdpBufferError::EndOfBuffer)
        } else {
            Ok(self.inner[self.pos])
        }
    }

    pub fn get_u8(&mut self) -> Result<u8, UdpBufferError> {
        self.read()
    }

    pub fn get_u16(&mut self) -> Result<u16, UdpBufferError> {
        let mut res = (self.read()? as u16) << 8;
        res |= self.read()? as u16;
        Ok(res)
    }

    pub fn get_u32(&mut self) -> Result<u32, UdpBufferError> {
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
