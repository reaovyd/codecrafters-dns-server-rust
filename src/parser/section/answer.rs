use anyhow::{anyhow, Result};
use bytes::Buf;
use std::io::Cursor;

use crate::parser::section::parse_single_section;

use super::{Section, SectionBytes};

#[derive(Debug, Clone)]
pub struct ASection {
    inner: Section,
    ttl: (u32, [u8; 4]),
    length: (u16, [u8; 2]),
    data: Vec<u8>,
}

impl ASection {
    pub fn new(inner: Section, ttl: (u32, [u8; 4]), length: (u16, [u8; 2]), data: Vec<u8>) -> Self {
        ASection {
            inner,
            ttl,
            length,
            data,
        }
    }
}

impl SectionBytes for ASection {
    fn into_bytes(self) -> Vec<u8> {
        self.into()
    }
    fn section(&self) -> &Section {
        &self.inner
    }
}

impl From<ASection> for Vec<u8> {
    fn from(value: ASection) -> Self {
        let mut vec = Vec::<u8>::from(value.inner);
        for byte in value.ttl.1 {
            vec.push(byte);
        }
        for byte in value.length.1 {
            vec.push(byte);
        }
        for byte in value.data {
            vec.push(byte);
        }
        vec
    }
}

pub(crate) fn parse_single_asection(cursor: &mut Cursor<&[u8]>) -> Result<ASection> {
    let section = parse_single_section(cursor)?;
    let mut ttl = [0u8; 4];
    let mut length = [0u8; 2];

    let mut byte_filler = |arr: &mut [u8], cap| {
        let mut bytes_co = 0;
        while cursor.has_remaining() && bytes_co != cap {
            let byte = cursor.get_u8();
            arr[bytes_co] = byte;
            bytes_co += 1;
        }
        if bytes_co != cap {
            Err(anyhow!("Error parsing; invalid number of bytes"))
        } else {
            Ok(())
        }
    };
    byte_filler(&mut ttl[..], 4)?;
    byte_filler(&mut length[..], 2)?;
    let ttl_val = ((ttl[0] as u32) << 24)
        | ((ttl[1] as u32) << 16)
        | ((ttl[2] as u32) << 8)
        | (ttl[3] as u32);
    let length_val = ((length[0] as u16) << 8) | length[1] as u16;

    let mut data = Vec::<u8>::with_capacity(length_val as usize);
    let mut co = 0u16;
    while cursor.has_remaining() && co != length_val {
        data.push(cursor.get_u8());
        co += 1;
    }
    if co != length_val {
        Err(anyhow!("Error parsing; invalid number of bytes"))
    } else {
        Ok(ASection {
            inner: section,
            ttl: (ttl_val, ttl),
            length: (length_val, length),
            data,
        })
    }
}
