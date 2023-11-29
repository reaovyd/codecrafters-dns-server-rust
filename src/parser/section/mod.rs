use anyhow::{anyhow, Error};
use bytes::Buf;
use std::io::Cursor;

use crate::parser::section::answer::parse_single_asection;

use self::{
    answer::ASection,
    question::{parse_single_qsection, QSection},
};
pub mod answer;
pub mod question;

pub trait SectionBytes {
    fn into_bytes(self) -> Vec<u8>;
    fn section(&self) -> &Section;
}

#[derive(Debug, Clone, PartialEq)]
pub enum RRType {
    A,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RRClass {
    Internet,
    Csnet,
    Chaos,
    Hesiod,
}

impl TryFrom<u16> for RRClass {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Internet),
            2 => Ok(Self::Csnet),
            3 => Ok(Self::Chaos),
            4 => Ok(Self::Hesiod),
            _ => Err(anyhow!("unimplemnted")),
        }
    }
}

impl From<RRClass> for [u8; 2] {
    fn from(value: RRClass) -> Self {
        match value {
            RRClass::Internet => [0x0, 0x1],
            RRClass::Csnet => [0x0, 0x2],
            RRClass::Chaos => [0x0, 0x3],
            RRClass::Hesiod => [0x0, 0x4],
        }
    }
}

impl TryFrom<u16> for RRType {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::NS),
            3 => Ok(Self::MD),
            4 => Ok(Self::MF),
            5 => Ok(Self::CNAME),
            6 => Ok(Self::SOA),
            7 => Ok(Self::MB),
            8 => Ok(Self::MG),
            9 => Ok(Self::MR),
            10 => Ok(Self::NULL),
            11 => Ok(Self::WKS),
            12 => Ok(Self::PTR),
            13 => Ok(Self::HINFO),
            14 => Ok(Self::MINFO),
            15 => Ok(Self::MX),
            16 => Ok(Self::TXT),
            _ => Err(anyhow!("unimplemented")),
        }
    }
}

impl From<RRType> for [u8; 2] {
    fn from(value: RRType) -> Self {
        match value {
            RRType::A => [0x0, 0x1],
            RRType::NS => [0x0, 0x2],
            RRType::MD => [0x0, 0x3],
            RRType::MF => [0x0, 0x4],
            RRType::CNAME => [0x0, 0x5],
            RRType::SOA => [0x0, 0x6],
            RRType::MB => [0x0, 0x7],
            RRType::MG => [0x0, 0x8],
            RRType::MR => [0x0, 0x9],
            RRType::NULL => [0x0, 0xA],
            RRType::WKS => [0x0, 0xB],
            RRType::PTR => [0x0, 0xC],
            RRType::HINFO => [0x0, 0xD],
            RRType::MINFO => [0x0, 0xE],
            RRType::MX => [0x0, 0xF],
            RRType::TXT => [0x1, 0x0],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    domain: String,
    raw_domain: Vec<u8>,
    rr_type: RRType,
    rr_class: RRClass,
}

impl Section {
    pub fn new(domain: String, raw_domain: Vec<u8>, rr_type: RRType, rr_class: RRClass) -> Self {
        Section {
            domain,
            raw_domain,
            rr_type,
            rr_class,
        }
    }
}

impl From<Section> for Vec<u8> {
    fn from(value: Section) -> Self {
        let mut res = value.raw_domain;
        let rr_type = <[u8; 2]>::from(value.rr_type);
        let rr_class = <[u8; 2]>::from(value.rr_class);
        res.push(rr_type[0]);
        res.push(rr_type[1]);
        res.push(rr_class[0]);
        res.push(rr_class[1]);

        res
    }
}

fn parse_single_section(cursor: &mut Cursor<&[u8]>) -> Result<Section, Error> {
    let mut raw_domain = vec![];
    let mut domain = String::new();
    while cursor.has_remaining() {
        let mut len = cursor.get_u8();
        raw_domain.push(len);
        if len == 0 {
            break;
        } else {
            while cursor.has_remaining() && len > 0 {
                let c = cursor.get_u8();
                if !c.is_ascii() || (c != b'-' && !c.is_ascii_alphanumeric()) {
                    return Err(anyhow!("Error parsing; invalid char found"));
                }
                domain.push(c as char);
                raw_domain.push(c);
                len -= 1;
            }
            if len > 0 {
                return Err(anyhow!("Error parsing; invalid length given"));
            } else {
                domain.push('.');
            }
        }
    }
    domain.pop();
    let mut len = 4;
    let mut rrs = vec![];
    while cursor.has_remaining() && len > 0 {
        rrs.push(cursor.get_u8());
        len -= 1;
    }
    if rrs.len() != 4 {
        Err(anyhow!("Error parsing; RRs not found"))
    } else {
        let rr_type = RRType::try_from(((rrs[0] as u16) << 8) | (rrs[1] as u16));
        let rr_class = RRClass::try_from(((rrs[2] as u16) << 8) | (rrs[3] as u16));
        match (rr_type, rr_class) {
            (Ok(rr_type), Ok(rr_class)) => Ok(Section {
                raw_domain,
                domain,
                rr_type,
                rr_class,
            }),
            (_err1, _err2) => Err(anyhow!("Error parsing; RRs not found")),
        }
    }
}

pub fn parse_all_sections(
    value: &[u8],
    mut qdcount: u16,
    mut ancount: u16,
) -> Result<(Vec<QSection>, Vec<ASection>), Error> {
    let mut cursor = Cursor::new(value);
    let mut qsecs: Vec<QSection> = vec![];
    let mut asecs: Vec<ASection> = vec![];

    while qdcount != 0 {
        let qsection = parse_single_qsection(&mut cursor)?;
        qsecs.push(qsection);
        qdcount -= 1;
    }

    while ancount != 0 {
        let asection = parse_single_asection(&mut cursor)?;
        asecs.push(asection);
        ancount -= 1;
    }
    Ok((qsecs, asecs))
}
