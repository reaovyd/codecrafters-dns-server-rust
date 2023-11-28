use anyhow::{anyhow, Error};

pub mod question;

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

impl From<RRClass> for u16 {
    fn from(value: RRClass) -> Self {
        match value {
            RRClass::Internet => 1,
            RRClass::Csnet => 2,
            RRClass::Chaos => 3,
            RRClass::Hesiod => 4,
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

impl From<RRType> for u16 {
    fn from(value: RRType) -> Self {
        match value {
            RRType::A => 1,
            RRType::NS => 2,
            RRType::MD => 3,
            RRType::MF => 4,
            RRType::CNAME => 5,
            RRType::SOA => 6,
            RRType::MB => 7,
            RRType::MG => 8,
            RRType::MR => 9,
            RRType::NULL => 10,
            RRType::WKS => 11,
            RRType::PTR => 12,
            RRType::HINFO => 13,
            RRType::MINFO => 14,
            RRType::MX => 15,
            RRType::TXT => 16,
        }
    }
}
