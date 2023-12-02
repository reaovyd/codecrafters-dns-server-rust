use crate::{
    big_endian_convert_u16_to_u8_array, big_endian_convert_u32_to_u8_array, error::ParseError,
};

pub(crate) type AsectionContents = (u32, u16, Vec<u8>);

#[derive(Debug, Clone, PartialEq)]
pub struct SectionGroup {
    pub domain: Vec<String>,
    pub group_type: Type,
    pub class: Class,
    pub asection: Option<AsectionContents>,
}
#[derive(Debug, Clone, PartialEq)]
pub struct Section {
    pub groups: Vec<SectionGroup>,
    pub raw_domain: Vec<u8>,
}

impl Section {
    pub fn new(groups: Vec<SectionGroup>, raw_domain: Vec<u8>) -> Self {
        Self { groups, raw_domain }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Class {
    In = 1,
    Cs = 2,
    Ch = 3,
    Hs = 4,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    A = 1,
    Ns = 2,
    Md = 3,
    Mf = 4,
    Cname = 5,
    Soa = 6,
    Mb = 7,
    Mg = 8,
    Mr = 9,
    Null = 10,
    Wks = 11,
    Ptr = 12,
    Hinfo = 13,
    Minfo = 14,
    Mx = 15,
    Txt = 16,
}

impl From<Section> for Vec<u8> {
    fn from(value: Section) -> Self {
        value.raw_domain
    }
}

impl SectionGroup {
    pub fn new(
        domain: Vec<String>,
        group_type: Type,
        class: Class,
        asection: Option<AsectionContents>,
    ) -> Self {
        Self {
            domain,
            group_type,
            class,
            asection,
        }
    }

    pub fn domain(&self) -> &Vec<String> {
        &self.domain
    }

    pub fn group_type(&self) -> &Type {
        &self.group_type
    }

    pub fn class(&self) -> &Class {
        &self.class
    }
}

impl TryFrom<SectionGroup> for Vec<u8> {
    type Error = ParseError;
    fn try_from(value: SectionGroup) -> Result<Self, Self::Error> {
        let mut res = Vec::new();
        for domain in value.domain {
            let len = u8::try_from(domain.len()).map_err(|_| ParseError::ConversionError)?;
            res.push(len);
            domain
                .into_bytes()
                .into_iter()
                .for_each(|byte| res.push(byte))
        }
        res.push(0);
        let group_type = value.group_type as u8;
        let class = value.class as u8;
        res.push(group_type);
        res.push(class);
        if let Some((ttl, length, data)) = value.asection {
            big_endian_convert_u32_to_u8_array(ttl)
                .into_iter()
                .for_each(|elem| {
                    res.push(elem);
                });
            big_endian_convert_u16_to_u8_array(length)
                .into_iter()
                .for_each(|elem| {
                    res.push(elem);
                });
            data.into_iter().for_each(|elem| {
                res.push(elem);
            })
        }
        Ok(res)
    }
}

impl TryFrom<u16> for Type {
    type Error = ParseError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Type::A),
            2 => Ok(Type::Ns),
            3 => Ok(Type::Md),
            4 => Ok(Type::Mf),
            5 => Ok(Type::Cname),
            6 => Ok(Type::Soa),
            7 => Ok(Type::Mb),
            8 => Ok(Type::Mg),
            9 => Ok(Type::Mr),
            10 => Ok(Type::Null),
            11 => Ok(Type::Wks),
            12 => Ok(Type::Ptr),
            13 => Ok(Type::Hinfo),
            14 => Ok(Type::Minfo),
            15 => Ok(Type::Mx),
            16 => Ok(Type::Txt),
            _ => Err(ParseError::UnimplementedError),
        }
    }
}

impl TryFrom<u16> for Class {
    type Error = ParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Class::In),
            2 => Ok(Class::Cs),
            3 => Ok(Class::Ch),
            4 => Ok(Class::Hs),
            _ => Err(ParseError::UnimplementedError),
        }
    }
}
