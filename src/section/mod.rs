use crate::error::ParseError;

pub mod asection;
pub mod qsection;

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

impl TryFrom<u8> for Type {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
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

impl TryFrom<u8> for Class {
    type Error = ParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Class::In),
            2 => Ok(Class::Cs),
            3 => Ok(Class::Ch),
            4 => Ok(Class::Hs),
            _ => Err(ParseError::UnimplementedError),
        }
    }
}
