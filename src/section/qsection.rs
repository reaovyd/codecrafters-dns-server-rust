use crate::error::ParseError;

use super::Type;

#[derive(Debug, Clone, PartialEq)]
pub enum QType {
    NormalType(Type),
    Axfr,
    Mailb,
    Maila,
    Any,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QClass {
    NormalType(Type),
    Any,
}

impl From<QType> for u8 {
    fn from(value: QType) -> Self {
        match value {
            QType::NormalType(reg_type) => reg_type as u8,
            QType::Axfr => 252,
            QType::Mailb => 253,
            QType::Maila => 254,
            QType::Any => 255,
        }
    }
}

impl TryFrom<u8> for QType {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            252 => Ok(QType::Axfr),
            253 => Ok(QType::Mailb),
            254 => Ok(QType::Maila),
            255 => Ok(QType::Any),
            _ => Ok(QType::NormalType(Type::try_from(value)?)),
        }
    }
}

impl TryFrom<u8> for QClass {
    type Error = ParseError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            255 => Ok(QClass::Any),
            _ => Ok(QClass::NormalType(Type::try_from(value)?)),
        }
    }
}
