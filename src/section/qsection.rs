use crate::error::ParseError;

use super::{Section, Type};

#[derive(Debug, Clone, PartialEq)]
pub struct QSection {
    inner: Section,
    domains: Vec<(String, QType, QClass)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum QType {
    NormalType(Type),
    Axfr,
    MailB,
    MailA,
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
            QType::MailB => 253,
            QType::MailA => 254,
            QType::Any => 255,
        }
    }
}

impl TryFrom<u16> for QType {
    type Error = ParseError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            252 => Ok(QType::Axfr),
            253 => Ok(QType::MailB),
            254 => Ok(QType::MailA),
            255 => Ok(QType::Any),
            _ => Ok(QType::NormalType(Type::try_from(value)?)),
        }
    }
}

impl TryFrom<u16> for QClass {
    type Error = ParseError;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            255 => Ok(QClass::Any),
            _ => Ok(QClass::NormalType(Type::try_from(value)?)),
        }
    }
}
