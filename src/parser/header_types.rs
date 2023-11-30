use anyhow::{anyhow, Error};

#[derive(Default, Debug, PartialEq, Clone)]
pub enum QrIndicator {
    #[default]
    Question,
    Reply,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub enum OpCode {
    #[default]
    Query,
    IQuery,
    Status,
    FutureUse,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub enum AuthAnswer {
    #[default]
    NotAuthoritative,
    Authoritative,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub enum Truncation {
    #[default]
    NotTruncated,
    Truncated,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub enum RecursionDesired {
    #[default]
    NoRecursion,
    Recursion,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub enum RecursionStatus {
    #[default]
    NotAvailable,
    Available,
}

#[derive(Default, Debug, PartialEq, Clone)]
pub enum ResponseCode {
    #[default]
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl TryFrom<u8> for ResponseCode {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoError),
            1 => Ok(Self::FormatError),
            2 => Ok(Self::ServerFailure),
            3 => Ok(Self::NameError),
            4 => Ok(Self::NotImplemented),
            5 => Ok(Self::Refused),
            _ => Err(anyhow!("unimplemented")),
        }
    }
}

impl From<ResponseCode> for u8 {
    fn from(value: ResponseCode) -> Self {
        match value {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
        }
    }
}

impl TryFrom<u8> for RecursionStatus {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotAvailable),
            1 => Ok(Self::Available),
            _ => Err(anyhow!("RECURSION STATUS: UNSUPPORTED")),
        }
    }
}

impl From<RecursionStatus> for u8 {
    fn from(value: RecursionStatus) -> Self {
        match value {
            RecursionStatus::NotAvailable => 0,
            RecursionStatus::Available => 1,
        }
    }
}

impl TryFrom<u8> for RecursionDesired {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NoRecursion),
            1 => Ok(Self::Recursion),
            _ => Err(anyhow!("RECURSION DESIRED: UNSUPPORTED")),
        }
    }
}

impl From<RecursionDesired> for u8 {
    fn from(value: RecursionDesired) -> Self {
        match value {
            RecursionDesired::NoRecursion => 0,
            RecursionDesired::Recursion => 1,
        }
    }
}

impl TryFrom<u8> for Truncation {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotTruncated),
            1 => Ok(Self::Truncated),
            _ => Err(anyhow!("TRUNCATION: UNSUPPORTED")),
        }
    }
}

impl From<Truncation> for u8 {
    fn from(value: Truncation) -> Self {
        match value {
            Truncation::NotTruncated => 0,
            Truncation::Truncated => 1,
        }
    }
}

impl TryFrom<u8> for AuthAnswer {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::NotAuthoritative),
            1 => Ok(Self::Authoritative),
            _ => Err(anyhow!("AUTHANSWER: UNSUPPORTED")),
        }
    }
}

impl From<AuthAnswer> for u8 {
    fn from(value: AuthAnswer) -> Self {
        match value {
            AuthAnswer::NotAuthoritative => 0,
            AuthAnswer::Authoritative => 1,
        }
    }
}

impl TryFrom<u8> for QrIndicator {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Question),
            1 => Ok(Self::Reply),
            _ => Err(anyhow!("QRINDICATOR: UNSUPPORTED")),
        }
    }
}

impl From<QrIndicator> for u8 {
    fn from(value: QrIndicator) -> Self {
        match value {
            QrIndicator::Question => 0,
            QrIndicator::Reply => 1,
        }
    }
}

impl TryFrom<u8> for OpCode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Query),
            1 => Ok(Self::IQuery),
            2 => Ok(Self::Status),
            _ => {
                if (3..=15).contains(&value) {
                    Ok(Self::FutureUse)
                } else {
                    Err(anyhow!("OPCODE: UNSUPPORTED"))
                }
            }
        }
    }
}

impl From<OpCode> for u8 {
    fn from(value: OpCode) -> Self {
        match value {
            OpCode::Query => 0,
            OpCode::IQuery => 1,
            OpCode::Status => 2,
            OpCode::FutureUse => 3,
        }
    }
}
