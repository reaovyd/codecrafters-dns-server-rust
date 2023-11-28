use anyhow::{anyhow, Error};
use std::io::Cursor;

use bytes::Buf;

use super::{RRClass, RRType};

#[derive(Debug, Clone, PartialEq)]
pub struct QSection {
    domain: String,
    raw_domain: Vec<u8>,
    rr_type: RRType,
    rr_class: RRClass,
}

impl From<QSection> for Vec<u8> {
    fn from(value: QSection) -> Self {
        let mut res = value.raw_domain;
        let rr_type = u16::from(value.rr_type);
        let rr_class = u16::from(value.rr_class);
        let (rr_type_1, rr_type_2) = ((rr_type & 0xFF) as u8, ((rr_type >> 8) & 0xFF) as u8);
        let (rr_class_1, rr_class_2) = ((rr_class & 0xFF) as u8, ((rr_class >> 8) & 0xFF) as u8);
        res.push(rr_type_2);
        res.push(rr_type_1);
        res.push(rr_class_2);
        res.push(rr_class_1);

        res
    }
}

fn parse_single_qsection(cursor: &mut Cursor<&[u8]>) -> Result<QSection, Error> {
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
            (Ok(rr_type), Ok(rr_class)) => Ok(QSection {
                raw_domain,
                domain,
                rr_type,
                rr_class,
            }),
            (_err1, _err2) => Err(anyhow!("Error parsing; RRs not found")),
        }
    }
}

pub fn parse_qsection(value: &[u8], mut qdcount: u16) -> Result<Vec<QSection>, Error> {
    let mut cursor = Cursor::new(value);
    let mut qsecs = vec![];

    while qdcount != 0 {
        let qsection = parse_single_qsection(&mut cursor)?;
        qsecs.push(qsection);
        qdcount -= 1;
    }
    Ok(qsecs)
}

#[cfg(test)]
mod tests {
    use crate::parser::section::{question::parse_qsection, RRClass, RRType};

    #[test]
    fn parse_question_given_good_input() {
        let section: [u8; 16] = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x0, 0x01, 0x0,
            0x01,
        ];
        let res = &section[..];
        let qs = parse_qsection(res, 1).unwrap();
        let qs = qs.get(0).unwrap();
        assert_eq!(
            qs.raw_domain,
            [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0].to_vec()
        );
        assert_eq!(qs.rr_class, RRClass::Internet);
        assert_eq!(qs.rr_type, RRType::A);
        assert_eq!(qs.domain, "google.com".to_owned());
    }

    #[test]
    #[should_panic(expected = "Error parsing; invalid char")]
    fn parse_question_given_smaller_length_invalid_char() {
        let section: [u8; 16] = [
            4, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x0, 0x01, 0x0,
            0x01,
        ];
        let res = &section[..];
        let qs = parse_qsection(res, 1).unwrap();
        let _qs = qs.get(0).unwrap();
    }

    #[test]
    #[should_panic(expected = "Error parsing; invalid length")]
    fn parse_question_given_longer_length_than_arr() {
        let section: [u8; 3] = [4, 0x67, 0x6f];
        let res = &section[..];
        let _qs = parse_qsection(res, 1).unwrap();
    }

    #[test]
    #[should_panic(expected = "Error parsing; RRs not found")]
    fn parse_question_given_no_domain_end() {
        let section: [u8; 16] = [
            6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 4, 0x67, 0x67, 0x67,
            0x67,
        ];
        let res = &section[..];
        let _qs = parse_qsection(res, 1).unwrap();
    }
}
