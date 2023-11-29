use anyhow::Result;
use std::io::Cursor;

use super::{parse_single_section, Section, SectionBytes};

#[derive(Debug, Clone, PartialEq)]
pub struct QSection {
    inner: Section,
}

impl SectionBytes for QSection {
    fn into_bytes(self) -> Vec<u8> {
        self.into()
    }

    fn section(&self) -> &Section {
        &self.inner
    }
}

impl From<QSection> for Vec<u8> {
    fn from(value: QSection) -> Self {
        Vec::<u8>::from(value.inner)
    }
}

pub(crate) fn parse_single_qsection(cursor: &mut Cursor<&[u8]>) -> Result<QSection> {
    let section = parse_single_section(cursor)?;
    Ok(QSection { inner: section })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::parse_single_qsection;
    use crate::parser::section::{RRClass, RRType};

    #[test]
    fn parse_question_given_good_input() {
        let section: [u8; 16] = [
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x0, 0x01, 0x0,
            0x01,
        ];
        let mut res = Cursor::new(&section[..]);
        let qs = parse_single_qsection(&mut res).unwrap();
        assert_eq!(
            qs.inner.raw_domain,
            [6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0].to_vec()
        );
        assert_eq!(qs.inner.rr_class, RRClass::Internet);
        assert_eq!(qs.inner.rr_type, RRType::A);
        assert_eq!(qs.inner.domain, "google.com".to_owned());
    }

    #[test]
    #[should_panic(expected = "Error parsing; invalid char")]
    fn parse_question_given_smaller_length_invalid_char() {
        let section: [u8; 16] = [
            4, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x0, 0x01, 0x0,
            0x01,
        ];
        let mut res = Cursor::new(&section[..]);
        let _qs = parse_single_qsection(&mut res).unwrap();
    }

    #[test]
    #[should_panic(expected = "Error parsing; invalid length")]
    fn parse_question_given_longer_length_than_arr() {
        let section: [u8; 3] = [4, 0x67, 0x6f];
        let mut res = Cursor::new(&section[..]);
        let _qs = parse_single_qsection(&mut res).unwrap();
    }

    #[test]
    #[should_panic(expected = "Error parsing; RRs not found")]
    fn parse_question_given_no_domain_end() {
        let section: [u8; 16] = [
            6, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 4, 0x67, 0x67, 0x67,
            0x67,
        ];
        let mut res = Cursor::new(&section[..]);
        let _qs = parse_single_qsection(&mut res).unwrap();
    }
}
