#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod buffer;
pub mod error;
pub mod header;
pub mod section;

fn big_endian_convert_u32_to_u8_array(num: u32) -> [u8; 4] {
    let mut res = [0u8; 4];
    res.iter_mut().enumerate().for_each(|(idx, elem)| {
        *elem = (num >> (8 * (3 - idx)) & 0xFF) as u8;
    });
    res
}

fn big_endian_convert_u16_to_u8_array(num: u16) -> [u8; 2] {
    let mut res = [0u8; 2];
    res.iter_mut().enumerate().for_each(|(idx, elem)| {
        *elem = (num >> (8 * (1 - idx)) & 0xFF) as u8;
    });
    res
}

#[cfg(test)]
mod tests {
    use crate::{big_endian_convert_u16_to_u8_array, big_endian_convert_u32_to_u8_array};

    #[test]
    fn test_big_endian_convert_u32_to_u8_array() {
        let input = 0x89ABFFDB;
        assert_eq!(
            big_endian_convert_u32_to_u8_array(input),
            [0x89, 0xAB, 0xFF, 0xDB]
        )
    }

    #[test]
    fn test_big_endian_convert_u16_to_u8_array() {
        let input = 0x89AB;
        assert_eq!(big_endian_convert_u16_to_u8_array(input), [0x89, 0xAB])
    }
}
