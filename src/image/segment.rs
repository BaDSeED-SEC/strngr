use std::default::Default;

use base64;
use byteorder::ByteOrder;
use failure::Error;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Fail)]
pub enum SegmentError {
    #[fail(display = "range of {:x}-{:x} not found in any segment", start_addr, end_addr)]
    RangeNotFound {
        start_addr: u64,
        end_addr: u64,
    },
    #[fail(display = "range of {:x}-{:x} contains uninitialised data", start_addr, end_addr)]
    UninitialisedRange {
        start_addr: u64,
        end_addr: u64,
    },
}

#[derive(Debug, Deserialize)]
pub struct Segment {
    pub (crate) start_addr: u64,
    pub (crate) end_addr: u64,
    pub (crate) name: String,
    #[serde(deserialize_with = "Segment::bytes_from_base64")]
    pub (crate) bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct Segments(Vec<Segment>);

impl Segment {
    fn bytes_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where D: Deserializer<'de> {

        use serde::de::Error;
        String::deserialize(deserializer)
            .and_then(|s| base64::decode(&s).map_err(Error::custom))
    }
}

impl Segments {
    pub fn new() -> Segments {
        Segments(Vec::new())
    }

    #[allow(unused)]
    pub fn add(&mut self, segment: Segment) {
        // TODO: Enforce that segments do not overlap
        self.0.push(segment)
    }

    pub fn get_segment(&self, start_addr: u64, end_addr: u64) -> Result<&Segment, Error> {
        // Perform a binary search for the correct segment
        let len = self.0.len();
        let mut upper = len;
        let mut lower = 0;

        while lower < upper {
            let mid = lower + (upper - lower) / 2;
            let seg = &self.0[mid];

            if seg.start_addr <= start_addr && seg.end_addr >= end_addr {
                return Ok(seg);
            }

            if start_addr >= seg.end_addr {
                lower = mid + 1;
            } else if end_addr <= seg.start_addr {
                upper = mid;
            } else {
                break;
            }
        }

        Err(SegmentError::RangeNotFound { start_addr, end_addr }.into())
    }

    pub fn get_bytes(&self, start_addr: u64, end_addr: u64) -> Result<&[u8], Error> {
        let seg = self.get_segment(start_addr, end_addr)?;
        let start = (start_addr - seg.start_addr) as usize;
        let end = (end_addr - seg.start_addr) as usize;

        if seg.bytes.len() >= end {
            Ok(&seg.bytes[start..end])
        } else {
            Err(SegmentError::UninitialisedRange { start_addr, end_addr }.into())
        }
    }

    #[allow(unused)]
    pub fn get_i16<T: ByteOrder>(&self, addr: u64) -> Result<i16, Error> {
        self.get_bytes(addr, addr.wrapping_add(2)).map(T::read_i16)
    }

    pub fn get_i32<T: ByteOrder>(&self, addr: u64) -> Result<i32, Error> {
        self.get_bytes(addr, addr.wrapping_add(4)).map(T::read_i32)
    }

    #[allow(unused)]
    pub fn get_i64<T: ByteOrder>(&self, addr: u64) -> Result<i64, Error> {
        self.get_bytes(addr, addr.wrapping_add(8)).map(T::read_i64)
    }

    pub fn get_cstring(&self, addr: u64, limit: Option<usize>) -> Result<Option<&[u8]>, Error> {
        let seg = self.get_segment(addr, addr.wrapping_add(1))?; // Minimum length of 1 character
        let start = (addr - seg.start_addr) as usize;
        let end = start + limit.unwrap_or(16);

        if seg.bytes.len() < end {
            return Err(SegmentError::UninitialisedRange { start_addr: addr, end_addr: addr }.into());
        }

        let bytes = &seg.bytes[start..end];

        for (i, b) in bytes.iter().enumerate() {
            if b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || b.is_ascii_whitespace() {
                continue;
            } else if *b == 0 {
                return Ok(Some(&bytes[..i]));
            } else {
                break;
            }
        }

        Ok(None)
    }
}

impl Default for Segments {
    fn default() -> Segments {
        Segments::new()
    }
}
