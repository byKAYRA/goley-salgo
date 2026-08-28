

use bytes::{BufMut, BytesMut};
use thiserror::Error;

pub const MAX_SCALAR: u32 = i32::MAX as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scalar(u32);

impl Scalar {
    
    pub fn new(value: u32) -> Result<Self, ScalarError> {
        if value > MAX_SCALAR {
            return Err(ScalarError::TooLarge { value });
        }
        Ok(Self(value))
    }

#[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

#[must_use]
    pub const fn encoded_len(self) -> usize {
        1 + self.value_width()
    }

pub fn encode(self, destination: &mut BytesMut) {
        match self.value_width() {
            1 => {
                destination.put_u8(1);
                destination.put_u8(self.0 as u8);
            }
            2 => {
                destination.put_u8(2);
                destination.put_i16_le(self.0 as i16);
            }
            4 => {
                destination.put_u8(4);
                destination.put_i32_le(self.0 as i32);
            }
            _ => unreachable!("value_width returns only ProudNet scalar widths"),
        }
    }

pub fn decode(source: &[u8]) -> Result<(Self, usize), ScalarError> {
        match Self::try_decode(source)? {
            Some(decoded) => Ok(decoded),
            None => {
                let needed = required_len(source)?;
                Err(ScalarError::Truncated {
                    needed,
                    available: source.len(),
                })
            }
        }
    }

pub fn try_decode(source: &[u8]) -> Result<Option<(Self, usize)>, ScalarError> {
        let Some(&prefix) = source.first() else {
            return Ok(None);
        };
        let width = width_from_prefix(prefix)?;
        let encoded_len = 1 + width;
        if source.len() < encoded_len {
            return Ok(None);
        }

        let value = match width {
            1 => u32::from(source[1]),
            2 => {
                let value = i16::from_le_bytes([source[1], source[2]]);
                u32::try_from(value).map_err(|_| ScalarError::Negative {
                    width: prefix,
                    value: i64::from(value),
                })?
            }
            4 => {
                let value = i32::from_le_bytes([source[1], source[2], source[3], source[4]]);
                u32::try_from(value).map_err(|_| ScalarError::Negative {
                    width: prefix,
                    value: i64::from(value),
                })?
            }
            _ => unreachable!("width_from_prefix validates scalar widths"),
        };

        Ok(Some((Self(value), encoded_len)))
    }

    const fn value_width(self) -> usize {
        if self.0 < 128 {
            1
        } else if self.0 < 32_768 {
            2
        } else {
            4
        }
    }
}

impl TryFrom<u32> for Scalar {
    type Error = ScalarError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<usize> for Scalar {
    type Error = ScalarError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        let value =
            u32::try_from(value).map_err(|_| ScalarError::PlatformValueTooLarge { value })?;
        Self::new(value)
    }
}

impl From<Scalar> for u32 {
    fn from(value: Scalar) -> Self {
        value.get()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScalarError {
    
    #[error("invalid ProudNet scalar width prefix {prefix}; expected 1, 2, or 4")]
    InvalidPrefix { prefix: u8 },
    
    #[error("negative ProudNet scalar value {value} in {width}-byte form")]
    Negative { width: u8, value: i64 },
    
    #[error("ProudNet scalar value {value} exceeds {MAX_SCALAR}")]
    TooLarge { value: u32 },
    
    #[error("platform value {value} does not fit a ProudNet scalar")]
    PlatformValueTooLarge { value: usize },
    
    #[error("truncated ProudNet scalar: need {needed} bytes, have {available}")]
    Truncated { needed: usize, available: usize },
}

fn width_from_prefix(prefix: u8) -> Result<usize, ScalarError> {
    match prefix {
        1 | 2 | 4 => Ok(usize::from(prefix)),
        _ => Err(ScalarError::InvalidPrefix { prefix }),
    }
}

fn required_len(source: &[u8]) -> Result<usize, ScalarError> {
    let Some(&prefix) = source.first() else {
        return Ok(1);
    };
    Ok(1 + width_from_prefix(prefix)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(value: u32) -> Vec<u8> {
        let mut bytes = BytesMut::new();
        Scalar::new(value).unwrap().encode(&mut bytes);
        bytes.to_vec()
    }

    #[test]
    fn encoder_uses_canonical_thresholds() {
        assert_eq!(encoded(0), [1, 0]);
        assert_eq!(encoded(127), [1, 127]);
        assert_eq!(encoded(128), [2, 128, 0]);
        assert_eq!(encoded(32_767), [2, 0xff, 0x7f]);
        assert_eq!(encoded(32_768), [4, 0x00, 0x80, 0x00, 0x00]);
        assert_eq!(encoded(MAX_SCALAR), [4, 0xff, 0xff, 0xff, 0x7f]);
    }

    #[test]
    fn decoder_reports_consumed_bytes_and_leaves_trailing_explicit() {
        let (value, consumed) = Scalar::decode(&[2, 0x34, 0x12, 0xaa, 0xbb]).unwrap();
        assert_eq!(value.get(), 0x1234);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn decoder_accepts_representable_noncanonical_forms() {
        assert_eq!(Scalar::decode(&[1, 200]).unwrap().0.get(), 200);
        assert_eq!(Scalar::decode(&[2, 1, 0]).unwrap().0.get(), 1);
        assert_eq!(Scalar::decode(&[4, 1, 0, 0, 0]).unwrap().0.get(), 1);
    }

    #[test]
    fn incomplete_input_is_distinct_from_malformed_input() {
        assert_eq!(Scalar::try_decode(&[]).unwrap(), None);
        assert_eq!(Scalar::try_decode(&[4, 1, 2]).unwrap(), None);
        assert_eq!(
            Scalar::decode(&[4, 1, 2]).unwrap_err(),
            ScalarError::Truncated {
                needed: 5,
                available: 3
            }
        );
        assert_eq!(
            Scalar::try_decode(&[3]).unwrap_err(),
            ScalarError::InvalidPrefix { prefix: 3 }
        );
    }

    #[test]
    fn negative_and_oversized_values_are_rejected() {
        assert!(matches!(
            Scalar::decode(&[2, 0xff, 0xff]),
            Err(ScalarError::Negative { .. })
        ));
        assert!(matches!(
            Scalar::decode(&[4, 0xff, 0xff, 0xff, 0xff]),
            Err(ScalarError::Negative { .. })
        ));
        assert_eq!(
            Scalar::new(MAX_SCALAR + 1).unwrap_err(),
            ScalarError::TooLarge {
                value: MAX_SCALAR + 1
            }
        );
    }
}
