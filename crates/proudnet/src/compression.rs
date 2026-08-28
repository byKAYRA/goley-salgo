

use std::io::{self, Read, Write};

use bytes::{Bytes, BytesMut};
use flate2::{Compression, bufread::ZlibDecoder, write::ZlibEncoder};
use thiserror::Error;

use crate::{Scalar, ScalarError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompressionLimits {
    
    pub max_compressed_len: usize,
    
    pub max_decompressed_len: usize,
}

impl CompressionLimits {
    
    #[must_use]
    pub const fn new(max_compressed_len: usize, max_decompressed_len: usize) -> Self {
        Self {
            max_compressed_len,
            max_decompressed_len,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedPayload {
    
    pub decompressed_len: usize,
    
    pub compressed: Bytes,
    
    pub trailing: Bytes,
}

impl CompressedPayload {
    
    pub fn decode(input: Bytes, limits: CompressionLimits) -> Result<Self, CompressionError> {
        let (compressed_len, first_len) = Scalar::decode(&input)?;
        let (decompressed_len, second_len) = Scalar::decode(&input[first_len..])?;
        let compressed_len = scalar_to_usize(compressed_len)?;
        let decompressed_len = scalar_to_usize(decompressed_len)?;

        if compressed_len > limits.max_compressed_len {
            return Err(CompressionError::CompressedLimit {
                length: compressed_len,
                maximum: limits.max_compressed_len,
            });
        }
        if decompressed_len > limits.max_decompressed_len {
            return Err(CompressionError::DecompressedLimit {
                length: decompressed_len,
                maximum: limits.max_decompressed_len,
            });
        }

        let data_start = first_len
            .checked_add(second_len)
            .ok_or(CompressionError::LengthOverflow)?;
        let data_end = data_start
            .checked_add(compressed_len)
            .ok_or(CompressionError::LengthOverflow)?;
        if input.len() < data_end {
            return Err(CompressionError::TruncatedCompressedData {
                declared: compressed_len,
                available: input.len().saturating_sub(data_start),
            });
        }

        Ok(Self {
            decompressed_len,
            compressed: input.slice(data_start..data_end),
            trailing: input.slice(data_end..),
        })
    }

pub fn compress(plaintext: &[u8], limits: CompressionLimits) -> Result<Self, CompressionError> {
        if plaintext.len() > limits.max_decompressed_len {
            return Err(CompressionError::DecompressedLimit {
                length: plaintext.len(),
                maximum: limits.max_decompressed_len,
            });
        }
        Scalar::try_from(plaintext.len())?;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext)?;
        let compressed = encoder.finish()?;
        if compressed.len() > limits.max_compressed_len {
            return Err(CompressionError::CompressedLimit {
                length: compressed.len(),
                maximum: limits.max_compressed_len,
            });
        }
        Scalar::try_from(compressed.len())?;

        Ok(Self {
            decompressed_len: plaintext.len(),
            compressed: Bytes::from(compressed),
            trailing: Bytes::new(),
        })
    }

pub fn decompress(&self, limits: CompressionLimits) -> Result<Bytes, CompressionError> {
        if self.compressed.len() > limits.max_compressed_len {
            return Err(CompressionError::CompressedLimit {
                length: self.compressed.len(),
                maximum: limits.max_compressed_len,
            });
        }
        if self.decompressed_len > limits.max_decompressed_len {
            return Err(CompressionError::DecompressedLimit {
                length: self.decompressed_len,
                maximum: limits.max_decompressed_len,
            });
        }

        let read_limit = self
            .decompressed_len
            .checked_add(1)
            .ok_or(CompressionError::LengthOverflow)?;
        let mut decoder = ZlibDecoder::new(self.compressed.as_ref());
        let mut output = Vec::with_capacity(self.decompressed_len);
        {
            let mut bounded = (&mut decoder)
                .take(u64::try_from(read_limit).map_err(|_| CompressionError::LengthOverflow)?);
            bounded.read_to_end(&mut output)?;
        }
        if output.len() != self.decompressed_len {
            return Err(CompressionError::DecompressedLengthMismatch {
                declared: self.decompressed_len,
                actual: output.len(),
            });
        }
        if !decoder.get_ref().is_empty() {
            return Err(CompressionError::TrailingCompressedBytes {
                count: decoder.get_ref().len(),
            });
        }
        Ok(Bytes::from(output))
    }

pub fn encode(&self, limits: CompressionLimits) -> Result<Bytes, CompressionError> {
        if self.compressed.len() > limits.max_compressed_len {
            return Err(CompressionError::CompressedLimit {
                length: self.compressed.len(),
                maximum: limits.max_compressed_len,
            });
        }
        if self.decompressed_len > limits.max_decompressed_len {
            return Err(CompressionError::DecompressedLimit {
                length: self.decompressed_len,
                maximum: limits.max_decompressed_len,
            });
        }
        let compressed_len = Scalar::try_from(self.compressed.len())?;
        let decompressed_len = Scalar::try_from(self.decompressed_len)?;
        let capacity = compressed_len
            .encoded_len()
            .checked_add(decompressed_len.encoded_len())
            .and_then(|length| length.checked_add(self.compressed.len()))
            .and_then(|length| length.checked_add(self.trailing.len()))
            .ok_or(CompressionError::LengthOverflow)?;
        let mut encoded = BytesMut::with_capacity(capacity);
        compressed_len.encode(&mut encoded);
        decompressed_len.encode(&mut encoded);
        encoded.extend_from_slice(&self.compressed);
        encoded.extend_from_slice(&self.trailing);
        Ok(encoded.freeze())
    }
}

fn scalar_to_usize(value: Scalar) -> Result<usize, CompressionError> {
    usize::try_from(value.get())
        .map_err(|_| CompressionError::LengthDoesNotFitPlatform { value: value.get() })
}

#[derive(Debug, Error)]
pub enum CompressionError {
    
    #[error(transparent)]
    Scalar(#[from] ScalarError),
    
    #[error("compressed payload length {value} does not fit this platform")]
    LengthDoesNotFitPlatform { value: u32 },
    
    #[error("compressed length {length} exceeds configured maximum {maximum}")]
    CompressedLimit { length: usize, maximum: usize },
    
    #[error("decompressed length {length} exceeds configured maximum {maximum}")]
    DecompressedLimit { length: usize, maximum: usize },
    
    #[error("compressed data declares {declared} bytes, but only {available} are available")]
    TruncatedCompressedData { declared: usize, available: usize },
    
    #[error("decompressed length mismatch: declared {declared}, produced {actual}")]
    DecompressedLengthMismatch { declared: usize, actual: usize },
    
    #[error("zlib member has {count} unconsumed trailing compressed byte(s)")]
    TrailingCompressedBytes { count: usize },
    
    #[error("compressed payload length overflow")]
    LengthOverflow,
    
    #[error("zlib processing failed: {0}")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: CompressionLimits = CompressionLimits::new(1024, 4096);

    #[test]
    fn zlib_envelope_round_trips() {
        let plaintext = b"goley ProudNet zlib payload".repeat(8);
        let compressed = CompressedPayload::compress(&plaintext, LIMITS).unwrap();
        assert_eq!(compressed.decompress(LIMITS).unwrap(), plaintext);

        let encoded = compressed.encode(LIMITS).unwrap();
        let decoded = CompressedPayload::decode(encoded, LIMITS).unwrap();
        assert_eq!(decoded.decompress(LIMITS).unwrap(), plaintext);
        assert!(decoded.trailing.is_empty());
    }

    #[test]
    fn envelope_models_and_reencodes_trailing_bytes() {
        let mut compressed = CompressedPayload::compress(b"abc", LIMITS).unwrap();
        compressed.trailing = Bytes::from_static(&[0xde, 0xad]);
        let encoded = compressed.encode(LIMITS).unwrap();
        let decoded = CompressedPayload::decode(encoded.clone(), LIMITS).unwrap();
        assert_eq!(decoded.trailing, &[0xde, 0xad][..]);
        assert_eq!(decoded.encode(LIMITS).unwrap(), encoded);
    }

    #[test]
    fn declared_limits_are_checked_before_decompression() {
        let encoded = Bytes::from_static(&[1, 0, 2, 0x00, 0x10]);
        assert!(matches!(
            CompressedPayload::decode(encoded, CompressionLimits::new(1, 1024)),
            Err(CompressionError::DecompressedLimit {
                length: 4096,
                maximum: 1024
            })
        ));
    }

    #[test]
    fn truncated_member_and_wrong_output_length_are_rejected() {
        let encoded = Bytes::from_static(&[1, 3, 1, 1, 0xaa, 0xbb]);
        assert!(matches!(
            CompressedPayload::decode(encoded, LIMITS),
            Err(CompressionError::TruncatedCompressedData {
                declared: 3,
                available: 2
            })
        ));

        let mut compressed = CompressedPayload::compress(b"abc", LIMITS).unwrap();
        compressed.decompressed_len = 2;
        assert!(matches!(
            compressed.decompress(LIMITS),
            Err(CompressionError::DecompressedLengthMismatch { .. })
        ));
    }
}
