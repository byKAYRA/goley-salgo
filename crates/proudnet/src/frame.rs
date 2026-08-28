

use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;
use tokio_util::codec::{Decoder, Encoder};

use crate::{Scalar, ScalarError};

pub const TCP_MAGIC: u16 = 0x5713;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    
    pub payload: Bytes,
}

impl Frame {
    
    #[must_use]
    pub const fn new(payload: Bytes) -> Self {
        Self { payload }
    }
}

impl From<Bytes> for Frame {
    fn from(payload: Bytes) -> Self {
        Self::new(payload)
    }
}

#[derive(Debug, Clone)]
pub struct FrameCodec {
    max_payload_len: usize,
}

impl FrameCodec {
    
    #[must_use]
    pub const fn new(max_payload_len: usize) -> Self {
        Self { max_payload_len }
    }

#[must_use]
    pub const fn max_payload_len(&self) -> usize {
        self.max_payload_len
    }
}

impl Decoder for FrameCodec {
    type Item = Frame;
    type Error = FrameError;

    fn decode(&mut self, source: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if source.len() < 2 {
            return Ok(None);
        }

        let magic = u16::from_le_bytes([source[0], source[1]]);
        if magic != TCP_MAGIC {
            return Err(FrameError::InvalidMagic { actual: magic });
        }

        let Some((payload_len, scalar_len)) = Scalar::try_decode(&source[2..])? else {
            return Ok(None);
        };
        let payload_len = usize::try_from(payload_len.get()).map_err(|_| {
            FrameError::LengthDoesNotFitPlatform {
                value: payload_len.get(),
            }
        })?;
        if payload_len > self.max_payload_len {
            return Err(FrameError::PayloadTooLarge {
                length: payload_len,
                maximum: self.max_payload_len,
            });
        }

        let header_len = 2usize
            .checked_add(scalar_len)
            .ok_or(FrameError::FrameLengthOverflow)?;
        let frame_len = header_len
            .checked_add(payload_len)
            .ok_or(FrameError::FrameLengthOverflow)?;
        if source.len() < frame_len {
            source.reserve(frame_len - source.len());
            return Ok(None);
        }

        let mut encoded_frame = source.split_to(frame_len);
        encoded_frame.advance(header_len);
        Ok(Some(Frame::new(encoded_frame.freeze())))
    }
}

impl Encoder<Frame> for FrameCodec {
    type Error = FrameError;

    fn encode(&mut self, item: Frame, destination: &mut BytesMut) -> Result<(), Self::Error> {
        let payload_len = item.payload.len();
        if payload_len > self.max_payload_len {
            return Err(FrameError::PayloadTooLarge {
                length: payload_len,
                maximum: self.max_payload_len,
            });
        }
        let scalar = Scalar::try_from(payload_len)?;
        let encoded_len = 2usize
            .checked_add(scalar.encoded_len())
            .and_then(|length| length.checked_add(payload_len))
            .ok_or(FrameError::FrameLengthOverflow)?;

        destination.reserve(encoded_len);
        destination.put_u16_le(TCP_MAGIC);
        scalar.encode(destination);
        destination.extend_from_slice(&item.payload);
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum FrameError {
    
    #[error("ProudNet frame I/O failed: {0}")]
    Io(#[from] io::Error),
    
    #[error("invalid ProudNet TCP magic 0x{actual:04x}; expected 0x{TCP_MAGIC:04x}")]
    InvalidMagic { actual: u16 },
    
    #[error(transparent)]
    Scalar(#[from] ScalarError),
    
    #[error("ProudNet payload length {length} exceeds configured maximum {maximum}")]
    PayloadTooLarge { length: usize, maximum: usize },
    
    #[error("ProudNet payload length {value} does not fit this platform")]
    LengthDoesNotFitPlatform { value: u32 },
    
    #[error("ProudNet frame length overflow")]
    FrameLengthOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_small_frame_vector_round_trips() {
        let mut codec = FrameCodec::new(1024);
        let mut encoded = BytesMut::new();
        codec
            .encode(Frame::new(Bytes::from_static(b"abc")), &mut encoded)
            .unwrap();
        assert_eq!(&encoded[..], &[0x13, 0x57, 1, 3, b'a', b'b', b'c']);

        assert_eq!(
            codec.decode(&mut encoded).unwrap().unwrap().payload,
            &b"abc"[..]
        );
        assert!(encoded.is_empty());
    }

    #[test]
    fn partial_input_waits_without_consuming() {
        let complete = [0x13, 0x57, 2, 0x80, 0x00];
        let mut codec = FrameCodec::new(256);
        for end in 0..complete.len() {
            let mut partial = BytesMut::from(&complete[..end]);
            let before = partial.clone();
            assert!(codec.decode(&mut partial).unwrap().is_none());
            assert_eq!(partial, before);
        }
    }

    #[test]
    fn decoder_consumes_exactly_one_frame() {
        let mut codec = FrameCodec::new(16);
        let mut encoded =
            BytesMut::from(&[0x13, 0x57, 1, 1, 0xaa, 0x13, 0x57, 1, 2, 0xbb, 0xcc][..]);
        assert_eq!(
            codec.decode(&mut encoded).unwrap().unwrap().payload,
            &[0xaa][..]
        );
        assert_eq!(
            codec.decode(&mut encoded).unwrap().unwrap().payload,
            &[0xbb, 0xcc][..]
        );
        assert!(encoded.is_empty());
    }

    #[test]
    fn malformed_and_oversized_frames_are_rejected_without_allocation() {
        let mut codec = FrameCodec::new(4);
        let mut bad_magic = BytesMut::from(&[0, 0, 1, 0][..]);
        assert!(matches!(
            codec.decode(&mut bad_magic),
            Err(FrameError::InvalidMagic { .. })
        ));

        let mut bad_scalar = BytesMut::from(&[0x13, 0x57, 3][..]);
        assert!(matches!(
            codec.decode(&mut bad_scalar),
            Err(FrameError::Scalar(ScalarError::InvalidPrefix { .. }))
        ));

        let mut oversized = BytesMut::from(&[0x13, 0x57, 1, 5][..]);
        assert!(matches!(
            codec.decode(&mut oversized),
            Err(FrameError::PayloadTooLarge {
                length: 5,
                maximum: 4
            })
        ));
    }

    #[test]
    fn encoder_enforces_limits_and_scalar_range() {
        let mut destination = BytesMut::new();
        let mut codec = FrameCodec::new(2);
        assert!(matches!(
            codec.encode(Frame::new(Bytes::from_static(b"abc")), &mut destination),
            Err(FrameError::PayloadTooLarge { .. })
        ));
        assert!(destination.is_empty());
    }
}
