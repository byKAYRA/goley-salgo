

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoreOpcode {
    
    Rmi,
    
    UserMessage,
    
    EncryptedReliable,
    
    EncryptedUnreliable,
    
    Compressed,
    
    Unknown(u8),
}

impl CoreOpcode {
    
    #[must_use]
    pub const fn from_wire(value: u8) -> Self {
        match value {
            1 => Self::Rmi,
            2 => Self::UserMessage,
            36 => Self::EncryptedReliable,
            37 => Self::EncryptedUnreliable,
            38 => Self::Compressed,
            value => Self::Unknown(value),
        }
    }

#[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Rmi => 1,
            Self::UserMessage => 2,
            Self::EncryptedReliable => 36,
            Self::EncryptedUnreliable => 37,
            Self::Compressed => 38,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreMessage {
    
    pub opcode: CoreOpcode,
    
    pub body: Bytes,
}

impl CoreMessage {
    
    #[must_use]
    pub const fn new(opcode: CoreOpcode, body: Bytes) -> Self {
        Self { opcode, body }
    }

pub fn decode(payload: Bytes) -> Result<Self, CoreDecodeError> {
        let Some(&opcode) = payload.first() else {
            return Err(CoreDecodeError::MissingOpcode);
        };
        Ok(Self {
            opcode: CoreOpcode::from_wire(opcode),
            body: payload.slice(1..),
        })
    }

#[must_use]
    pub fn encode(&self) -> Bytes {
        let mut encoded = BytesMut::with_capacity(1 + self.body.len());
        encoded.put_u8(self.opcode.to_wire());
        encoded.extend_from_slice(&self.body);
        encoded.freeze()
    }

pub fn decode_rmi(&self) -> Result<RmiMessage, RmiDecodeError> {
        if self.opcode != CoreOpcode::Rmi {
            return Err(RmiDecodeError::WrongCoreOpcode {
                actual: self.opcode,
            });
        }
        RmiMessage::decode(self.body.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RmiMessage {
    
    pub id: u16,
    
    pub parameters: Bytes,
}

impl RmiMessage {
    
    #[must_use]
    pub const fn new(id: u16, parameters: Bytes) -> Self {
        Self { id, parameters }
    }

pub fn decode(body: Bytes) -> Result<Self, RmiDecodeError> {
        if body.len() < 2 {
            return Err(RmiDecodeError::MissingId {
                available: body.len(),
            });
        }
        let id = u16::from_le_bytes([body[0], body[1]]);
        Ok(Self {
            id,
            parameters: body.slice(2..),
        })
    }

#[must_use]
    pub fn encode_body(&self) -> Bytes {
        let mut body = BytesMut::with_capacity(2 + self.parameters.len());
        body.put_u16_le(self.id);
        body.extend_from_slice(&self.parameters);
        body.freeze()
    }

#[must_use]
    pub fn into_core(self) -> CoreMessage {
        CoreMessage::new(CoreOpcode::Rmi, self.encode_body())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreDecodeError {
    
    #[error("ProudNet core message has no opcode")]
    MissingOpcode,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RmiDecodeError {
    
    #[error("core opcode {actual:?} is not an RMI")]
    WrongCoreOpcode { actual: CoreOpcode },
    
    #[error("RMI body needs a 2-byte id, but only {available} byte(s) are available")]
    MissingId { available: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_and_unknown_opcodes_round_trip_losslessly() {
        for byte in [1, 2, 36, 37, 38, 0, 255] {
            let input = Bytes::from(vec![byte, 0xaa, 0xbb]);
            let message = CoreMessage::decode(input.clone()).unwrap();
            assert_eq!(message.encode(), input);
        }
    }

    #[test]
    fn empty_core_message_is_rejected() {
        assert_eq!(
            CoreMessage::decode(Bytes::new()).unwrap_err(),
            CoreDecodeError::MissingOpcode
        );
    }

    #[test]
    fn rmi_parameters_are_never_silently_discarded() {
        let core = CoreMessage::decode(Bytes::from_static(&[1, 0xe6, 0x05, 9, 8, 7])).unwrap();
        let rmi = core.decode_rmi().unwrap();
        assert_eq!(rmi.id, 1510);
        assert_eq!(rmi.parameters, &[9, 8, 7][..]);
        assert_eq!(rmi.into_core().encode(), &[1, 0xe6, 0x05, 9, 8, 7][..]);
    }

    #[test]
    fn rmi_requires_matching_opcode_and_complete_id() {
        let user = CoreMessage::new(CoreOpcode::UserMessage, Bytes::from_static(&[1, 2]));
        assert!(matches!(
            user.decode_rmi(),
            Err(RmiDecodeError::WrongCoreOpcode { .. })
        ));
        assert_eq!(
            RmiMessage::decode(Bytes::from_static(&[1])).unwrap_err(),
            RmiDecodeError::MissingId { available: 1 }
        );
    }
}
