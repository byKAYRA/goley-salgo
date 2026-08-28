

use bytes::{BufMut, Bytes, BytesMut};
use pkcs1::EncodeRsaPublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use thiserror::Error;

#[derive(Clone)]
pub struct ServerRsaKeys {
    private_key: RsaPrivateKey,
    public_key_pkcs1_der: Bytes,
}

impl ServerRsaKeys {
    
    pub fn generate() -> Result<Self, CryptoError> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|err| CryptoError::RsaKeyGeneration(err.to_string()))?;
        Self::from_private_key(private_key)
    }

pub fn from_private_key(private_key: RsaPrivateKey) -> Result<Self, CryptoError> {
        let public_key = RsaPublicKey::from(&private_key);
        let doc = public_key
            .to_pkcs1_der()
            .map_err(|err| CryptoError::RsaKeyEncoding(err.to_string()))?;
        let public_key_pkcs1_der = Bytes::copy_from_slice(doc.as_bytes());
        Ok(Self {
            private_key,
            public_key_pkcs1_der,
        })
    }

#[must_use]
    pub fn public_key_pkcs1_der(&self) -> &Bytes {
        &self.public_key_pkcs1_der
    }

#[must_use]
    pub fn private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

pub fn decrypt_oaep_sha1(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let padding = Oaep::new::<sha1::Sha1>();
        self.private_key
            .decrypt(padding, ciphertext)
            .map_err(|err| CryptoError::RsaDecryption(err.to_string()))
    }

pub fn decrypt_oaep_sha256(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let padding = Oaep::new::<sha2::Sha256>();
        self.private_key
            .decrypt(padding, ciphertext)
            .map_err(|err| CryptoError::RsaDecryption(err.to_string()))
    }
}

impl std::fmt::Debug for ServerRsaKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerRsaKeys")
            .field("public_key_der_len", &self.public_key_pkcs1_der.len())
            .finish_non_exhaustive()
    }
}

pub const AES_BLOCK_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionKind {
    
    Secure,
    
    Fast,
    
    Unknown(u8),
}

impl EncryptionKind {
    
    #[must_use]
    pub const fn from_wire(value: u8) -> Self {
        match value {
            1 => Self::Secure,
            2 => Self::Fast,
            value => Self::Unknown(value),
        }
    }

#[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Secure => 1,
            Self::Fast => 2,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reliability {
    
    Reliable,
    
    Unreliable,
}

impl Reliability {
    const fn header_len(self) -> usize {
        match self {
            Self::Reliable => 1 + 4 + 2,
            Self::Unreliable => 1 + 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePlaintext {
    
    pub crc32: u32,
    
    pub counter: Option<u16>,
    
    pub data: Bytes,
}

impl SecurePlaintext {

pub fn decode(
        plaintext: Bytes,
        reliability: Reliability,
        max_data_len: usize,
    ) -> Result<Self, CryptoError> {
        validate_aes_ecb_len(plaintext.len())?;
        let header_len = reliability.header_len();
        if plaintext.len() < header_len {
            return Err(CryptoError::SecurePlaintextTooShort {
                needed: header_len,
                available: plaintext.len(),
            });
        }

        let padding_len = usize::from(plaintext[0]);
        if !(1..=AES_BLOCK_LEN).contains(&padding_len) {
            return Err(CryptoError::InvalidPaddingLength {
                length: padding_len,
            });
        }
        let data_end = plaintext.len().checked_sub(padding_len).ok_or(
            CryptoError::PaddingExceedsPlaintext {
                padding: padding_len,
                plaintext: plaintext.len(),
            },
        )?;
        if data_end < header_len {
            return Err(CryptoError::PaddingExceedsPlaintext {
                padding: padding_len,
                plaintext: plaintext.len(),
            });
        }

        let data_len = data_end - header_len;
        if data_len > max_data_len {
            return Err(CryptoError::DataTooLarge {
                length: data_len,
                maximum: max_data_len,
            });
        }
        let expected_padding = padding_len_for(header_len, data_len)?;
        if padding_len != expected_padding {
            return Err(CryptoError::NonCanonicalPadding {
                actual: padding_len,
                expected: expected_padding,
            });
        }
        if let Some((offset, value)) = plaintext[data_end..]
            .iter()
            .copied()
            .enumerate()
            .find(|(_, byte)| *byte != 0)
        {
            return Err(CryptoError::NonZeroPadding {
                offset: data_end + offset,
                value,
            });
        }

        let crc32 = u32::from_le_bytes([plaintext[1], plaintext[2], plaintext[3], plaintext[4]]);
        let (counter, data_start) = match reliability {
            Reliability::Reliable => (
                Some(u16::from_le_bytes([plaintext[5], plaintext[6]])),
                header_len,
            ),
            Reliability::Unreliable => (None, header_len),
        };

        Ok(Self {
            crc32,
            counter,
            data: plaintext.slice(data_start..data_end),
        })
    }

pub fn encode(
        &self,
        reliability: Reliability,
        max_data_len: usize,
    ) -> Result<Bytes, CryptoError> {
        if self.data.len() > max_data_len {
            return Err(CryptoError::DataTooLarge {
                length: self.data.len(),
                maximum: max_data_len,
            });
        }
        match (reliability, self.counter) {
            (Reliability::Reliable, None) => return Err(CryptoError::MissingReliableCounter),
            (Reliability::Unreliable, Some(counter)) => {
                return Err(CryptoError::UnexpectedUnreliableCounter { counter });
            }
            _ => {}
        }

        let header_len = reliability.header_len();
        let padding_len = padding_len_for(header_len, self.data.len())?;
        let total_len = header_len
            .checked_add(self.data.len())
            .and_then(|length| length.checked_add(padding_len))
            .ok_or(CryptoError::LengthOverflow)?;
        let mut encoded = BytesMut::with_capacity(total_len);
        encoded.put_u8(padding_len as u8);
        encoded.put_u32_le(self.crc32);
        if let Some(counter) = self.counter {
            encoded.put_u16_le(counter);
        }
        encoded.extend_from_slice(&self.data);
        encoded.resize(total_len, 0);
        Ok(encoded.freeze())
    }
}

pub fn validate_aes_ecb_len(length: usize) -> Result<(), CryptoError> {
    if length == 0 || !length.is_multiple_of(AES_BLOCK_LEN) {
        return Err(CryptoError::InvalidAesBlockLength { length });
    }
    Ok(())
}

fn padding_len_for(header_len: usize, data_len: usize) -> Result<usize, CryptoError> {
    let unpadded = header_len
        .checked_add(data_len)
        .ok_or(CryptoError::LengthOverflow)?;
    Ok(AES_BLOCK_LEN - (unpadded % AES_BLOCK_LEN))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    
    #[error("AES-ECB input length {length} is not a non-empty multiple of {AES_BLOCK_LEN}")]
    InvalidAesBlockLength { length: usize },
    
    #[error("secure plaintext needs at least {needed} bytes, but has {available}")]
    SecurePlaintextTooShort { needed: usize, available: usize },
    
    #[error("invalid secure plaintext padding length {length}")]
    InvalidPaddingLength { length: usize },
    
    #[error("padding length {padding} exceeds secure plaintext length {plaintext}")]
    PaddingExceedsPlaintext { padding: usize, plaintext: usize },
    
    #[error("non-canonical secure padding length {actual}; expected {expected}")]
    NonCanonicalPadding { actual: usize, expected: usize },
    
    #[error("secure padding byte at offset {offset} is 0x{value:02x}, expected zero")]
    NonZeroPadding { offset: usize, value: u8 },
    
    #[error("secure data length {length} exceeds configured maximum {maximum}")]
    DataTooLarge { length: usize, maximum: usize },
    
    #[error("reliable secure plaintext is missing its counter")]
    MissingReliableCounter,
    
    #[error("unreliable secure plaintext unexpectedly has counter {counter}")]
    UnexpectedUnreliableCounter { counter: u16 },
    
    #[error("RSA key generation failed: {0}")]
    RsaKeyGeneration(String),
    
    #[error("RSA public key PKCS#1 DER encoding failed: {0}")]
    RsaKeyEncoding(String),
    
    #[error("RSA decryption failed: {0}")]
    RsaDecryption(String),
    
    #[error("secure plaintext length overflow")]
    LengthOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_key_generates_270_byte_pkcs1_der_public_key() {
        let keys = ServerRsaKeys::generate().unwrap();
        assert_eq!(keys.public_key_pkcs1_der().len(), 270);
    }

    #[test]
    fn reliable_plaintext_round_trips_with_full_block_padding() {
        let value = SecurePlaintext {
            crc32: 0x1234_5678,
            counter: Some(0xabcd),
            data: Bytes::from_static(b"123456789"),
        };
        let encoded = value.encode(Reliability::Reliable, 64).unwrap();
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[0], 16);
        assert_eq!(
            SecurePlaintext::decode(encoded, Reliability::Reliable, 64).unwrap(),
            value
        );
    }

    #[test]
    fn unreliable_plaintext_round_trips() {
        let value = SecurePlaintext {
            crc32: 0x89ab_cdef,
            counter: None,
            data: Bytes::from_static(b"payload"),
        };
        let encoded = value.encode(Reliability::Unreliable, 64).unwrap();
        assert_eq!(encoded.len(), 16);
        assert_eq!(encoded[0], 4);
        assert_eq!(
            SecurePlaintext::decode(encoded, Reliability::Unreliable, 64).unwrap(),
            value
        );
    }

    #[test]
    fn alignment_limits_and_counter_shape_are_enforced() {
        assert!(matches!(
            validate_aes_ecb_len(15),
            Err(CryptoError::InvalidAesBlockLength { .. })
        ));
        assert!(matches!(
            SecurePlaintext {
                crc32: 0,
                counter: None,
                data: Bytes::from_static(b"x"),
            }
            .encode(Reliability::Reliable, 1),
            Err(CryptoError::MissingReliableCounter)
        ));
        assert!(matches!(
            SecurePlaintext {
                crc32: 0,
                counter: Some(1),
                data: Bytes::new(),
            }
            .encode(Reliability::Unreliable, 1),
            Err(CryptoError::UnexpectedUnreliableCounter { .. })
        ));
    }

    #[test]
    fn corrupt_padding_and_excess_data_are_rejected() {
        let value = SecurePlaintext {
            crc32: 0,
            counter: None,
            data: Bytes::from_static(b"abc"),
        };
        let mut encoded = BytesMut::from(&value.encode(Reliability::Unreliable, 3).unwrap()[..]);
        let last = encoded.len() - 1;
        encoded[last] = 1;
        assert!(matches!(
            SecurePlaintext::decode(encoded.freeze(), Reliability::Unreliable, 3),
            Err(CryptoError::NonZeroPadding { .. })
        ));

        let encoded = value.encode(Reliability::Unreliable, 3).unwrap();
        assert!(matches!(
            SecurePlaintext::decode(encoded, Reliability::Unreliable, 2),
            Err(CryptoError::DataTooLarge {
                length: 3,
                maximum: 2
            })
        ));
    }

    #[test]
    fn encryption_kind_preserves_unknown_values() {
        for value in [0, 1, 2, 255] {
            assert_eq!(EncryptionKind::from_wire(value).to_wire(), value);
        }
    }
}
