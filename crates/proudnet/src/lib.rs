

#![forbid(unsafe_code)]

pub mod compression;
pub mod core;
pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod scalar;

pub use compression::{CompressedPayload, CompressionError, CompressionLimits};
pub use core::{CoreDecodeError, CoreMessage, CoreOpcode, RmiDecodeError, RmiMessage};
pub use crypto::{
    AES_BLOCK_LEN, CryptoError, EncryptionKind, Reliability, SecurePlaintext, ServerRsaKeys,
};
pub use frame::{Frame, FrameCodec, FrameError, TCP_MAGIC};
pub use handshake::{
    ClientEncryptedSessionKeys, FastKeyLengthField, FastKeyLengthLayout, HandshakeError,
    NOTIFY_CS_ENCRYPTED_SESSION_KEY, NOTIFY_CS_SESSION_KEY_SUCCESS, NOTIFY_SERVER_CONNECTION_HINT,
    NOTIFY_SERVER_CONNECTION_REQUEST_DATA, ServerConnectionHint, ServerConnectionRequestData,
    session_key_success_payload,
};
pub use scalar::{MAX_SCALAR, Scalar, ScalarError};

pub const CRATE_PURPOSE: &str = "standalone ProudNet transport";
