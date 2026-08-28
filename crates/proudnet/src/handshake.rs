

use bytes::{BufMut, Bytes, BytesMut};
use thiserror::Error;

use crate::{Scalar, ScalarError};

pub const NOTIFY_SERVER_CONNECTION_HINT: u8 = 4;

pub const NOTIFY_CS_ENCRYPTED_SESSION_KEY: u8 = 5;

pub const NOTIFY_CS_SESSION_KEY_SUCCESS: u8 = 6;

pub const NOTIFY_SERVER_CONNECTION_REQUEST_DATA: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FastKeyLengthLayout {
    
    Absent,
    
    Present,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FastKeyLengthField {
    
    Absent,
    
    Present(u32),
}

impl FastKeyLengthField {
    
    #[must_use]
    pub const fn layout(self) -> FastKeyLengthLayout {
        match self {
            Self::Absent => FastKeyLengthLayout::Absent,
            Self::Present(_) => FastKeyLengthLayout::Present,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServerConnectionHint {
    
    pub enable_server_log: bool,
    
    pub fallback_method: u8,
    
    pub message_max_length: u32,
    
    pub idle_timeout: f64,
    
    pub direct_p2p_start_condition: u8,
    
    pub over_send_suspecting_threshold_in_bytes: u32,
    
    pub enable_nagle_algorithm: bool,
    
    pub encrypted_message_key_length: u32,
    
    pub fast_encrypted_message_key_length: FastKeyLengthField,
    
    pub allow_server_as_p2p_group_member: bool,
    
    pub enable_p2p_encrypted_messaging: bool,
    
    pub upnp_detect_nat_device: bool,
    
    pub upnp_tcp_addr_port_mapping: bool,
    
    pub enable_lookahead_p2p_send: bool,
    
    pub enable_ping_test: bool,
    
    pub emergency_log_line_count: u32,
    
    pub rsa_public_key_der: Bytes,
    
    pub trailing: Bytes,
}

impl ServerConnectionHint {
    
    #[must_use]
    pub fn probe_default(fast_key_length: FastKeyLengthField, rsa_public_key_der: Bytes) -> Self {
        Self {
            enable_server_log: false,
            fallback_method: 0,
            message_max_length: 1_048_576,
            idle_timeout: 900.0,
            direct_p2p_start_condition: 1,
            over_send_suspecting_threshold_in_bytes: 15_360,
            enable_nagle_algorithm: true,
            encrypted_message_key_length: 256,
            fast_encrypted_message_key_length: fast_key_length,
            allow_server_as_p2p_group_member: false,
            enable_p2p_encrypted_messaging: false,
            upnp_detect_nat_device: true,
            upnp_tcp_addr_port_mapping: true,
            enable_lookahead_p2p_send: false,
            enable_ping_test: false,
            emergency_log_line_count: 0,
            rsa_public_key_der,
            trailing: Bytes::new(),
        }
    }

pub fn encode_payload(&self) -> Result<Bytes, HandshakeError> {
        let key_len = Scalar::try_from(self.rsa_public_key_der.len())?;
        let mut output = BytesMut::with_capacity(
            1 + 38 + key_len.encoded_len() + self.rsa_public_key_der.len() + self.trailing.len(),
        );

        output.put_u8(NOTIFY_SERVER_CONNECTION_HINT);
        put_bool(&mut output, self.enable_server_log);
        output.put_u8(self.fallback_method);
        output.put_u32_le(self.message_max_length);
        output.put_f64_le(self.idle_timeout);
        output.put_u8(self.direct_p2p_start_condition);
        output.put_u32_le(self.over_send_suspecting_threshold_in_bytes);
        put_bool(&mut output, self.enable_nagle_algorithm);
        output.put_u32_le(self.encrypted_message_key_length);
        if let FastKeyLengthField::Present(value) = self.fast_encrypted_message_key_length {
            output.put_u32_le(value);
        }
        put_bool(&mut output, self.allow_server_as_p2p_group_member);
        put_bool(&mut output, self.enable_p2p_encrypted_messaging);
        put_bool(&mut output, self.upnp_detect_nat_device);
        put_bool(&mut output, self.upnp_tcp_addr_port_mapping);
        put_bool(&mut output, self.enable_lookahead_p2p_send);
        put_bool(&mut output, self.enable_ping_test);
        output.put_u32_le(self.emergency_log_line_count);
        key_len.encode(&mut output);
        output.extend_from_slice(&self.rsa_public_key_der);
        output.extend_from_slice(&self.trailing);
        Ok(output.freeze())
    }

pub fn decode_payload(
        payload: Bytes,
        fast_key_layout: FastKeyLengthLayout,
        max_rsa_public_key_len: usize,
    ) -> Result<Self, HandshakeError> {
        let mut offset = 0;
        expect_opcode(&payload, &mut offset, NOTIFY_SERVER_CONNECTION_HINT)?;
        let enable_server_log = read_bool(&payload, &mut offset, "enable_server_log")?;
        let fallback_method = read_u8(&payload, &mut offset, "fallback_method")?;
        let message_max_length = read_u32(&payload, &mut offset, "message_max_length")?;
        let idle_timeout = read_f64(&payload, &mut offset, "idle_timeout")?;
        let direct_p2p_start_condition =
            read_u8(&payload, &mut offset, "direct_p2p_start_condition")?;
        let over_send_suspecting_threshold_in_bytes = read_u32(
            &payload,
            &mut offset,
            "over_send_suspecting_threshold_in_bytes",
        )?;
        let enable_nagle_algorithm = read_bool(&payload, &mut offset, "enable_nagle_algorithm")?;
        let encrypted_message_key_length =
            read_u32(&payload, &mut offset, "encrypted_message_key_length")?;
        let fast_encrypted_message_key_length = match fast_key_layout {
            FastKeyLengthLayout::Absent => FastKeyLengthField::Absent,
            FastKeyLengthLayout::Present => FastKeyLengthField::Present(read_u32(
                &payload,
                &mut offset,
                "fast_encrypted_message_key_length",
            )?),
        };
        let allow_server_as_p2p_group_member =
            read_bool(&payload, &mut offset, "allow_server_as_p2p_group_member")?;
        let enable_p2p_encrypted_messaging =
            read_bool(&payload, &mut offset, "enable_p2p_encrypted_messaging")?;
        let upnp_detect_nat_device = read_bool(&payload, &mut offset, "upnp_detect_nat_device")?;
        let upnp_tcp_addr_port_mapping =
            read_bool(&payload, &mut offset, "upnp_tcp_addr_port_mapping")?;
        let enable_lookahead_p2p_send =
            read_bool(&payload, &mut offset, "enable_lookahead_p2p_send")?;
        let enable_ping_test = read_bool(&payload, &mut offset, "enable_ping_test")?;
        let emergency_log_line_count = read_u32(&payload, &mut offset, "emergency_log_line_count")?;
        let rsa_public_key_der = read_byte_array(
            &payload,
            &mut offset,
            "rsa_public_key_der",
            max_rsa_public_key_len,
        )?;
        let trailing = payload.slice(offset..);

        Ok(Self {
            enable_server_log,
            fallback_method,
            message_max_length,
            idle_timeout,
            direct_p2p_start_condition,
            over_send_suspecting_threshold_in_bytes,
            enable_nagle_algorithm,
            encrypted_message_key_length,
            fast_encrypted_message_key_length,
            allow_server_as_p2p_group_member,
            enable_p2p_encrypted_messaging,
            upnp_detect_nat_device,
            upnp_tcp_addr_port_mapping,
            enable_lookahead_p2p_send,
            enable_ping_test,
            emergency_log_line_count,
            rsa_public_key_der,
            trailing,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientEncryptedSessionKeys {
    
    pub encrypted_session_key: Bytes,
    
    pub encrypted_fast_session_key: Bytes,
    
    pub trailing: Bytes,
}

impl ClientEncryptedSessionKeys {
    
    pub fn decode_payload(
        payload: Bytes,
        max_session_key_blob_len: usize,
        max_fast_key_blob_len: usize,
    ) -> Result<Self, HandshakeError> {
        let mut offset = 0;
        expect_opcode(&payload, &mut offset, NOTIFY_CS_ENCRYPTED_SESSION_KEY)?;
        let encrypted_session_key = read_byte_array(
            &payload,
            &mut offset,
            "encrypted_session_key",
            max_session_key_blob_len,
        )?;
        let encrypted_fast_session_key = read_byte_array(
            &payload,
            &mut offset,
            "encrypted_fast_session_key",
            max_fast_key_blob_len,
        )?;
        let trailing = payload.slice(offset..);
        Ok(Self {
            encrypted_session_key,
            encrypted_fast_session_key,
            trailing,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConnectionRequestData {
    
    pub user_data: Bytes,
    
    pub protocol_version_guid_wire: [u8; 16],
    
    pub internal_version: u32,
    
    pub trailing: Bytes,
}

impl ServerConnectionRequestData {
    
    pub fn decode_payload(
        payload: Bytes,
        max_user_data_len: usize,
    ) -> Result<Self, HandshakeError> {
        let mut offset = 0;
        expect_opcode(&payload, &mut offset, NOTIFY_SERVER_CONNECTION_REQUEST_DATA)?;
        let user_data = read_byte_array(
            &payload,
            &mut offset,
            "connection_request_user_data",
            max_user_data_len,
        )?;
        let guid = read_exact(&payload, &mut offset, 16, "protocol_version_guid_wire")?;
        let mut protocol_version_guid_wire = [0_u8; 16];
        protocol_version_guid_wire.copy_from_slice(guid);
        let internal_version = read_u32(&payload, &mut offset, "internal_version")?;
        let trailing = payload.slice(offset..);
        Ok(Self {
            user_data,
            protocol_version_guid_wire,
            internal_version,
            trailing,
        })
    }
}

#[must_use]
pub fn session_key_success_payload() -> Bytes {
    Bytes::from_static(&[NOTIFY_CS_SESSION_KEY_SUCCESS])
}

fn put_bool(output: &mut BytesMut, value: bool) {
    output.put_u8(u8::from(value));
}

fn expect_opcode(input: &[u8], offset: &mut usize, expected: u8) -> Result<(), HandshakeError> {
    let actual = read_u8(input, offset, "opcode")?;
    if actual != expected {
        return Err(HandshakeError::WrongOpcode { expected, actual });
    }
    Ok(())
}

fn read_bool(
    input: &[u8],
    offset: &mut usize,
    field: &'static str,
) -> Result<bool, HandshakeError> {
    let value = read_u8(input, offset, field)?;
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(HandshakeError::InvalidBoolean { field, value }),
    }
}

fn read_u8(input: &[u8], offset: &mut usize, field: &'static str) -> Result<u8, HandshakeError> {
    Ok(read_exact(input, offset, 1, field)?[0])
}

fn read_u32(input: &[u8], offset: &mut usize, field: &'static str) -> Result<u32, HandshakeError> {
    let bytes = read_exact(input, offset, 4, field)?;
    Ok(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
}

fn read_f64(input: &[u8], offset: &mut usize, field: &'static str) -> Result<f64, HandshakeError> {
    let bytes = read_exact(input, offset, 8, field)?;
    Ok(f64::from_le_bytes(bytes.try_into().expect("eight bytes")))
}

fn read_byte_array(
    input: &Bytes,
    offset: &mut usize,
    field: &'static str,
    maximum: usize,
) -> Result<Bytes, HandshakeError> {
    let (length, scalar_len) = Scalar::decode(&input[*offset..])?;
    let length = usize::try_from(length.get()).map_err(|_| HandshakeError::LengthOverflow)?;
    if length > maximum {
        return Err(HandshakeError::ByteArrayTooLarge {
            field,
            length,
            maximum,
        });
    }
    *offset = offset
        .checked_add(scalar_len)
        .ok_or(HandshakeError::LengthOverflow)?;
    let start = *offset;
    let _ = read_exact(input, offset, length, field)?;
    Ok(input.slice(start..*offset))
}

fn read_exact<'a>(
    input: &'a [u8],
    offset: &mut usize,
    length: usize,
    field: &'static str,
) -> Result<&'a [u8], HandshakeError> {
    let end = offset
        .checked_add(length)
        .ok_or(HandshakeError::LengthOverflow)?;
    let Some(bytes) = input.get(*offset..end) else {
        return Err(HandshakeError::Truncated {
            field,
            needed: length,
            available: input.len().saturating_sub(*offset),
        });
    };
    *offset = end;
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HandshakeError {
    
    #[error(transparent)]
    Scalar(#[from] ScalarError),
    
    #[error("wrong handshake opcode {actual}; expected {expected}")]
    WrongOpcode { expected: u8, actual: u8 },
    
    #[error("handshake field {field} has invalid boolean byte {value}")]
    InvalidBoolean { field: &'static str, value: u8 },
    
    #[error("handshake field {field} needs {needed} byte(s), but only {available} remain")]
    Truncated {
        field: &'static str,
        needed: usize,
        available: usize,
    },
    
    #[error("handshake field {field} length {length} exceeds configured maximum {maximum}")]
    ByteArrayTooLarge {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    
    #[error("handshake payload length overflow")]
    LengthOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hint(fast_key: FastKeyLengthField) -> ServerConnectionHint {
        ServerConnectionHint {
            enable_server_log: false,
            fallback_method: 0,
            message_max_length: 1_048_576,
            idle_timeout: 900.0,
            direct_p2p_start_condition: 1,
            over_send_suspecting_threshold_in_bytes: 15_360,
            enable_nagle_algorithm: true,
            encrypted_message_key_length: 256,
            fast_encrypted_message_key_length: fast_key,
            allow_server_as_p2p_group_member: false,
            enable_p2p_encrypted_messaging: false,
            upnp_detect_nat_device: true,
            upnp_tcp_addr_port_mapping: true,
            enable_lookahead_p2p_send: false,
            enable_ping_test: false,
            emergency_log_line_count: 0,
            rsa_public_key_der: Bytes::from_static(&[0x30, 0x00]),
            trailing: Bytes::new(),
        }
    }

    #[test]
    fn field_eight_presence_moves_only_the_later_bytes() {
        let absent = hint(FastKeyLengthField::Absent).encode_payload().unwrap();
        let present = hint(FastKeyLengthField::Present(512))
            .encode_payload()
            .unwrap();

        assert_eq!(&absent[..25], &present[..25]);
        assert_eq!(&present[25..29], &[0x00, 0x02, 0x00, 0x00]);
        assert_eq!(&absent[25..], &present[29..]);
        assert_eq!(absent.len(), 39);
        assert_eq!(present.len(), 43);
        assert_eq!(&absent[35..], &[1, 2, 0x30, 0x00]);
        assert_eq!(&present[39..], &[1, 2, 0x30, 0x00]);
    }

    #[test]
    fn both_hint_layouts_round_trip_and_keep_trailing_bytes() {
        for field in [FastKeyLengthField::Absent, FastKeyLengthField::Present(512)] {
            let mut expected = hint(field);
            expected.trailing = Bytes::from_static(&[0xde, 0xad]);
            let encoded = expected.encode_payload().unwrap();
            let decoded =
                ServerConnectionHint::decode_payload(encoded.clone(), field.layout(), 1024)
                    .unwrap();
            assert_eq!(decoded, expected);
            assert_eq!(decoded.encode_payload().unwrap(), encoded);
        }
    }

    #[test]
    fn encrypted_key_blobs_and_request_unknowns_are_retained() {
        let keys = ClientEncryptedSessionKeys::decode_payload(
            Bytes::from_static(&[5, 1, 2, 0xaa, 0xbb, 1, 1, 0xcc, 0xdd]),
            16,
            16,
        )
        .unwrap();
        assert_eq!(keys.encrypted_session_key, &[0xaa, 0xbb][..]);
        assert_eq!(keys.encrypted_fast_session_key, &[0xcc][..]);
        assert_eq!(keys.trailing, &[0xdd][..]);

        let mut request = vec![7, 1, 2, 0x10, 0x20];
        request.extend(0_u8..16);
        request.extend_from_slice(&196_980_u32.to_le_bytes());
        request.push(0xee);
        let decoded =
            ServerConnectionRequestData::decode_payload(Bytes::from(request), 16).unwrap();
        assert_eq!(decoded.user_data, &[0x10, 0x20][..]);
        assert_eq!(
            decoded.protocol_version_guid_wire,
            std::array::from_fn(|i| i as u8)
        );
        assert_eq!(decoded.internal_version, 196_980);
        assert_eq!(decoded.trailing, &[0xee][..]);
    }

    #[test]
    fn wrong_opcode_invalid_boolean_and_limits_fail_closed() {
        let encoded = hint(FastKeyLengthField::Absent).encode_payload().unwrap();
        let mut wrong_opcode = BytesMut::from(&encoded[..]);
        wrong_opcode[0] = 5;
        assert!(matches!(
            ServerConnectionHint::decode_payload(
                wrong_opcode.freeze(),
                FastKeyLengthLayout::Absent,
                1024
            ),
            Err(HandshakeError::WrongOpcode { .. })
        ));

        let mut bad_bool = BytesMut::from(&encoded[..]);
        bad_bool[1] = 2;
        assert!(matches!(
            ServerConnectionHint::decode_payload(
                bad_bool.freeze(),
                FastKeyLengthLayout::Absent,
                1024
            ),
            Err(HandshakeError::InvalidBoolean { .. })
        ));

        assert!(matches!(
            ServerConnectionHint::decode_payload(encoded, FastKeyLengthLayout::Absent, 1),
            Err(HandshakeError::ByteArrayTooLarge { .. })
        ));
    }

    #[test]
    fn session_key_success_is_opcode_only() {
        assert_eq!(session_key_success_payload(), &[6][..]);
    }
}
