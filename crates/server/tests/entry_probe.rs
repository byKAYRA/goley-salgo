use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use goley_server::VariantChoice;
use proudnet::{
    FastKeyLengthField, Frame, FrameCodec, NOTIFY_CS_ENCRYPTED_SESSION_KEY,
    NOTIFY_SERVER_CONNECTION_HINT, Scalar, ServerConnectionHint, ServerRsaKeys,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, Encoder};

#[tokio::test]
async fn entry_server_sends_variant_a_opcode4_and_receives_opcode5() {
    let rsa_keys = Arc::new(ServerRsaKeys::generate().unwrap());
    assert_eq!(rsa_keys.public_key_pkcs1_der().len(), 270);

let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = listener.local_addr().unwrap();

    let server_keys = Arc::clone(&rsa_keys);
    let server_task = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        goley_server::entry::handle_connection(
            stream,
            peer_addr,
            VariantChoice::VariantA,
            server_keys,
        )
        .await
        .unwrap();
    });

let mut client_stream = TcpStream::connect(bind_addr).await.unwrap();
    let mut codec = FrameCodec::new(65536);
    let mut read_buf = BytesMut::new();

let mut chunk = [0u8; 1024];
    let n = client_stream.read(&mut chunk).await.unwrap();
    assert!(n > 0);
    read_buf.extend_from_slice(&chunk[..n]);

    let frame = codec.decode(&mut read_buf).unwrap().expect("frame decoded");
    assert_eq!(frame.payload[0], NOTIFY_SERVER_CONNECTION_HINT);
    assert_eq!(frame.payload.len(), 312); 

let hint = ServerConnectionHint::decode_payload(
        frame.payload.clone(),
        proudnet::FastKeyLengthLayout::Present,
        1024,
    )
    .unwrap();
    assert_eq!(
        hint.fast_encrypted_message_key_length,
        FastKeyLengthField::Present(512)
    );
    assert_eq!(hint.rsa_public_key_der.len(), 270);

let mock_session_key = Bytes::from_static(&[0x11, 0x22, 0x33, 0x44]);
    let mock_fast_key = Bytes::from_static(&[0xaa, 0xbb]);
    let mut op5_payload = BytesMut::new();
    op5_payload.extend_from_slice(&[NOTIFY_CS_ENCRYPTED_SESSION_KEY]);
    Scalar::try_from(mock_session_key.len())
        .unwrap()
        .encode(&mut op5_payload);
    op5_payload.extend_from_slice(&mock_session_key);
    Scalar::try_from(mock_fast_key.len())
        .unwrap()
        .encode(&mut op5_payload);
    op5_payload.extend_from_slice(&mock_fast_key);

    let mut op5_frame_bytes = BytesMut::new();
    codec
        .encode(Frame::new(op5_payload.freeze()), &mut op5_frame_bytes)
        .unwrap();

    client_stream.write_all(&op5_frame_bytes).await.unwrap();
    client_stream.flush().await.unwrap();

drop(client_stream);

    server_task.await.unwrap();
}

#[tokio::test]
async fn entry_server_sends_variant_b_opcode4() {
    let rsa_keys = Arc::new(ServerRsaKeys::generate().unwrap());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bind_addr = listener.local_addr().unwrap();

    let server_keys = Arc::clone(&rsa_keys);
    let server_task = tokio::spawn(async move {
        let (stream, peer_addr) = listener.accept().await.unwrap();
        goley_server::entry::handle_connection(
            stream,
            peer_addr,
            VariantChoice::VariantB,
            server_keys,
        )
        .await
        .unwrap();
    });

    let mut client_stream = TcpStream::connect(bind_addr).await.unwrap();
    let mut codec = FrameCodec::new(65536);
    let mut read_buf = BytesMut::new();

    let mut chunk = [0u8; 1024];
    let n = client_stream.read(&mut chunk).await.unwrap();
    assert!(n > 0);
    read_buf.extend_from_slice(&chunk[..n]);

    let frame = codec.decode(&mut read_buf).unwrap().expect("frame decoded");
    assert_eq!(frame.payload[0], NOTIFY_SERVER_CONNECTION_HINT);
    assert_eq!(frame.payload.len(), 308); 

    let hint = ServerConnectionHint::decode_payload(
        frame.payload.clone(),
        proudnet::FastKeyLengthLayout::Absent,
        1024,
    )
    .unwrap();
    assert_eq!(
        hint.fast_encrypted_message_key_length,
        FastKeyLengthField::Absent
    );
    assert_eq!(hint.rsa_public_key_der.len(), 270);

    drop(client_stream);
    server_task.await.unwrap();
}
