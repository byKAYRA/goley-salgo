

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use proudnet::ServerRsaKeys;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::auth::{
    build_auth_response_frame, decrypt_payload, remove_dummy,
};
use crate::entry::{descramble_opcode, scramble_opcode, VariantChoice};

#[derive(Debug, Clone)]
pub struct LobbyServerConfig {
    pub bind_addr: SocketAddr,
    pub variant: VariantChoice,
}

pub struct LobbyServer {
    config: LobbyServerConfig,
    rsa_keys: Arc<ServerRsaKeys>,
}

impl LobbyServer {
    #[must_use]
    pub fn new(config: LobbyServerConfig, rsa_keys: Arc<ServerRsaKeys>) -> Self {
        Self { config, rsa_keys }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .with_context(|| format!("Failed to bind lobby server to {}", self.config.bind_addr))?;

        info!(
            event_type = "lobby_server_started",
            bind_addr = %self.config.bind_addr,
            "Lobby server listening on {}", self.config.bind_addr
        );

        loop {
            let (stream, peer_addr) = listener
                .accept()
                .await
                .context("Failed to accept TCP connection")?;

            let rsa_keys = Arc::clone(&self.rsa_keys);
            let variant = self.config.variant;

            tokio::spawn(async move {
                if let Err(err) = handle_lobby_connection(stream, peer_addr, variant, rsa_keys)
                    .await
                {
                    error!(
                        event_type = "lobby_connection_error",
                        peer_addr = %peer_addr,
                        error = %err,
                        "Error handling lobby client connection"
                    );
                }
            });
        }
    }
}

async fn handle_lobby_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    _variant: VariantChoice,
    _rsa_keys: Arc<ServerRsaKeys>,
) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    let mut response_seq = 0u8;
    let mut setup_sent = false;

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .context("Failed to read from lobby connection")?;
        if n == 0 {
            info!(
                event_type = "lobby_client_eof",
                peer_addr = %peer_addr,
                "Client closed the lobby connection"
            );
            return Ok(());
        }

        info!(
            event_type = "lobby_raw_bytes",
            peer_addr = %peer_addr,
            bytes_count = n,
            hex_dump = %hex::encode(&buf[..n]),
            "Received {} raw bytes on lobby port",
            n
        );
        pending.extend_from_slice(&buf[..n]);

        while pending.len() >= 4 {
            if pending[0] != 0x32 {
                warn!(
                    event_type = "lobby_bad_magic",
                    peer_addr = %peer_addr,
                    first_byte = format!("0x{:02x}", pending[0]),
                    "Frame does not start with AniPark magic 0x32; dropping buffer"
                );
                pending.clear();
                break;
            }
            let payload_len = u16::from_le_bytes([pending[1], pending[2]]) as usize;
            let frame_total = 4 + payload_len;
            if pending.len() < frame_total {
                break;
            }

            let client_seq = pending[3];
            let clean = remove_dummy(&pending[4..frame_total], payload_len);
            let decrypted = decrypt_payload(&clean, client_seq);
            pending.drain(..frame_total);

            let opcode_dword = if decrypted.len() >= 4 {
                u32::from_le_bytes([decrypted[0], decrypted[1], decrypted[2], decrypted[3]])
            } else {
                0
            };
            let (main, sub) = descramble_opcode(opcode_dword);

            info!(
                event_type = "lobby_frame_decrypted",
                peer_addr = %peer_addr,
                client_seq = client_seq,
                opcode_main = main,
                opcode_sub = sub,
                opcode_dword = format!("0x{opcode_dword:08x}"),
                decrypted_len = decrypted.len(),
                decrypted_hex = %hex::encode(&decrypted),
                "Lobby frame: opcode (main={main}, sub={sub})"
            );

            if main == 0 && sub == 0 && !setup_sent {
                
                let mut plain_setup = [0u8; 28];
                plain_setup[13..24].copy_from_slice(b"RealMadrid\0");
                let frame = build_auth_response_frame(&plain_setup, response_seq, 36);
                stream
                    .write_all(&frame)
                    .await
                    .context("Failed to send lobby cipher-setup frame")?;
                stream
                    .flush()
                    .await
                    .context("Failed to flush lobby cipher-setup frame")?;
                info!(
                    event_type = "lobby_setup_sent",
                    peer_addr = %peer_addr,
                    seq = response_seq,
                    frame_len = frame.len(),
                    "Sent lobby (0,0) cipher-setup reply"
                );
                response_seq = response_seq.wrapping_add(1);

let mut plain_login = [0u8; 28];
                plain_login[0..4].copy_from_slice(&scramble_opcode(0, 0x01).to_le_bytes());
                plain_login[4..15].copy_from_slice(b"RealMadrid\0");
                plain_login[0x0F] = 0;
                let login_frame = build_auth_response_frame(&plain_login, response_seq, 36);
                stream
                    .write_all(&login_frame)
                    .await
                    .context("Failed to send lobby login-ok frame")?;
                stream.flush().await.context("Failed to flush lobby login-ok frame")?;
                info!(
                    event_type = "lobby_login_ok_sent",
                    peer_addr = %peer_addr,
                    seq = response_seq,
                    "Sent lobby (0, 0x01) LOGIN-OK"
                );
                response_seq = response_seq.wrapping_add(1);

let mut plain_channel = [0u8; 28];
                plain_channel[0..4].copy_from_slice(&scramble_opcode(0, 0x03).to_le_bytes());
                plain_channel[7] = 1;
                let channel_frame = build_auth_response_frame(&plain_channel, response_seq, 36);
                stream
                    .write_all(&channel_frame)
                    .await
                    .context("Failed to send lobby channel-init frame")?;
                stream.flush().await.context("Failed to flush lobby channel-init frame")?;
                info!(
                    event_type = "lobby_channel_init_sent",
                    peer_addr = %peer_addr,
                    seq = response_seq,
                    "Sent lobby (0, 0x03) Channel Init"
                );
                response_seq = response_seq.wrapping_add(1);
                setup_sent = true;
            } else {
                match (main, sub) {
                    
                    _ => {
                        info!(
                            event_type = "lobby_opportunity",
                            peer_addr = %peer_addr,
                            opcode_main = main,
                            opcode_sub = sub,
                            decrypted_len = decrypted.len(),
                            decrypted_hex = %hex::encode(&decrypted),
                            "Lobby received opcode ({main},{sub}) — logging for RE"
                        );
                    }
                }
            }
        }
    }
}
