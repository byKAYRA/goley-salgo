

use std::net::SocketAddr;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

const KEY_STR: &[u8; 40] = b"RealMadridRealMadridRealMadridRealMadrid";

const F856B0: [usize; 17] = [0, 1, 2, 3, 3, 3, 4, 5, 6, 6, 7, 7, 8, 8, 8, 9, 10];

const F856F8: [[usize; 10]; 17] = [
    [0; 10],
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 4, 0, 0, 0, 0, 0, 0, 0, 0],
    [1, 4, 4, 0, 0, 0, 0, 0, 0, 0],
    [4, 4, 6, 0, 0, 0, 0, 0, 0, 0],
    [8, 4, 11, 0, 0, 0, 0, 0, 0, 0],
    [7, 8, 9, 11, 0, 0, 0, 0, 0, 0],
    [4, 7, 14, 13, 6, 0, 0, 0, 0, 0],
    [3, 15, 9, 16, 5, 7, 0, 0, 0, 0],
    [6, 14, 12, 14, 7, 10, 0, 0, 0, 0],
    [9, 2, 12, 14, 11, 16, 13, 0, 0, 0],
    [11, 4, 21, 12, 14, 12, 11, 0, 0, 0],
    [4, 24, 19, 6, 24, 16, 4, 10, 0, 0],
    [8, 4, 11, 17, 26, 18, 19, 26, 0, 0],
    [3, 17, 15, 19, 27, 11, 32, 34, 0, 0],
    [4, 16, 33, 26, 23, 22, 32, 15, 23, 0],
    [14, 8, 21, 29, 39, 35, 17, 32, 37, 24],
];

const F859E8: [[usize; 10]; 17] = [
    [0; 10],
    [3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [3, 3, 0, 0, 0, 0, 0, 0, 0, 0],
    [3, 1, 2, 0, 0, 0, 0, 0, 0, 0],
    [2, 3, 3, 0, 0, 0, 0, 0, 0, 0],
    [3, 2, 3, 0, 0, 0, 0, 0, 0, 0],
    [3, 3, 3, 2, 0, 0, 0, 0, 0, 0],
    [2, 2, 2, 2, 3, 0, 0, 0, 0, 0],
    [2, 2, 2, 3, 2, 2, 0, 0, 0, 0],
    [2, 3, 2, 2, 2, 2, 0, 0, 0, 0],
    [2, 3, 2, 3, 3, 3, 2, 0, 0, 0],
    [3, 2, 3, 2, 2, 3, 3, 0, 0, 0],
    [1, 3, 3, 3, 3, 2, 3, 1, 0, 0],
    [3, 3, 1, 3, 2, 3, 3, 1, 0, 0],
    [2, 1, 3, 3, 3, 2, 3, 3, 0, 0],
    [1, 3, 2, 3, 3, 2, 3, 2, 1, 0],
    [3, 3, 3, 2, 2, 3, 2, 2, 2, 3],
];

fn sub_a6a4b0(result: usize) -> usize {
    let idx = if result >= 79 {
        if result >= 150 {
            if result >= 221 {
                usize::from(result >= 281) + 15
            } else {
                usize::from(result >= 181) + 13
            }
        } else if result >= 114 {
            usize::from(result >= 130) + 11
        } else {
            usize::from(result >= 99) + 9
        }
    } else if result >= 34 {
        if result >= 57 {
            usize::from(result >= 69) + 7
        } else {
            usize::from(result >= 47) + 5
        }
    } else if result >= 17 {
        usize::from(result >= 24) + 3
    } else if result != 0 {
        usize::from(result >= 12) + 1
    } else {
        0
    };
    idx.min(16)
}

fn generate_flat_table() -> Vec<[u8; 4]> {
    let funcs: [fn(u8) -> u8; 10] = [
        |a| 255 - a,
        |a| {
            let a = a as i32;
            if (a & 1) != 0 {
                (128 - (a + 1) / 2) as u8
            } else {
                ((a + 1) / 2 + 128) as u8
            }
        },
        |a| a,
        |a| {
            let a = a as i32;
            if a > 0x7F {
                (2 * a - 256) as u8
            } else {
                (255 - 2 * a) as u8
            }
        },
        |a| (2 * a as u16) as u8,
        |a| {
            let a = a as i32;
            if (a & 1) != 0 {
                (128 - (255 - a) / 2) as u8
            } else {
                ((255 - a) / 2 + 128) as u8
            }
        },
        |a| {
            let a = a as i32;
            (255 - ((a - 128) / 8) * ((a - 128) / 8)) as u8
        },
        |a| (a >> 4) * (a >> 4),
        |a| (255_i32 - 2 * a as i32) as u8,
        |a| {
            let a = a as i32;
            if a > 0x7F {
                (511 - 2 * a) as u8
            } else {
                (2 * a) as u8
            }
        },
    ];

    let mut flat = Vec::with_capacity(2560);
    for f in funcs {
        for i in 0..=255 {
            let v = f(i as u8);
            flat.push([v, v, v, v]);
        }
    }
    flat
}

fn get_key_dwords() -> [u32; 10] {
    let mut dwords = [0u32; 10];
    for (i, chunk) in KEY_STR.chunks_exact(4).enumerate() {
        dwords[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    dwords
}

#[must_use]
pub fn remove_dummy(data: &[u8], wire_len: usize) -> Vec<u8> {
    let v4 = sub_a6a4b0(wire_len);
    let count = F856B0[v4];
    if count == 0 {
        return data.to_vec();
    }
    let f_lens = F856F8[v4];
    let d_lens = F859E8[v4];
    let mut src = 0;
    let mut out = Vec::new();
    for i in 0..count {
        let flen = f_lens[i];
        let dlen = d_lens[i];
        if src + flen <= data.len() {
            out.extend_from_slice(&data[src..src + flen]);
        }
        src += flen + dlen;
    }
    if src < data.len() {
        out.extend_from_slice(&data[src..]);
    }
    out
}

#[must_use]
pub fn wire_len_for(plain_len: usize) -> usize {
    for wire in plain_len..=plain_len + 64 {
        let v4 = sub_a6a4b0(wire);
        let count = F856B0[v4];
        let dummies: usize = F859E8[v4].iter().take(count).sum();
        if wire == plain_len + dummies {
            return wire;
        }
    }
    plain_len
}

fn add_dummy(data: &[u8], wire_len: usize) -> Vec<u8> {
    let v4 = sub_a6a4b0(wire_len);
    let count = F856B0[v4];
    if count == 0 {
        return data.to_vec();
    }
    let f_lens = F856F8[v4];
    let d_lens = F859E8[v4];
    let mut src = 0;
    let mut out = Vec::new();
    for i in 0..count {
        let flen = f_lens[i];
        let dlen = d_lens[i];
        if src + flen <= data.len() {
            out.extend_from_slice(&data[src..src + flen]);
        }
        src += flen;
        out.extend(std::iter::repeat_n(0x00, dlen));
    }
    if src < data.len() {
        out.extend_from_slice(&data[src..]);
    }
    out
}

#[must_use]
pub fn decrypt_payload(payload: &[u8], seq: u8) -> Vec<u8> {
    let table = generate_flat_table();
    let key_dwords = get_key_dwords();
    let mut data = payload.to_vec();
    let n = data.len();

let t_seq = table[seq as usize % table.len()];
    for i in 0..n {
        data[i] ^= t_seq[i % 4];
    }

for b in 0..(n / 10) {
        if (seq as usize & 0xFF) != (b & 0xFF) {
            let tb = table[b & 0xFF];
            for j in 0..10 {
                data[10 * b + j] ^= tb[j % 4];
            }
        }
    }
    let rem = n % 10;
    if rem != 0 {
        let b = n / 10;
        if (seq as usize & 0xFF) != (b & 0xFF) {
            let tb = table[b & 0xFF];
            for j in 0..rem {
                data[10 * b + j] ^= tb[j % 4];
            }
        }
    }

for i in (0..n.saturating_sub(n % 4)).step_by(4) {
        let k = key_dwords[(i / 4) % 10];
        let val = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        data[i..i + 4].copy_from_slice(&(val ^ k).to_le_bytes());
    }
    let rem_bytes = n % 4;
    if rem_bytes > 0 {
        let k_bytes = key_dwords[(n / 4) % 10].to_le_bytes();
        let start = n - rem_bytes;
        for j in 0..rem_bytes {
            data[start + j] ^= k_bytes[j];
        }
    }

    data
}

#[must_use]
pub fn encrypt_payload(plain: &[u8], seq: u8, wire_len: usize) -> Vec<u8> {
    let table = generate_flat_table();
    let key_dwords = get_key_dwords();
    let mut data = plain.to_vec();
    let n = data.len();

for i in (0..n.saturating_sub(n % 4)).step_by(4) {
        let k = key_dwords[(i / 4) % 10];
        let val = u32::from_le_bytes(data[i..i + 4].try_into().unwrap());
        data[i..i + 4].copy_from_slice(&(val ^ k).to_le_bytes());
    }
    let rem_bytes = n % 4;
    if rem_bytes > 0 {
        let k_bytes = key_dwords[(n / 4) % 10].to_le_bytes();
        let start = n - rem_bytes;
        for j in 0..rem_bytes {
            data[start + j] ^= k_bytes[j];
        }
    }

for b in 0..(n / 10) {
        if (seq as usize & 0xFF) != (b & 0xFF) {
            let tb = table[b & 0xFF];
            for j in 0..10 {
                data[10 * b + j] ^= tb[j % 4];
            }
        }
    }
    let rem = n % 10;
    if rem != 0 {
        let b = n / 10;
        if (seq as usize & 0xFF) != (b & 0xFF) {
            let tb = table[b & 0xFF];
            for j in 0..rem {
                data[10 * b + j] ^= tb[j % 4];
            }
        }
    }

let t_seq = table[seq as usize % table.len()];
    for i in 0..n {
        data[i] ^= t_seq[i % 4];
    }

    add_dummy(&data, wire_len)
}

#[must_use]
pub fn build_auth_response_frame(plain_payload: &[u8], seq: u8, wire_len: usize) -> Vec<u8> {
    let encrypted_body = encrypt_payload(plain_payload, seq, wire_len);
    let mut frame = Vec::with_capacity(4 + encrypted_body.len());
    frame.push(0x32); 
    let len_bytes = (encrypted_body.len() as u16).to_le_bytes();
    frame.extend_from_slice(&len_bytes);
    frame.push(seq);
    frame.extend_from_slice(&encrypted_body);
    frame
}

#[derive(Debug, Clone)]
pub struct AuthServerConfig {
    
    pub bind_addr: SocketAddr,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8000)),
        }
    }
}

pub struct AuthServer {
    config: AuthServerConfig,
}

impl AuthServer {
    
    #[must_use]
    pub fn new(config: AuthServerConfig) -> Self {
        Self { config }
    }

pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .with_context(|| format!("Failed to bind auth server to {}", self.config.bind_addr))?;

        info!(
            event_type = "auth_server_started",
            bind_addr = %self.config.bind_addr,
            "Auth server listening on {}", self.config.bind_addr
        );

        loop {
            let (stream, peer_addr) = listener
                .accept()
                .await
                .context("Failed to accept TCP connection on auth port")?;

            info!(
                event_type = "auth_client_connected",
                peer_addr = %peer_addr,
                "Client connected to Auth server"
            );

            tokio::spawn(async move {
                if let Err(e) = handle_auth_connection(stream, peer_addr).await {
                    error!(
                        event_type = "auth_connection_error",
                        peer_addr = %peer_addr,
                        error = %e,
                        "Error handling auth connection: {:#}", e
                    );
                }
            });
        }
    }
}

async fn handle_auth_connection(mut stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
    let mut buffer = [0u8; 4096];
    let mut response_seq = 0u8;

    loop {
        let n = match stream.read(&mut buffer).await {
            Ok(0) => {
                info!(
                    event_type = "auth_client_disconnected",
                    peer_addr = %peer_addr,
                    "Client closed auth connection"
                );
                return Ok(());
            }
            Ok(n) => n,
            Err(e) => {
                warn!(
                    event_type = "auth_read_error",
                    peer_addr = %peer_addr,
                    error = %e,
                    "Socket read error on auth connection"
                );
                return Err(e.into());
            }
        };

        let raw_bytes = &buffer[..n];
        let hash = Sha256::digest(raw_bytes);
        let sha256_hex = hex::encode(hash);
        let hex_dump = hex::encode(raw_bytes);

        info!(
            event_type = "auth_packet_received",
            peer_addr = %peer_addr,
            bytes_count = n,
            sha256 = %sha256_hex,
            hex_dump = %hex_dump,
            "Received {} raw bytes on Auth port", n
        );

if raw_bytes.len() >= 4 && raw_bytes[0] == 0x32 {
            let payload_len = u16::from_le_bytes([raw_bytes[1], raw_bytes[2]]) as usize;
            let client_seq = raw_bytes[3];
            let encrypted_payload = &raw_bytes[4..raw_bytes.len().min(4 + payload_len)];

            let clean_payload = remove_dummy(encrypted_payload, payload_len);
            let decrypted = decrypt_payload(&clean_payload, client_seq);

            info!(
                event_type = "auth_packet_decrypted",
                peer_addr = %peer_addr,
                client_seq = client_seq,
                decrypted_len = decrypted.len(),
                decrypted_hex = %hex::encode(&decrypted),
                "Decrypted AniPark Auth packet"
            );

            let response_frame = if client_seq == 0 {
                
                let mut plain_setup = [0u8; 28];
                plain_setup[13..24].copy_from_slice(b"RealMadrid\0");
                build_auth_response_frame(&plain_setup, response_seq, 36)
            } else {
                
                let mut plain_op11 = [0u8; 32];
                plain_op11[0..4].copy_from_slice(&0x7f000000u32.to_le_bytes()); 
                plain_op11[4..8].copy_from_slice(&1u32.to_le_bytes()); 
                plain_op11[8..12].copy_from_slice(&1u32.to_le_bytes()); 
                plain_op11[15..19].copy_from_slice(&1u32.to_le_bytes()); 
                plain_op11[22..24].copy_from_slice(&2270u16.to_le_bytes()); 
                plain_op11[26..30].copy_from_slice(&[213, 74, 179, 12]); 
                build_auth_response_frame(&plain_op11, response_seq, 40)
            };
            response_seq = response_seq.wrapping_add(1);

            stream
                .write_all(&response_frame)
                .await
                .context("Failed to write auth response")?;
            stream
                .flush()
                .await
                .context("Failed to flush auth response")?;

            info!(
                event_type = "auth_response_sent",
                peer_addr = %peer_addr,
                client_seq = client_seq,
                response_len = response_frame.len(),
                response_hex = %hex::encode(&response_frame),
                "Sent encrypted Auth response frame to client"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anipark_cipher_round_trip() {
        let plain = [0u8; 16];
        let encrypted = encrypt_payload(&plain, 0, 24);
        assert_eq!(encrypted.len(), 24);
        let cleaned = remove_dummy(&encrypted, 24);
        let decrypted = decrypt_payload(&cleaned, 0);
        assert_eq!(decrypted, plain);
    }
}
