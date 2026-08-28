

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::BytesMut;
use proudnet::{
    ClientEncryptedSessionKeys, FastKeyLengthField, Frame, FrameCodec,
    NOTIFY_CS_ENCRYPTED_SESSION_KEY, ServerConnectionHint, ServerRsaKeys,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{error, info, warn};

use crate::auth::{build_auth_response_frame, decrypt_payload, remove_dummy, wire_len_for};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VariantChoice {
    
    #[default]
    VariantA,
    
    VariantB,
}

impl VariantChoice {
    
    #[must_use]
    pub const fn fast_key_field(self) -> FastKeyLengthField {
        match self {
            Self::VariantA => FastKeyLengthField::Present(512),
            Self::VariantB => FastKeyLengthField::Absent,
        }
    }

#[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VariantA => "Variant A (field-8 present, 317 bytes)",
            Self::VariantB => "Variant B (field-8 absent, 313 bytes)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntryServerConfig {
    
    pub bind_addr: SocketAddr,
    
    pub variant: VariantChoice,
}

impl Default for EntryServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 2270)),
            variant: VariantChoice::VariantA,
        }
    }
}

pub struct EntryServer {
    config: EntryServerConfig,
    rsa_keys: Arc<ServerRsaKeys>,
}

impl EntryServer {
    
    #[must_use]
    pub fn new(config: EntryServerConfig, rsa_keys: Arc<ServerRsaKeys>) -> Self {
        Self { config, rsa_keys }
    }

pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.config.bind_addr)
            .await
            .with_context(|| format!("Failed to bind entry server to {}", self.config.bind_addr))?;

        info!(
            event_type = "entry_server_started",
            bind_addr = %self.config.bind_addr,
            variant = self.config.variant.label(),
            rsa_public_key_len = self.rsa_keys.public_key_pkcs1_der().len(),
            "Entry server listening on {}", self.config.bind_addr
        );

        loop {
            let (stream, peer_addr) = listener
                .accept()
                .await
                .context("Failed to accept TCP connection")?;

            info!(
                event_type = "client_connected",
                peer_addr = %peer_addr,
                "New client connection accepted"
            );

            let rsa_keys = Arc::clone(&self.rsa_keys);
            let variant = self.config.variant;

            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, peer_addr, variant, rsa_keys).await {
                    error!(
                        event_type = "connection_error",
                        peer_addr = %peer_addr,
                        error = %err,
                        "Error handling client connection"
                    );
                }
            });
        }
    }
}

const OPCODE_SCRAMBLE_K: u32 = 0xAAF2_9BF3;

#[must_use]
pub const fn descramble_opcode(dword: u32) -> (u8, u8) {
    let v = dword.wrapping_mul(OPCODE_SCRAMBLE_K) >> 16;
    (((v >> 8) & 0xFF) as u8, (v & 0xFF) as u8)
}

const OPCODE_SCRAMBLE_K_INV: u32 = 0xA7F0_753B;

#[must_use]
pub const fn scramble_opcode(main: u8, sub: u8) -> u32 {
    let t = ((main as u32) << 8) | (sub as u32);
    (t << 16).wrapping_mul(OPCODE_SCRAMBLE_K_INV)
}

const STARTER_RECORD_SIZE: usize = 582;

const TOURNAMENT_RECORD_SIZE: usize = 208; 

const LEAGUE_CATEGORIES: [u32; 5] = [7, 3, 4, 8, 100];
const LEAGUE_NAMES: [&str; 5] = ["Süper Lig", "G.Avrupa", "B.Avrupa", "K.Avrupa", "K-Lig"];

fn build_tournament_records() -> Vec<u8> {
    let mut payload = vec![0u8; 9 + 5 * TOURNAMENT_RECORD_SIZE];
    payload[0..4].copy_from_slice(&scramble_opcode(3, 4).to_le_bytes());
    payload[7] = 0; 
    payload[8] = 5; 

    for i in 0..5 {
        let tid = LEAGUE_CATEGORIES[i];
        let off = 9 + i * TOURNAMENT_RECORD_SIZE;
        let rec = &mut payload[off..off + TOURNAMENT_RECORD_SIZE];

rec[0..4].copy_from_slice(&tid.to_le_bytes());

rec[4..8].copy_from_slice(&1u32.to_le_bytes());

rec[8..12].copy_from_slice(&1u32.to_le_bytes());

let name_str = LEAGUE_NAMES[i];
        let name_u16: Vec<u16> = name_str.encode_utf16().collect();
        for (idx, c) in name_u16.iter().enumerate() {
            if 0x0C + idx * 2 + 1 < 0x4C {
                let b = c.to_le_bytes();
                rec[0x0C + idx * 2] = b[0];
                rec[0x0C + idx * 2 + 1] = b[1];
            }
        }

rec[0xAC] = 1;
        rec[0xB5] = 1;
        rec[0xCC] = 1;
    }

    payload
}

#[allow(dead_code)]
fn build_tutorial_match_frame() -> Vec<u8> {
    let mut payload = vec![0u8; 64];
    payload[0..4].copy_from_slice(&scramble_opcode(2, 0).to_le_bytes());

payload[9] = 1;

let home_club_id: u32 = 1001;
    let away_club_id: u32 = 2001;
    let stadium_id: u32 = 1;
    let weather_id: u32 = 0;
    let duration: u32 = 5;
    let difficulty: u32 = 1;
    let ball_id: u32 = 1;
    let camera_id: u32 = 1;

    payload[0x0C..0x10].copy_from_slice(&home_club_id.to_le_bytes());
    payload[0x10..0x14].copy_from_slice(&away_club_id.to_le_bytes());
    payload[0x14..0x18].copy_from_slice(&stadium_id.to_le_bytes());
    payload[0x18..0x1C].copy_from_slice(&weather_id.to_le_bytes());
    payload[0x1C..0x20].copy_from_slice(&duration.to_le_bytes());
    payload[0x20..0x24].copy_from_slice(&difficulty.to_le_bytes());
    payload[0x24..0x28].copy_from_slice(&ball_id.to_le_bytes());
    payload[0x28..0x2C].copy_from_slice(&camera_id.to_le_bytes());

    payload
}

fn build_league_clubs_records() -> Vec<u8> {
    let mut payload = vec![0u8; 5 + 5 * 255];
    payload[0..4].copy_from_slice(&scramble_opcode(5, 4).to_le_bytes());

    for league_idx in 0..5 {
        let block_offset = 5 + league_idx * 255;
        let block = &mut payload[block_offset..block_offset + 255];

        let cat_id = LEAGUE_CATEGORIES[league_idx];
        block[0..4].copy_from_slice(&cat_id.to_le_bytes());
        block[4] = 1; 

        let club_ids: &[u32] = match cat_id {
            3 => &[1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016],
            4 => &[2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014],
            7 => &[3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010],
            8 => &[4001],
            _ => &[1001, 2001, 3001],
        };

        for (i, &cid) in club_ids.iter().enumerate() {
            let off = 8 + i * 12;
            if off + 4 <= 255 {
                block[off..off + 4].copy_from_slice(&cid.to_le_bytes());
                block[off + 4] = 1; 
            }
        }
    }

    payload
}

fn build_starter_league_records() -> Vec<u8> {
    let mut records = vec![0u8; 5 * STARTER_RECORD_SIZE];

    for category_idx in 0..5 {
        let category_id = LEAGUE_CATEGORIES[category_idx];
        let rec = &mut records
            [category_idx * STARTER_RECORD_SIZE..(category_idx + 1) * STARTER_RECORD_SIZE];

rec[0..4].copy_from_slice(&category_id.to_le_bytes());

rec[4] = 1;

let name_str = LEAGUE_NAMES[category_idx];
        let name_u16: Vec<u16> = name_str.encode_utf16().collect();
        for (i, c) in name_u16.iter().enumerate() {
            if 8 + i * 2 + 1 < 0x28 {
                let b = c.to_le_bytes();
                rec[8 + i * 2] = b[0];
                rec[8 + i * 2 + 1] = b[1];
            }
        }

let club_ids: &[u32] = match category_id {
            3 => &[1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016],
            4 => &[2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014],
            7 => &[3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010],
            8 => &[4001, 1001, 1002],
            _ => &[1001, 2001, 3001],
        };
        for (i, &cid) in club_ids.iter().enumerate() {
            let off = 0x30 + i * 4;
            if off + 4 <= 0x47 {
                rec[off..off + 4].copy_from_slice(&cid.to_le_bytes());
            }
        }

let star_players: &[u32] = match category_id {
            3 => &[1001, 1002, 1003],
            4 => &[2001, 2002, 2003],
            7 => &[3001, 3002, 3003],
            8 => &[4001, 1001, 1002],
            _ => &[1001, 2001, 3001],
        };
        for (i, &pid) in star_players.iter().enumerate() {
            let off = 0x47 + i * 4;
            if off + 4 <= 0x53 {
                rec[off..off + 4].copy_from_slice(&pid.to_le_bytes());
            }
        }

let base_card = match category_id {
            3 => 1001u32,
            4 => 2001u32,
            7 => 3001u32,
            8 => 4001u32,
            _ => 5001u32,
        };
        for i in 0..11 {
            let off = 0xED + i * 8;
            let card_id = base_card + i as u32;
            let season_year = 2013u32;
            rec[off..off + 4].copy_from_slice(&card_id.to_le_bytes());
            rec[off + 4..off + 8].copy_from_slice(&season_year.to_le_bytes());
        }
    }

    records
}

fn build_player_summary_record() -> Vec<u8> {
    let mut p = vec![0u8; 4 + 5 + 73];
    p[0..4].copy_from_slice(&scramble_opcode(5, 5).to_le_bytes());

p[9..13].copy_from_slice(&100u32.to_le_bytes());
    p
}

fn build_multi_league_records() -> Vec<u8> {
    let starter = build_starter_league_records();
    let mut p = vec![0u8; 4 + 5 * STARTER_RECORD_SIZE];
    p[0..4].copy_from_slice(&scramble_opcode(7, 0).to_le_bytes());
    p[4..4 + starter.len()].copy_from_slice(&starter);
    p
}

async fn send_entry_frame(
    stream: &mut TcpStream,
    peer_addr: SocketAddr,
    seq: &mut u8,
    plain: &[u8],
    label: &'static str,
    main: u8,
    sub: u8,
) -> Result<()> {
    let wire = wire_len_for(plain.len());
    let frame = build_auth_response_frame(plain, *seq, wire);
    stream
        .write_all(&frame)
        .await
        .context("Failed to send entry reply frame")?;
    stream
        .flush()
        .await
        .context("Failed to flush entry reply frame")?;
    info!(
        event_type = "entry_reply_sent",
        peer_addr = %peer_addr,
        label = label,
        opcode_main = main,
        opcode_sub = sub,
        seq = *seq,
        plain_len = plain.len(),
        wire_len = wire,
        frame_len = frame.len(),
        "Replied to ({main}, {sub}) [{label}]"
    );
    *seq = seq.wrapping_add(1);
    Ok(())
}

async fn handle_anipark_connection(
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
            .context("Failed to read from AniPark entry connection")?;
        if n == 0 {
            info!(
                event_type = "entry_client_eof",
                peer_addr = %peer_addr,
                unparsed = pending.len(),
                "Client closed the 2270 connection"
            );
            return Ok(());
        }

        info!(
            event_type = "entry_raw_bytes",
            peer_addr = %peer_addr,
            bytes_count = n,
            hex_dump = %hex::encode(&buf[..n]),
            "Received {} raw bytes on entry port 2270",
            n
        );
        pending.extend_from_slice(&buf[..n]);

        while pending.len() >= 4 {
            if pending[0] != 0x32 {
                warn!(
                    event_type = "entry_bad_magic",
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
                event_type = "entry_frame_decrypted",
                peer_addr = %peer_addr,
                client_seq = client_seq,
                opcode_main = main,
                opcode_sub = sub,
                opcode_dword = format!("0x{opcode_dword:08x}"),
                decrypted_len = decrypted.len(),
                decrypted_hex = %hex::encode(&decrypted),
                "Entry frame: opcode (main={main}, sub={sub})"
            );

            if main == 0 && sub == 0 && !setup_sent {

let mut plain_setup = [0u8; 28];
                plain_setup[13..24].copy_from_slice(b"RealMadrid\0");
                let frame = build_auth_response_frame(&plain_setup, response_seq, 36);

                stream
                    .write_all(&frame)
                    .await
                    .context("Failed to send entry cipher-setup frame")?;
                stream
                    .flush()
                    .await
                    .context("Failed to flush entry cipher-setup frame")?;

                info!(
                    event_type = "entry_setup_sent",
                    peer_addr = %peer_addr,
                    seq = response_seq,
                    frame_len = frame.len(),
                    hex_dump = %hex::encode(&frame),
                    "Sent (0,0) cipher-setup reply; this should set client state 0x200D=2 \
                     and enable the entry dispatcher"
                );
                response_seq = response_seq.wrapping_add(1);

if std::env::var_os("GOLEY_PROBE_DISCONNECT").is_some() {
                    let mut probe = [0u8; 28];
                    probe[0..4].copy_from_slice(&scramble_opcode(0, 0x02).to_le_bytes());
                    probe[9] = 0x7F; 
                    let probe_frame = build_auth_response_frame(&probe, response_seq, 36);
                    stream
                        .write_all(&probe_frame)
                        .await
                        .context("Failed to send disconnect probe")?;
                    stream.flush().await.context("Failed to flush probe")?;
                    info!(
                        event_type = "entry_disconnect_probe_sent",
                        peer_addr = %peer_addr,
                        seq = response_seq,
                        opcode_dword = format!("0x{:08x}", scramble_opcode(0, 0x02)),
                        hex_dump = %hex::encode(&probe_frame),
                        "PROBE: sent (0, 0x02) forced-disconnect. If the client closes \
                         the socket, our frames are being decrypted and dispatched."
                    );
                    response_seq = response_seq.wrapping_add(1);
                    setup_sent = true;
                    continue;
                }

let mut plain_login = [0u8; 28];
                plain_login[0..4].copy_from_slice(&scramble_opcode(0, 0x01).to_le_bytes());
                plain_login[4..15].copy_from_slice(b"RealMadrid\0");
                plain_login[0x0F] = 0;
                let login_frame = build_auth_response_frame(&plain_login, response_seq, 36);
                stream
                    .write_all(&login_frame)
                    .await
                    .context("Failed to send entry login-ok frame")?;
                stream.flush().await.context("Failed to flush login-ok frame")?;
                info!(
                    event_type = "entry_login_ok_sent",
                    peer_addr = %peer_addr,
                    seq = response_seq,
                    opcode_dword = format!("0x{:08x}", scramble_opcode(0, 0x01)),
                    frame_len = login_frame.len(),
                    hex_dump = %hex::encode(&login_frame),
                    "Sent (0, 0x01) LOGIN-OK (status=0) - expect the client to start sending requests"
                );
                response_seq = response_seq.wrapping_add(1);

let mut plain_channel = [0u8; 28];
                plain_channel[0..4].copy_from_slice(&scramble_opcode(0, 0x03).to_le_bytes());
                plain_channel[7] = 1;
                let channel_frame = build_auth_response_frame(&plain_channel, response_seq, 36);
                stream
                    .write_all(&channel_frame)
                    .await
                    .context("Failed to send channel config frame")?;
                stream.flush().await.context("Failed to flush channel config frame")?;
                info!(
                    event_type = "entry_channel_init_sent",
                    peer_addr = %peer_addr,
                    seq = response_seq,
                    opcode_dword = format!("0x{:08x}", scramble_opcode(0, 0x03)),
                    frame_len = channel_frame.len(),
                    hex_dump = %hex::encode(&channel_frame),
                    "Sent (0, 0x03) Channel/Server Feature Init (status=1)"
                );
                response_seq = response_seq.wrapping_add(1);
                setup_sent = true;
            } else {
                match (main, sub) {

(3, 4) => {
                        let p = build_tournament_records();
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "3-4 active tournaments",
                            3,
                            4,
                        )
                        .await?;
                    }

(0x6A, 0) => {
                        let mut p = [0u8; 28];
                        p[0..4].copy_from_slice(&scramble_opcode(0x6A, 0).to_le_bytes());
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "6A-0",
                            0x6A,
                            0,
                        )
                        .await?;
                    }

(5, 0) => {
                        let team_name_raw = if decrypted.len() > 12 {
                            &decrypted[12..]
                        } else {
                            &[]
                        };
                        let team_name_u16: Vec<u16> = team_name_raw
                            .chunks_exact(2)
                            .take_while(|c| c != &[0, 0])
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        let team_name = String::from_utf16_lossy(&team_name_u16);
                        let action_flag = if decrypted.len() >= 12 {
                            u32::from_le_bytes([
                                decrypted[8],
                                decrypted[9],
                                decrypted[10],
                                decrypted[11],
                            ])
                        } else {
                            0
                        };

                        info!(
                            event_type = "team_name_check",
                            peer_addr = %peer_addr,
                            team_name = %team_name,
                            action_flag = action_flag,
                            "Client sent team creation action (action={action_flag})"
                        );

                        if action_flag == 0 {

let starter_records = build_starter_league_records();
                            let total_len = 0x2CC + starter_records.len();
                            let mut p = vec![0u8; total_len];
                            p[0..4].copy_from_slice(&scramble_opcode(5, 1).to_le_bytes());

let name_bytes: Vec<u8> =
                                team_name_u16.iter().flat_map(|c| c.to_le_bytes()).collect();
                            let copy_len = name_bytes.len().min(42);
                            p[8..8 + copy_len].copy_from_slice(&name_bytes[..copy_len]);

p[0xA8] = 7;

p[0x2C7] = 0;

p[0x2CC..0x2CC + starter_records.len()]
                                .copy_from_slice(&starter_records);

                            send_entry_frame(
                                &mut stream,
                                peer_addr,
                                &mut response_seq,
                                &p,
                                "5-1 name-available + starter leagues",
                                5,
                                1,
                            )
                            .await?;
                        } else {

let mut p = vec![0u8; 0x2CA];
                            p[0..4].copy_from_slice(&scramble_opcode(5, 0).to_le_bytes());

                            let name_bytes: Vec<u8> =
                                team_name_u16.iter().flat_map(|c| c.to_le_bytes()).collect();
                            let copy_len = name_bytes.len().min(42);
                            if 10 + copy_len <= p.len() {
                                p[10..10 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
                            }

send_entry_frame(
                                &mut stream,
                                peer_addr,
                                &mut response_seq,
                                &p,
                                "5-0 team-create-success",
                                5,
                                0,
                            )
                            .await?;
                        }
                    }

(5, 3) => {

let mut p = vec![0u8; 5 + 704];
                        p[0..4].copy_from_slice(&scramble_opcode(5, 3).to_le_bytes());
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "5-3 player-data-echo",
                            5,
                            3,
                        )
                        .await?;

let mut first = vec![0u8; 8 + 704];
                        first[0..4].copy_from_slice(&scramble_opcode(0, 0x09).to_le_bytes());
                        first[7] = 1; 
                        
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &first,
                            "0-09 CreateTeamPane",
                            0,
                            9,
                        )
                        .await?;
                    }

(5, 1) => {
                        let league_cat_id = if decrypted.len() >= 12 {
                            decrypted[11] as u32
                        } else {
                            7
                        };
                        info!(
                            event_type = "team_selection_confirm",
                            peer_addr = %peer_addr,
                            league_category = league_cat_id,
                            decrypted_hex = %hex::encode(&decrypted),
                            "Client confirmed team selection"
                        );

let starter_records = build_starter_league_records();
                        let cat_bytes = league_cat_id.to_le_bytes();
                        let mut selected_record = [0u8; STARTER_RECORD_SIZE];
                        for chunk in starter_records.chunks_exact(STARTER_RECORD_SIZE) {
                            if chunk[0..4] == cat_bytes {
                                selected_record.copy_from_slice(chunk);
                                break;
                            }
                        }

                        let total = 0x2CC + STARTER_RECORD_SIZE;
                        let mut p = vec![0u8; total];
                        p[0..4].copy_from_slice(&scramble_opcode(5, 1).to_le_bytes());

p[0xA8] = (league_cat_id & 0xFF) as u8;

p[0x2C7] = 0;

p[0x2CC..0x2CC + STARTER_RECORD_SIZE]
                            .copy_from_slice(&selected_record);

                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "5-1 team-selection-confirmed",
                            5,
                            1,
                        )
                        .await?;
                    }

(5, 4) => {
                        info!(
                            event_type = "league_clubs_request",
                            peer_addr = %peer_addr,
                            "Client requests league clubs data"
                        );
                        let p = build_league_clubs_records();
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "5-4 league-clubs",
                            5,
                            4,
                        )
                        .await?;
                    }

(5, 5) => {
                        info!(
                            event_type = "player_summary_request",
                            peer_addr = %peer_addr,
                            "Client requests player summary"
                        );
                        let p = build_player_summary_record();
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "5-5 player-summary",
                            5,
                            5,
                        )
                        .await?;
                    }

(7, 0) => {
                        info!(
                            event_type = "multi_league_request",
                            peer_addr = %peer_addr,
                            "Client requests multi-league records"
                        );
                        let p = build_multi_league_records();
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &p,
                            "7-0 multi-league-records",
                            7,
                            0,
                        )
                        .await?;
                    }

(7, 1) => {
                        let mut resp = vec![0u8; 16];
                        resp[0..4].copy_from_slice(&scramble_opcode(7, 1).to_le_bytes());
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &resp,
                            "7-1 correlation-ack",
                            7,
                            1,
                        )
                        .await?;
                    }
                    (7, 5) => {
                        let mut resp = vec![0u8; 16];
                        resp[0..4].copy_from_slice(&scramble_opcode(7, 5).to_le_bytes());
                        send_entry_frame(
                            &mut stream,
                            peer_addr,
                            &mut response_seq,
                            &resp,
                            "7-5 starter league query response",
                            7,
                            5,
                        )
                        .await?;
                    }
                    _ => {
                        info!(
                            event_type = "entry_awaiting_measurement",
                            peer_addr = %peer_addr,
                            opcode_main = main,
                            opcode_sub = sub,
                            decrypted_len = decrypted.len(),
                            decrypted_hex = %hex::encode(&decrypted),
                            "No measured reply for opcode ({main},{sub}) yet - \
                             logging full payload for RE, not guessing a reply"
                        );
                    }
                }
            }
        }
    }
}

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    variant: VariantChoice,
    rsa_keys: Arc<ServerRsaKeys>,
) -> Result<()> {

let mut peek_buf = [0u8; 1];
    let is_anipark = matches!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1000),
            stream.peek(&mut peek_buf),
        )
        .await,
        Ok(Ok(n)) if n > 0 && peek_buf[0] == 0x32
    );

    if is_anipark {
        handle_anipark_connection(stream, peer_addr, variant, rsa_keys).await
    } else {
        handle_proudnet_connection(stream, peer_addr, variant, rsa_keys, BytesMut::new()).await
    }
}

async fn handle_proudnet_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    variant: VariantChoice,
    rsa_keys: Arc<ServerRsaKeys>,
    mut decode_buf: BytesMut,
) -> Result<()> {
    let mut read_buf = [0u8; 4096];
    let mut codec = FrameCodec::new(65536);

let hint = ServerConnectionHint::probe_default(
        variant.fast_key_field(),
        rsa_keys.public_key_pkcs1_der().clone(),
    );
    let payload = hint
        .encode_payload()
        .context("Failed to encode opcode-4 payload")?;

    let mut frame_bytes = BytesMut::new();
    codec
        .encode(Frame::new(payload.clone()), &mut frame_bytes)
        .context("Failed to encode ProudNet frame")?;

    let mut hasher = Sha256::new();
    hasher.update(&frame_bytes);
    let frame_sha256 = hex::encode(hasher.finalize());

    info!(
        event_type = "handshake_opcode4_sent",
        variant = variant.label(),
        peer_addr = %peer_addr,
        frame_len = frame_bytes.len(),
        payload_len = payload.len(),
        sha256 = %frame_sha256,
        first_bytes = %hex::encode(&frame_bytes[..frame_bytes.len().min(8)]),
        hex_dump = %hex::encode(&frame_bytes),
        "Sending opcode-4 (NotifyServerConnectionHint) to ProudNet client ({} bytes)",
        frame_bytes.len()
    );

stream
        .write_all(&frame_bytes)
        .await
        .context("Failed to send opcode-4 frame to client")?;
    stream.flush().await.context("Failed to flush TCP stream")?;

    info!(
        event_type = "opcode4_flush_complete",
        peer_addr = %peer_addr,
        "Opcode-4 frame successfully written and flushed to socket. Awaiting client response..."
    );

loop {
        while let Some(frame) = codec
            .decode(&mut decode_buf)
            .context("Failed to decode ProudNet frame")?
        {
            let opcode = frame.payload.first().copied();

            info!(
                event_type = "frame_decoded",
                peer_addr = %peer_addr,
                opcode = ?opcode,
                payload_len = frame.payload.len(),
                "ProudNet frame decoded from stream"
            );

            match opcode {
                Some(NOTIFY_CS_ENCRYPTED_SESSION_KEY) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&frame.payload);
                    let payload_sha256 = hex::encode(hasher.finalize());

                    info!(
                        event_type = "handshake_opcode5_received",
                        peer_addr = %peer_addr,
                        payload_len = frame.payload.len(),
                        payload_sha256 = %payload_sha256,
                        first_bytes = %hex::encode(&frame.payload[..frame.payload.len().min(16)]),
                        hex_dump = %hex::encode(&frame.payload),
                        "SUCCESS: Received opcode-5 (NotifyCSEncryptedSessionKey) from client! Target reached."
                    );

                    match ClientEncryptedSessionKeys::decode_payload(frame.payload, 1024, 1024) {
                        Ok(keys) => {
                            info!(
                                event_type = "session_keys_parsed",
                                session_key_len = keys.encrypted_session_key.len(),
                                session_key_hex = %hex::encode(&keys.encrypted_session_key),
                                fast_key_len = keys.encrypted_fast_session_key.len(),
                                fast_key_hex = %hex::encode(&keys.encrypted_fast_session_key),
                                trailing_len = keys.trailing.len(),
                                trailing_hex = %hex::encode(&keys.trailing),
                                "Client session key blobs parsed successfully"
                            );

match rsa_keys.decrypt_oaep_sha1(&keys.encrypted_session_key) {
                                Ok(decrypted) => {
                                    info!(
                                        event_type = "rsa_oaep_sha1_success",
                                        decrypted_len = decrypted.len(),
                                        decrypted_hex = %hex::encode(&decrypted),
                                        "RSA-OAEP-SHA1 decryption succeeded! Decrypted {} bytes",
                                        decrypted.len()
                                    );
                                }
                                Err(err) => {
                                    info!(
                                        event_type = "rsa_oaep_sha1_failed",
                                        error = %err,
                                        "RSA-OAEP-SHA1 decryption failed"
                                    );
                                }
                            }

match rsa_keys.decrypt_oaep_sha256(&keys.encrypted_session_key) {
                                Ok(decrypted) => {
                                    info!(
                                        event_type = "rsa_oaep_sha256_success",
                                        decrypted_len = decrypted.len(),
                                        decrypted_hex = %hex::encode(&decrypted),
                                        "RSA-OAEP-SHA256 decryption succeeded! Decrypted {} bytes",
                                        decrypted.len()
                                    );
                                }
                                Err(err) => {
                                    info!(
                                        event_type = "rsa_oaep_sha256_failed",
                                        error = %err,
                                        "RSA-OAEP-SHA256 decryption failed"
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            error!(
                                event_type = "session_keys_decode_error",
                                error = %err,
                                "Failed to decode opcode-5 payload into ClientEncryptedSessionKeys"
                            );
                        }
                    }

                    return Ok(());
                }
                Some(other) => {
                    info!(
                        event_type = "other_opcode_received",
                        peer_addr = %peer_addr,
                        opcode = other,
                        payload_len = frame.payload.len(),
                        "Received non-opcode-5 ProudNet message from client"
                    );
                }
                None => {
                    warn!(
                        event_type = "empty_frame_received",
                        peer_addr = %peer_addr,
                        "Received empty ProudNet frame"
                    );
                }
            }
        }

        let n = stream
            .read(&mut read_buf)
            .await
            .context("Error reading from TCP stream")?;

        if n == 0 {
            info!(
                event_type = "client_eof",
                peer_addr = %peer_addr,
                "Client disconnected (EOF received). Total buffer unparsed bytes: {}",
                decode_buf.len()
            );
            break;
        }

        let raw_chunk = &read_buf[..n];
        let mut chunk_hasher = Sha256::new();
        chunk_hasher.update(raw_chunk);
        let chunk_sha256 = hex::encode(chunk_hasher.finalize());

        info!(
            event_type = "raw_bytes_received",
            peer_addr = %peer_addr,
            bytes_count = n,
            sha256 = %chunk_sha256,
            first_bytes = %hex::encode(&raw_chunk[..n.min(8)]),
            hex_dump = %hex::encode(raw_chunk),
            "Received {} raw bytes from client",
            n
        );

        decode_buf.extend_from_slice(raw_chunk);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starter_league_records_have_correct_stride_and_counts() {
        let records = build_starter_league_records();
        assert_eq!(records.len(), 5 * STARTER_RECORD_SIZE);
        assert_eq!(STARTER_RECORD_SIZE, 582);

        for i in 0..5 {
            let offset = i * STARTER_RECORD_SIZE;
            let rec = &records[offset..offset + STARTER_RECORD_SIZE];

let cat_id = u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]);
            assert_eq!(cat_id, LEAGUE_CATEGORIES[i]);

assert_eq!(rec[4], 1);

let first_club = u32::from_le_bytes([rec[0x30], rec[0x31], rec[0x32], rec[0x33]]);
            assert!(first_club > 0);

let first_card = u32::from_le_bytes([rec[0xED], rec[0xEE], rec[0xEF], rec[0xF0]]);
            let first_season = u32::from_le_bytes([rec[0xF1], rec[0xF2], rec[0xF3], rec[0xF4]]);
            assert!(first_card > 0);
            assert_eq!(first_season, 2013);
        }
    }

    #[test]
    fn opcode_scrambling_round_trips() {
        for main in [0u8, 3, 5, 106] {
            for sub in [0u8, 1, 2, 3, 4, 9] {
                let dword = scramble_opcode(main, sub);
                let (dec_main, dec_sub) = descramble_opcode(dword);
                assert_eq!(dec_main, main);
                assert_eq!(dec_sub, sub);
            }
        }
    }
}
