

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::{Parser, ValueEnum};
use goley_server::{AuthServer, AuthServerConfig, EntryServer, EntryServerConfig, LobbyServer, LobbyServerConfig, VariantChoice};
use proudnet::ServerRsaKeys;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliVariant {
    
    A,
    
    B,
}

impl From<CliVariant> for VariantChoice {
    fn from(v: CliVariant) -> Self {
        match v {
            CliVariant::A => Self::VariantA,
            CliVariant::B => Self::VariantB,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "goley-server",
    about = "Goley server emulator and ProudNet handshake probe"
)]
struct Cli {
    
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

#[arg(short, long, default_value_t = 2270)]
    port: u16,

#[arg(long, default_value_t = 8000)]
    auth_port: u16,

#[arg(short, long, value_enum, default_value_t = CliVariant::A)]
    variant: CliVariant,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,goley_server=debug,proudnet=debug"));
    fmt().with_env_filter(filter).init();

    let args = Cli::parse();

    let bind_ip: std::net::IpAddr = args.bind.parse()?;
    let bind_addr = SocketAddr::new(bind_ip, args.port);
    let auth_addr = SocketAddr::new(bind_ip, args.auth_port);
    let variant: VariantChoice = args.variant.into();

    info!(
        event_type = "server_init",
        entry_bind_addr = %bind_addr,
        auth_bind_addr = %auth_addr,
        variant = variant.label(),
        "Initializing Goley Combined Emulator Server"
    );

info!("Generating 2048-bit RSA keypair...");
    let rsa_keys = Arc::new(ServerRsaKeys::generate()?);
    info!(
        public_key_der_len = rsa_keys.public_key_pkcs1_der().len(),
        "RSA keypair generated successfully (PKCS#1 DER public key is {} bytes)",
        rsa_keys.public_key_pkcs1_der().len()
    );

    let auth_config = AuthServerConfig {
        bind_addr: auth_addr,
    };
    let auth_server = AuthServer::new(auth_config);

    let entry_config = EntryServerConfig { bind_addr, variant };
    let entry_server = EntryServer::new(entry_config, Arc::clone(&rsa_keys));

    let lobby_addr = SocketAddr::new(bind_ip, 2271);
    let lobby_config = LobbyServerConfig {
        bind_addr: lobby_addr,
        variant,
    };
    let lobby_server = LobbyServer::new(lobby_config, Arc::clone(&rsa_keys));

    tokio::try_join!(auth_server.run(), entry_server.run(), lobby_server.run())?;

    Ok(())
}
