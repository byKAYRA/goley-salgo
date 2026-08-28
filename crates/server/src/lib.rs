

pub mod auth;
pub mod entry;
pub mod lobby;

pub use auth::{AuthServer, AuthServerConfig};
pub use entry::{EntryServer, EntryServerConfig, VariantChoice};
pub use lobby::{LobbyServer, LobbyServerConfig};

pub const SERVICE_ROLES: &[&str] = &["entry", "lobby", "battle"];
