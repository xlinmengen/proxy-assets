use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub username: String,
    pub password: String,
    pub server_ip: String,
    pub client_id: String,
    pub client_secret: String,
    pub mainhost: String,
    pub mainport: u16,
    pub frpc_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            server_ip: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            mainhost: "127.0.0.1".to_string(),
            mainport: 9500,
            frpc_port: 9501,
        }
    }
}

impl Settings {
    pub fn load() -> anyhow::Result<Self> {
        let path = PathBuf::from("data.db");
        if path.exists() {
            let content = fs::read_to_string(path)?;
            let mut s: Settings = serde_json::from_str(&content)?;
            if s.mainhost.is_empty() {
                s.mainhost = "127.0.0.1".to_string();
            }
            if s.mainport == 0 {
                s.mainport = 9500;
            }
            if s.frpc_port == 0 {
                s.frpc_port = 9501;
            }
            Ok(s)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        fs::write("data.db", serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn check_available(&self) -> bool {
        !self.server_ip.is_empty()
            && !self.username.is_empty()
            && !self.client_id.is_empty()
            && !self.client_secret.is_empty()
            && self.frpc_port > 0
    }

    pub fn check_password(&self, password: &str) -> bool {
        self.password.is_empty() || self.password == password
    }

    pub fn reset_all(&mut self) {
        self.username.clear();
        self.password.clear();
        self.server_ip.clear();
        self.client_id.clear();
        self.client_secret.clear();
    }
}