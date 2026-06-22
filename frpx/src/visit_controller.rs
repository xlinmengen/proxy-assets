use serde_json::{Value, json};
use anyhow::Result;
use tracing::error;

pub struct VisitController {
    api_callback: Box<dyn Fn(String, String, Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(bool, u16, String)>> + Send>> + Send + Sync>,
}

impl VisitController {
    pub fn new<F>(api: F) -> Self
    where
        F: Fn(String, String, Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(bool, u16, String)>> + Send>> + Send + Sync + 'static,
    {
        Self { api_callback: Box::new(api) }
    }

    pub async fn get_config(&self) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), "store/visitors".to_string(), Value::Null).await?;
        if ok { serde_json::from_str(&body).map(|v| (true, v)).or(Ok((false, Value::Null))) } else { Ok((false, Value::Null)) }
    }

    pub async fn add_stcp(&self, name: &str, bind_port: u16, server_name: &str, secret_key: &str) -> Result<(bool, Value)> {
        let payload = json!({ "name": name, "type": "stcp", "stcp": { "bindPort": bind_port, "serverName": server_name, "secretKey": secret_key } });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/visitors".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_sudp(&self, name: &str, bind_port: u16, server_name: &str, secret_key: &str) -> Result<(bool, Value)> {
        let payload = json!({ "name": name, "type": "sudp", "sudp": { "bindPort": bind_port, "serverName": server_name, "secretKey": secret_key } });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/visitors".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_xtcp(&self, name: &str, bind_port: u16, server_name: &str, secret_key: &str) -> Result<(bool, Value)> {
        let payload = json!({ "name": name, "type": "xtcp", "xtcp": { "bindPort": bind_port, "serverName": server_name, "secretKey": secret_key } });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/visitors".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn get(&self, name: &str) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), format!("store/visitors/{}", name), Value::Null).await?;
        if ok {
            match serde_json::from_str::<Value>(&body) {
                Ok(info) => {
                    let typ = info.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let result = json!({
                        "name": name,
                        "type": typ,
                        "enabled": info[&typ]["enabled"].as_bool().unwrap_or(true),
                        "bindport": info[&typ]["bindPort"].as_u64().unwrap_or(80),
                        "servername": info[&typ]["serverName"].as_str().unwrap_or(""),
                        "secretkey": info[&typ]["secretKey"].as_str().unwrap_or(""),
                    });
                    Ok((true, result))
                }
                Err(e) => { error!("解析 get 响应失败: {}", e); Ok((false, Value::Null)) }
            }
        } else { Ok((false, Value::Null)) }
    }

    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), format!("store/visitors/{}", name), Value::Null).await?;
        if !ok { return Ok((false, json!({ "error": "Failed to get visitor" }))); }
        let mut info: Value = serde_json::from_str(&body)?;
        let typ = info.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if typ.is_empty() { return Ok((false, json!({ "error": "Invalid visitor type" }))); }
        if let Some(obj) = info.get_mut(&typ) { obj["enabled"] = json!(enabled); }
        let (ok2, code, body2) = (self.api_callback)("PUT".to_string(), format!("store/visitors/{}", name), info).await?;
        Ok((ok2 && code == 200, if ok2 && code == 200 { json!({ "success": true }) } else { json!({ "error": body2 }) }))
    }

    pub async fn delete(&self, name: &str) -> Result<(bool, Value)> {
        let (ok, code, body) = (self.api_callback)("DELETE".to_string(), format!("store/visitors/{}", name), Value::Null).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn update(&self, name: &str, bind_port: u16, server_name: &str, secret_key: &str) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), format!("store/visitors/{}", name), Value::Null).await?;
        if !ok { return Ok((false, json!({ "error": "Failed to get visitor" }))); }
        let info: Value = serde_json::from_str(&body)?;
        let typ = info.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if typ.is_empty() { return Ok((false, json!({ "error": "Invalid visitor type" }))); }
        let payload = json!({ "name": name, "type": typ, typ: { "bindPort": bind_port, "serverName": server_name, "secretKey": secret_key } });
        let (ok2, code, body2) = (self.api_callback)("PUT".to_string(), format!("store/visitors/{}", name), payload).await?;
        Ok((ok2 && code == 200, if ok2 && code == 200 { json!({ "success": true }) } else { json!({ "error": body2 }) }))
    }
}