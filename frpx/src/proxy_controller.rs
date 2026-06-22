use serde_json::{Value, json};
use anyhow::Result;
use tracing::error;
use crate::utils::{format_local_addr, compute_cert_names};

pub struct ProxyController {
    api_callback: Box<dyn Fn(String, String, Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(bool, u16, String)>> + Send>> + Send + Sync>,
    check_cert: Box<dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync>,
    issue_cert: Box<dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync>,
}

impl ProxyController {
    pub fn new<F, C, I>(api: F, check_cert: C, issue_cert: I) -> Self
    where
        F: Fn(String, String, Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(bool, u16, String)>> + Send>> + Send + Sync + 'static,
        C: Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync + 'static,
        I: Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync + 'static,
    {
        Self { api_callback: Box::new(api), check_cert: Box::new(check_cert), issue_cert: Box::new(issue_cert) }
    }

    async fn get_type(&self, name: &str) -> Result<String> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), format!("store/proxies/{}", name), Value::Null).await?;
        if ok {
            if let Ok(info) = serde_json::from_str::<Value>(&body) {
                if let Some(typ) = info.get("type").and_then(|v| v.as_str()) {
                    return Ok(typ.to_string());
                }
            }
        }
        Ok(String::new())
    }

    pub async fn get_config(&self) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), "store/proxies".to_string(), Value::Null).await?;
        if ok { serde_json::from_str(&body).map(|v| (true, v)).or(Ok((false, Value::Null))) } else { Ok((false, Value::Null)) }
    }

    pub async fn get_status(&self) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), "status".to_string(), Value::Null).await?;
        if ok { serde_json::from_str(&body).map(|v| (true, v)).or(Ok((false, Value::Null))) } else { Ok((false, Value::Null)) }
    }

    pub async fn add_tcp(&self, name: &str, local: &str, remote_port: u16) -> Result<(bool, Value)> {
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let payload = json!({ "name": name, "type": "tcp", "tcp": { "remotePort": remote_port, "localIP": ip, "localPort": port }, "useEncryption": false, "useCompression": false });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/proxies".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_http(&self, name: &str, local: &str, domain: &str, auth: Value) -> Result<(bool, Value)> {
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let username = auth.get("username").and_then(|v| v.as_str()).unwrap_or("");
        let password = auth.get("password").and_then(|v| v.as_str()).unwrap_or("");
        let payload = json!({ "name": name, "type": "http", "http": { "customDomains": [domain], "localIP": ip, "localPort": port, "httpUser": username, "httpPassword": password }, "useEncryption": false, "useCompression": false });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/proxies".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_https(&self, name: &str, local: &str, domain: &str) -> Result<(bool, Value)> {
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let (wildcard, base_name) = compute_cert_names(domain);
        let crt_path = format!("./cert/pool/{}.crt", base_name);
        let key_path = format!("./cert/pool/{}.key", base_name);
        if !(self.check_cert)(wildcard.clone()).await { (self.issue_cert)(wildcard).await; }
        let payload = json!({ "name": name, "type": "https", "https": { "customDomains": [domain], "plugin": { "type": "tls2raw", "localAddr": format!("{}:{}", ip, port), "crtPath": crt_path, "keyPath": key_path } }, "useEncryption": false, "useCompression": false });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/proxies".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_stcp(&self, name: &str, local: &str, secret_key: &str) -> Result<(bool, Value)> {
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let payload = json!({ "name": name, "type": "stcp", "stcp": { "localIP": ip, "localPort": port, "secretKey": secret_key } });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/proxies".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_sudp(&self, name: &str, local: &str, secret_key: &str) -> Result<(bool, Value)> {
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let payload = json!({ "name": name, "type": "sudp", "sudp": { "localIP": ip, "localPort": port, "secretKey": secret_key } });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/proxies".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn add_xtcp(&self, name: &str, local: &str, secret_key: &str) -> Result<(bool, Value)> {
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let payload = json!({ "name": name, "type": "xtcp", "xtcp": { "localIP": ip, "localPort": port, "secretKey": secret_key } });
        let (ok, code, body) = (self.api_callback)("POST".to_string(), "store/proxies".to_string(), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn get(&self, name: &str) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), format!("store/proxies/{}", name), Value::Null).await?;
        if ok {
            match serde_json::from_str::<Value>(&body) {
                Ok(info) => {
                    let typ = info.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let mut result = json!({ "name": name, "type": typ, "enabled": info[&typ]["enabled"].as_bool().unwrap_or(true) });
                    match typ.as_str() {
                        "tcp" => {
                            result["local"] = format!("{}:{}", info[&typ]["localIP"].as_str().unwrap_or("127.0.0.1"), info[&typ]["localPort"].as_u64().unwrap_or(80)).into();
                            result["remote"] = info["tcp"]["remotePort"].as_u64().unwrap_or(0).into();
                        }
                        "http" => {
                            result["local"] = format!("{}:{}", info[&typ]["localIP"].as_str().unwrap_or("127.0.0.1"), info[&typ]["localPort"].as_u64().unwrap_or(80)).into();
                            result["remote"] = info[&typ]["customDomains"][0].as_str().unwrap_or("").into();
                            result["auth"] = json!({ "username": info[&typ]["httpUser"].as_str().unwrap_or(""), "password": info[&typ]["httpPassword"].as_str().unwrap_or("") });
                        }
                        "https" => {
                            result["local"] = info[&typ]["plugin"]["localAddr"].as_str().unwrap_or("127.0.0.1:80").into();
                            result["remote"] = info[&typ]["customDomains"][0].as_str().unwrap_or("").into();
                        }
                        "stcp" | "sudp" | "xtcp" => {
                            result["local"] = format!("{}:{}", info[&typ]["localIP"].as_str().unwrap_or("127.0.0.1"), info[&typ]["localPort"].as_u64().unwrap_or(80)).into();
                            result["secretkey"] = info[&typ]["secretKey"].as_str().unwrap_or("").into();
                        }
                        _ => {}
                    }
                    Ok((true, result))
                }
                Err(e) => { error!("解析 get 响应失败: {}", e); Ok((false, Value::Null)) }
            }
        } else { Ok((false, Value::Null)) }
    }

    pub async fn set_enabled(&self, name: &str, enabled: bool) -> Result<(bool, Value)> {
        let (ok, _, body) = (self.api_callback)("GET".to_string(), format!("store/proxies/{}", name), Value::Null).await?;
        if !ok { return Ok((false, json!({ "error": "Failed to get proxy" }))); }
        let mut info: Value = serde_json::from_str(&body)?;
        let typ = info.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if typ.is_empty() { return Ok((false, json!({ "error": "Invalid proxy type" }))); }
        if let Some(obj) = info.get_mut(&typ) { obj["enabled"] = json!(enabled); }
        let (ok2, code, body2) = (self.api_callback)("PUT".to_string(), format!("store/proxies/{}", name), info).await?;
        Ok((ok2 && code == 200, if ok2 && code == 200 { json!({ "success": true }) } else { json!({ "error": body2 }) }))
    }

    pub async fn delete(&self, name: &str) -> Result<(bool, Value)> {
        let (ok, code, body) = (self.api_callback)("DELETE".to_string(), format!("store/proxies/{}", name), Value::Null).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }

    pub async fn update(&self, name: &str, local: &str, domain: &str, remote_port: u16, secret_key: &str, auth: Value) -> Result<(bool, Value)> {
        let typ = self.get_type(name).await?;
        if typ.is_empty() { return Ok((false, json!({ "error": "Proxy not found" }))); }
        let addr = format_local_addr(local, false, "127.0.0.1");
        let parts: Vec<&str> = addr.split(':').collect();
        if parts.len() != 2 { return Ok((false, json!({ "error": "Invalid local address" }))); }
        let ip = parts[0].to_string(); let port: u16 = parts[1].parse().unwrap_or(80);
        let mut payload = json!({ "name": name, "type": typ });
        match typ.as_str() {
            "tcp" => { payload["tcp"] = json!({ "remotePort": remote_port, "localIP": ip, "localPort": port }); payload["useEncryption"] = json!(false); payload["useCompression"] = json!(false); }
            "http" => { payload["http"] = json!({ "customDomains": [domain], "localIP": ip, "localPort": port, "httpUser": auth.get("username").and_then(|v|v.as_str()).unwrap_or(""), "httpPassword": auth.get("password").and_then(|v|v.as_str()).unwrap_or("") }); payload["useEncryption"] = json!(false); payload["useCompression"] = json!(false); }
            "https" => {
                let (wildcard, base_name) = compute_cert_names(domain);
                let crt_path = format!("./cert/pool/{}.crt", base_name);
                let key_path = format!("./cert/pool/{}.key", base_name);
                if !(self.check_cert)(wildcard.clone()).await { (self.issue_cert)(wildcard).await; }
                payload["https"] = json!({ "customDomains": [domain], "plugin": { "type": "tls2raw", "localAddr": format!("{}:{}", ip, port), "crtPath": crt_path, "keyPath": key_path } });
            }
            "stcp" | "sudp" | "xtcp" => { payload[&typ] = json!({ "localIP": ip, "localPort": port, "secretKey": secret_key }); }
            _ => return Ok((false, json!({ "error": "Unsupported type" }))),
        }
        let (ok, code, body) = (self.api_callback)("PUT".to_string(), format!("store/proxies/{}", name), payload).await?;
        Ok((ok && code == 200, if ok && code == 200 { json!({ "success": true }) } else { json!({ "error": body }) }))
    }
}