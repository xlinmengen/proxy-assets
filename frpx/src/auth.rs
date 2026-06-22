use anyhow::{Result, bail};
use reqwest::Client;
use serde_json::{Value, from_str, json};
use std::time::Duration;

/// 创建带 Cookie 存储的 HTTP 客户端（禁用证书验证）
pub fn create_client() -> Result<Client> {
    Ok(Client::builder()
        .danger_accept_invalid_certs(true)
        .cookie_store(true)
        .timeout(Duration::from_secs(30))
        .build()?)
}

/// 执行登录请求，返回解析后的 JSON 和状态码
pub async fn login(client: &Client, server_ip: &str, payload: Value) -> Result<(Value, u16)> {
    if server_ip.is_empty() {
        bail!("服务器 IP 为空");
    }
    let url = format!("https://{}:1000/api/login", server_ip);
    let resp = client.post(&url).json(&payload).send().await?;
    let status = resp.status().as_u16();
    let text = resp.text().await?; // 先获取文本
    match from_str::<Value>(&text) {
        Ok(json) => Ok((json, status)),
        Err(_) => {
            // 非 JSON 响应，返回错误 JSON
            let error_json = json!({
                "status": false,
                "code": status,
                "message": format!("服务器返回非 JSON 响应: {}", text)
            });
            Ok((error_json, status))
        }
    }
}

/// 获取 user_id 和 authorization_code（需先登录成功）
pub async fn get_user_authorization(client: &Client, server_ip: &str) -> Result<(String, String)> {
    let id_resp = client
        .post(&format!("https://{}:1000/api/get_user_id", server_ip))
        .send()
        .await?;
    if !id_resp.status().is_success() {
        bail!("获取 user_id 失败");
    }
    let id_json: Value = id_resp.json().await?;
    let user_id = id_json["info"]["user_id"].as_str().unwrap_or("").to_string();

    let code_resp = client
        .post(&format!("https://{}:1000/api/get_authorization_code", server_ip))
        .send()
        .await?;
    if !code_resp.status().is_success() {
        bail!("获取 authorization_code 失败");
    }
    let code_json: Value = code_resp.json().await?;
    let auth_code = code_json["info"]["authorization_code"].as_str().unwrap_or("").to_string();

    if user_id.is_empty() || auth_code.is_empty() {
        bail!("凭证为空");
    }
    Ok((user_id, auth_code))
}