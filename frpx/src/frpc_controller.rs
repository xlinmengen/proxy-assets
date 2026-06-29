use std::sync::Arc;
use std::path::PathBuf;
use std::future::Future;
use std::pin::Pin;
use tokio::sync::Mutex;
use tokio::process::Command;
use tokio::time::{sleep, Duration};
use serde_json::{Value, json};
use reqwest::Client;
use tracing::{info, error, warn};
use anyhow::{Result, anyhow};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use crate::utils::{write_file, extract_cert_from_zip};
use crate::proxy_controller::ProxyController;
use crate::visit_controller::VisitController;

pub struct FRPCController {
    ip: String,
    port: u16,
    auth: Value,
    audience: Arc<Mutex<String>>,
    auth_available : Arc<Mutex<bool>>,
    auth_navailable: Arc<Mutex<bool>>,
    shutdown_signal: Arc<Mutex<bool>>,
    root_path: PathBuf,
    cert_path: PathBuf,
    cert_pool_path: PathBuf,
    frpc_path: PathBuf,
    proxy: Arc<Mutex<Option<ProxyController>>>,
    visit: Arc<Mutex<Option<VisitController>>>,
    process: Arc<Mutex<Option<tokio::process::Child>>>,
    http_client: Client,
    frpc_client: Client,
    pid: Arc<Mutex<Option<u32>>>,
}

impl FRPCController {
    pub async fn new(server_ip: String, frpc_port: u16, client_id: String, client_secret: String) -> Arc<Self> {
        let auth = json!({ "clientid": client_id, "clientst": client_secret });
        let root = PathBuf::from(".");
        let cert = root.join("cert");
        let pool = cert.join("pool");
        let frpc = root.join("frpc");
        tokio::fs::create_dir_all(&cert).await.ok();
        tokio::fs::create_dir_all(&pool).await.ok();
        tokio::fs::create_dir_all(&frpc).await.ok();

        let controller = Arc::new(FRPCController {
            ip: server_ip,
            port: frpc_port,
            auth,
            audience: Arc::new(Mutex::new(String::new())),
            auth_available : Arc::new(Mutex::new(false)),
            auth_navailable: Arc::new(Mutex::new(false)),
            shutdown_signal: Arc::new(Mutex::new(false)),
            root_path: root,
            cert_path: cert,
            cert_pool_path: pool,
            frpc_path: frpc,
            proxy: Arc::new(Mutex::new(None)),
            visit: Arc::new(Mutex::new(None)),
            process: Arc::new(Mutex::new(None)),
            http_client: Client::builder().danger_accept_invalid_certs(true).build().unwrap(),
            frpc_client: Client::builder().build().unwrap(),  pid: Arc::new(Mutex::new(None)),
        });

        // 闭包注册（保持不变）
        let c1 = controller.clone();
        let proxy_controller = ProxyController::new(
            move |method: String, url: String, body: Value| {
                let c = c1.clone();
                Box::pin(async move { c.frpc_request(&method, &url, body).await })
            },
            {
                let c = controller.clone();
                move |domain: String| {
                    let c2 = c.clone();
                    Box::pin(async move { c2.check_cert(&domain).await })
                }
            },
            {
                let c = controller.clone();
                move |domain: String| {
                    let c2 = c.clone();
                    Box::pin(async move { c2.issue_cert(&domain).await })
                }
            },
        );

        let c2 = controller.clone();
        let visit_controller = VisitController::new(
            move |method: String, url: String, body: Value| {
                let c = c2.clone();
                Box::pin(async move { c.frpc_request(&method, &url, body).await })
            },
        );

        *controller.proxy.lock().await = Some(proxy_controller);
        *controller.visit.lock().await = Some(visit_controller);

        // 启动 checker
        let checker_controller = controller.clone();
        let first_interval = checker_controller.clone()._checker().await;
        tokio::spawn(async move {
            sleep(Duration::from_secs_f64(first_interval)).await;
            loop {
                let interval = checker_controller.clone()._checker().await;
                sleep(Duration::from_secs_f64(interval)).await;
            }
        });

        controller
    }

    async fn _checker(self: Arc<Self>) -> f64{
        let mut interval = 60.0;
        if *self.shutdown_signal.lock().await {
            return interval;
        }
        let result = self.check_audience().await;
        match result {
            Ok(audience) => {
                let mut cur = self.audience.lock().await;
                if !cur.is_empty() && audience != *cur && !audience.is_empty() {
                    self.shutdown().await;
                    let c = self.clone();
                    tokio::spawn(async move {
                        c.setup_thread(true, 10.0).await;
                    });
                } else if cur.is_empty() && !audience.is_empty() {
                    *cur = audience;
                    *self.auth_available.lock().await = true;
                    info!("Audience 获取成功，auth_available 已设为 true");
                }
            }
            Err(e) => {
                if let Some(reqwest_err) = e.downcast_ref::<reqwest::Error>() {
                    if let Some(status) = reqwest_err.status() {
                        if status.as_u16() == 401 {
                            self.shutdown().await;
                            *self.auth_available .lock().await = false;
                            *self.auth_navailable.lock().await = true;
                        } else if status.as_u16() == 415 {
                            interval = 300.0;
                        }
                    }
                } else { interval = 2.0 };
            }
        }
        interval
    }

    async fn check_audience(&self) -> Result<String> {
        let result = self._request("POST", "audience", Value::Null).await?;
        if let Some(aud) = result.get("info").and_then(|v| v.as_str()) {
            Ok(aud.to_string())
        } else {
            Ok(String::new())
        }
    }

    fn _get_headers(&self) -> String {
        let client_id = self.auth["clientid"].as_str().unwrap_or("");
        let client_secret = self.auth["clientst"].as_str().unwrap_or("");
        format!("Basic {}", BASE64.encode(format!("{}:{}", client_id, client_secret)))
    }

    async fn _request(&self, method: &str, url: &str, body: Value) -> Result<Value> {
        let url_full = format!("https://{}:1000/oauth2/{}", self.ip, url);
        let mut req = self.http_client.request(
            match method {
                "GET" => reqwest::Method::GET,
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                _ => return Err(anyhow!("Unsupported method")),
            },
            &url_full,
        )
        .header("Authorization", &self._get_headers())
        .header("Content-Type", "application/json");
        if !body.is_null() {
            req = req.json(&body);
        }
        let resp = req.send().await?;
        let resp = resp.error_for_status()?;
        let bytes = resp.bytes().await?;
        if let Ok(json) = serde_json::from_slice(&bytes) {
            Ok(json)
        } else {
            Ok(Value::String(String::from_utf8_lossy(&bytes).to_string()))
        }
    }

    async fn _request_bytes(&self, method: &str, url: &str, body: Value) -> Result<Vec<u8>> {
        let url_full = format!("https://{}:1000/oauth2/{}", self.ip, url);
        let mut req = self.http_client.request(
            match method {
                "GET" => reqwest::Method::GET,
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                _ => return Err(anyhow!("Unsupported method")),
            },
            &url_full,
        )
        .header("Authorization", &self._get_headers())
        .header("Content-Type", "application/json");
        if !body.is_null() {
            req = req.json(&body);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        if status >= 200 && status < 300 {
            Ok(resp.bytes().await?.to_vec())
        } else {
            Err(anyhow!("HTTP error {} when fetching bytes", status))
        }
    }

    async fn _setup_config(&self) -> bool {
        info!("开始生成 frpc 配置...");
        if !*self.auth_available.lock().await {
            warn!("auth_available 为 false，无法生成配置");
            return false;
        }

        let audience = match self._request("POST", "audience", Value::Null).await {
            Ok(val) => val.get("info").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            Err(e) => {
                error!("获取 audience 失败: {}", e);
                return false;
            }
        };
        if audience.is_empty() {
            error!("获取 audience 为空");
            return false;
        }
        info!("audience 获取成功: {}", audience);

        let config = format!(
            r#"serverAddr = "{}"
serverPort = 10
webServer.addr = "127.0.0.1"
webServer.port = {}
webServer.user = "{}"
webServer.password = "{}"

auth.method = "oidc"
auth.oidc.audience = "{}"
auth.oidc.clientID = "{}"
auth.oidc.clientSecret = "{}"
auth.oidc.tokenEndpointURL = "https://{}:1000/oauth2/token"

transport.tcpMux = true
transport.poolCount = 10
transport.wireProtocol = "v2"

transport.tls.enable = true
transport.tls.keyFile = "./cert/client.key"
transport.tls.certFile = "./cert/client.crt"
transport.tls.trustedCaFile = "./cert/ca.crt"

[store]
path = "./frpc.db""#,
            self.ip,
            self.port,
            self.auth["clientid"].as_str().unwrap_or(""),
            self.auth["clientst"].as_str().unwrap_or(""),
            audience,
            self.auth["clientid"].as_str().unwrap_or(""),
            self.auth["clientst"].as_str().unwrap_or(""),
            self.ip
        );
        let config_path = self.frpc_path.join("frpc.toml");
        if let Err(e) = write_file(&config_path.to_string_lossy(), &config) {
            error!("写入 frpc.toml 失败: {}", e);
            return false;
        }
        info!("frpc.toml 已写入: {:?}", config_path);

        match self._request("POST", "cert", Value::Null).await {
            Ok(ca_cert) => {
                if let Some(ca_data) = ca_cert.as_str() {
                    let ca_path = self.cert_path.join("ca.crt");
                    if let Err(e) = write_file(&ca_path.to_string_lossy(), ca_data) {
                        error!("写入 ca.crt 失败: {}", e);
                        return false;
                    }
                    info!("ca.crt 已写入: {:?}", ca_path);
                } else {
                    error!("CA 证书响应格式错误");
                    return false;
                }
            }
            Err(e) => {
                error!("下载 CA 证书失败: {}", e);
                return false;
            }
        }

        let cert_req = json!({
            "domain": self.ip,
            "TLS_Web_AType": "CLIENT",
            "IncludeCaCert": true,
        });
        match self._request_bytes("POST", "issue_cert", cert_req).await {
            Ok(zip_bytes) => {
                let (crt, key) = extract_cert_from_zip(&zip_bytes);
                if crt.is_empty() || key.is_empty() {
                    error!("解压客户端证书失败: 缺少 cert.crt 或 cert.key");
                    return false;
                }
                let crt_path = self.cert_path.join("client.crt");
                let key_path = self.cert_path.join("client.key");
                if let Err(e) = write_file(&crt_path.to_string_lossy(), &String::from_utf8_lossy(&crt)) {
                    error!("写入 client.crt 失败: {}", e);
                    return false;
                }
                if let Err(e) = write_file(&key_path.to_string_lossy(), &String::from_utf8_lossy(&key)) {
                    error!("写入 client.key 失败: {}", e);
                    return false;
                }
                info!("客户端证书已写入: {:?}, {:?}", crt_path, key_path);
            }
            Err(e) => {
                error!("签发客户端证书失败: {}", e);
                return false;
            }
        }

        *self.audience.lock().await = audience;
        *self.auth_available.lock().await = true;
        info!("frpc 配置生成完毕");
        true
    }

    pub async fn check_cert(&self, domain: &str) -> bool {
        let base = self.cert_pool_path.join(domain.replace('*', "_") + ".0");
        base.with_extension("crt").exists() && base.with_extension("key").exists()
    }

    pub async fn issue_cert(&self, domain: &str) -> bool {
        let base = self.cert_pool_path.join(domain.replace('*', "_") + ".0");
        let cert_req = json!({
            "domain": domain,
            "TLS_Web_AType": "SERVER",
            "IncludeCaCert": true,
        });
        match self._request_bytes("POST", "issue_cert", cert_req).await {
            Ok(zip_bytes) => {
                let (crt, key) = extract_cert_from_zip(&zip_bytes);
                if crt.is_empty() || key.is_empty() {
                    error!("解压证书失败: 缺少 cert.crt 或 cert.key");
                    return false;
                }
                let crt_path = base.with_extension("crt");
                let key_path = base.with_extension("key");
                if let Err(e) = write_file(&crt_path.to_string_lossy(), &String::from_utf8_lossy(&crt)) {
                    error!("写入证书失败: {}", e);
                    return false;
                }
                if let Err(e) = write_file(&key_path.to_string_lossy(), &String::from_utf8_lossy(&key)) {
                    error!("写入私钥失败: {}", e);
                    return false;
                }
                info!("证书已签发: {:?}", crt_path);
                true
            }
            Err(e) => {
                error!("签发证书失败: {}", e);
                false
            }
        }
    }

    async fn frpc_request(&self, method: &str, url: &str, body: Value) -> Result<(bool, u16, String)> {
        let url_full = format!("http://127.0.0.1:{}/api/{}", self.port, url);
        let mut req = self.frpc_client.request(
            match method {
                "GET" => reqwest::Method::GET,
                "POST" => reqwest::Method::POST,
                "PUT" => reqwest::Method::PUT,
                "DELETE" => reqwest::Method::DELETE,
                _ => return Err(anyhow!("Unsupported method")),
            },
            &url_full,
        )
        .header("Authorization", &self._get_headers())
        .header("Content-Type", "application/json");
        if !body.is_null() {
            req = req.json(&body);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        let ok = status >= 200 && status < 300;
        let content = resp.text().await.unwrap_or_default();
        Ok((ok, status, content))
    }

    pub fn setup_thread(self: Arc<Self>, auto_reboot: bool, interval: f64) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            // 1. 尝试生成配置
            let config_ok = self._setup_config().await;
            if  config_ok {
                *self.shutdown_signal.lock().await = false;
                // 启动子进程
                let frpc_exe = self.frpc_path.join(if cfg!(windows) { "frpc.exe" } else { "frpc" });
                let config_path = self.frpc_path.join("frpc.toml");
                let mut cmd = Command::new(&frpc_exe);
                cmd.arg("-c").arg(&config_path);

                #[cfg(windows)]
                {
                    const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
                    cmd.creation_flags(CREATE_NEW_PROCESS_GROUP);
                }
                #[cfg(unix)]
                {
                    unsafe {
                        cmd.pre_exec(|| {
                            nix::unistd::setsid()
                                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                            Ok(())
                        });
                    }
                }

                match cmd.spawn() {
                    Ok(child) => {
                        *self.pid.lock().await = child.id();
                        *self.process.lock().await = Some(child);
                        info!("frpc 进程已启动 (PID: {:?})", self.pid);
                    }
                    Err(e) => {
                        error!("启动 frpc 失败: {}", e);
                    }
                }
            } else {
                error!("配置生成失败，将进入重启循环");
            }

            // 2. 如果 auto_reboot 为 true，启动后台监控任务（无论配置是否成功）
            if auto_reboot {
                let controller = self.clone();
                tokio::spawn(async move {
                    // 等待子进程退出（如果有）
                    let child_opt = controller.process.lock().await.take();
                    if let Some(mut child) = child_opt {
                        let _ = child.wait().await;
                    }
                    // 检查是否被主动关闭
                    if !*controller.shutdown_signal.lock().await {
                        info!("frpc 异常退出或未启动，将在 {} 秒后自动重启", interval);
                        sleep(Duration::from_secs_f64(interval)).await;
                        // 递归调用 setup_thread
                        controller.clone().setup_thread(auto_reboot, interval).await;
                    }
                });
            }
        })
    }

    pub async fn is_auth_failed(&self) -> bool {
        *self.auth_navailable.lock().await
    }

    pub async fn shutdown(&self) {
        *self.shutdown_signal.lock().await = true;
        if let Some(pid) = self.pid.lock().await.take() {
            #[cfg(windows)] {
                let _ = tokio::process::Command::new("taskkill")
                    .args(&["/F", "/T", "/PID", &pid.to_string()])
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await;
            }
            #[cfg(unix)] {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;
                let _ = kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
            }
        }
        if let Some(mut child) = self.process.lock().await.take() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        info!("frpc 进程已终止");
    }

    /// 代理方法调用转发
    pub async fn proxy_call(&self, path: &str, body: Value) -> Result<(bool, Value)> {
        let proxy_opt = self.proxy.lock().await;
        if let Some(proxy) = proxy_opt.as_ref() {
            let result = match path {
                "get_config" => proxy.get_config().await,
                "get_status" => proxy.get_status().await,
                "add_tcp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let remote_port = body["remote_port"].as_u64().unwrap_or(0) as u16;
                    proxy.add_tcp(&name, &local, remote_port).await
                }
                "add_http" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let domain = body["domain"].as_str().unwrap_or("").to_string();
                    let auth = body.get("auth").cloned().unwrap_or(Value::Null);
                    proxy.add_http(&name, &local, &domain, auth).await
                }
                "add_https" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let domain = body["domain"].as_str().unwrap_or("").to_string();
                    proxy.add_https(&name, &local, &domain).await
                }
                "add_stcp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    proxy.add_stcp(&name, &local, &secretkey).await
                }
                "add_sudp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    proxy.add_sudp(&name, &local, &secretkey).await
                }
                "add_xtcp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    proxy.add_xtcp(&name, &local, &secretkey).await
                }
                "get" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    proxy.get(&name).await
                }
                "set_enabled" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let enabled = body["enabled"].as_bool().unwrap_or(false);
                    proxy.set_enabled(&name, enabled).await
                }
                "delete" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    proxy.delete(&name).await
                }
                "update" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let local = body["local"].as_str().unwrap_or("").to_string();
                    let domain = body.get("domain").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let remote_port = body.get("remote_port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                    let secretkey = body.get("secretkey").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let auth = body.get("auth").cloned().unwrap_or(Value::Null);
                    proxy.update(&name, &local, &domain, remote_port, &secretkey, auth).await
                }
                _ => return Err(anyhow!("未知方法: {}", path)),
            };
            result
        } else {
            Err(anyhow!("ProxyController 未初始化"))
        }
    }

    /// 访客方法调用转发
    pub async fn visit_call(&self, path: &str, body: Value) -> Result<(bool, Value)> {
        let visit_opt = self.visit.lock().await;
        if let Some(visit) = visit_opt.as_ref() {
            let result = match path {
                "get_config" => visit.get_config().await,
                "add_stcp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let bindport = body["bindport"].as_u64().unwrap_or(0) as u16;
                    let servername = body["servername"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    visit.add_stcp(&name, bindport, &servername, &secretkey).await
                }
                "add_sudp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let bindport = body["bindport"].as_u64().unwrap_or(0) as u16;
                    let servername = body["servername"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    visit.add_sudp(&name, bindport, &servername, &secretkey).await
                }
                "add_xtcp" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let bindport = body["bindport"].as_u64().unwrap_or(0) as u16;
                    let servername = body["servername"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    visit.add_xtcp(&name, bindport, &servername, &secretkey).await
                }
                "get" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    visit.get(&name).await
                }
                "set_enabled" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let enabled = body["enabled"].as_bool().unwrap_or(false);
                    visit.set_enabled(&name, enabled).await
                }
                "delete" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    visit.delete(&name).await
                }
                "update" => {
                    let name = body["name"].as_str().unwrap_or("").to_string();
                    let bindport = body["bindport"].as_u64().unwrap_or(0) as u16;
                    let servername = body["servername"].as_str().unwrap_or("").to_string();
                    let secretkey = body["secretkey"].as_str().unwrap_or("").to_string();
                    visit.update(&name, bindport, &servername, &secretkey).await
                }
                _ => return Err(anyhow!("未知方法: {}", path)),
            };
            result
        } else {
            Err(anyhow!("VisitController 未初始化"))
        }
    }
}

impl Clone for FRPCController {
    fn clone(&self) -> Self {
        FRPCController {
            ip: self.ip.clone(),
            port: self.port,
            auth: self.auth.clone(),
            audience: self.audience.clone(),
            auth_available : self.auth_available .clone(),
            auth_navailable: self.auth_navailable.clone(),
            shutdown_signal: self.shutdown_signal.clone(),
            root_path: self.root_path.clone(),
            cert_path: self.cert_path.clone(),
            cert_pool_path: self.cert_pool_path.clone(),
            frpc_path: self.frpc_path.clone(),
            proxy: self.proxy.clone(),
            visit: self.visit.clone(),
            process: self.process.clone(),
            http_client: self.http_client.clone(),
            frpc_client: self.frpc_client.clone(),
            pid: self.pid.clone(),
        }
    }
}