mod settings;
mod utils;
mod auth;
mod frpc_controller;
mod proxy_controller;
mod visit_controller;

use std::sync::Arc;
use std::path::PathBuf;
use axum::middleware::Next;
use axum::{
    Router, routing::{get, post}, response::{Html, Json, IntoResponse},
    extract::{Path, State, Request}, http::StatusCode, middleware,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tracing::{info, error};
use tracing_subscriber::{fmt, EnvFilter};
use settings::Settings;
use frpc_controller::FRPCController;
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

#[derive(Embed)]
#[folder = "templates/"]
struct TemplateAssets;

struct AppState {
    settings: Arc<Mutex<Settings>>,
    frpc: Arc<Mutex<Option<Arc<FRPCController>>>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt().with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into())).init();

    let settings = Arc::new(Mutex::new(Settings::load().unwrap_or_default()));
    // 确保 data.db 存在
    {
        let s = settings.lock().await;
        let path = PathBuf::from("data.db");
        if !path.exists() {
            let _ = s.save();
        }
    }

    let frpc = Arc::new(Mutex::new(None));
    let state = Arc::new(AppState { settings: settings.clone(), frpc: frpc.clone() });

    // 后台监控（对应 Python 的 __thread__）
    let monitor_state = state.clone();
    tokio::spawn(async move {
        loop {
            {
                let mut settings_guard = monitor_state.settings.lock().await;
                let mut available = settings_guard.check_available();
                let mut frpc_guard = monitor_state.frpc.lock().await;
                if frpc_guard.is_some() {
                if frpc_guard.as_ref().unwrap().is_auth_failed().await {
                    settings_guard.reset_all();
                    let _ = settings_guard.save();
                    available = false;
                }}
                if available {
                    if frpc_guard.is_none() {
                        info!("FRPC 条件满足，启动控制器");
                        let controller = FRPCController::new(
                            settings_guard.server_ip.clone(),
                            settings_guard.frpc_port,
                            settings_guard.client_id.clone(),
                            settings_guard.client_secret.clone(),
                        ).await;
                        // 后台启动 frpc，不阻塞
                        tokio::spawn(controller.clone().setup_thread(true, 10.0));
                        *frpc_guard = Some(controller);
                    }
                } else {
                    if frpc_guard.is_some() {
                    if let Some(ctrl) = frpc_guard.take() { ctrl.shutdown().await; }
                    }
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    });

    let protected_api = Router::new()
        .route("/api/frpc/proxy/*path", post(proxy_handler))
        .route("/api/frpc/visit/*path", post(visit_handler))
        .route("/api/logout", post(logout_handler))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware));
    
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/static/*path", get(static_handler))
        .route("/api/login", post(login_handler))
        .route("/api/status", post(status_handler))
        .route("/api/index/login", post(index_login_handler))
        .route("/api/index/status", get(index_status_handler))
        .route("/api/index/set_password", post(index_set_password_handler))
        .merge(protected_api)
        .with_state(state);

    let mainhost = settings.lock().await.mainhost.clone();
    let mainport = settings.lock().await.mainport;
    let addr = format!("{}:{}", mainhost, mainport);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Web server running on http://{}", addr);
    let serve_future = axum::serve(listener, app);

    // 监听 Ctrl+C 信号
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl+c");
        info!("收到退出信号，正在关闭 FRPC...");
    };

    // 同时等待服务结束或退出信号
    tokio::select! {
        _ = serve_future => {
            info!("Web 服务已停止");
        }
        _ = ctrl_c => {
            // 关闭 FRPC
            let frpc_guard = frpc.lock().await;
            if let Some(ctrl) = frpc_guard.as_ref() {
                ctrl.shutdown().await;
                info!("FRPC 已关闭");
            }
        }
    }
    Ok(())
}

async fn static_handler(Path(path): Path<String>) -> impl IntoResponse {
    if let Some(content) = StaticAssets::get(&path) {
        let mime = mime_guess::from_path(&path).first_or_octet_stream();
        let body = axum::body::Body::from(content.data);
        ([(axum::http::header::CONTENT_TYPE, mime.as_ref())], body).into_response()
    } else {
        (StatusCode::NOT_FOUND, "Not found").into_response()
    }
}

async fn index_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = state.settings.lock().await;
    let file_name = if settings.check_available() { "index.html" } else { "login.html" };
    if let Some(content) = TemplateAssets::get(file_name) {
        let html = String::from_utf8_lossy(&content.data).to_string();
        Html(html).into_response()
    } else {
        (StatusCode::NOT_FOUND, "Template not found").into_response()
    }
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    // 1. 获取 serverip（优先使用 payload，否则从 settings 读取）
    let mut serverip = payload
        .get("serverip")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if serverip.is_none() {
        let settings = state.settings.lock().await;
        if !settings.server_ip.is_empty() {
            serverip = Some(settings.server_ip.clone());
        }
    }

    let serverip = match serverip {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, Json(json!({
                "status": false, "code": 400, "message": "缺少服务器 IP"
            })));
        }
    };

    // 2. 保存 serverip 和 username 到 settings
    {
        let mut s = state.settings.lock().await;
        s.server_ip = serverip.clone();
        if let Some(username) = payload.get("username").and_then(|v| v.as_str()) {
            s.username = username.to_string();
        }
        let _ = s.save();
    }

    // 3. 构建转发 payload（移除 serverip 字段）
    let mut forward_payload = payload.clone();
    forward_payload.as_object_mut().and_then(|obj| obj.remove("serverip"));

    // 4. 创建带 Cookie 的 HTTP 客户端
    let client = match auth::create_client() {
        Ok(c) => c,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({
                "status": false, "code": 500, "message": format!("创建 HTTP 客户端失败: {}", e)
            })));
        }
    };

    // 5. 执行登录
    match auth::login(&client, &serverip, forward_payload).await {
        Ok((resp_json, status_code)) => {
            let authenticated = resp_json
                .get("authenticated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if authenticated {
                // 登录成功，获取凭证
                match auth::get_user_authorization(&client, &serverip).await {
                    Ok((user_id, auth_code)) => {
                        let mut s = state.settings.lock().await;
                        s.client_id = user_id;
                        s.client_secret = auth_code;
                        let _ = s.save();
                        return (StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK), Json(resp_json));
                    }
                    Err(e) => {
                        return (StatusCode::UNAUTHORIZED, Json(json!({
                            "status": false, "code": 401, "message": format!("获取凭证失败: {}", e)
                        })));
                    }
                }
            } else {
                // 需要二次验证（直接返回远程响应，前端继续处理）
                return (StatusCode::from_u16(status_code).unwrap_or(StatusCode::OK), Json(resp_json));
            }
        }
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({
                "status": false, "code": 401, "message": format!("登录请求失败: {}", e)
            })));
        }
    }
}

async fn logout_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let mut settings = state.settings.lock().await;
    settings.reset_all();
    let _ = settings.save();
    Json(json!({ "status": true, "message": "已退出登录", "code": 200, "info": "" }))
}

async fn status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = state.settings.lock().await;
    Json(json!({
        "status": true, "code": 200,
        "info": { "username": settings.username, "authenticated": settings.check_available() }
    }))
}

async fn proxy_handler(
    Path(path): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let frpc_guard = state.frpc.lock().await;
    if let Some(controller) = frpc_guard.as_ref() {
        match controller.proxy_call(&path, body).await {
            Ok((success, info)) => {
                let code = if success { 200 } else { 400 };
                (StatusCode::from_u16(code).unwrap(), Json(json!({ "status": success, "code": code, "info": info })))
            }
            Err(e) => {
                error!("proxy 调用失败: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": false, "code": 500, "message": format!("Error: {}", e) })))
            }
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": false, "code": 503, "message": "FRPC not available" })))
    }
}

async fn visit_handler(
    Path(path): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let frpc_guard = state.frpc.lock().await;
    if let Some(controller) = frpc_guard.as_ref() {
        match controller.visit_call(&path, body).await {
            Ok((success, info)) => {
                let code = if success { 200 } else { 400 };
                (StatusCode::from_u16(code).unwrap(), Json(json!({ "status": success, "code": code, "info": info })))
            }
            Err(e) => {
                error!("visit 调用失败: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": false, "code": 500, "message": format!("Error: {}", e) })))
            }
        }
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": false, "code": 503, "message": "FRPC not available" })))
    }
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<axum::response::Response, (StatusCode, Json<Value>)> {
    let password_required = {
        let settings = state.settings.lock().await;
        !settings.password.is_empty()
    };
    if !password_required {
        return Ok(next.run(req).await);
    }

    let password = req.headers()
        .get("X-Password")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_valid = {
        let settings = state.settings.lock().await;
        settings.password == password
    };

    if  is_valid { Ok(next.run(req).await) } else {
        Err((StatusCode::UNAUTHORIZED, Json(json!({
            "status": false,
            "message": "需要独立密码认证"
        }))))
    }
}

async fn index_status_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let settings = state.settings.lock().await;
    Json(json!({
        "requires_password": !settings.password.is_empty()
    }))
}

async fn index_login_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let password = payload.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let settings = state.settings.lock().await;
    if settings.check_password(password) {
        (StatusCode::OK, Json(json!({ "status": true, "message": "密码正确" })))
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({ "status": false, "message": "密码错误" })))
    }
}

async fn index_set_password_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    let old_password = payload.get("old_password").and_then(|v| v.as_str()).unwrap_or("");
    let new_password = payload.get("new_password").and_then(|v| v.as_str()).unwrap_or("");
    let mut settings = state.settings.lock().await;
    if !settings.password.is_empty() && !settings.check_password(old_password) {
        return (StatusCode::UNAUTHORIZED, Json(json!({ "status": false, "message": "旧密码错误" })));
    }   settings.password = new_password.to_string();
    if let Err(e) = settings.save() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "status": false, "message": format!("保存失败: {}", e) })));
    }
    (StatusCode::OK, Json(json!({ "status": true, "message": "密码已更新" })))
}