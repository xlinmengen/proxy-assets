use regex::Regex;
use std::fs;
use std::io::Read;
use zip::ZipArchive;
use std::io::Cursor;

pub fn write_file(path: &str, data: &str) -> Result<(), std::io::Error> {
    fs::write(path, data)
}

pub fn compute_cert_names(domain: &str) -> (String, String) {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() > 2 {
        let suffix = parts[1..].join(".");
        let wildcard = format!("*.{}", suffix);
        let base_name = format!("_.{}", suffix);
        (wildcard, base_name)
    } else {
        let wildcard = domain.to_string();
        let base_name = domain.to_string();
        (wildcard, base_name)
    }
}

pub fn format_local_addr(local: &str, reserve_protocol: bool, normal_ip: &str) -> String {
    let mut local = local.trim_end_matches(':').trim_end_matches('\n').to_string();
    local = local.replace("::", ":").replace("..", ".");
    let mut protocol = String::new();
    if local.contains("://") {
        let parts: Vec<&str> = local.splitn(2, "://").collect();
        protocol = format!("{}://", parts[0]);
        local = parts[1].to_string();
    }
    if let Some(idx) = local.find('/') {
        local = local[..idx].to_string();
    }
    let re = Regex::new(r"[^a-zA-Z0-9.:/]").unwrap();
    local = re.replace_all(&local, "").to_string();
    local = local.trim_end_matches(':').trim_end_matches('\n').to_string();

    if local.is_empty() {
        let port = if protocol == "https://" { "443" } else { "80" };
        return format!("{}{}:{}", normal_ip, if reserve_protocol { "" } else { "" }, port);
    }

    let (host, port) = if protocol.is_empty() {
        if local.contains(':') {
            let parts: Vec<&str> = local.splitn(2, ':').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else if local.contains('.') {
            (local.clone(), "80".to_string())
        } else {
            (normal_ip.to_string(), local.clone())
        }
    } else {
        if local.contains(':') {
            let parts: Vec<&str> = local.splitn(2, ':').collect();
            (parts[0].to_string(), parts[1].to_string())
        } else {
            (local.clone(), if protocol == "https://" { "443".to_string() } else { "80".to_string() })
        }
    };
    let host = if host.is_empty() { normal_ip.to_string() } else { host };
    let port = if port.is_empty() { if protocol == "https://" { "443".to_string() } else { "80".to_string() } } else { port };
    if reserve_protocol {
        format!("{}{}:{}", protocol, host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

pub fn extract_cert_from_zip(zip_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut crt = Vec::new();
    let mut key = Vec::new();
    if let Ok(mut archive) = ZipArchive::new(Cursor::new(zip_data)) {
        for i in 0..archive.len() {
            if let Ok(mut file) = archive.by_index(i) {
                let name = file.name().to_string();
                let mut content = Vec::new();
                if file.read_to_end(&mut content).is_ok() {
                    if name == "cert.crt" { crt = content; }
                    else if name == "cert.key" { key = content; }
                }
            }
        }
    }
    (crt, key)
}