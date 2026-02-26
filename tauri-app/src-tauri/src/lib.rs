// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_sql::Builder::default().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            generate_google_token,
            send_password_reset_email,
            send_email_verification_email,
            send_smtp_test_email
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use chrono::{Utc, Duration};
use lettre::{Message, SmtpTransport, Transport};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use std::time::Duration as StdDuration;

const SMTP_SEND_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: i64,
    iat: i64,
    // Optional but recommended: identify the subject of the token.
    // For simple service-account auth, this can match `iss`.
    sub: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ServiceAccount {
    private_key: String,
    client_email: String,
    // Used as JWT header `kid` so Google can pick the right key.
    private_key_id: Option<String>,
}

#[tauri::command]
async fn generate_google_token(service_account_json: String) -> Result<String, String> {
    let service_account: ServiceAccount = match serde_json::from_str(&service_account_json) {
        Ok(sa) => sa,
        Err(e) => {
            eprintln!("Failed to parse service account JSON: {}", e);
            return Err(format!("Failed to parse service account JSON: {}", e));
        }
    };

    let now = Utc::now();
    let claims = Claims {
        iss: service_account.client_email.clone(),
        scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        iat: now.timestamp(),
        exp: (now + Duration::hours(1)).timestamp(),
        sub: service_account.client_email.clone(),
    };

    let private_key_pem = service_account.private_key.as_bytes();
    let encoding_key = match EncodingKey::from_rsa_pem(private_key_pem) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to create encoding key from PEM: {}", e);
            return Err(format!("Failed to create encoding key from PEM: {}", e));
        }
    };

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());
    if let Some(kid) = service_account.private_key_id.clone() {
        header.kid = Some(kid);
    }

    let jwt = match encode(&header, &claims, &encoding_key) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to encode JWT: {}", e);
            return Err(format!("Failed to encode JWT: {}", e));
        }
    };

    let client = reqwest::Client::new();
    let params = [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &jwt),
    ];

    let res = match client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            eprintln!("Failed to send token request: {}", e);
            return Err(format!("Failed to send token request: {}", e));
        }
    };

    if !res.status().is_success() {
        let status = res.status();
        let error_text = res.text().await.unwrap_or_else(|_| "Unknown error".to_string());
        eprintln!("Failed to get access token: {} - {}", status, error_text);
        return Err(format!("Failed to get access token: {} - {}", status, error_text));
    }

    let token_response: serde_json::Value = match res
        .json()
        .await
    {
        Ok(json) => json,
        Err(e) => {
            eprintln!("Failed to parse token response: {}", e);
            return Err(format!("Failed to parse token response: {}", e));
        }
    };

    token_response["access_token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            eprintln!("Access token not found in response");
            "Access token not found in response".to_string()
        })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResetEmailArgs {
    username: String,
    to_email: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_security: String,
    smtp_username: String,
    smtp_password: String,
    from_email: String,
    code: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmtpTestArgs {
    to_email: String,
    smtp_host: String,
    smtp_port: u16,
    smtp_security: String,
    smtp_username: String,
    smtp_password: String,
    from_email: String,
}

#[tauri::command]
async fn send_password_reset_email(args: ResetEmailArgs) -> Result<(), String> {
    let smtp_password = args.smtp_password;

    let to_email = args.to_email;
    let from_email = args.from_email;
    let code = args.code;
    let smtp_username = args.smtp_username;
    let smtp_security = args.smtp_security;
    let smtp_host = args.smtp_host;
    let smtp_port = args.smtp_port;

    let send_result = tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let message = Message::builder()
            .from(from_email.parse().map_err(|err| format!("Invalid from email: {err}"))?)
            .to(to_email.parse().map_err(|err| format!("Invalid recipient email: {err}"))?)
            .subject("Client Records Password Reset Code")
            .body(format!(
                "Your Client Records password reset code is: {}\n\nThis code expires in 10 minutes.\nIf you did not request this, you can ignore this email.",
                code
            ))
            .map_err(|err| format!("Failed to compose email: {err}"))?;

        let creds = Credentials::new(smtp_username, smtp_password);
        let security = smtp_security.to_lowercase();

        let mailer = if security == "ssl" {
            let tls_params = TlsParameters::new(smtp_host.clone()).map_err(|err| format!("TLS error: {err}"))?;
            SmtpTransport::builder_dangerous(&smtp_host)
                .port(smtp_port)
                .credentials(creds)
                .tls(Tls::Wrapper(tls_params))
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        } else if security == "tls" || security == "starttls" {
            SmtpTransport::starttls_relay(&smtp_host)
                .map_err(|err| format!("SMTP relay error: {err}"))?
                .port(smtp_port)
                .credentials(creds)
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        } else {
            SmtpTransport::builder_dangerous(&smtp_host)
                .port(smtp_port)
                .credentials(creds)
                .tls(Tls::None)
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        };

        mailer
            .send(&message)
            .map_err(|err| format!("Failed to send password reset email: {err}"))?;

        Ok(())
    })
    .await
    .map_err(|err| format!("Email task failed: {err}"))?;

    send_result?;

    Ok(())
}

#[tauri::command]
async fn send_email_verification_email(args: ResetEmailArgs) -> Result<(), String> {
    let smtp_password = args.smtp_password;

    let to_email = args.to_email;
    let from_email = args.from_email;
    let code = args.code;
    let smtp_username = args.smtp_username;
    let smtp_security = args.smtp_security;
    let smtp_host = args.smtp_host;
    let smtp_port = args.smtp_port;

    let send_result = tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let message = Message::builder()
            .from(from_email.parse().map_err(|err| format!("Invalid from email: {err}"))?)
            .to(to_email.parse().map_err(|err| format!("Invalid recipient email: {err}"))?)
            .subject("Client Records Email Verification Code")
            .body(format!(
                "Your Client Records email verification code is: {}\n\nThis code expires in 10 minutes.",
                code
            ))
            .map_err(|err| format!("Failed to compose email: {err}"))?;

        let creds = Credentials::new(smtp_username, smtp_password);
        let security = smtp_security.to_lowercase();

        let mailer = if security == "ssl" {
            let tls_params = TlsParameters::new(smtp_host.clone()).map_err(|err| format!("TLS error: {err}"))?;
            SmtpTransport::builder_dangerous(&smtp_host)
                .port(smtp_port)
                .credentials(creds)
                .tls(Tls::Wrapper(tls_params))
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        } else if security == "tls" || security == "starttls" {
            SmtpTransport::starttls_relay(&smtp_host)
                .map_err(|err| format!("SMTP relay error: {err}"))?
                .port(smtp_port)
                .credentials(creds)
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        } else {
            SmtpTransport::builder_dangerous(&smtp_host)
                .port(smtp_port)
                .credentials(creds)
                .tls(Tls::None)
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        };

        mailer
            .send(&message)
            .map_err(|err| format!("Failed to send verification email: {err}"))?;

        Ok(())
    })
    .await
    .map_err(|err| format!("Email task failed: {err}"))?;

    send_result?;

    Ok(())
}

#[tauri::command]
async fn send_smtp_test_email(args: SmtpTestArgs) -> Result<(), String> {
    let to_email = args.to_email;
    let from_email = args.from_email;
    let smtp_username = args.smtp_username;
    let smtp_password = args.smtp_password;
    let smtp_security = args.smtp_security;
    let smtp_host = args.smtp_host;
    let smtp_port = args.smtp_port;

    let send_result = tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let message = Message::builder()
            .from(from_email.parse().map_err(|err| format!("Invalid from email: {err}"))?)
            .to(to_email.parse().map_err(|err| format!("Invalid recipient email: {err}"))?)
            .subject("Client Records SMTP Test")
            .body("SMTP test successful. Your recovery email configuration is working.".to_string())
            .map_err(|err| format!("Failed to compose test email: {err}"))?;

        let creds = Credentials::new(smtp_username, smtp_password);
        let security = smtp_security.to_lowercase();

        let mailer = if security == "ssl" {
            let tls_params = TlsParameters::new(smtp_host.clone()).map_err(|err| format!("TLS error: {err}"))?;
            SmtpTransport::builder_dangerous(&smtp_host)
                .port(smtp_port)
                .credentials(creds)
                .tls(Tls::Wrapper(tls_params))
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        } else if security == "tls" || security == "starttls" {
            SmtpTransport::starttls_relay(&smtp_host)
                .map_err(|err| format!("SMTP relay error: {err}"))?
                .port(smtp_port)
                .credentials(creds)
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        } else {
            SmtpTransport::builder_dangerous(&smtp_host)
                .port(smtp_port)
                .credentials(creds)
                .tls(Tls::None)
                .timeout(Some(StdDuration::from_secs(SMTP_SEND_TIMEOUT_SECS)))
                .build()
        };

        mailer
            .send(&message)
            .map_err(|err| format!("Failed to send SMTP test email: {err}"))?;

        Ok(())
    })
    .await
    .map_err(|err| format!("Email task failed: {err}"))?;

    send_result?;

    Ok(())
}
