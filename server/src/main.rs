use axum::{routing::post, Json, Router};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use configfs_tsm::create_tdx_quote;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use tdx_workload_attestation::tdx::LinuxTdxProvider;
use tdx_workload_attestation::provider::AttestationProvider;

// ============================================================================
// Configuration
// ============================================================================

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Deserialize, Debug)]
struct AttestRequest {
    /// Client-provided nonce for freshness (32 bytes as hex string)
    nonce: String,
    /// Optional application binary to include in attestation (e.g., "python3")
    /// If provided, will be hashed and included in report_data
    application: Option<String>,
}

#[derive(Serialize, Debug)]
struct InfoResponse {
    /// Cloud provider (e.g., "gcp", "azure", "unknown")
    cloud_provider: String,
    /// OS image name (e.g., "ubuntu-2404-tdx-v20250115")
    os_image: String,
    /// MRTD extracted from TD report (48 bytes hex)
    mrtd: String,
}

#[derive(Serialize, Debug)]
struct AttestResponse {
    /// Base64-encoded TDX quote
    quote_b64: String,
    /// Hex-encoded report_data (64 bytes)
    /// Format: nonce[32] || hash(server_hash || app_hash)[32]
    report_data_hex: String,
}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    error: String,
}

// ============================================================================
// Internal Types
// ============================================================================

struct HostInfo {
    cloud_provider: String,
    os_image: String,
    mrtd: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

fn hash_file(path: &str) -> Result<String, std::io::Error> {
    let contents = std::fs::read(path)?;
    let hash = Sha256::digest(&contents);
    Ok(hex::encode(hash))
}

fn get_server_hash() -> String {
    let exe_path = std::env::current_exe().expect("Failed to get current executable path");
    hash_file(exe_path.to_str().unwrap()).expect("Failed to hash server binary")
}


fn get_mrtd() -> Result<String, String> {
    let provider = LinuxTdxProvider::new();
    let mrtd = provider.get_launch_measurement()
        .map_err(|e| format!("Failed to get launch measurement: {:?}", e))?;

    Ok(hex::encode(mrtd))
}

async fn detect_host_info() -> Result<HostInfo, String> {
    // Get MRTD first
    let mrtd = get_mrtd()?;

    // Try to detect GCP
    if let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
    {
        if let Ok(response) = client
            .get("http://metadata.google.internal/computeMetadata/v1/instance/image")
            .header("Metadata-Flavor", "Google")
            .send()
            .await
        {
            if let Ok(image) = response.text().await {
                let image_name = image.split('/').last().unwrap_or(&image).to_string();

                let _project_id = match client
                    .get("http://metadata.google.internal/computeMetadata/v1/project/project-id")
                    .header("Metadata-Flavor", "Google")
                    .send()
                    .await
                {
                    Ok(r) => r.text().await.ok(),
                    Err(_) => None,
                }
                .unwrap_or_else(|| "ubuntu-os-cloud".to_string());

                return Ok(HostInfo {
                    cloud_provider: "gcp".to_string(),
                    os_image: image_name.clone(),
                    mrtd,
                });
            }
        }
    }

    // Fallback: Unknown platform
    Ok(HostInfo {
        cloud_provider: "unknown".to_string(),
        os_image: "unknown".to_string(),
        mrtd,
    })
}

fn get_application_path(app_name: &str) -> String {
    // Common locations for binaries
    for prefix in ["/usr/bin", "/usr/local/bin", "/bin"] {
        let path = format!("{}/{}", prefix, app_name);
        if std::path::Path::new(&path).exists() {
            return path;
        }
    }
    // Fallback to /usr/bin
    format!("/usr/bin/{}", app_name)
}

// ============================================================================
// Info Endpoint
// ============================================================================

async fn info() -> Result<Json<InfoResponse>, Json<ErrorResponse>> {
    // Get host info
    let host_info = detect_host_info().await.map_err(|e| {
        Json(ErrorResponse {
            error: format!("Failed to get host info: {}", e),
        })
    })?;

    Ok(Json(InfoResponse {
        cloud_provider: host_info.cloud_provider,
        os_image: host_info.os_image,
        mrtd: host_info.mrtd,
    }))
}

// ============================================================================
// Attestation Endpoint
// ============================================================================

async fn attest(
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, Json<ErrorResponse>> {
    // 1. Validate nonce
    let nonce = hex::decode(&req.nonce).map_err(|_| {
        Json(ErrorResponse {
            error: "Invalid nonce format (must be 64 hex characters)".to_string(),
        })
    })?;

    if nonce.len() != 32 {
        return Err(Json(ErrorResponse {
            error: "Nonce must be exactly 32 bytes (64 hex characters)".to_string(),
        }));
    }

    // 2. Get server hash
    let server_hash = get_server_hash();

    // 3. Get application hash (if requested)
    let app_hash = if let Some(app_name) = &req.application {
        let app_path = get_application_path(app_name);
        hash_file(&app_path).map_err(|e| {
            Json(ErrorResponse {
                error: format!("Failed to hash application '{}': {}", app_name, e),
            })
        })?
    } else {
        String::new()
    };

    // 4. Build report_data: nonce[32] || hash(server_hash || app_hash)[32]
    // NOTE: Server hash is included in report_data but NOT returned to client because:
    // - Non-sealed: Server could fake the hash anyway (meaningless to return it)
    // - Sealed: Server identity is proven by MRTD (hash is already measured)
    // The hash is still included in report_data to bind the attestation to the
    // server binary, but client cannot verify it in non-sealed mode.
    let combined = if app_hash.is_empty() {
        server_hash
    } else {
        format!("{}{}", server_hash, app_hash)
    };
    let combined_hash = Sha256::digest(combined.as_bytes());

    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&nonce);
    report_data[32..].copy_from_slice(&combined_hash[..32]);

    // 5. Generate TDX quote
    let quote_bytes = create_tdx_quote(report_data).map_err(|e| {
        Json(ErrorResponse {
            error: format!("Failed to generate TDX quote: {:?}", e),
        })
    })?;

    // 6. Return attestation
    Ok(Json(AttestResponse {
        quote_b64: base64_engine.encode(&quote_bytes),
        report_data_hex: hex::encode(report_data),
    }))
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    println!("=================================================");
    println!("TDX Attestation Server");
    println!("=================================================");

    let app = Router::new()
        .route("/info", axum::routing::get(info))
        .route("/attest", post(attest));

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("Listening on http://{}", addr);
    println!("Endpoints:");
    println!("  GET  /info   - Get server and host information");
    println!("  POST /attest - Generate attestation quote");
    println!();

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind to address");

    axum::serve(listener, app)
        .await
        .expect("Server failed");
}
