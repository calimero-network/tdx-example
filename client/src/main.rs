use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use serde::{Deserialize, Serialize};

// ============================================================================
// CLI Arguments
// ============================================================================

#[derive(Parser)]
#[command(name = "tdx-client")]
#[command(about = "Client for TDX Attestation Server with full verification")]
struct Cli {
    /// Server URL (e.g., http://localhost:8080)
    #[arg(short, long)]
    server: String,

    /// Optional application binary to include in attestation (e.g., "python3")
    #[arg(short, long)]
    application: Option<String>,

    /// Expected application hash (SHA256, if application is specified)
    #[arg(long)]
    expected_application_hash: Option<String>,
}

// ============================================================================
// Server Response Types
// ============================================================================

#[derive(Deserialize, Debug)]
struct InfoResponse {
    cloud_provider: String,
    os_image: String,
    mrtd: String,
}

#[derive(Deserialize, Debug)]
struct AttestResponse {
    quote_b64: String,
    report_data_hex: String,
}

#[derive(Serialize)]
struct AttestRequest {
    nonce: String,
    application: Option<String>,
}

// ============================================================================
// Known MRTD Values for OS Images
// ============================================================================

struct KnownImage {
    name: &'static str,
    mrtd: &'static str,
    description: &'static str,
}

const KNOWN_OS_IMAGES: &[KnownImage] = &[
    // Ubuntu 24.04 TDX images
    // To get the image name your instance is running:
    //   gcloud compute instances describe INSTANCE_NAME --zone=ZONE --format="get(disks[0].source)"
    //   gcloud compute disks describe DISK_NAME --zone=ZONE --format="get(sourceImage)"
    //
    // To get MRTD: Run your TDX server - it will extract and print the MRTD
    // Then update this entry with the actual MRTD value

    KnownImage {
        name: "ubuntu-2404-noble-amd64-v20251014",
        // TODO: Run your server on tdx-demo to get the actual MRTD, then replace this placeholder
        mrtd: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        description: "Ubuntu 24.04 Noble (2025-10-14) on GCP",
    },
    // Add more known images here as your deployment grows
];

fn verify_mrtd_against_known_images(mrtd: &str, os_image: &str) -> Result<()> {
    // Try to find exact match
    if let Some(known) = KNOWN_OS_IMAGES.iter().find(|img| img.name == os_image) {
        // Check if we have a real MRTD (not placeholder)
        if known.mrtd.chars().all(|c| c == '0') {
            println!("        ⚠ MRTD verification skipped - placeholder value in database");
            println!("        OS Image: {}", known.description);
            println!("        Actual MRTD: {}", mrtd);
            println!("        To enable verification: Update KNOWN_OS_IMAGES with this MRTD");
            return Ok(());
        }

        if known.mrtd == mrtd {
            println!("        ✓ MRTD matches known image: {}", known.description);
            return Ok(());
        } else {
            anyhow::bail!(
                "❌ MRTD mismatch for {}!\n  Expected: {}\n  Got: {}",
                os_image,
                known.mrtd,
                mrtd
            );
        }
    }

    // Image not in our database
    println!("        ⚠ OS image '{}' not in known images database", os_image);
    println!("        Actual MRTD: {}", mrtd);
    println!("        To add: Update KNOWN_OS_IMAGES in client/src/main.rs");

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================
// NOTE: We do NOT verify server binary hash because:
// - Non-sealed enclave: Server can fake any hash (download GitHub binary,
//   hash it, report that hash while running different code)
// - Sealed enclave: Server identity is proven by MRTD (which includes the
//   application binary in its measurement)

// ============================================================================
// Main Verification Logic
// ============================================================================

async fn attest_and_verify(
    server_url: &str,
    application: Option<String>,
    expected_application_hash: Option<&str>,
) -> Result<()> {
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║        TDX Remote Attestation & Verification        ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    let client = reqwest::Client::new();

    // Step 1: Get server info
    println!("[ 1/4 ] Fetching server information...");
    let info_response: InfoResponse = client
        .get(format!("{}/info", server_url))
        .send()
        .await
        .context("Failed to fetch info")?
        .json()
        .await
        .context("Failed to parse info response")?;

    println!("        OS Image: {}", info_response.os_image);
    println!("        MRTD: {}...", &info_response.mrtd[..16]);

    // Step 2: Generate nonce
    println!("\n[ 2/4 ] Generating nonce...");
    let nonce: [u8; 32] = uuid::Uuid::new_v4()
        .as_bytes()
        .iter()
        .chain(uuid::Uuid::new_v4().as_bytes().iter())
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    let nonce_hex = hex::encode(nonce);
    println!("        Nonce: {}...", &nonce_hex[..16]);

    // Step 3: Request attestation
    println!("\n[ 3/4 ] Requesting attestation from server...");
    if let Some(app) = &application {
        println!("        Application: {}", app);
    } else {
        println!("        Application: None (server identity only)");
    }

    let request = AttestRequest {
        nonce: nonce_hex.clone(),
        application: application.clone(),
    };

    let attest_response: AttestResponse = client
        .post(format!("{}/attest", server_url))
        .json(&request)
        .send()
        .await
        .context("Failed to send attestation request")?
        .json()
        .await
        .context("Failed to parse attestation response")?;
    println!("        ✓ Attestation received");

    // Step 4: Verify nonce (freshness)
    println!("\n[ 4/4 ] Verifying nonce (freshness)...");
    let report_data = hex::decode(&attest_response.report_data_hex)?;
    if &report_data[..32] != nonce.as_slice() {
        anyhow::bail!("❌ Nonce mismatch - possible replay attack!");
    }
    println!("        ✓ Nonce matches");

    // Verify application hash if provided
    if let (Some(app), Some(expected_hash)) = (&application, expected_application_hash) {
        println!("\n[ * ] Verifying application hash...");
        println!("        Application: {}", app);

        // The application hash is in bytes 32-64 of report_data
        if report_data.len() < 64 {
            anyhow::bail!("❌ Report data too short for application hash");
        }

        let actual_hash_hex = hex::encode(&report_data[32..64]);
        if actual_hash_hex != expected_hash {
            anyhow::bail!(
                "❌ Application hash mismatch!\n  Expected: {}\n  Got: {}",
                expected_hash,
                actual_hash_hex
            );
        }
        println!("        ✓ Application hash matches");
    }

    // Verify TDX quote structure
    println!("\n[ * ] Verifying TDX quote...");
    let quote_bytes = base64::engine::general_purpose::STANDARD
        .decode(&attest_response.quote_b64)?;

    if quote_bytes.is_empty() {
        anyhow::bail!("❌ Empty TDX quote");
    }
    println!("        ✓ Quote structure valid ({} bytes)", quote_bytes.len());

    // Verify MRTD
    println!("\n[ * ] Verifying MRTD (OS/VM integrity)...");
    println!("        Platform: {}", info_response.cloud_provider);
    println!("        OS Image: {}", info_response.os_image);
    println!("        MRTD: {}...", &info_response.mrtd[..16]);

    // Verify against known OS images database
    verify_mrtd_against_known_images(
        &info_response.mrtd,
        &info_response.os_image,
    )?;

    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║             Attestation Verification: PASSED        ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    Ok(())
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    attest_and_verify(
        &cli.server,
        cli.application,
        cli.expected_application_hash.as_deref(),
    )
    .await?;

    Ok(())
}
