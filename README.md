# TDX Remote Attestation Example

A minimal TDX remote attestation implementation demonstrating:
1. Server runs on genuine Intel TDX hardware
2. Application binary verification via hash in TDX quote
3. OS/VM integrity via MRTD verification
4. Freshness via client-generated nonce

## Quick Start

### Server (On TDX VM)

```bash
cargo build --release -p server
./target/release/server

# Output:
# =================================================
# TDX Attestation Server
# =================================================
# Listening on http://0.0.0.0:8080
# Endpoints:
#   GET  /info   - Get server and host information
#   POST /attest - Generate attestation quote
```

### Client (Any Machine)

```bash
# Basic attestation (no application verification)
cargo build --release -p client
./target/release/client --server http://YOUR_SERVER:8080

# With application verification
# First, calculate expected hash:
sha256sum /usr/bin/curl | awk '{ print $1 }'
# aca992dba6da014cd5baaa739624e68362c8930337f3a547114afdbd708d06a4

./target/release/client \
  --server http://YOUR_SERVER:8080 \
  --application curl \
  --expected-application-hash aca992dba6da014cd5baaa739624e68362c8930337f3a547114afdbd708d06a4

# Verification steps:
# ✓ Server information fetched
# ✓ Nonce generated
# ✓ Attestation received
# ✓ TDX quote parsed
# ✓ Nonce verified (freshness)
# ✓ Application hash verified
# ✓ MRTD verified
```

## How It Works

### Attestation Flow

```
┌──────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
│          │                              │  (TDX)   │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ 1. GET /info                            │
     │────────────────────────────────────────>│
     │                                         │
     │<────────────────────────────────────────│
     │    { cloud_provider, os_image, mrtd }   │
     │                                         │
     │ 2. Generate nonce (32 bytes)            │
     │                                         │
     │ 3. POST /attest                         │
     │    { nonce, application? }              │
     │────────────────────────────────────────>│
     │                                         │
     │                                         │ 4. Hash application (if requested)
     │                                         │ 5. Build report_data:
     │                                         │    [nonce][app_hash]
     │                                         │ 6. Generate TDX quote
     │                                         │
     │<────────────────────────────────────────│
     │    { quote_b64 }                        │
     │                                         │
     │ 7. Parse TDX quote                      │
     │ 8. Extract report_data from quote       │
     │ 9. Verify nonce matches (freshness)     │
     │ 10. Verify application hash             │
     │ 11. Verify MRTD against known images    │
     │                                         │
     └─ ✓ TRUSTED                              │
```

### Report Data Structure

```
report_data [64 bytes]:
  [0..32]  = nonce (client-generated, prevents replay)
  [32..64] = SHA256(application_binary) or zeros
```

**Key Security Property**: The client **extracts report_data from the cryptographically signed TDX quote**, not from server claims. The server cannot lie about what's in the quote.

## API

### GET /info

Returns server and host information.

**Response**:
```json
{
  "cloud_provider": "gcp",
  "os_image": "ubuntu-2404-noble-amd64-v20251014",
  "mrtd": "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694"
}
```

### POST /attest

Generates a TDX attestation quote.

**Request**:
```json
{
  "nonce": "64-character-hex-string",
  "application": "curl"  // Optional: binary name to verify
}
```

**Response**:
```json
{
  "quote_b64": "base64-encoded-tdx-quote"
}
```

The quote contains the `report_data` which the client must parse and verify.

## Security Properties

### What This Proves

| Property | Verification | Trust Anchor |
|----------|--------------|--------------|
| **Hardware** | TDX quote signature (⚠ not yet verified) | Intel |
| **OS Image** | MRTD comparison | Cloud provider + known images DB |
| **Application Binary** | Hash in quote's report_data | TDX hardware measurement |
| **Freshness** | Nonce in quote's report_data | Client-generated randomness |

### Current Security Level

✓ **Protects against:**
- Wrong OS image (MRTD verification)
- Tampered application binary (hash in TDX quote)
- Replay attacks (nonce verification)
- Server lying about report_data (extracted from signed quote)

⚠ **Does NOT protect against:**
- Fake TDX hardware (quote signature not verified yet - see "Missing Features")
- Server operator swapping application after attestation
- Malicious server operator with root access

## Architecture

### Server (`server/src/main.rs`)

**Key Functions**:
- `get_mrtd()` - Extracts MRTD using `LinuxTdxProvider::get_launch_measurement()`
- `detect_host_info()` - Detects cloud provider and OS image
- `hash_file()` - Computes SHA256 of application binary
- `create_tdx_quote()` - Generates TDX quote via configfs-tsm

**Report Data Construction**:
```rust
let mut report_data = [0u8; 64];
report_data[..32].copy_from_slice(&nonce);
report_data[32..].copy_from_slice(&app_hash);  // or zeros if no app
```

### Client (`client/src/main.rs`)

**Key Functions**:
- `verify_mrtd_against_known_images()` - Checks MRTD against database
- Uses `tdx-quote` crate to parse TDX quotes and extract report_data

**Verification Steps**:
1. Fetch server info (`/info`)
2. Generate 32-byte nonce
3. Request attestation (`/attest`)
4. **Parse TDX quote** using `tdx_quote::Quote::from_bytes()`
5. **Extract report_data** from quote using `quote.report_input_data()`
6. Verify nonce matches (bytes 0-32)
7. Verify application hash (bytes 32-64) if provided
8. Verify MRTD against known images

### Known OS Images Database

The client maintains a list of known OS images with their MRTDs in `client/src/main.rs`:

```rust
const KNOWN_OS_IMAGES: &[KnownImage] = &[
    KnownImage {
        name: "ubuntu-2404-noble-amd64-v20251014",
        mrtd: "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694",
        description: "Ubuntu 24.04 Noble (2025-10-14) on GCP",
    },
];
```

**To add a new OS image**:
1. Deploy and run your TDX server
2. Call `/info` endpoint to get the MRTD
3. Add entry to `KNOWN_OS_IMAGES` array
4. Recompile client

## Missing Features

### Certificate Chain Verification ⚠️

**Current**: The TDX quote signature is **not verified**. The quote contains:
- Attestation key certificate
- PCK (Provisioning Certification Key) certificate chain
- Intel signature

**What's needed**: Verify the complete certificate chain:
1. Parse quote's certification data
2. Extract PCK certificate chain
3. Verify chain up to Intel root CA
4. Verify quote signature with attestation key

**Libraries to use**:
- `tdx-quote` crate already parses certification data
- Need to add certificate chain validation using `x509-parser` or similar
- Intel's DCAP library provides reference implementation

**Security impact**: Without this, a sophisticated attacker could forge quotes. MRTD verification provides some protection (must match cloud provider's measurements), but full chain verification is essential for production.

## Advanced Topics

- **Protecting against malicious operators**: See `SECURITY-ADVANCED.md` for solutions including:
  - Sealed Enclave (recommended for high security)
  - Multi-Party Computation
  - HSM Hybrid approach
  - Continuous Re-Attestation

## Resources

- [Intel TDX Documentation](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [GCP Confidential VMs](https://cloud.google.com/confidential-computing)
- [tdx_workload_attestation](https://github.com/IntelLabs/tdx-workload-attestation)
- [tdx-quote](https://github.com/entropyxyz/tdx-quote)
- [configfs-tsm](https://docs.kernel.org/ABI/testing/configfs-tsm)
