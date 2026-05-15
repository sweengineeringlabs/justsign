# Just-Sign Deployment Guide

Just-Sign provides cryptographic signing primitives for attesting artifacts. Used to create SLSA provenance and signed attestations in the vmisolate build and release pipeline.

## Prerequisites by Environment

### Windows
- **Rust 1.70+** (for building from source)
- **Git** (with SSH configured for GitHub access)
- **PowerShell 7+** or **Git Bash**
- **OpenSSL 1.1+** or **compatible crypto libs** (depends on sign module)

### Linux / WSL2
- **Rust 1.70+** (for building from source)
- **Git** (with SSH configured for GitHub access)
- **GCC / build-essential** (for linking)
- **OpenSSL development headers** (if needed): `libssl-dev` on Debian/Ubuntu

---

## Installation / Build

### Windows

#### Option A: Build from Source
```powershell
cd C:\phd-systems\swelabs\virtualization\justsign
cargo build --release

# Library and artifacts in
.\target\release\
```

**Add to PATH (optional, if binaries are exposed):**
```powershell
$env:PATH = "C:\phd-systems\swelabs\virtualization\justsign\target\release;" + $env:PATH
```

#### Option B: Download Prebuilt Release
Check GitHub releases for Windows release assets.

---

### Linux / WSL2

#### Option A: Build from Source
```bash
# Install dependencies (if needed)
sudo apt-get install -y libssl-dev build-essential

cd /path/to/justsign
cargo build --release

# Library and artifacts in
./target/release/

# Add to PATH if binaries are exposed
export PATH="./target/release:$PATH"
```

#### Option B: Download Prebuilt Release
```bash
# Check GitHub releases for Linux release assets
wget https://github.com/sweengineeringlabs/justsign/releases/download/vX.Y.Z/justsign-x86_64-unknown-linux-gnu.tar.gz
tar xzf justsign-x86_64-unknown-linux-gnu.tar.gz
```

---

## Verification

### Windows
```powershell
# Check if library is available to dependent crates
cargo build -p swe_justsign_sign --release
```

### Linux / WSL2
```bash
# Check if library is available to dependent crates
cargo build -p swe_justsign_sign --release
```

---

## Library Usage

Just-Sign is primarily used as a **library dependency** for cryptographic operations. Dependent crates include it in `Cargo.toml`:

```toml
sign = { path = "../justsign/sign", package = "swe_justsign_sign" }
```

### Example: Using in SLSA Attestation

From vmisolate's attestation pipeline:
```rust
use swe_justsign_sign::{Signer, PrivateKey};

// Load signing key
let key = PrivateKey::from_pem_file("signing.key")?;
let signer = Signer::new(key);

// Sign attestation
let statement = build_slsa_statement(&builder, &config)?;
let signature = signer.sign_json(&statement)?;
```

---

## Key Management

### Generating Signing Keys (Linux / WSL2)
```bash
# Generate ECDP256 key
openssl ecparam -name prime256v1 -genkey -noout -out signing.key

# Generate RSA key (2048-bit)
openssl genrsa -out signing.key 2048

# Export public key
openssl ec -in signing.key -pubout -out signing.pub
```

### Windows
Use PowerShell with OpenSSL installed, or generate keys in WSL2 and copy to Windows.

---

## Cross-Platform Notes

- **Cryptographic library**: Uses platform-native crypto (ring on default feature set)
- **SSH key support**: Can sign with SSH keys if configured
- **Attestation format**: Standard SLSA provenance and in-toto attestations
- **Deterministic signing**: Produces reproducible signatures for the same input

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `cargo not found` | Install Rust: https://rustup.rs |
| `git not found` | Install Git for your platform |
| `openssl not found` (Linux) | Install: `sudo apt-get install libssl-dev` |
| `key load failed` | Ensure private key is in PKCS#8 or PEM format |
| `path too long` (Windows) | Enable long paths: `git config --global core.longpaths true` |

---

## Integration with vmisolate

Just-Sign is used in the release and attestation pipeline:

- Signs OCI images and build artifacts
- Generates SLSA provenance statements
- Creates in-toto attestations for CI/CD tracking
- Enables signature verification for supply-chain security

See:
- [vmisolate Release Pipeline](../../scripts/ci/)
- [SLSA Provenance](../../docs/architecture/slsa.md) (if exists)
