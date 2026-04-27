# ssync

Securely back up and restore SSH artifacts to Cloudflare R2. All encryption happens client-side — your private keys never leave your machine in plaintext.

## How it works

- Encrypts each SSH artifact (private keys, public keys, `config`, `known_hosts`) with **AES-256-GCM** before upload
- Derives the encryption key from your password using **Argon2id** with a fresh random salt per artifact
- Stores encrypted artifacts in a Cloudflare R2 bucket via the S3-compatible API
- R2 credentials are stored locally in an encrypted file (protected by your OS keychain or a local passphrase)
- Generates **8 single-use backup codes** on first push so you can recover access if you forget your password

## Installation

```bash
go install github.com/imadenugraha/ssync@latest
```

Or build from source:

```bash
git clone https://github.com/imadenugraha/ssync
cd ssync
make build
```

The binary is placed at `./bin/ssync`.

## Quick start

### 1. Configure R2 credentials

```bash
ssync configure
```

You'll be prompted for your Cloudflare R2 access key ID, secret access key, endpoint URL, and bucket name. Credentials are encrypted and stored at `~/.config/ssync/credentials.enc` with mode `0600`.

### 2. Push SSH artifacts

```bash
ssync push
```

On first push, ssync will:
1. Scan `~/.ssh` for private keys, public keys, `config`, and `known_hosts`
2. Show the discovered files and ask which to include
3. Prompt for an encryption password (minimum 12 characters)
4. Generate and display 8 backup codes — **store these offline**
5. Encrypt and upload each artifact

### 3. Pull SSH artifacts on a new machine

```bash
ssync pull
```

Downloads and decrypts all artifacts from R2 into `~/.ssh`.

## Commands

| Command | Description |
|---|---|
| `ssync configure` | Store R2 credentials |
| `ssync push` | Encrypt and upload SSH artifacts |
| `ssync pull` | Download and decrypt SSH artifacts |
| `ssync recover` | Reset encryption password using a backup code |
| `ssync regenerate-backup-codes` | Generate a new set of backup codes |

### Global flags

| Flag | Default | Description |
|---|---|---|
| `--ssh-dir` | `~/.ssh` | Path to the SSH directory |
| `--force` | `false` | Skip conflict detection on push |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | User error (wrong password, validation failure, etc.) |
| `2` | I/O or network error |

## Password recovery

If you forget your encryption password, use a backup code:

```bash
ssync recover
```

You'll be prompted for a backup code, your current password (to decrypt existing artifacts), and a new password. All artifacts are re-encrypted with the new password and the used backup code is invalidated.

To generate a fresh set of backup codes (invalidates all previous ones):

```bash
ssync regenerate-backup-codes
```

## Conflict detection

On `push`, ssync compares local file modification times against the `uploaded_at` timestamps in the remote manifest. If a remote artifact is newer than the local file, you'll be prompted to confirm before overwriting. Use `--force` to skip this check.

## Security notes

- AES-256-GCM provides authenticated encryption — any tampering with a stored artifact is detected on download
- Argon2id parameters: memory=64 MiB, iterations=3, parallelism=4
- Each encryption call uses a fresh random 32-byte salt and 12-byte nonce, so encrypting the same file twice produces different ciphertext
- Backup codes use ~117 bits of entropy and are stored as Argon2id hashes (never plaintext) in R2
- The credential file is refused if its permissions are broader than `0600`
- Passwords, keys, and plaintext backup codes are never written to logs or stderr

## Development

```bash
make test        # run all tests
make test-short  # skip integration tests
make build       # build binary to ./bin/ssync
make lint        # run go vet
make clean       # remove build artifacts
```

### Project structure

```
cmd/                    CLI commands (configure, push, pull, recover, regenerate-backup-codes)
internal/
  crypto/               AES-256-GCM + Argon2id encryption engine
  credentials/          Encrypted local credential store
  r2/                   Cloudflare R2 client (S3-compatible)
  scanner/              SSH artifact discovery
  manifest/             Remote manifest management
  backup/               Backup code generation and verification
  conflict/             Timestamp-based conflict detection
  types.go              Shared domain types
main.go
```

### Running tests

```bash
make test
```

Property-based tests use [gopter](https://github.com/leanovate/gopter). The Argon2id-heavy tests run with reduced iteration counts (5 iterations) to keep the suite fast (~50s total). Increase `MinSuccessfulTests` in the test files for more thorough validation.
