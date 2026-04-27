# Implementation Plan: SSH Config Sync (`ssync`)

## Overview

Implement `ssync`, a Go CLI tool that encrypts SSH artifacts with AES-256-GCM and syncs them to Cloudflare R2. Tasks are ordered to build foundational crypto and storage layers first, then wire them into CLI commands. Each task builds directly on the previous ones with no orphaned code.

## Tasks

- [x] 1. Scaffold Go module and project structure
  - Run `go mod init github.com/user/ssync` and create the directory tree: `cmd/`, `internal/crypto/`, `internal/credentials/`, `internal/r2/`, `internal/scanner/`, `internal/manifest/`, `internal/backup/`, `internal/conflict/`
  - Add `go.mod` dependencies: `github.com/spf13/cobra`, `github.com/aws/aws-sdk-go-v2`, `github.com/zalando/go-keyring`, `github.com/leanovate/gopter`, `golang.org/x/crypto`
  - Create `main.go` that calls `cmd.Execute()`
  - Create `cmd/root.go` with the root Cobra command, global `--ssh-dir` and `--force` flags, and stub sub-commands (`configure`, `push`, `pull`, `recover`, `regenerate-backup-codes`)
  - Define shared domain types in `internal/types.go`: `SSHArtifact`, `R2Credentials`, `Manifest`, `ManifestArtifact`, `EncryptedBlob`, `BackupCodeRecord`, `BackupCode`
  - _Requirements: 1.1, 3.1, 4.4_

- [x] 2. Implement EncryptionEngine
  - [x] 2.1 Implement `internal/crypto/engine.go`
    - Define `EncryptionEngine` interface with `Encrypt(plaintext []byte, password string) ([]byte, error)` and `Decrypt(blob []byte, password string) ([]byte, error)`
    - Implement `Encrypt`: validate password length ≥ 12, generate 32-byte random salt and 12-byte random nonce, derive 32-byte key with Argon2id (memory=65536, time=3, threads=4), AES-256-GCM seal, write binary blob: magic `SSCS` + version `0x01` + salt + nonce + tag + ciphertext
    - Implement `Decrypt`: parse blob header, derive key with Argon2id using stored salt, AES-256-GCM open (returns error on tag mismatch), unmarshal JSON envelope to extract content, filename, and relative path
    - Implement `ValidatePassword(password string) error` — rejects strings shorter than 12 characters
    - Implement JSON envelope marshal/unmarshal for `{name, relative_path, content}`
    - _Requirements: 1.1, 1.2, 1.3, 2.2, 2.3, 2.4, 9.1, 9.2, 9.3_

  - [x] 2.2 Write property test: Property 1 — Encryption round-trip preserves content and metadata
    - File: `internal/crypto/engine_test.go`
    - Use `gopter` generators for random byte slices (artifact content), random filenames, random relative paths, and random valid passwords (length ≥ 12)
    - Assert byte-identical content, identical filename, identical relative path after encrypt→decrypt
    - Tag: `// Feature: ssh-config-sync, Property 1: Encryption round-trip preserves content and metadata`
    - _Requirements: 9.1, 9.3, 2.2_

  - [x] 2.3 Write property test: Property 2 — Each encryption produces unique ciphertext
    - File: `internal/crypto/engine_test.go`
    - For the same plaintext and password, call `Encrypt` twice; assert nonces differ, salts differ, ciphertext bytes differ
    - Tag: `// Feature: ssh-config-sync, Property 2: Each encryption produces unique ciphertext`
    - _Requirements: 9.2, 1.2, 1.3_

  - [x] 2.4 Write property test: Property 3 — Wrong password fails decryption
    - File: `internal/crypto/engine_test.go`
    - Generate two distinct valid passwords A and B; encrypt with A, attempt decrypt with B; assert error returned and no plaintext bytes returned
    - Tag: `// Feature: ssh-config-sync, Property 3: Wrong password fails decryption`
    - _Requirements: 2.5_

  - [x] 2.5 Write property test: Property 4 — Tampered ciphertext fails decryption
    - File: `internal/crypto/engine_test.go`
    - After encrypting, mutate a random byte in the ciphertext or tag region (offset ≥ 65 bytes from start); assert `Decrypt` returns an authentication error and no plaintext
    - Tag: `// Feature: ssh-config-sync, Property 4: Tampered ciphertext fails decryption`
    - _Requirements: 2.3, 2.4_

  - [x] 2.6 Write property test: Property 13 — Short passwords are rejected
    - File: `internal/crypto/engine_test.go`
    - Generate random strings of length 0–11 (including empty and whitespace-only); assert `ValidatePassword` returns an error for all of them
    - Tag: `// Feature: ssh-config-sync, Property 13: Short passwords are rejected`
    - _Requirements: 1.5_

- [x] 3. Checkpoint — Ensure all crypto tests pass
  - Run `go test ./internal/crypto/...` and confirm all tests pass. Ask the user if any questions arise.

- [x] 4. Implement CredentialStore
  - [x] 4.1 Implement `internal/credentials/store.go`
    - Define `CredentialStore` interface with `Save(creds R2Credentials) error` and `Load() (R2Credentials, error)`
    - Implement keychain path: use `go-keyring` (service `ssync`, account `master-key`) to store/retrieve a random 32-byte master key; on first save, generate and store the master key
    - Implement fallback path (keychain unavailable): prompt user for a local passphrase, derive key with Argon2id, store salt in `~/.config/ssync/credentials.salt`
    - Serialize `R2Credentials` to JSON, encrypt with `EncryptionEngine` using the master key (or derived key), write to `~/.config/ssync/credentials.enc` with `os.Chmod(path, 0600)`
    - On `Load`: check file permissions with `os.Stat`; if broader than `0600`, return a security error without reading the file; decrypt and unmarshal credentials
    - _Requirements: 4.1, 4.2, 4.3, 4.5, 10.1, 10.2_

  - [x] 4.2 Write property test: Property 5 — Credential store round-trip
    - File: `internal/credentials/store_test.go`
    - Use `gopter` generators for random non-empty strings for all four credential fields; assert `Save` then `Load` returns byte-identical values
    - Tag: `// Feature: ssh-config-sync, Property 5: Credential store round-trip`
    - _Requirements: 10.1_

  - [x] 4.3 Write property test: Property 6 — Tampered credential file fails load
    - File: `internal/credentials/store_test.go`
    - After `Save`, mutate a random byte in the credential file; assert `Load` returns an error and no credential data
    - Tag: `// Feature: ssh-config-sync, Property 6: Tampered credential file fails load`
    - _Requirements: 10.2_

  - [x] 4.4 Write property test: Property 7 — Credential file permissions are enforced
    - File: `internal/credentials/store_test.go`
    - After `Save`, assert file has mode `0600`; programmatically widen permissions (e.g., `0644`), call `Load`, assert security error returned
    - Tag: `// Feature: ssh-config-sync, Property 7: Credential file permissions are enforced`
    - _Requirements: 4.3, 4.5_

- [x] 5. Implement R2Client
  - [x] 5.1 Implement `internal/r2/client.go`
    - Define `R2Client` interface with `Upload(key string, data []byte) error`, `Download(key string) ([]byte, error)`, `List() ([]string, error)`, `Delete(key string) error`
    - Implement using `aws-sdk-go-v2/service/s3` configured with the endpoint URL and credentials from `R2Credentials`
    - Translate S3 SDK errors into domain errors (connection error → exit code 2, not-found → typed error)
    - Implement `NewR2Client(creds R2Credentials) (R2Client, error)` constructor
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.6_

  - [x] 5.2 Write unit tests for R2Client with mock S3 backend
    - File: `internal/r2/client_test.go`
    - Use `aws-sdk-go-v2` mock transport or `httptest.Server` to simulate S3 responses
    - Test: successful upload, successful download, list objects, connection failure returns exit-code-2 error, partial failure reports per-artifact results
    - _Requirements: 3.5, 3.6_

- [x] 6. Implement ArtifactScanner
  - [x] 6.1 Implement `internal/scanner/scanner.go`
    - Define `ArtifactScanner` interface with `Scan(dir string) ([]SSHArtifact, error)`
    - Discover private keys (no extension or `.pem`, not `.pub`, mode 0600), public keys (`.pub`), `config`, `known_hosts`
    - Return descriptive error if directory does not exist or is empty
    - _Requirements: 7.1, 7.3, 7.4_

  - [x] 6.2 Write unit tests for ArtifactScanner
    - File: `internal/scanner/scanner_test.go`
    - Use `os.MkdirTemp` to create test SSH directories with various file combinations
    - Test: discovers all expected file types, ignores unrecognized files, returns error for missing directory, returns error for empty directory
    - _Requirements: 7.1, 7.3, 7.4_

- [x] 7. Implement ManifestManager
  - [x] 7.1 Implement `internal/manifest/manager.go`
    - Define `ManifestManager` interface with `Fetch() (Manifest, error)` and `Update(manifest Manifest) error`
    - `Fetch`: download `manifest.json` from R2 via `R2Client`; return empty manifest if object does not exist
    - `Update`: marshal `Manifest` to JSON, upload to R2 as `manifest.json`
    - _Requirements: 3.4, 8.1_

  - [x] 7.2 Write property test: Property 14 — Manifest serialization round-trip
    - File: `internal/manifest/manager_test.go`
    - Use `gopter` generators for random `Manifest` structs with arbitrary artifact entries, timestamps, and SHA256 strings
    - Assert marshal→unmarshal produces identical artifact names, R2 keys, sizes, timestamps, and SHA256 hashes
    - Tag: `// Feature: ssh-config-sync, Property 14: Manifest serialization round-trip`
    - _Requirements: 3.4_

- [x] 8. Implement ConflictDetector
  - [x] 8.1 Implement `internal/conflict/detector.go`
    - Define `ConflictResult` type with values `RemoteNewer`, `LocalNewer`, `Equal`
    - Implement `Detect(localModifiedAt, remoteUploadedAt time.Time) ConflictResult`
    - Return `RemoteNewer` when remote is strictly after local, `LocalNewer` when local is strictly after remote, `Equal` when identical
    - _Requirements: 8.1, 8.2, 8.3_

  - [x] 8.2 Write property test: Property 12 — Conflict detection correctly identifies newer artifact
    - File: `internal/conflict/detector_test.go`
    - Use `gopter` generators for random timestamp pairs; assert all three cases (`RemoteNewer`, `LocalNewer`, `Equal`) are correctly identified
    - Tag: `// Feature: ssh-config-sync, Property 12: Conflict detection correctly identifies newer artifact`
    - _Requirements: 8.1, 8.2, 8.3_

- [x] 9. Implement BackupCodeManager
  - [x] 9.1 Implement `internal/backup/manager.go`
    - Define `BackupCodeManager` interface with `Generate() ([]BackupCode, error)`, `StoreHashes(codes []BackupCode) error`, `Verify(code string) (bool, error)`, `Invalidate(code string) error`, `LoadHashes() ([]BackupCodeRecord, error)`
    - `Generate`: use `crypto/rand` to generate 16 random bytes per code, base32-encode, format as `XXXXX-XXXXX-XXXXX-XXXXX`; generate exactly 8 codes
    - `StoreHashes`: hash each code with Argon2id (PHC format, unique random salt per code), marshal to `BackupCodeRecord` JSON, upload to R2 as `backup-codes.json`
    - `Verify`: load hashes from R2, hash provided code with stored salt, constant-time compare; return `false` for used codes
    - `Invalidate`: load hashes, set matching record's `used = true`, re-upload `backup-codes.json`
    - _Requirements: 5.1, 5.2, 5.3, 6.1, 6.4_

  - [x] 9.2 Write property test: Property 8 — Backup codes stored as hashes, not plaintext
    - File: `internal/backup/manager_test.go`
    - After `StoreHashes`, read the raw bytes of `backup-codes.json`; assert none of the plaintext code strings appear in the raw bytes
    - Tag: `// Feature: ssh-config-sync, Property 8: Backup codes are stored as hashes, not plaintext`
    - _Requirements: 5.3_

  - [x] 9.3 Write property test: Property 9 — Backup code lifecycle: valid before use, invalid after
    - File: `internal/backup/manager_test.go`
    - Generate a set of codes; assert `Verify` returns `true` for each before use; call `Invalidate` on a randomly selected code; assert `Verify` returns `false` for that code and `true` for all others
    - Tag: `// Feature: ssh-config-sync, Property 9: Backup code lifecycle — valid before use, invalid after`
    - _Requirements: 6.1, 6.4_

  - [x] 9.4 Write property test: Property 10 — Regeneration invalidates all previous backup codes
    - File: `internal/backup/manager_test.go`
    - Generate and store an initial set of codes; generate and store a new set; assert every code from the original set fails `Verify`
    - Tag: `// Feature: ssh-config-sync, Property 10: Regeneration invalidates all previous backup codes`
    - _Requirements: 5.4_

- [x] 10. Checkpoint — Ensure all internal package tests pass
  - Run `go test ./internal/...` and confirm all tests pass. Ask the user if any questions arise.

- [x] 11. Implement `configure` command
  - [x] 11.1 Implement `cmd/configure.go`
    - Prompt user interactively for R2 access key ID, secret access key, endpoint URL, and bucket name using `bufio.Scanner` or `cobra` `RunE`
    - Validate that no field is empty
    - Call `CredentialStore.Save(creds)` and print success confirmation
    - _Requirements: 4.4_

  - [x] 11.2 Write unit tests for `configure` command
    - File: `cmd/configure_test.go`
    - Test: valid input saves credentials, empty field shows validation error, credential store error surfaces to user
    - _Requirements: 4.4_

- [x] 12. Implement `push` command
  - [x] 12.1 Implement `cmd/push.go`
    - Load credentials via `CredentialStore.Load()`
    - Call `ArtifactScanner.Scan(sshDir)` to discover artifacts; display list and prompt user to confirm selection
    - Fetch remote manifest via `ManifestManager.Fetch()`
    - For each confirmed artifact, run `ConflictDetector.Detect(localTime, remoteTime)`; if `RemoteNewer` and `--force` not set, warn and prompt confirmation
    - Prompt for `Encryption_Password` (validate ≥ 12 chars); on first push, also call `BackupCodeManager.Generate()`, display codes once with offline storage warning, call `BackupCodeManager.StoreHashes()`
    - For each artifact: call `EncryptionEngine.Encrypt(content, password)`, call `R2Client.Upload(key, blob)`
    - Call `ManifestManager.Update(manifest)` after all uploads
    - Report per-artifact success/failure; exit code 2 on any I/O or network error
    - _Requirements: 1.1, 1.4, 3.2, 5.1, 5.2, 7.1, 7.2, 8.1, 8.2, 8.3, 8.4_

  - [x] 12.2 Write unit tests for `push` command
    - File: `cmd/push_test.go`
    - Use mock implementations of all internal interfaces
    - Test: successful push flow, conflict detection prompts, `--force` skips conflict prompt, first-push generates backup codes, partial upload failure reports correctly
    - _Requirements: 3.6, 5.1, 8.2, 8.4_

- [x] 13. Implement `pull` command
  - [x] 13.1 Implement `cmd/pull.go`
    - Load credentials via `CredentialStore.Load()`
    - Prompt user for `Encryption_Password`
    - Fetch manifest via `ManifestManager.Fetch()`; exit with error if manifest is empty
    - For each artifact in manifest: call `R2Client.Download(key)`, call `EncryptionEngine.Decrypt(blob, password)`
    - On GCM tag failure: print tamper warning for that artifact, continue with remaining artifacts
    - On wrong password: display error, prompt retry or use backup code
    - Write decrypted content to local SSH directory path from envelope metadata
    - Report per-artifact success/failure; exit code 2 on network errors
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.3_

  - [x] 13.2 Write unit tests for `pull` command
    - File: `cmd/pull_test.go`
    - Test: successful pull flow, wrong password shows error and prompts retry, GCM failure shows tamper warning and continues, missing manifest exits with error
    - _Requirements: 2.4, 2.5_

- [x] 14. Implement `recover` command
  - [x] 14.1 Implement `cmd/recover.go`
    - Prompt user for a backup code
    - Call `BackupCodeManager.Verify(code)`; if invalid, display error and decrement remaining attempts counter; if all codes exhausted, display permanent loss warning and exit code 1
    - On valid code: prompt user for new `Encryption_Password` (validate ≥ 12 chars)
    - Fetch manifest, download all artifacts, decrypt with old password (stored in R2 as re-encryption requires the old key — note: recovery re-encrypts using the backup code to derive a temporary key; implement re-encryption loop: decrypt each artifact with current key, re-encrypt with new password key, re-upload)
    - Call `BackupCodeManager.Invalidate(code)` after successful re-encryption
    - Update manifest and re-upload
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [x] 14.2 Write property test: Property 11 — Re-encryption after recovery uses new password
    - File: `internal/crypto/engine_test.go`
    - Generate a set of random artifacts encrypted with password A; simulate recovery by re-encrypting all with password B; assert each artifact decrypts successfully with B and fails with A
    - Tag: `// Feature: ssh-config-sync, Property 11: Re-encryption after recovery uses new password`
    - _Requirements: 6.3_

  - [x] 14.3 Write unit tests for `recover` command
    - File: `cmd/recover_test.go`
    - Test: valid backup code triggers re-encryption and invalidation, invalid code decrements attempts, exhausted codes shows permanent loss message
    - _Requirements: 6.1, 6.4, 6.5, 6.6_

- [x] 15. Implement `regenerate-backup-codes` command
  - [x] 15.1 Implement `cmd/regenerate_backup_codes.go`
    - Prompt user for current `Encryption_Password` and verify it can decrypt at least one artifact from R2 (proves knowledge of password)
    - Call `BackupCodeManager.Generate()` to produce 8 new codes
    - Display new codes once with offline storage warning
    - Call `BackupCodeManager.StoreHashes(newCodes)` to upload new hashes (overwrites old `backup-codes.json`, invalidating all previous codes)
    - _Requirements: 5.4, 5.5_

  - [x] 15.2 Write unit tests for `regenerate-backup-codes` command
    - File: `cmd/regenerate_backup_codes_test.go`
    - Test: correct password generates and displays new codes, wrong password rejected, new codes stored and old codes invalidated
    - _Requirements: 5.4, 5.5_

- [x] 16. Checkpoint — Ensure all tests pass
  - Run `go test ./...` and confirm all tests pass. Ask the user if any questions arise.

- [x] 17. Wire integration and final polish
  - [x] 17.1 Write integration tests against local MinIO
    - File: `cmd/integration_test.go`
    - Use `httptest.Server` or a MinIO Docker container (skip with `testing.Short()` if unavailable) to run end-to-end push→pull round-trips
    - Test: full push/pull cycle preserves all artifact content, partial upload failure reports correctly, conflict detection works end-to-end
    - _Requirements: 3.1, 3.2, 3.3, 3.6, 9.1_

  - [x] 17.2 Verify exit codes and error message formatting
    - Audit all command `RunE` functions to ensure exit code `0` on success, `1` on user errors, `2` on I/O/network errors
    - Ensure no passwords, keys, or plaintext backup codes are written to stdout/stderr logs
    - _Requirements: 3.5, 4.5, 6.6, 7.4_

- [x] 18. Final checkpoint — Ensure all tests pass
  - Run `go test ./...` and confirm the full test suite passes. Ask the user if any questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at each layer boundary
- Property tests validate universal correctness properties using `gopter` with ≥ 100 iterations each
- Unit tests validate specific examples, error conditions, and CLI behavior
- The `recover` command requires careful handling: the backup code itself is not used as a decryption key — the recovery flow must have access to the current encrypted artifacts; consider storing a copy of the encryption key encrypted under each backup code, or requiring the user to provide the old password alongside the backup code (design decision to resolve during implementation of task 14)
