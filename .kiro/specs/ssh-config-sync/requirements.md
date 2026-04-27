# Requirements Document

## Introduction

SSH Config Sync is a command-line application that allows users to securely back up and restore their SSH configuration files (private keys, public keys, config files, and host aliases) to Cloudflare R2 cloud storage. All SSH artifacts are encrypted locally before upload using a user-provided password. Storage credentials are persisted locally in a secure, non-plaintext format. The application provides backup codes as a recovery mechanism when the user forgets their encryption password.

## Glossary

- **CLI**: The SSH Config Sync command-line interface application
- **SSH_Artifact**: A file from the user's SSH configuration directory, including private keys, public keys, config files, and host alias entries
- **Encryption_Engine**: The component responsible for encrypting and decrypting SSH artifacts using a password-derived key
- **Credential_Store**: The component responsible for securely persisting and retrieving R2 storage credentials on the local filesystem
- **R2_Client**: The component responsible for communicating with Cloudflare R2 storage using the S3-compatible API
- **Backup_Code_Manager**: The component responsible for generating, storing, and validating backup codes used for password recovery
- **Encryption_Password**: The user-provided password used to derive the encryption key for protecting SSH artifacts
- **Backup_Code**: A one-time-use recovery code that allows the user to reset the encryption password when the original password is forgotten
- **Manifest**: A metadata file stored alongside encrypted artifacts in R2 that tracks which SSH artifacts have been uploaded and their versions

## Requirements

### Requirement 1: Encrypt SSH Artifacts Before Upload

**User Story:** As a user, I want my SSH private keys, public keys, config files, and host aliases to be encrypted before they leave my machine, so that my sensitive credentials are never exposed in plaintext on the cloud.

#### Acceptance Criteria

1. WHEN the user initiates a sync upload, THE Encryption_Engine SHALL encrypt each SSH_Artifact using a key derived from the Encryption_Password before passing it to the R2_Client
2. THE Encryption_Engine SHALL use a recognized authenticated encryption algorithm (AES-256-GCM) with a unique initialization vector per artifact
3. THE Encryption_Engine SHALL derive the encryption key from the Encryption_Password using a key derivation function (Argon2id) with a random salt
4. WHEN the user initiates a sync upload for the first time, THE CLI SHALL prompt the user to create an Encryption_Password
5. IF the Encryption_Password is shorter than 12 characters, THEN THE CLI SHALL reject the password and display a descriptive error message

### Requirement 2: Decrypt and Restore SSH Artifacts

**User Story:** As a user, I want to download and decrypt my SSH artifacts from the cloud onto a new or existing machine, so that I can restore my SSH configuration seamlessly.

#### Acceptance Criteria

1. WHEN the user initiates a sync download, THE CLI SHALL prompt the user for the Encryption_Password
2. WHEN a valid Encryption_Password is provided, THE Encryption_Engine SHALL decrypt each downloaded SSH_Artifact and write it to the local SSH directory
3. THE Encryption_Engine SHALL verify the authentication tag of each encrypted artifact during decryption
4. IF the authentication tag verification fails, THEN THE Encryption_Engine SHALL abort the decryption of that artifact and display an error indicating potential data tampering
5. IF the provided Encryption_Password is incorrect, THEN THE CLI SHALL display an error message and prompt the user to retry or use a Backup_Code

### Requirement 3: Store and Retrieve Data Using Cloudflare R2

**User Story:** As a user, I want my encrypted SSH artifacts stored on Cloudflare R2 using the S3-compatible API, so that I can access them from any machine with an internet connection.

#### Acceptance Criteria

1. THE R2_Client SHALL communicate with Cloudflare R2 using the S3-compatible API
2. WHEN the user initiates a sync upload, THE R2_Client SHALL upload each encrypted SSH_Artifact to the configured R2 bucket
3. WHEN the user initiates a sync download, THE R2_Client SHALL download all encrypted SSH_Artifacts from the configured R2 bucket
4. THE R2_Client SHALL upload and maintain a Manifest file in the R2 bucket that records the list of stored artifacts and their metadata
5. IF the R2_Client fails to connect to the R2 endpoint, THEN THE CLI SHALL display a descriptive connection error and exit with a non-zero status code
6. IF an upload or download operation fails partway through, THEN THE R2_Client SHALL report which artifacts succeeded and which failed

### Requirement 4: Secure Local Storage of R2 Credentials

**User Story:** As a user, I want my R2 access key ID and secret access key stored securely on my local machine, so that they are not exposed in plaintext configuration files.

#### Acceptance Criteria

1. WHEN the user configures R2 credentials for the first time, THE Credential_Store SHALL encrypt the access key ID, secret access key, and endpoint URL before writing them to disk
2. THE Credential_Store SHALL encrypt credentials using a key derived from the user's operating system keychain or a local passphrase
3. THE Credential_Store SHALL store encrypted credentials in a dedicated configuration directory with file permissions restricted to the owning user (mode 0600)
4. THE CLI SHALL provide a `configure` command that prompts the user for R2 access key ID, secret access key, endpoint URL, and bucket name
5. IF the Credential_Store detects that the credential file has permissions broader than owner-only, THEN THE CLI SHALL display a security warning and refuse to proceed until permissions are corrected

### Requirement 5: Backup Code Generation and Management

**User Story:** As a user, I want to generate backup codes during initial setup, so that I can recover access to my encrypted SSH artifacts if I forget my encryption password.

#### Acceptance Criteria

1. WHEN the user creates an Encryption_Password for the first time, THE Backup_Code_Manager SHALL generate a set of 8 single-use Backup_Codes
2. THE Backup_Code_Manager SHALL display the generated Backup_Codes to the user exactly once and instruct the user to store them securely offline
3. THE Backup_Code_Manager SHALL store a hashed representation of each Backup_Code alongside the encrypted artifacts in the R2 bucket
4. THE CLI SHALL provide a `regenerate-backup-codes` command that generates a new set of Backup_Codes and invalidates all previous codes
5. WHEN the user runs the `regenerate-backup-codes` command, THE CLI SHALL require the current Encryption_Password before generating new codes

### Requirement 6: Password Recovery Using Backup Codes

**User Story:** As a user, I want to use a backup code to reset my encryption password when I have forgotten it, so that I do not permanently lose access to my SSH artifacts.

#### Acceptance Criteria

1. WHEN the user provides a valid Backup_Code during password recovery, THE Backup_Code_Manager SHALL verify the code against the stored hashed codes
2. WHEN a Backup_Code is verified successfully, THE CLI SHALL prompt the user to set a new Encryption_Password
3. WHEN a new Encryption_Password is set via recovery, THE Encryption_Engine SHALL re-encrypt all stored SSH_Artifacts with a key derived from the new password
4. WHEN a Backup_Code is used successfully, THE Backup_Code_Manager SHALL invalidate that specific code so it cannot be reused
5. IF an invalid Backup_Code is provided, THEN THE CLI SHALL display an error message and decrement the remaining recovery attempts
6. IF the user exhausts all valid Backup_Codes without a successful recovery, THEN THE CLI SHALL display a message indicating that recovery is no longer possible and the encrypted data cannot be accessed

### Requirement 7: SSH Artifact Discovery and Selection

**User Story:** As a user, I want the CLI to automatically discover my SSH artifacts from the standard SSH directory, so that I do not have to manually specify each file.

#### Acceptance Criteria

1. WHEN the user initiates a sync upload without specifying files, THE CLI SHALL scan the default SSH directory (~/.ssh) for private keys, public keys, config files, and known_hosts files
2. THE CLI SHALL display the list of discovered SSH_Artifacts and prompt the user to confirm which artifacts to include in the sync
3. WHERE the user specifies a custom SSH directory path, THE CLI SHALL scan that directory instead of the default
4. IF the SSH directory does not exist or is empty, THEN THE CLI SHALL display a descriptive error message and exit with a non-zero status code

### Requirement 8: Sync Conflict Detection

**User Story:** As a user, I want the CLI to detect conflicts between local and remote SSH artifacts, so that I do not accidentally overwrite newer configurations.

#### Acceptance Criteria

1. WHEN the user initiates a sync upload, THE CLI SHALL compare local artifact timestamps against the Manifest metadata in the R2 bucket
2. IF a remote artifact is newer than the local artifact, THEN THE CLI SHALL warn the user and prompt for confirmation before overwriting
3. IF a local artifact is newer than the remote artifact, THEN THE CLI SHALL proceed with the upload
4. THE CLI SHALL provide a `--force` flag that skips conflict detection and overwrites remote artifacts unconditionally

### Requirement 9: Encryption Round-Trip Integrity

**User Story:** As a developer, I want to verify that encrypting and then decrypting any SSH artifact produces the original file content, so that data integrity is guaranteed.

#### Acceptance Criteria

1. FOR ALL valid SSH_Artifacts, encrypting with the Encryption_Engine and then decrypting with the same Encryption_Password SHALL produce byte-identical output to the original artifact (round-trip property)
2. FOR ALL valid SSH_Artifacts, encrypting the same artifact twice with the same Encryption_Password SHALL produce different ciphertext due to unique initialization vectors
3. THE Encryption_Engine SHALL preserve the original file name and relative path metadata through the encryption and decryption round-trip

### Requirement 10: Credential Serialization Round-Trip

**User Story:** As a developer, I want to verify that serializing and deserializing R2 credentials produces identical credential data, so that credential storage is reliable.

#### Acceptance Criteria

1. FOR ALL valid credential sets, serializing with the Credential_Store and then deserializing SHALL produce identical access key ID, secret access key, endpoint URL, and bucket name (round-trip property)
2. IF the credential file is corrupted or tampered with, THEN THE Credential_Store SHALL detect the corruption and display an error rather than returning invalid credentials
