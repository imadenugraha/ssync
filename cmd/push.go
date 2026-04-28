package cmd

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/user/ssync/internal"
	"github.com/user/ssync/internal/backup"
	"github.com/user/ssync/internal/conflict"
	"github.com/user/ssync/internal/credentials"
	"github.com/user/ssync/internal/crypto"
	"github.com/user/ssync/internal/manifest"
	"github.com/user/ssync/internal/r2"
	"github.com/user/ssync/internal/scanner"
)

// artifactEncrypter is a local interface so we don't need to modify the crypto package.
type artifactEncrypter interface {
	EncryptArtifact(content []byte, name, relativePath, password string) ([]byte, error)
}

// pushRunner holds injectable dependencies for the push command.
type pushRunner struct {
	in       io.Reader
	out      io.Writer
	store    credentials.CredentialStore
	scanner  scanner.ArtifactScanner
	r2       r2.R2Client
	engine   artifactEncrypter
	manifest manifest.ManifestManager
	backup   backup.BackupCodeManager
	force    bool
	sshDir   string
	pwReader passwordReader
	sc       *bufio.Scanner // shared scanner; nil means create from r.in
}

func (r *pushRunner) run() error {
	if r.sc == nil {
		r.sc = bufio.NewScanner(r.in)
	}
	sc := r.sc

	prompt := func(label string) (string, error) {
		fmt.Fprintf(r.out, "%s", label)
		if !sc.Scan() {
			if err := sc.Err(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("unexpected end of input")
		}
		return strings.TrimSpace(sc.Text()), nil
	}

	// 1. Discover artifacts.
	artifacts, err := r.scanner.Scan(r.sshDir)
	if err != nil {
		return &exitError{code: 1, msg: fmt.Sprintf("scan SSH directory: %v", err)}
	}

	// 2. Display list and prompt for confirmation.
	fmt.Fprintln(r.out, "Artifacts found:")
	for i, a := range artifacts {
		fmt.Fprintf(r.out, "  %d. %s\n", i+1, a.Name)
	}

	confirmed, err := r.selectArtifacts(artifacts, prompt)
	if err != nil {
		return err
	}
	if len(confirmed) == 0 {
		fmt.Fprintln(r.out, "No artifacts selected. Aborting.")
		return nil
	}

	// 3. Fetch remote manifest.
	remoteManifest, err := r.manifest.Fetch()
	if err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("fetch manifest: %v", err)}
	}

	// Build a lookup map for remote artifact timestamps.
	remoteByName := make(map[string]internal.ManifestArtifact)
	for _, ma := range remoteManifest.Artifacts {
		remoteByName[ma.Name] = ma
	}

	// 4. Prompt for encryption password (validate ≥ 12 chars).
	password, err := r.promptPassword(prompt)
	if err != nil {
		return err
	}

	// 5. First-push detection: try LoadHashes; if ErrNotFound or empty → first push.
	isFirstPush := false
	hashes, hashErr := r.backup.LoadHashes()
	if hashErr != nil {
		if errors.Is(hashErr, r2.ErrNotFound) || strings.Contains(hashErr.Error(), "not found") {
			isFirstPush = true
		}
		// Other errors are non-fatal for this check; we'll treat as not-first-push.
	} else if len(hashes) == 0 {
		isFirstPush = true
	}

	if isFirstPush {
		codes, err := r.backup.Generate()
		if err != nil {
			return &exitError{code: 2, msg: fmt.Sprintf("generate backup codes: %v", err)}
		}
		fmt.Fprintln(r.out, "\n*** BACKUP CODES — store these offline, they will not be shown again ***")
		for i, c := range codes {
			fmt.Fprintf(r.out, "  %d. %s\n", i+1, c.Code)
		}
		fmt.Fprintln(r.out, "*** END BACKUP CODES ***")

		if err := r.backup.StoreHashes(codes); err != nil {
			return &exitError{code: 2, msg: fmt.Sprintf("store backup code hashes: %v", err)}
		}
	}

	// 6. Encrypt and upload each confirmed artifact.
	type result struct {
		name string
		err  error
	}
	results := make([]result, 0, len(confirmed))

	updatedArtifacts := make([]internal.ManifestArtifact, 0, len(remoteManifest.Artifacts))
	// Keep existing artifacts that are not being pushed.
	for _, ma := range remoteManifest.Artifacts {
		keep := true
		for _, a := range confirmed {
			if a.Name == ma.Name {
				keep = false
				break
			}
		}
		if keep {
			updatedArtifacts = append(updatedArtifacts, ma)
		}
	}

	for _, artifact := range confirmed {
		// Conflict detection.
		if !r.force {
			if remote, ok := remoteByName[artifact.Name]; ok {
				cr := conflict.Detect(artifact.ModifiedAt, remote.UploadedAt)
				if cr == conflict.RemoteNewer {
					ans, err := prompt(fmt.Sprintf("Remote is newer for %q. Overwrite? [y/N] ", artifact.Name))
					if err != nil {
						return err
					}
					if ans != "y" && ans != "Y" {
						fmt.Fprintf(r.out, "Skipping %s\n", artifact.Name)
						results = append(results, result{name: artifact.Name, err: fmt.Errorf("skipped (remote newer)")})
						continue
					}
				}
			}
		}

		// Read artifact content.
		content, err := os.ReadFile(artifact.AbsolutePath)
		if err != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("read file: %w", err)})
			continue
		}

		// Encrypt.
		blob, err := r.engine.EncryptArtifact(content, artifact.Name, artifact.RelativePath, password)
		if err != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("encrypt: %w", err)})
			continue
		}

		// Upload.
		key := "artifacts/" + artifact.Name + ".enc"
		if err := r.r2.Upload(key, blob); err != nil {
			results = append(results, result{name: artifact.Name, err: fmt.Errorf("upload: %w", err)})
			continue
		}

		// Compute SHA256 of plaintext content.
		sum := sha256.Sum256(content)
		sha256hex := fmt.Sprintf("%x", sum)

		updatedArtifacts = append(updatedArtifacts, internal.ManifestArtifact{
			Name:            artifact.Name,
			RelativePath:    artifact.RelativePath,
			R2Key:           key,
			SizeBytes:       artifact.Size,
			LocalModifiedAt: artifact.ModifiedAt,
			UploadedAt:      time.Now().UTC(),
			SHA256:          sha256hex,
		})

		results = append(results, result{name: artifact.Name, err: nil})
	}

	// 7. Update manifest.
	newManifest := internal.Manifest{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Artifacts: updatedArtifacts,
	}
	if err := r.manifest.Update(newManifest); err != nil {
		return &exitError{code: 2, msg: fmt.Sprintf("update manifest: %v", err)}
	}

	// 8. Report per-artifact status.
	anyFailed := false
	fmt.Fprintln(r.out, "\nPush results:")
	for _, res := range results {
		if res.err != nil {
			fmt.Fprintf(r.out, "  ✗ %s: %v\n", res.name, res.err)
			if !strings.Contains(res.err.Error(), "skipped") {
				anyFailed = true
			}
		} else {
			fmt.Fprintf(r.out, "  ✓ %s\n", res.name)
		}
	}

	if anyFailed {
		return &exitError{code: 2, msg: "one or more artifacts failed to upload"}
	}
	return nil
}

// selectArtifacts displays the artifact list and prompts the user to confirm selection.
func (r *pushRunner) selectArtifacts(artifacts []internal.SSHArtifact, prompt func(string) (string, error)) ([]internal.SSHArtifact, error) {
	ans, err := prompt("Push all? [Y/n] ")
	if err != nil {
		return nil, err
	}
	if ans != "n" && ans != "N" {
		return artifacts, nil
	}

	// Prompt for comma-separated numbers.
	nums, err := prompt("Enter comma-separated numbers to include: ")
	if err != nil {
		return nil, err
	}

	var selected []internal.SSHArtifact
	for _, part := range strings.Split(nums, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx, err := strconv.Atoi(part)
		if err != nil || idx < 1 || idx > len(artifacts) {
			fmt.Fprintf(r.out, "Invalid selection %q, skipping.\n", part)
			continue
		}
		selected = append(selected, artifacts[idx-1])
	}
	return selected, nil
}

// promptPassword prompts for the encryption password without echoing, re-prompting if too short.
func (r *pushRunner) promptPassword(_ func(string) (string, error)) (string, error) {
	for {
		pw, err := r.pwReader(r.out, "Encryption password (≥12 chars): ")
		if err != nil {
			return "", err
		}
		if len(pw) >= 12 {
			return pw, nil
		}
		fmt.Fprintln(r.out, "Password must be at least 12 characters. Please try again.")
	}
}

var pushCmd = &cobra.Command{
	Use:   "push",
	Short: "Encrypt and upload SSH artifacts to R2",
	Long:  `Discovers SSH artifacts, encrypts them with AES-256-GCM, and uploads to Cloudflare R2.`,
	// Exit code contract:
	//   0 — all selected artifacts uploaded successfully
	//   1 — user error (no artifacts found, invalid selection, password too short)
	//   2 — I/O/network error (credential load failure, R2 upload failure, manifest update failure)
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := credentials.NewCredentialStore()
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to initialize credential store:", err)
			os.Exit(2)
		}
		creds, err := store.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to load credentials:", err)
			os.Exit(2)
		}
		r2Client, err := r2.NewR2Client(creds)
		if err != nil {
			fmt.Fprintln(os.Stderr, "failed to create R2 client:", err)
			os.Exit(2)
		}

		runner := &pushRunner{
			in:       os.Stdin,
			out:      os.Stdout,
			store:    store,
			scanner:  scanner.New(),
			r2:       r2Client,
			engine:   crypto.NewAESEngine(),
			manifest: manifest.NewManifestManager(r2Client),
			backup:   backup.NewManager(r2Client),
			force:    force,
			sshDir:   sshDir,
			pwReader: readPassword,
		}
		if err := runner.run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			if ee, ok := err.(*exitError); ok {
				os.Exit(ee.code)
			}
			os.Exit(1)
		}
		return nil
	},
}
