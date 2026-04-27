package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	sshDir string
	force  bool
)

var rootCmd = &cobra.Command{
	Use:   "ssync",
	Short: "Securely sync SSH artifacts to Cloudflare R2",
	Long: `ssync encrypts your SSH private keys, public keys, config files, and
known_hosts before uploading them to Cloudflare R2 object storage.
All encryption is performed client-side using AES-256-GCM.`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&sshDir, "ssh-dir", "~/.ssh", "Path to the SSH directory")
	rootCmd.PersistentFlags().BoolVar(&force, "force", false, "Skip conflict detection and overwrite remote artifacts")

	rootCmd.AddCommand(configureCmd)
	rootCmd.AddCommand(pushCmd)
	rootCmd.AddCommand(pullCmd)
	rootCmd.AddCommand(recoverCmd)
	rootCmd.AddCommand(regenerateBackupCodesCmd)
}
