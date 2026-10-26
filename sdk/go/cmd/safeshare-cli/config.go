package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func configCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show server configuration",
		Long: `Display the SafeShare server's public configuration.

Example:
  safeshare-cli config`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkConfig(); err != nil {
				return err
			}

			// Create client
			client, err := newClient(baseURL, apiToken)
			if err != nil {
				return err
			}

			ctx := context.Background()
			config, err := client.GetConfig(ctx)
			if err != nil {
				return err
			}

			fmt.Printf("SafeShare Server Configuration\n")
			fmt.Printf("URL: %s\n", baseURL)
			fmt.Println(strings.Repeat("─", 40))
			if config.Version != "" {
				fmt.Printf("%-25s %s\n", "Server Version:", display(config.Version))
			}
			fmt.Printf("%-25s %s\n", "Max File Size:", formatBytes(config.MaxFileSize))
			fmt.Printf("%-25s %s\n", "Chunked Upload Threshold:", formatBytes(config.ChunkUploadThreshold))
			fmt.Printf("%-25s %s\n", "Chunk Size:", formatBytes(config.ChunkSize))
			fmt.Printf("%-25s %d hours\n", "Max Expiration:", config.MaxExpirationHours)
			fmt.Printf("%-25s %v\n", "Registration Enabled:", config.RegistrationEnabled)
			fmt.Printf("%-25s %v\n", "Ghost (anonymous) Mode:", config.AnonymousMode)
			fmt.Printf("%-25s %v\n", "Encryption Required:", config.ClientEncryptionRequired)
			fmt.Printf("%-25s %v\n", "Strips Metadata:", config.StripMetadata)
			fmt.Println(strings.Repeat("─", 40))

			return nil
		},
	}

	return cmd
}
