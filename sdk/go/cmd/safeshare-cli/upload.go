package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
	"github.com/spf13/cobra"
)

func uploadCmd() *cobra.Command {
	var (
		expiresInHours int
		downloadLimit  int
		password       string
		noProgress     bool
	)

	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Upload a file to SafeShare",
		Long: `Upload a file to SafeShare and get a claim code for downloading.

Examples:
  safeshare-cli upload document.pdf
  safeshare-cli upload large-file.zip --expires 48 --limit 5
  safeshare-cli upload secret.txt --password mysecret`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkConfig(); err != nil {
				return err
			}

			filePath := args[0]

			// Verify file exists
			info, err := os.Stat(filePath)
			if err != nil {
				return fmt.Errorf("file not found: %s", filePath)
			}

			// Create client
			client, err := safeshare.NewClient(safeshare.ClientConfig{
				BaseURL:  baseURL,
				APIToken: apiToken,
			})
			if err != nil {
				return err
			}

			// Prepare options
			opts := &safeshare.UploadOptions{}
			if cmd.Flags().Changed("expires") {
				opts.ExpiresInHours = &expiresInHours
			}
			if cmd.Flags().Changed("limit") {
				opts.DownloadLimit = &downloadLimit
			}
			if password != "" {
				opts.Password = password
			}

			// Progress callback
			if !noProgress {
				opts.OnProgress = func(p safeshare.UploadProgress) {
					bar := progressBar(p.Percentage)
					status := fmt.Sprintf("\r%s %3d%% (%s/%s)",
						bar,
						p.Percentage,
						formatBytes(p.BytesUploaded),
						formatBytes(p.TotalBytes),
					)
					if p.TotalChunks > 0 {
						status += fmt.Sprintf(" [chunk %d/%d]", p.CurrentChunk, p.TotalChunks)
					}
					fmt.Print(status)
				}
			}

			fmt.Printf("Uploading: %s (%s)\n", filePath, formatBytes(info.Size()))

			// Upload
			ctx := context.Background()
			result, err := client.Upload(ctx, filePath, opts)
			if err != nil {
				fmt.Println() // Clear progress line
				return err
			}

			fmt.Println() // Clear progress line
			fmt.Println()
			fmt.Println(strings.Repeat("─", 50))
			fmt.Printf("Upload successful!\n")
			fmt.Println(strings.Repeat("─", 50))
			fmt.Printf("Claim Code:  %s\n", result.ClaimCode)
			fmt.Printf("Filename:    %s\n", result.Filename)
			fmt.Printf("Size:        %s\n", formatBytes(result.Size))
			fmt.Printf("MIME Type:   %s\n", result.MimeType)
			if result.ExpiresAt != nil {
				fmt.Printf("Expires:     %s\n", result.ExpiresAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("Expires:     Never\n")
			}
			if result.DownloadLimit != nil {
				fmt.Printf("Downloads:   %d\n", *result.DownloadLimit)
			} else {
				fmt.Printf("Downloads:   Unlimited\n")
			}
			fmt.Printf("Password:    %v\n", result.PasswordProtected)
			fmt.Println(strings.Repeat("─", 50))
			fmt.Printf("\nDownload URL: %s/claim/%s\n", baseURL, result.ClaimCode)

			return nil
		},
	}

	cmd.Flags().IntVarP(&expiresInHours, "expires", "e", 0, "Hours until expiration (0 = never)")
	cmd.Flags().IntVarP(&downloadLimit, "limit", "l", 0, "Maximum downloads (0 = unlimited)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password protect the file")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress bar")

	return cmd
}

func progressBar(percentage int) string {
	width := 30
	filled := percentage * width / 100
	empty := width - filled
	return fmt.Sprintf("[%s%s]", strings.Repeat("█", filled), strings.Repeat("░", empty))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
