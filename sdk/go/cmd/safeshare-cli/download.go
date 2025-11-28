package main

import (
	"context"
	"fmt"
	"strings"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
	"github.com/spf13/cobra"
)

func downloadCmd() *cobra.Command {
	var (
		password   string
		noProgress bool
	)

	cmd := &cobra.Command{
		Use:   "download <claim-code> [destination]",
		Short: "Download a file by claim code",
		Long: `Download a file from SafeShare using its claim code.

If no destination is specified, the file is saved to the current directory
with its original filename.

Examples:
  safeshare-cli download abc12345
  safeshare-cli download abc12345 ./myfile.pdf
  safeshare-cli download abc12345 --password secret`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkConfig(); err != nil {
				return err
			}

			claimCode := args[0]

			// Create client
			client, err := safeshare.NewClient(safeshare.ClientConfig{
				BaseURL:  baseURL,
				APIToken: apiToken,
			})
			if err != nil {
				return err
			}

			ctx := context.Background()

			// Get file info first
			info, err := client.GetFileInfo(ctx, claimCode)
			if err != nil {
				return fmt.Errorf("getting file info: %w", err)
			}

			// Determine destination
			destination := info.Filename
			if len(args) > 1 {
				destination = args[1]
			}

			fmt.Println("File Information:")
			fmt.Println(strings.Repeat("─", 40))
			fmt.Printf("Filename:    %s\n", info.Filename)
			fmt.Printf("Size:        %s\n", formatBytes(info.Size))
			fmt.Printf("MIME Type:   %s\n", info.MimeType)
			if info.ExpiresAt != nil {
				fmt.Printf("Expires:     %s\n", info.ExpiresAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("Expires:     Never\n")
			}
			if info.DownloadsRemaining != nil {
				fmt.Printf("Downloads:   %d remaining\n", *info.DownloadsRemaining)
			} else {
				fmt.Printf("Downloads:   Unlimited\n")
			}
			fmt.Printf("Password:    %v\n", info.PasswordProtected)
			fmt.Println(strings.Repeat("─", 40))
			fmt.Printf("\nDownloading to: %s\n", destination)

			// Prepare options
			opts := &safeshare.DownloadOptions{}
			if password != "" {
				opts.Password = password
			}

			// Progress callback
			if !noProgress {
				opts.OnProgress = func(p safeshare.DownloadProgress) {
					bar := progressBar(p.Percentage)
					if p.Percentage >= 0 {
						fmt.Printf("\r%s %3d%% (%s/%s)",
							bar,
							p.Percentage,
							formatBytes(p.BytesDownloaded),
							formatBytes(p.TotalBytes),
						)
					} else {
						fmt.Printf("\rDownloading... %s", formatBytes(p.BytesDownloaded))
					}
				}
			}

			// Download
			if err := client.Download(ctx, claimCode, destination, opts); err != nil {
				fmt.Println() // Clear progress line
				return err
			}

			fmt.Println() // Clear progress line
			fmt.Println("\nDownload complete!")

			return nil
		},
	}

	cmd.Flags().StringVarP(&password, "password", "p", "", "Password for protected files")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress bar")

	return cmd
}

func infoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info <claim-code>",
		Short: "Get information about a file",
		Long: `Get information about a file without downloading it.

Example:
  safeshare-cli info abc12345`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkConfig(); err != nil {
				return err
			}

			claimCode := args[0]

			// Create client
			client, err := safeshare.NewClient(safeshare.ClientConfig{
				BaseURL:  baseURL,
				APIToken: apiToken,
			})
			if err != nil {
				return err
			}

			ctx := context.Background()
			info, err := client.GetFileInfo(ctx, claimCode)
			if err != nil {
				return err
			}

			fmt.Println("File Information:")
			fmt.Println(strings.Repeat("─", 40))
			fmt.Printf("Filename:    %s\n", info.Filename)
			fmt.Printf("Size:        %s\n", formatBytes(info.Size))
			fmt.Printf("MIME Type:   %s\n", info.MimeType)
			if info.ExpiresAt != nil {
				fmt.Printf("Expires:     %s\n", info.ExpiresAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Printf("Expires:     Never\n")
			}
			if info.DownloadsRemaining != nil {
				fmt.Printf("Downloads:   %d remaining\n", *info.DownloadsRemaining)
			} else {
				fmt.Printf("Downloads:   Unlimited\n")
			}
			fmt.Printf("Password:    %v\n", info.PasswordProtected)
			fmt.Println(strings.Repeat("─", 40))

			return nil
		},
	}

	return cmd
}
