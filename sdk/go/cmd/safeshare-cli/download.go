package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
	"github.com/spf13/cobra"
)

func downloadCmd() *cobra.Command {
	var (
		password   string
		noProgress bool
		overwrite  bool
	)

	cmd := &cobra.Command{
		Use:   "download <claim-code | share-link | -> [destination]",
		Short: "Download a file by claim code or encrypted share link",
		Long: `Download a file from SafeShare using its claim code.

If no destination is specified, the file is saved to the current directory
with its original filename.

End-to-end encrypted files are decrypted on this machine. Give the share link
(https://host/#/claim/CODE/key/KEY), or "-" to read it from standard input so
the key stays out of your shell history and the process list. Alternatively
give the claim code and put the key in the SAFESHARE_KEY environment variable.

Examples:
  safeshare-cli download abc12345
  safeshare-cli download abc12345 ./myfile.pdf
  safeshare-cli download abc12345 --password secret
  safeshare-cli download - < link.txt
  SAFESHARE_KEY=... safeshare-cli download abc12345`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			if target == "-" {
				line, err := bufio.NewReader(io.LimitReader(os.Stdin, 8192)).ReadString('\n')
				if err != nil && err != io.EOF {
					return fmt.Errorf("reading the share link from standard input: %w", err)
				}
				target = strings.TrimSpace(line)
				if target == "" {
					return fmt.Errorf("no share link on standard input")
				}
			} else if strings.Contains(target, "/key/") {
				fmt.Fprintln(os.Stderr, "[WARNING] The share link (and its key) on the command line is visible in the process list and shell history. Use \"download -\" to read it from standard input.")
			}

			claimCode, key := target, os.Getenv("SAFESHARE_KEY")
			keyFromEnv := key != ""
			server, token := baseURL, apiToken
			if strings.Contains(target, "://") {
				link, err := safeshare.ParseShareURL(target)
				if err != nil {
					return err
				}
				claimCode, key, server = link.ClaimCode, link.Key, link.BaseURL
				keyFromEnv = false
				if strings.TrimRight(baseURL, "/") != link.BaseURL {
					// The link names the server; never send the API token to a
					// host that only a share link vouches for.
					token = ""
					if baseURL != "" {
						fmt.Fprintf(os.Stderr, "[WARNING] Using the server from the share link (%s), not %s; your API token is not sent to it.\n", link.BaseURL, baseURL)
					}
				}
			} else if err := checkConfig(); err != nil {
				return err
			}

			// Create client
			client, err := newClient(server, token)
			if err != nil {
				return err
			}

			ctx := context.Background()

			// Prepare options
			opts := &safeshare.DownloadOptions{Overwrite: overwrite}
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

			if key != "" && !keyFromEnv {
				return downloadEncrypted(ctx, client, claimCode, key, args[1:], opts)
			}

			// Get file info first
			info, err := client.GetFileInfo(ctx, claimCode)
			if err != nil {
				return fmt.Errorf("getting file info: %w", err)
			}
			if keyFromEnv {
				if info.ClientEncrypted {
					return downloadEncrypted(ctx, client, claimCode, key, args[1:], opts)
				}
				fmt.Fprintln(os.Stderr, "[WARNING] SAFESHARE_KEY is set but this file is not end-to-end encrypted; downloading it as is.")
			}

			// Determine destination (the stored name comes from the uploader)
			destination := safeshare.SafeFilename(info.Filename, "download.bin")
			if len(args) > 1 {
				destination = args[1]
			}

			fmt.Println("File Information:")
			fmt.Println(strings.Repeat("─", 40))
			fmt.Printf("Filename:    %s\n", display(info.Filename))
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
			if info.ClientEncrypted || info.Filename == safeshare.EncryptedFilename {
				fmt.Fprintln(os.Stderr, "[WARNING] This looks like an end-to-end encrypted file. Without its share link it is saved still encrypted.")
			}
			fmt.Printf("\nDownloading to: %s\n", destination)

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
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Replace the destination file if it exists")

	return cmd
}

// downloadEncrypted downloads and decrypts an end-to-end encrypted file in
// memory, then writes it (mode 0600) to the destination given or, by default,
// to its original name in the current directory. A destination given
// explicitly is checked before downloading, so a limited download is not
// used up for nothing; a default name that is taken gets a " (n)" suffix.
func downloadEncrypted(ctx context.Context, client *safeshare.Client, claimCode, key string, dest []string, opts *safeshare.DownloadOptions) error {
	if len(dest) > 0 {
		if err := safeshare.CheckDestination(dest[0], opts.Overwrite); err != nil {
			return friendlyExists(err)
		}
	}
	file, err := client.DownloadDecrypted(ctx, claimCode, key, opts)
	fmt.Println() // Clear progress line
	if err != nil {
		return err
	}
	destination := ""
	if len(dest) > 0 {
		destination = dest[0]
	} else {
		destination = freeName(safeshare.SafeFilename(file.Filename, "download.bin"), opts.Overwrite)
	}
	if err := file.Save(destination, opts.Overwrite); err != nil {
		return friendlyExists(err)
	}
	fmt.Printf("Decrypted %s (%s) to %s\n", display(file.Filename), formatBytes(int64(len(file.Data))), destination)
	return nil
}

func friendlyExists(err error) error {
	if errors.Is(err, safeshare.ErrDestinationExists) {
		return fmt.Errorf("%w; give another destination or use --overwrite", err)
	}
	return err
}

// freeName returns name, or "stem (n).ext" for the first n that does not exist.
func freeName(name string, overwrite bool) string {
	if overwrite {
		return name
	}
	if _, err := os.Lstat(name); errors.Is(err, fs.ErrNotExist) {
		return name
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for n := 1; n < 1000; n++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, n, ext)
		if _, err := os.Lstat(candidate); errors.Is(err, fs.ErrNotExist) {
			return candidate
		}
	}
	return name // Save then refuses it rather than overwriting
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
			client, err := newClient(baseURL, apiToken)
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
			fmt.Printf("Filename:    %s\n", display(info.Filename))
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
