package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
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
		encrypt        bool
		noEncrypt      bool
		showFilename   bool
		keepMetadata   bool
	)

	cmd := &cobra.Command{
		Use:   "upload <file>",
		Short: "Upload a file to SafeShare",
		Long: `Upload a file to SafeShare and get a claim code for downloading.

Encryption:
  On servers in Ghost (anonymous) mode or that require client-side encryption,
  and always over a proxy or to an .onion address, the file is encrypted on
  this machine before upload, in the same format as the web app, and padded to
  a size bucket. You get a share link with the key after the "#". The server
  never sees the key, the content or (unless --show-filename) the name. Use
  --encrypt to encrypt on any server. The file is held in memory while it is
  encrypted.

  The CLI cannot remove metadata (photo location, author names). On Ghost
  servers it refuses JPEG, PNG, PDF and Office files the web app would have
  cleaned; scrub them first (for example with mat2), or pass --keep-metadata.

  To upload over Tor: --proxy socks5h://127.0.0.1:9050 (or SAFESHARE_PROXY).

Examples:
  safeshare-cli upload document.pdf
  safeshare-cli upload large-file.zip --expires 48 --limit 5
  safeshare-cli upload secret.txt --password mysecret
  safeshare-cli upload notes.txt --encrypt
  safeshare-cli upload notes.txt --json | jq -r .url

With --json, the "url" field is the link to open. For an encrypted upload it
is the share link with the key, so the output is a secret: don't log it.`,
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
			client, err := newClient(baseURL, apiToken)
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
			switch {
			case encrypt && noEncrypt:
				return fmt.Errorf("--encrypt and --no-encrypt cannot be used together")
			case encrypt:
				opts.Encrypt = safeshare.EncryptAlways
			case noEncrypt:
				opts.Encrypt = safeshare.EncryptNever
			case proxyInUse() || isOnion(baseURL):
				// Over Tor or a proxy, don't let the server's own settings
				// decide: a seized server could report it isn't in Ghost mode.
				opts.Encrypt = safeshare.EncryptAlways
			}
			opts.ShowFilename = showFilename
			opts.KeepMetadata = keepMetadata

			// Progress callback
			if !noProgress && !jsonOut {
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

			// Human output goes nowhere with --json; stdout is the document.
			out := cmd.OutOrStdout()
			if jsonOut {
				out = io.Discard
			}

			fmt.Fprintf(out, "Uploading: %s (%s)\n", filePath, formatBytes(info.Size()))

			ctx := context.Background()

			willEncrypt, err := client.WillEncrypt(ctx, opts.Encrypt)
			if err != nil {
				return err
			}
			if willEncrypt {
				fmt.Fprintln(out, "Encrypting on this machine before upload.")
				if info.Size() > largeEncryptedFile {
					fmt.Fprintf(os.Stderr, "[WARNING] Encryption holds the whole file in memory (%s).\n", formatBytes(info.Size()))
				}
			} else {
				fmt.Fprintln(os.Stderr, "[NOTE] Not encrypting: this server doesn't require it. Use --encrypt to encrypt anyway.")
			}

			// Upload
			result, err := client.Upload(ctx, filePath, opts)
			if opts.OnProgress != nil {
				fmt.Println() // Clear progress line
			}
			if err != nil {
				if errors.Is(err, safeshare.ErrMetadataNotRemoved) {
					return fmt.Errorf("%w\nPass --keep-metadata to upload it anyway", err)
				}
				return err
			}
			if result.MetadataKept != "" {
				fmt.Fprintf(os.Stderr, "[WARNING] This %s was uploaded encrypted, so its metadata was not removed.\n", result.MetadataKept)
			}

			if jsonOut {
				return printJSON(cmd.OutOrStdout(), newUploadJSON(filePath, baseURL, result))
			}
			printUploadResult(out, result)
			return nil
		},
	}

	cmd.Flags().IntVarP(&expiresInHours, "expires", "e", 0, "Hours until expiration (0 = never)")
	cmd.Flags().IntVarP(&downloadLimit, "limit", "l", 0, "Maximum downloads (0 = unlimited)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Password protect the file")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress bar")
	cmd.Flags().BoolVar(&encrypt, "encrypt", false, "Encrypt before upload even if the server does not require it")
	cmd.Flags().BoolVar(&noEncrypt, "no-encrypt", false, "Do not encrypt (fails on servers that require encryption)")
	cmd.Flags().BoolVar(&showFilename, "show-filename", false, "Let the server see the filename of an encrypted upload")
	cmd.Flags().BoolVar(&keepMetadata, "keep-metadata", false, "Allow encrypted uploads of files whose metadata the CLI cannot remove")

	return cmd
}

// printUploadResult prints the summary of an upload and the link to open.
func printUploadResult(out io.Writer, result *safeshare.UploadResult) {
	fmt.Fprintln(out)
	fmt.Fprintln(out, strings.Repeat("─", 50))
	fmt.Fprintf(out, "Upload successful!\n")
	fmt.Fprintln(out, strings.Repeat("─", 50))
	fmt.Fprintf(out, "Claim Code:  %s\n", result.ClaimCode)
	fmt.Fprintf(out, "Filename:    %s\n", result.Filename)
	fmt.Fprintf(out, "Size:        %s\n", formatBytes(result.Size))
	fmt.Fprintf(out, "MIME Type:   %s\n", result.MimeType)
	if result.ExpiresAt != nil {
		fmt.Fprintf(out, "Expires:     %s\n", result.ExpiresAt.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Fprintf(out, "Expires:     Never\n")
	}
	if result.DownloadLimit != nil {
		fmt.Fprintf(out, "Downloads:   %d\n", *result.DownloadLimit)
	} else {
		fmt.Fprintf(out, "Downloads:   Unlimited\n")
	}
	fmt.Fprintf(out, "Password:    %v\n", result.PasswordProtected)
	fmt.Fprintf(out, "Encrypted:   %v\n", result.Encrypted)
	fmt.Fprintln(out, strings.Repeat("─", 50))
	if result.Encrypted {
		fmt.Fprintln(out, "\nShare link (contains the decryption key; anyone with it can read the file):")
		fmt.Fprintln(out, result.ShareURL)
		return
	}
	fmt.Fprintf(out, "\nDownload URL: %s\n", uploadURL(baseURL, result))
}

// uploadURL is the link to open for an upload: the share link (with the
// key) for an encrypted one, else the claim page.
func uploadURL(server string, result *safeshare.UploadResult) string {
	if result.Encrypted {
		return result.ShareURL
	}
	return strings.TrimRight(server, "/") + "/claim/" + result.ClaimCode
}

// isOnion reports whether the server URL is a Tor onion service.
func isOnion(server string) bool {
	u, err := url.Parse(server)
	return err == nil && strings.HasSuffix(strings.ToLower(u.Hostname()), ".onion")
}

// largeEncryptedFile is when to warn that encryption holds the file in memory
// (the web app warns at the same size).
const largeEncryptedFile = 500 * 1024 * 1024

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
