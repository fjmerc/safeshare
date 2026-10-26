package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"filippo.io/age"
	safeshare "github.com/fjmerc/safeshare/sdk/go"
	"github.com/spf13/cobra"
)

func downloadCmd() *cobra.Command {
	var (
		password   string
		noProgress bool
		overwrite  bool
		identity   string
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

Files sent with a server's drop page (/drop) are encrypted to the recipient's
age key. Give the key file with --identity: the drop is decrypted and its
files (and message.txt, if the sender wrote one) are put in a new directory,
the destination, by default drop-CODE.

Examples:
  safeshare-cli download abc12345
  safeshare-cli download abc12345 ./myfile.pdf
  safeshare-cli download abc12345 --password secret
  safeshare-cli download - < link.txt
  SAFESHARE_KEY=... safeshare-cli download abc12345
  safeshare-cli download abc12345 --identity drop-key.txt`,
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

			if identity != "" {
				if target != args[0] || strings.Contains(target, "://") {
					return fmt.Errorf("--identity takes the drop's claim code, not a share link")
				}
				if overwrite {
					fmt.Fprintln(os.Stderr, "[WARNING] --overwrite does not apply to drops: they are put in a new directory.")
				}
				return downloadDrop(cmd.OutOrStdout(), target, identity, args[1:], password, noProgress || jsonOut)
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

			if !noProgress && !jsonOut {
				opts.OnProgress = printDownloadProgress
			}

			out := humanOut(cmd)

			if key != "" && !keyFromEnv {
				return downloadEncrypted(ctx, cmd.OutOrStdout(), client, claimCode, key, args[1:], opts)
			}

			// Get file info first
			info, err := client.GetFileInfo(ctx, claimCode)
			if err != nil {
				return fmt.Errorf("getting file info: %w", err)
			}
			if keyFromEnv {
				if info.ClientEncrypted {
					return downloadEncrypted(ctx, cmd.OutOrStdout(), client, claimCode, key, args[1:], opts)
				}
				fmt.Fprintln(os.Stderr, "[WARNING] SAFESHARE_KEY is set but this file is not end-to-end encrypted; downloading it as is.")
			}

			// Determine destination (the stored name comes from the uploader)
			destination := safeshare.SafeFilename(info.Filename, "download.bin")
			if len(args) > 1 {
				destination = args[1]
			}

			fmt.Fprintln(out, "File Information:")
			fmt.Fprintln(out, strings.Repeat("─", 40))
			fmt.Fprintf(out, "Filename:    %s\n", display(info.Filename))
			fmt.Fprintf(out, "Size:        %s\n", formatBytes(info.Size))
			fmt.Fprintf(out, "MIME Type:   %s\n", info.MimeType)
			if info.ExpiresAt != nil {
				fmt.Fprintf(out, "Expires:     %s\n", info.ExpiresAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Fprintf(out, "Expires:     Never\n")
			}
			if info.DownloadsRemaining != nil {
				fmt.Fprintf(out, "Downloads:   %d remaining\n", *info.DownloadsRemaining)
			} else {
				fmt.Fprintf(out, "Downloads:   Unlimited\n")
			}
			fmt.Fprintf(out, "Password:    %v\n", info.PasswordProtected)
			fmt.Fprintln(out, strings.Repeat("─", 40))
			if info.Filename == safeshare.DropFilename {
				fmt.Fprintln(os.Stderr, "[WARNING] This is a drop-page submission, encrypted to the recipient's age key. Use --identity <key file> to decrypt it; without it, it is saved still encrypted.")
			} else if info.ClientEncrypted || info.Filename == safeshare.EncryptedFilename {
				fmt.Fprintln(os.Stderr, "[WARNING] This looks like an end-to-end encrypted file. Without its share link it is saved still encrypted.")
			}
			fmt.Fprintf(out, "\nDownloading to: %s\n", destination)

			// Download
			err = client.Download(ctx, claimCode, destination, opts)
			if opts.OnProgress != nil {
				fmt.Println() // Clear progress line
			}
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), downloadJSON{
					Schema: jsonSchema, ClaimCode: claimCode, Filename: info.Filename, Size: info.Size, Path: destination,
				})
			}
			fmt.Fprintln(out, "\nDownload complete!")

			return nil
		},
	}

	cmd.Flags().StringVarP(&password, "password", "p", "", "Password for protected files")
	cmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress bar")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "Replace the destination file if it exists")
	cmd.Flags().StringVarP(&identity, "identity", "i", "", "age key file to decrypt a drop-page submission with")

	return cmd
}

// downloadEncrypted downloads and decrypts an end-to-end encrypted file in
// memory, then writes it (mode 0600) to the destination given or, by default,
// to its original name in the current directory. A destination given
// explicitly is checked before downloading, so a limited download is not
// used up for nothing; a default name that is taken gets a " (n)" suffix.
func downloadEncrypted(ctx context.Context, out io.Writer, client *safeshare.Client, claimCode, key string, dest []string, opts *safeshare.DownloadOptions) error {
	if len(dest) > 0 {
		if err := safeshare.CheckDestination(dest[0], opts.Overwrite); err != nil {
			return friendlyExists(err)
		}
	}
	file, err := client.DownloadDecrypted(ctx, claimCode, key, opts)
	if opts.OnProgress != nil {
		fmt.Println() // Clear progress line
	}
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
	if jsonOut {
		return printJSON(out, downloadJSON{
			Schema: jsonSchema, ClaimCode: claimCode, Filename: file.Filename, Size: int64(len(file.Data)), Path: destination, Decrypted: true,
		})
	}
	fmt.Fprintf(out, "Decrypted %s (%s) to %s\n", display(file.Filename), formatBytes(int64(len(file.Data))), destination)
	return nil
}

// downloadJSON is the --json document for a downloaded file.
type downloadJSON struct {
	Schema    int    `json:"schema"`
	ClaimCode string `json:"claim_code"`
	// Filename is the name the uploader gave; Path is where it was saved.
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
	// Decrypted is true for an end-to-end encrypted file decrypted here.
	Decrypted bool `json:"decrypted"`
}

// downloadDrop downloads a drop-page submission, decrypts it with the age
// identities in identityPath and extracts it into a new directory: dest[0],
// or drop-CODE by default.
func downloadDrop(out io.Writer, claimCode, identityPath string, dest []string, password string, noProgress bool) error {
	if err := checkConfig(); err != nil {
		return err
	}
	if os.Getenv("SAFESHARE_KEY") != "" {
		fmt.Fprintln(os.Stderr, "[WARNING] SAFESHARE_KEY is set but not used: drops are decrypted with --identity.")
	}
	identities, err := readIdentities(identityPath)
	if err != nil {
		return err
	}
	client, err := newClient(baseURL, apiToken)
	if err != nil {
		return err
	}

	// Ctrl-C cancels the download, so the partly written directory is removed.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Check the code before choosing a directory named after it, and before
	// downloading, which may count against the file's limit.
	info, err := client.GetFileInfo(ctx, claimCode)
	if err != nil {
		return fmt.Errorf("getting file info: %w", err)
	}
	if info.Filename != safeshare.DropFilename {
		return fmt.Errorf("%s is not a drop-page submission (it is stored as %s); download it without --identity", claimCode, display(info.Filename))
	}
	dir := "drop-" + claimCode
	if len(dest) > 0 {
		dir = dest[0]
	}
	if err := safeshare.CheckDropDestination(dir); err != nil {
		return friendlyDropExists(err, dir)
	}

	opts := &safeshare.DownloadOptions{Password: password}
	if !noProgress {
		opts.OnProgress = printDownloadProgress
	}
	files, err := client.DownloadDrop(ctx, claimCode, dir, identities, opts)
	if !noProgress {
		fmt.Println() // Clear progress line
	}
	if err != nil {
		return friendlyDropExists(err, dir)
	}
	const untrusted = "Treat these files as untrusted: open them offline or in a disposable environment."
	if jsonOut {
		fmt.Fprintln(os.Stderr, "[NOTE] "+untrusted)
		type dropFile struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		}
		doc := struct {
			Schema    int        `json:"schema"`
			ClaimCode string     `json:"claim_code"`
			Path      string     `json:"path"`
			Files     []dropFile `json:"files"`
		}{Schema: jsonSchema, ClaimCode: claimCode, Path: dir, Files: []dropFile{}}
		for _, f := range files {
			doc.Files = append(doc.Files, dropFile{Name: f.Name, Size: f.Size})
		}
		return printJSON(out, doc)
	}
	fmt.Fprintf(out, "Decrypted the drop into %s:\n", dir)
	for _, f := range files {
		fmt.Fprintf(out, "  %s (%s)\n", display(f.Name), formatBytes(f.Size))
	}
	fmt.Fprintln(out, untrusted)
	return nil
}

// printDownloadProgress draws a progress line for a download.
func printDownloadProgress(p safeshare.DownloadProgress) {
	if p.Percentage >= 0 {
		fmt.Printf("\r%s %3d%% (%s/%s)", progressBar(p.Percentage), p.Percentage,
			formatBytes(p.BytesDownloaded), formatBytes(p.TotalBytes))
	} else {
		fmt.Printf("\rDownloading... %s", formatBytes(p.BytesDownloaded))
	}
}

func friendlyDropExists(err error, dir string) error {
	if errors.Is(err, safeshare.ErrDirectoryExists) {
		return fmt.Errorf("%s already exists; give a directory that does not exist yet", dir)
	}
	return err
}

// readIdentities reads age private keys (as written by age-keygen) from
// path. The file's contents are never printed: age's parse errors can quote
// part of a malformed key, so they are not passed on.
func readIdentities(path string) ([]age.Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening identity file: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("reading identity file %s: it does not hold a valid age private key (AGE-SECRET-KEY-…, as written by age-keygen)", path)
	}
	return ids, nil
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
	var showQR bool

	cmd := &cobra.Command{
		Use:   "info <claim-code>",
		Short: "Get information about a file",
		Long: `Get information about a file without downloading it.

--qr also draws the file's download page link as a QR code to scan with a
phone. End-to-end encrypted files have none: their link needs the key, which
only the uploader has.

Example:
  safeshare-cli info abc12345
  safeshare-cli info abc12345 --qr`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkConfig(); err != nil {
				return err
			}

			claimCode := args[0]
			if showQR && jsonOut {
				return errQRWithJSON
			}

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
			if jsonOut {
				return printJSON(cmd.OutOrStdout(), struct {
					Schema    int    `json:"schema"`
					ClaimCode string `json:"claim_code"`
					*safeshare.FileInfo
				}{Schema: jsonSchema, ClaimCode: claimCode, FileInfo: info})
			}

			out := cmd.OutOrStdout()
			fmt.Fprintln(out, "File Information:")
			fmt.Fprintln(out, strings.Repeat("─", 40))
			fmt.Fprintf(out, "Filename:    %s\n", display(info.Filename))
			fmt.Fprintf(out, "Size:        %s\n", formatBytes(info.Size))
			fmt.Fprintf(out, "MIME Type:   %s\n", info.MimeType)
			if info.ExpiresAt != nil {
				fmt.Fprintf(out, "Expires:     %s\n", info.ExpiresAt.Format("2006-01-02 15:04:05"))
			} else {
				fmt.Fprintf(out, "Expires:     Never\n")
			}
			if info.DownloadsRemaining != nil {
				fmt.Fprintf(out, "Downloads:   %d remaining\n", *info.DownloadsRemaining)
			} else {
				fmt.Fprintf(out, "Downloads:   Unlimited\n")
			}
			fmt.Fprintf(out, "Password:    %v\n", info.PasswordProtected)
			fmt.Fprintln(out, strings.Repeat("─", 40))

			if showQR {
				if info.ClientEncrypted {
					return fmt.Errorf("no QR code: this file is end-to-end encrypted, and its link needs the key from the uploader's share link")
				}
				link := claimURL(baseURL, claimCode)
				fmt.Fprintf(out, "\n%s\n", link)
				return printQR(out, link)
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&showQR, "qr", false, "Also show the file's link as a QR code to scan with a phone")

	return cmd
}
