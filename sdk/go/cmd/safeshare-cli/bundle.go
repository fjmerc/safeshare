package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
)

// bundleJSON is the --json document for upload --bundle.
type bundleJSON struct {
	Schema            int              `json:"schema"`
	BundleCode        string           `json:"bundle_code"`
	URL               string           `json:"url"` // holds the key for an encrypted bundle: a secret
	ExpiresAt         *time.Time       `json:"expires_at"`
	DownloadLimit     *int             `json:"download_limit"`
	PasswordProtected bool             `json:"password_protected"`
	Encrypted         bool             `json:"encrypted"`
	Files             []bundleFileJSON `json:"files"`
}

type bundleFileJSON struct {
	Position int    `json:"position"`
	File     string `json:"file"` // the path given on the command line
	Name     string `json:"name"`
	Size     int64  `json:"size"`
}

// bundleDownloadJSON is the --json document for downloading a bundle link.
type bundleDownloadJSON struct {
	Schema     int                   `json:"schema"`
	BundleCode string                `json:"bundle_code"`
	Dir        string                `json:"dir"`
	Files      []bundleSavedFileJSON `json:"files"`
	Decrypted  bool                  `json:"decrypted"`
}

type bundleSavedFileJSON struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// uploadBundle uploads files as one bundle and prints its one link.
func uploadBundle(ctx context.Context, cmd *cobra.Command, out io.Writer, client *safeshare.Client, files []string, sizes []int64,
	opts *safeshare.UploadOptions, willEncrypt, showQR bool) error {
	var total int64
	for i, s := range sizes {
		total += s
		if willEncrypt && s > largeEncryptedFile {
			fmt.Fprintf(os.Stderr, "[WARNING] Encryption holds the whole file in memory (%s: %s).\n", files[i], formatBytes(s))
		}
	}
	fmt.Fprintf(out, "Uploading %d files as one bundle (%s)\n", len(files), formatBytes(total))

	res, err := client.UploadBundle(ctx, files, opts)
	if opts.OnProgress != nil {
		fmt.Println()
	}
	if err != nil {
		var bErr *safeshare.BundleUploadError
		failed := ""
		if errors.As(err, &bErr) {
			failed = bErr.Path
			err = bErr.Err
		}
		if ctx.Err() != nil {
			err = errInterruptedDuring
		}
		if jsonOut {
			_ = printJSON(cmd.OutOrStdout(), uploadErrorJSON{Schema: jsonSchema, File: failed, jsonError: newJSONError(err)})
		}
		if failed != "" {
			return fmt.Errorf("bundle not created: uploading %s failed: %w", failed, err)
		}
		return fmt.Errorf("bundle not created: %w", err)
	}

	if jsonOut {
		doc := bundleJSON{Schema: jsonSchema, BundleCode: res.BundleCode, URL: res.BundleURL, ExpiresAt: res.ExpiresAt,
			DownloadLimit: res.DownloadLimit, PasswordProtected: res.PasswordProtected, Encrypted: res.Encrypted, Files: []bundleFileJSON{}}
		for i, f := range res.Files {
			doc.Files = append(doc.Files, bundleFileJSON{Position: f.Position, File: files[i], Name: f.Name, Size: f.Size})
		}
		return printJSON(cmd.OutOrStdout(), doc)
	}

	fmt.Fprintln(out)
	fmt.Fprintln(out, strings.Repeat("─", 50))
	fmt.Fprintf(out, "Bundle uploaded: %d files\n", len(res.Files))
	fmt.Fprintln(out, strings.Repeat("─", 50))
	fmt.Fprintf(out, "Bundle Code: %s\n", res.BundleCode)
	for _, f := range res.Files {
		fmt.Fprintf(out, "  %d. %s (%s)\n", f.Position+1, display(f.Name), formatBytes(f.Size))
	}
	if res.ExpiresAt != nil {
		fmt.Fprintf(out, "Expires:     %s\n", res.ExpiresAt.Format("2006-01-02 15:04:05"))
	}
	if res.DownloadLimit != nil {
		fmt.Fprintf(out, "Downloads:   %d per file\n", *res.DownloadLimit)
	} else {
		fmt.Fprintf(out, "Downloads:   Unlimited\n")
	}
	fmt.Fprintf(out, "Password:    %v\n", res.PasswordProtected)
	fmt.Fprintf(out, "Encrypted:   %v\n", res.Encrypted)
	fmt.Fprintln(out, strings.Repeat("─", 50))
	if res.Encrypted {
		fmt.Fprintln(out, "\nBundle link (contains the decryption key; anyone with it can read the files):")
	} else {
		fmt.Fprintln(out, "\nBundle link:")
	}
	fmt.Fprintln(out, res.BundleURL)
	if showQR {
		if res.Encrypted {
			fmt.Fprintln(os.Stderr, "[WARNING] The QR code holds the bundle link with its decryption key: anyone who sees your screen, or a recording or log of it, can read the files.")
		}
		fmt.Fprintln(out)
		return printQR(out, res.BundleURL)
	}
	return nil
}

// downloadBundleLink downloads every file of a bundle link into a directory
// (dest[0], or ./<bundle code>).
func downloadBundleLink(cmd *cobra.Command, target string, dest []string, password string, overwrite bool) error {
	link, err := safeshare.ParseBundleURL(target)
	if err != nil {
		return err
	}
	token := apiToken
	if strings.TrimRight(baseURL, "/") != link.BaseURL {
		token = "" // never send the API token to a host only a link vouches for
		if baseURL != "" {
			fmt.Fprintf(os.Stderr, "[WARNING] Using the server from the bundle link (%s), not %s; your API token is not sent to it.\n", link.BaseURL, baseURL)
		}
	}
	client, err := newClient(link.BaseURL, token)
	if err != nil {
		return err
	}

	dir := link.BundleCode
	if len(dest) > 0 {
		dir = dest[0]
	}
	if info, err := os.Lstat(dir); err == nil && !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dir)
	}

	out := humanOut(cmd)
	fmt.Fprintf(out, "Downloading bundle %s to %s\n", link.BundleCode, dir)
	saved, err := client.DownloadBundle(context.Background(), link, dir, &safeshare.DownloadOptions{Password: password, Overwrite: overwrite})
	if err != nil {
		if errors.Is(err, safeshare.ErrManifestMismatch) {
			return fmt.Errorf("%w; nothing was saved", err)
		}
		return err
	}

	if jsonOut {
		doc := bundleDownloadJSON{Schema: jsonSchema, BundleCode: link.BundleCode, Dir: dir, Decrypted: link.Key != "", Files: []bundleSavedFileJSON{}}
		for _, p := range saved {
			info, _ := os.Stat(p)
			var size int64
			if info != nil {
				size = info.Size()
			}
			doc.Files = append(doc.Files, bundleSavedFileJSON{Name: filepath.Base(p), Path: p, Size: size})
		}
		return printJSON(cmd.OutOrStdout(), doc)
	}
	for _, p := range saved {
		fmt.Fprintf(out, "  %s\n", display(p))
	}
	fmt.Fprintf(out, "\nSaved %d files.\n", len(saved))
	return nil
}

// listBundles prints the signed-in user's bundles.
func listBundles(ctx context.Context, cmd *cobra.Command, client *safeshare.Client, limit, offset int) error {
	page, err := client.ListBundles(ctx, limit, offset)
	if err != nil {
		return err
	}
	if jsonOut {
		return printJSON(cmd.OutOrStdout(), struct {
			Schema int `json:"schema"`
			*safeshare.UserBundlesResponse
		}{Schema: jsonSchema, UserBundlesResponse: page})
	}
	if len(page.Bundles) == 0 {
		fmt.Println("No bundles found.")
		return nil
	}
	fmt.Printf("Bundles (offset %d, showing %d of %d):\n", offset, len(page.Bundles), page.Total)
	fmt.Println(strings.Repeat("═", 80))
	for _, b := range page.Bundles {
		fmt.Printf("\n%-12s %s\n", "Bundle Code:", display(b.BundleCode))
		fmt.Printf("%-12s %d (%s)\n", "Files:", b.FileCount, formatBytes(b.TotalSize))
		for _, f := range b.Files {
			limit := "∞"
			if b.DownloadLimit != nil {
				limit = fmt.Sprint(*b.DownloadLimit)
			}
			fmt.Printf("  %d. %s (%s, %d/%s downloads)\n", f.Position+1, display(f.Name), formatBytes(f.Size), f.CompletedDownloads, limit)
		}
		fmt.Printf("%-12s %s\n", "Created:", b.CreatedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("%-12s %s\n", "Expires:", b.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("%-12s %v\n", "Password:", b.PasswordProtected)
		fmt.Printf("%-12s %v\n", "Encrypted:", b.Encrypted)
		fmt.Println(strings.Repeat("─", 80))
	}
	return nil
}
