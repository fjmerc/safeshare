package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
	"github.com/spf13/cobra"
)

// exitError makes main exit with a specific status after printing msg.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func verifyCmd() *cobra.Command {
	var (
		manifestFile string
		version      string
		repo         string
		all          bool
	)

	cmd := &cobra.Command{
		Use:   "verify [server-url]",
		Short: "Check a server's web app against a SafeShare release",
		Long: `Check that the web app a SafeShare server sends to browsers is exactly the
one published with a release, file by file (SHA-256).

The browser's end-to-end encryption runs in JavaScript the server sends, so
a tampered server could send code that leaks keys. This command fetches the
pages and scripts, and compares them with web-assets.sha256 from the GitHub
release the server reports (or --version, or a --manifest file you made with
scripts/web-asset-hashes.sh in a checkout of the release).

Limits: it checks what the server sent to this computer, now. A server that
recognises the check can still send other visitors something else. A CDN
that rewrites pages (for example, Cloudflare Rocket Loader or email
obfuscation) shows up as a mismatch.

Use --proxy (or ALL_PROXY) to check over Tor; the release download from
GitHub goes through the same proxy.

Exit status: 0 verified, 2 a file differs, 1 could not verify.

Examples:
  safeshare-cli verify https://share.example.com
  safeshare-cli verify --proxy socks5://127.0.0.1:9050 http://example.onion
  safeshare-cli verify https://share.example.com --manifest web-assets.sha256`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			server := baseURL
			if len(args) == 1 {
				server = args[0]
			}
			if server == "" {
				return fmt.Errorf("server URL is required (argument, --url or SAFESHARE_URL)")
			}
			// No token: verification uses only public pages.
			client, err := newClient(server, "")
			if err != nil {
				return err
			}
			return runVerify(cmd.Context(), cmd.OutOrStdout(), client, verifyOptions{
				manifestFile: manifestFile, version: version, repo: repo, all: all,
			})
		},
	}

	cmd.Flags().StringVar(&manifestFile, "manifest", "", "Compare against this web-assets.sha256 file instead of downloading it from the release")
	cmd.Flags().StringVar(&version, "version", "", "Release to compare against, e.g. 1.17.0 (default: the version the server reports)")
	cmd.Flags().StringVar(&repo, "repo", safeshare.DefaultReleaseRepo, "GitHub repository that publishes the releases")
	cmd.Flags().BoolVar(&all, "all", false, "List every file, not only the ones that did not match")

	return cmd
}

type verifyOptions struct {
	manifestFile string
	version      string
	repo         string
	all          bool
}

func runVerify(ctx context.Context, out io.Writer, client *safeshare.Client, opts verifyOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}

	reported := ""
	if cfg, err := client.GetConfig(ctx); err == nil {
		reported = cfg.Version
	} else if opts.version == "" && opts.manifestFile == "" {
		return fmt.Errorf("reading the server's version: %w (use --version)", err)
	}
	if reported != "" {
		fmt.Fprintf(out, "Server reports version %s\n", display(reported))
	}

	version := opts.version
	if version == "" {
		version = reported
	}

	var data []byte
	var against string
	if opts.manifestFile != "" {
		var err error
		if data, err = readManifestFile(opts.manifestFile); err != nil {
			return err
		}
		against = opts.manifestFile
	} else {
		if version == "" {
			return fmt.Errorf("the server doesn't report its version; use --version or --manifest")
		}
		var err error
		data, err = client.FetchReleaseManifest(ctx, opts.repo, version)
		if safeshare.IsNoManifest(err) {
			return fmt.Errorf("release v%s on github.com/%s has no %s (releases before 1.17.0 don't publish one). Make one with scripts/web-asset-hashes.sh in a checkout of that release and pass --manifest", display(version), opts.repo, safeshare.WebAssetManifestName)
		}
		if err != nil {
			return err
		}
		against = fmt.Sprintf("the v%s release (github.com/%s)", version, opts.repo)
	}
	manifest, err := safeshare.ParseWebAssetManifest(data)
	if err != nil {
		return fmt.Errorf("%s: %w", against, err)
	}
	fmt.Fprintf(out, "Comparing against %s\n\n", display(against))

	report, err := client.VerifyWebAssets(ctx, manifest)
	if err != nil {
		return err
	}

	for _, r := range report.Results {
		if r.Status == safeshare.AssetMatch && !opts.all {
			continue
		}
		where := r.URLPath
		if where == "" {
			where = r.File
		}
		line := fmt.Sprintf("  %-12s %s", r.Status, where)
		if r.Detail != "" {
			line += " (" + r.Detail + ")"
		}
		fmt.Fprintln(out, escapeControls(line))
		if r.Status == safeshare.AssetMismatch {
			fmt.Fprintf(out, "               expected %s\n               got      %s\n", r.Expected, r.Got)
		}
	}
	if n := report.Count(safeshare.AssetMatch); !opts.all && n > 0 {
		fmt.Fprintf(out, "  %d files match (--all lists them)\n", n)
	}
	fmt.Fprintln(out)

	if extra := report.LooseScriptPolicy(); len(extra) > 0 {
		fmt.Fprintln(out, escapeControls(fmt.Sprintf("Warning: the page's Content-Security-Policy lets scripts run from more than the server's own files (%s); SafeShare sends \"script-src 'self'\". Scripts injected that way aren't covered by this check.", strings.Join(extra, " "))))
	}
	if opts.manifestFile == "" {
		warnIfNotLatest(ctx, out, client, opts.repo, version)
	}
	if reported != "" && version != reported {
		fmt.Fprintf(out, "Note: the server reports %s but was compared against %s.\n", display(reported), display(version))
	}

	switch {
	case report.Tampered():
		return &exitError{2, fmt.Sprintf("NOT VERIFIED: %d file(s) differ from %s. The web app was changed on the server or on the way; don't trust this server's in-browser encryption.", report.Count(safeshare.AssetMismatch), against)}
	case report.Verified():
		fmt.Fprintf(out, "VERIFIED: all %d files fetched match %s", report.Count(safeshare.AssetMatch), display(against))
		if n := report.Count(safeshare.AssetNotChecked); n > 0 {
			fmt.Fprintf(out, " (%d not checked, see above)", n)
		}
		fmt.Fprintln(out, ".")
		fmt.Fprintln(out, "This covers what the server sent to this computer just now; it can't show what it sends to others.")
		return nil
	case report.Count(safeshare.AssetUnknown) > 0:
		return &exitError{1, "COULD NOT VERIFY: the release has files this safeshare-cli doesn't know how to check. Update safeshare-cli."}
	case report.Count(safeshare.AssetMissing) > 0:
		return &exitError{1, "COULD NOT VERIFY: the server didn't serve some files the release has (see above). It may be another version; nothing that was served differed."}
	default:
		return &exitError{1, "COULD NOT VERIFY: some files could not be fetched or checked (see above). Nothing differed, but the check is incomplete."}
	}
}

func readManifestFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 1<<20 {
		return nil, errors.New(path + " is too large for a " + safeshare.WebAssetManifestName)
	}
	return data, nil
}

// warnIfNotLatest points out when the release compared against isn't the
// newest one: a server can serve an old, genuine version that has known holes.
func warnIfNotLatest(ctx context.Context, out io.Writer, client *safeshare.Client, repo, version string) {
	latest, err := client.LatestReleaseVersion(ctx, repo)
	if err != nil {
		fmt.Fprintf(out, "Warning: couldn't check the latest release: %s\n", escapeControls(err.Error()))
		return
	}
	if latest != version {
		fmt.Fprintf(out, "Warning: compared against v%s, but the latest release is v%s. Older releases may have since-fixed security problems.\n", display(version), latest)
	}
}
