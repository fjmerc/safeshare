// safeshare-cli is a command-line interface for SafeShare file sharing.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"unicode"

	safeshare "github.com/fjmerc/safeshare/sdk/go"

	"github.com/spf13/cobra"
)

// version is set at build time (scripts/build-cli.sh passes
// -X main.version=<release>); plain go builds report "dev".
var version = "dev"

var (
	// Global flags
	baseURL  string
	apiToken string
	proxyURL string
	verbose  bool
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, escapeControls(err.Error()))
		var ee *exitError
		if errors.As(err, &ee) {
			os.Exit(ee.code)
		}
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "safeshare-cli",
		Short: "SafeShare CLI - File sharing from the command line",
		Long: `SafeShare CLI provides command-line access to the SafeShare file sharing service.

Upload, download, and manage files from your terminal.

Configuration:
  Set SAFESHARE_URL and SAFESHARE_TOKEN environment variables, or use --url and --token flags.

Examples:
  safeshare-cli upload myfile.txt --expires 24
  safeshare-cli download abc12345 ./output.pdf
  safeshare-cli list
  safeshare-cli delete abc12345
  safeshare-cli verify https://share.example.com`,
		Version: cliVersion(),
		// Errors are printed once by main; usage only on request.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.SetVersionTemplate("safeshare-cli {{.Version}}\n")

	// Global flags
	rootCmd.PersistentFlags().StringVar(&baseURL, "url", os.Getenv("SAFESHARE_URL"), "SafeShare server URL (or SAFESHARE_URL env)")
	rootCmd.PersistentFlags().StringVar(&apiToken, "token", os.Getenv("SAFESHARE_TOKEN"), "API token (or SAFESHARE_TOKEN env)")
	rootCmd.PersistentFlags().StringVar(&proxyURL, "proxy", os.Getenv("SAFESHARE_PROXY"), "Send every request through this proxy, e.g. socks5://127.0.0.1:9050 for Tor (or SAFESHARE_PROXY env; ALL_PROXY/HTTPS_PROXY/HTTP_PROXY also work)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(uploadCmd())
	rootCmd.AddCommand(downloadCmd())
	rootCmd.AddCommand(infoCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(deleteCmd())
	rootCmd.AddCommand(renameCmd())
	rootCmd.AddCommand(configCmd())
	rootCmd.AddCommand(verifyCmd())
	rootCmd.AddCommand(versionCmd())

	return rootCmd
}

// cliVersion returns the release this binary was built from: the stamped
// version, else the module version go install records, else "dev".
func cliVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the CLI's version",
		Long: `Show the release this safeshare-cli was built from, and the Go version and
platform it was built for. "dev" means it was not built by scripts/build-cli.sh
(or go install).

The server's version is in "safeshare-cli config".`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "safeshare-cli %s\n%s %s/%s\n", cliVersion(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}

// newClient creates an SDK client for server with the CLI's proxy setting.
func newClient(server, token string) (*safeshare.Client, error) {
	return safeshare.NewClient(safeshare.ClientConfig{BaseURL: server, APIToken: token, Proxy: proxyURL})
}

// proxyInUse reports whether requests go through a proxy (the --proxy flag or
// a proxy environment variable), which suggests the user is hiding their
// network location.
func proxyInUse() bool {
	if proxyURL != "" {
		return true
	}
	for _, n := range []string{"ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(n) != "" {
			return true
		}
	}
	return false
}

// display makes a name from the server or an uploader safe to print: names
// with control or invisible formatting characters (terminal escapes,
// right-to-left overrides) are shown quoted and escaped.
func display(name string) string {
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return strconv.Quote(name)
		}
	}
	return name
}

// escapeControls escapes control and invisible formatting characters
// (except newlines) in text that may come from a server, such as API error
// messages, so it can't drive the terminal.
func escapeControls(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// checkConfig validates that required configuration is present.
func checkConfig() error {
	if baseURL == "" {
		return fmt.Errorf("server URL is required (use --url or SAFESHARE_URL environment variable)")
	}
	return nil
}

// checkAuth validates that authentication is configured.
func checkAuth() error {
	if err := checkConfig(); err != nil {
		return err
	}
	if apiToken == "" {
		return fmt.Errorf("API token is required (use --token or SAFESHARE_TOKEN environment variable)")
	}
	// Security warning if token is passed via command line
	if os.Getenv("SAFESHARE_TOKEN") == "" && apiToken != "" {
		fmt.Fprintln(os.Stderr, "[WARNING] Token passed via command line is visible in process list. Use SAFESHARE_TOKEN environment variable instead.")
	}
	return nil
}
