// safeshare-cli is a command-line interface for SafeShare file sharing.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	baseURL  string
	apiToken string
	verbose  bool
)

func main() {
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
  safeshare-cli delete abc12345`,
	}

	// Global flags
	rootCmd.PersistentFlags().StringVar(&baseURL, "url", os.Getenv("SAFESHARE_URL"), "SafeShare server URL (or SAFESHARE_URL env)")
	rootCmd.PersistentFlags().StringVar(&apiToken, "token", os.Getenv("SAFESHARE_TOKEN"), "API token (or SAFESHARE_TOKEN env)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Add subcommands
	rootCmd.AddCommand(uploadCmd())
	rootCmd.AddCommand(downloadCmd())
	rootCmd.AddCommand(infoCmd())
	rootCmd.AddCommand(listCmd())
	rootCmd.AddCommand(deleteCmd())
	rootCmd.AddCommand(renameCmd())
	rootCmd.AddCommand(configCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
