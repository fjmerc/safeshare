package main

import (
	"context"
	"fmt"
	"strings"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
	"github.com/spf13/cobra"
)

func listCmd() *cobra.Command {
	var (
		limit  int
		offset int
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your uploaded files",
		Long: `List all files you have uploaded (requires authentication).

Examples:
  safeshare-cli list
  safeshare-cli list --limit 50 --offset 0`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkAuth(); err != nil {
				return err
			}

			// Create client
			client, err := safeshare.NewClient(safeshare.ClientConfig{
				BaseURL:  baseURL,
				APIToken: apiToken,
			})
			if err != nil {
				return err
			}

			ctx := context.Background()
			files, err := client.ListFiles(ctx, limit, offset)
			if err != nil {
				return err
			}

			if len(files.Files) == 0 {
				fmt.Println("No files found.")
				return nil
			}

			fmt.Printf("Files (offset %d, showing %d of %d):\n", offset, len(files.Files), files.Total)
			fmt.Println(strings.Repeat("═", 80))

			for _, f := range files.Files {
				fmt.Printf("\n%-12s %s\n", "Claim Code:", f.ClaimCode)
				fmt.Printf("%-12s %s\n", "Filename:", f.Filename)
				fmt.Printf("%-12s %s\n", "Size:", formatBytes(f.Size))
				fmt.Printf("%-12s %s\n", "Uploaded:", f.UploadedAt.Format("2006-01-02 15:04:05"))
				if f.ExpiresAt != nil {
					fmt.Printf("%-12s %s\n", "Expires:", f.ExpiresAt.Format("2006-01-02 15:04:05"))
				} else {
					fmt.Printf("%-12s Never\n", "Expires:")
				}
				downloadStr := fmt.Sprintf("%d", f.CompletedDownloads)
				if f.DownloadLimit != nil {
					downloadStr += fmt.Sprintf("/%d", *f.DownloadLimit)
				} else {
					downloadStr += "/∞"
				}
				fmt.Printf("%-12s %s\n", "Downloads:", downloadStr)
				fmt.Printf("%-12s %v\n", "Password:", f.PasswordProtected)
				fmt.Println(strings.Repeat("─", 80))
			}

			return nil
		},
	}

	cmd.Flags().IntVarP(&limit, "limit", "n", 50, "Number of files to show (max 100)")
	cmd.Flags().IntVarP(&offset, "offset", "o", 0, "Number of files to skip")

	return cmd
}

func deleteCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "delete <claim-code>",
		Short: "Delete a file",
		Long: `Delete a file by its claim code (requires authentication).

Example:
  safeshare-cli delete abc12345
  safeshare-cli delete abc12345 --force`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkAuth(); err != nil {
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

			// Get file info first for confirmation
			if !force {
				info, err := client.GetFileInfo(ctx, claimCode)
				if err != nil {
					return err
				}

				fmt.Printf("Delete file: %s (%s)?\n", info.Filename, formatBytes(info.Size))
				fmt.Print("Type 'yes' to confirm: ")

				var confirm string
				fmt.Scanln(&confirm)
				if confirm != "yes" {
					fmt.Println("Cancelled.")
					return nil
				}
			}

			if err := client.DeleteFile(ctx, claimCode); err != nil {
				return err
			}

			fmt.Println("File deleted successfully.")
			return nil
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")

	return cmd
}

func renameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <claim-code> <new-filename>",
		Short: "Rename a file",
		Long: `Rename a file by its claim code (requires authentication).

Example:
  safeshare-cli rename abc12345 new-name.pdf`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkAuth(); err != nil {
				return err
			}

			claimCode := args[0]
			newFilename := args[1]

			// Create client
			client, err := safeshare.NewClient(safeshare.ClientConfig{
				BaseURL:  baseURL,
				APIToken: apiToken,
			})
			if err != nil {
				return err
			}

			ctx := context.Background()
			result, err := client.RenameFile(ctx, claimCode, newFilename)
			if err != nil {
				return err
			}

			fmt.Printf("File renamed to: %s\n", result.NewFilename)
			return nil
		},
	}

	return cmd
}
