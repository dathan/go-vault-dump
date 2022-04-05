package cmd

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/spf13/cobra"
	"golang.org/x/text/message"
)

var (
	listCmd *cobra.Command
)

func init() {
	listCmd = &cobra.Command{
		Use:   "list s3://<bucket>/[path]",
		Short: "Lists vault state files in an S3 bucket",
		Args:  cobra.ExactArgs(1),
		RunE:  listExports,
	}
	rootCmd.AddCommand(listCmd)
}

func listExports(cmd *cobra.Command, args []string) error {

	s3path := args[0]
	if s3path == "" {
		return fmt.Errorf("'path' is a required argument but not found")
	}
	if len(s3path) < 5 || s3path[:5] != "s3://" {
		return errors.New("error: 'path' must begin with s3://")
	}

	results, err := aws.S3List(s3path, "."+cryptExt)
	if err != nil {
		return err
	}

	// We're using tabwriter to align arbitrary-width columns, but it can't handle mixing left- and
	// right-aligned columns, so the size column, where we can set a reasonable maximum (<1TB), is
	// explicitly right-aligned before printing.

	if len(results) == 0 {
		fmt.Printf("No results found at %s\nDone\n", s3path)

		return nil
	}

	msg := message.NewPrinter(message.MatchLanguage("en"))
	tab := tabwriter.NewWriter(os.Stdout, 0, 8, 2, ' ', 0)

	sizeStr := fmt.Sprintf("%15s", "Bytes")
	fmt.Fprintf(tab, "Filename\t%s\t\n", sizeStr)
	sizeStr = fmt.Sprintf("%15s", "---")

	fmt.Fprintf(tab, "---\t%s\t\n", sizeStr)

	for _, vv := range results {
		fmt.Fprintf(tab, "%s\t%s\t\n", vv.Key, msg.Sprintf("%15d", vv.Size))
	}

	tab.Flush()
	fmt.Printf("\nDone\n")

	return nil
}
