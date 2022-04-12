package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/dathan/go-vault-dump/pkg/transform"
	"github.com/spf13/cobra"
)

var (
	applyPath    string
	transformCmd *cobra.Command
)

func init() {
	transformCmd = &cobra.Command{
		Use:   "transform --apply <transform> <filename>",
		Short: "Apply transforms to a vault dump",
		Args:  cobra.ExactArgs(1),
		RunE:  doTransform,
	}
	transformCmd.Flags().StringVarP(&applyPath, "apply", "a", "", "path to transform definition")
	transformCmd.Flags().StringVarP(&destPath, "output", "o", "", "output path")
	rootCmd.AddCommand(transformCmd)
}

func doTransform(cmd *cobra.Command, args []string) error {

	transforms, err := loadJson(applyPath)
	if err != nil {
		return err
	}

	secretsPath := args[0]
	secrets, err := loadJson(secretsPath)
	if err != nil {
		return err
	}

	data, err := transform.Transform(transforms, secrets)
	if err != nil {
		return err
	}

	output, err := json.Marshal(data)
	if err != nil {
		return err
	}

	if destPath == "" {
		fmt.Print(string(output))
	} else {

		ff, err := os.Create(destPath)
		if err != nil {
			return err
		}

		err = ff.Chmod(UMASK)
		if err != nil {
			return err
		}

		_, err = ff.Write(output)
		if err != nil {
			return err
		}

	}

	return nil
}

func loadJson(filepath string) (map[string]interface{}, error) {
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return map[string]interface{}{}, err
	}

	dd := make(map[string]interface{})
	if err = json.Unmarshal(data, &dd); err != nil {
		return map[string]interface{}{}, err
	}

	return dd, nil
}
