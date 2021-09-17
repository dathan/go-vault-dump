package cmd

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dathan/go-vault-dump/pkg/aws"
	"github.com/dathan/go-vault-dump/pkg/dump"
	"github.com/dathan/go-vault-dump/pkg/vault"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	cryptExt        = "aes"
	destFlag        = "dest"
	fileFlag        = "filename"
	ignoreKeysFlag  = "ignore-keys"
	ignorePathsFlag = "ignore-paths"
	kmsKeyFlag      = "kms-key"
	pathsFlag       = "path"
	regionFlag      = "aws-region"
	vaFlag          = "vault-addr"
	vtFlag          = "vault-token"
)

var (
	cfgFile    string
	encoding   string
	kubeconfig string
	output     string
	tmpdir     string
	rootCmd    *cobra.Command

	// https://goreleaser.com/environment/#using-the-mainversion
	version = "dev"
	commit  = "none"
	date    = "unknown"
	builtBy = "unknown"
)

var (
	// Verbose
	Verbose bool
)

func exitErr(e error) {
	log.SetOutput(os.Stderr)
	log.Println(e)
	os.Exit(1)
}

func init() {
	rootCmd = &cobra.Command{
		Use:   "vault-dump",
		Short: "dump secrets from Vault",
		RunE:  dumpVault,
	}

	logSetup()
	cobra.OnInitialize(initConfig)

	rootCmd.Flags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.vault-dump/config.yaml)")
	rootCmd.Flags().String(vaFlag, "https://127.0.0.1:8200", "vault url")
	rootCmd.Flags().String(vtFlag, "", "vault token")
	rootCmd.Flags().StringP(fileFlag, "f", "vault-dump", "output filename (.json or .yaml extension will be added)")
	rootCmd.Flags().String(kmsKeyFlag, "", "KMS encryption key ARN (required for S3 uploads)")
	rootCmd.Flags().String(regionFlag, "us-east-1", "AWS region for KMS")
	rootCmd.Flags().StringP(pathsFlag, "p", "", "comma separated list of vault paths to export")
	rootCmd.Flags().StringP(destFlag, "d", "", "output directory or S3 path")
	rootCmd.Flags().StringSlice(ignoreKeysFlag, []string{}, "comma separated list of key names to ignore")
	rootCmd.Flags().StringSlice(ignorePathsFlag, []string{}, "comma separated list of paths to ignore")
	rootCmd.Flags().StringVarP(&encoding, "encoding", "e", "json", "encoding type [json, yaml]")
	rootCmd.Flags().StringVarP(&output, "output", "o", "file", "output type, [stdout, file, s3]")
	rootCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "location of kube config file")
	rootCmd.Flags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output")
	rootCmd.Version = version

	viper.BindPFlag(fileFlag, rootCmd.Flags().Lookup(fileFlag))
	viper.BindPFlag(destFlag, rootCmd.Flags().Lookup(destFlag))
	viper.BindPFlag(pathsFlag, rootCmd.Flags().Lookup(pathsFlag))
	viper.BindPFlag(ignorePathsFlag, rootCmd.Flags().Lookup(ignorePathsFlag))
	viper.BindPFlag(kmsKeyFlag, rootCmd.Flags().Lookup(kmsKeyFlag))
	viper.BindPFlag(regionFlag, rootCmd.Flags().Lookup(regionFlag))
	viper.BindPFlag(vaFlag, rootCmd.Flags().Lookup(vaFlag))
	viper.BindPFlag(vtFlag, rootCmd.Flags().Lookup(vtFlag))
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile) // Use config file from the flag.
	} else {
		viper.SetConfigName("config")            // name of config file (without extension)
		viper.SetConfigType("yaml")              // REQUIRED if the config file does not have the extension in the name
		viper.AddConfigPath("/etc/vault-dump/")  // path to look for the config file in
		viper.AddConfigPath("$HOME/.vault-dump") // call multiple times to add many search paths
	}

	if err := viper.ReadInConfig(); err != nil { // Handle errors reading the config file
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// Config file was found but another error was produced
			exitErr(fmt.Errorf("fatal error config file: %v", err))
		}
	}
	viper.SetEnvPrefix("VAULT_DUMP")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()
}

func logSetup() {
	log.SetFlags(0)
	if Verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		exitErr(err)
	}
}

func dumpVault(cmd *cobra.Command, args []string) error {

	paths := viper.GetString(pathsFlag)
	if paths == "" {
		return errors.New(fmt.Sprintf("'%s' is a required argument but not found", pathsFlag))
	}

	vc, err := vault.NewClient(&vault.Config{
		Address: viper.GetString(vaFlag),
		Ignore: &vault.Ignore{
			Keys:  viper.GetStringSlice(ignoreKeysFlag),
			Paths: viper.GetStringSlice(ignorePathsFlag),
		},
		Retries: 5,
		Token:   viper.GetString(vtFlag),
	})
	if err != nil {
		return err
	}

	outputPath := viper.GetString(destFlag)

	s3path := ""
	kmsKey := viper.GetString(kmsKeyFlag)
	if output == "s3" {
		if kmsKey == "" {
			return errors.New("Error: KMS key must be specified for S3 upload")
		}
		if outputPath == "" {
			return errors.New("Error: Must specify an output path for S3 upload")
		}
		s3path = vault.EnsureNoTrailingSlash(outputPath)
		if len(s3path) < 5 || s3path[:5] != "s3://" {
			return errors.New("Error: Output path for S3 upload must begin with s3://")
		}
		outputPath, err = ioutil.TempDir("", "vault-dump-*")
		if err != nil {
			log.Fatal(err)
		}
	}
	defer os.RemoveAll(outputPath)
	outputPath = dump.GetPathForOutput(outputPath)

	outputConfig, err := dump.NewOutput(
		outputPath,
		encoding,
		output,
	)
	if err != nil {
		return err
	}

	outputFilename := viper.GetString(fileFlag)
	dumper, err := dump.New(&dump.Config{
		Debug:       Verbose,
		InputPath:   paths,
		Filename:    outputFilename,
		Output:      outputConfig,
		VaultConfig: vc,
	})
	if err != nil {
		return err
	}

	if err := dumper.Secrets(); err != nil {
		return err
	}

	if output == "s3" {
		srcPath := fmt.Sprintf("%s/%s.%s", outputPath, outputFilename, encoding)
		dstPath := fmt.Sprintf("%s/%s.%s.%s", s3path, outputFilename, encoding, cryptExt)
		data, err := os.ReadFile(srcPath)
		if err != nil {
			// This is expected if no secrets were dumps
			log.Println("Nothing to upload")
			return nil
		}
		plaintext := string(data)
		ciphertext, err := aws.Encrypt(plaintext, kmsKey, viper.GetString(regionFlag))
		if err != nil {
			return err
		}
		err = aws.Upload(dstPath, ciphertext)
		if err != nil {
			return err
		}
	}

	return nil
}
