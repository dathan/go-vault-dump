package main

import (
	"fmt"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const debugFlag = "debug"
const vaFlag = "vault-addr"
const vtFlag = "vault-token"

/**
 * Auth with VAULT using common environment flags
 * List all the keys
 * recursively print out the values for each key
 */

var (
	debug bool
	wg    sync.WaitGroup
)

func init() {
	pflag.String(vaFlag, "https://127.0.0.1:8200", "vault url")
	pflag.String(vtFlag, "", "vault token")
	pflag.Bool("debug", false, "enables verbose messages")
	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

}

func checkErr(e error, msg string) {
	if e != nil {
		if msg != "" {
			fmt.Println(msg)
		}
		panic(e)
	}
}

func debugMsg(msg string) {
	if debug {
		fmt.Println(msg)
	}
}

func findVaultSecrets(c *vaultapi.Client, path string, smPointer *sync.Map) {
	wg.Add(1)
	debugMsg(path)

	go func(wg *sync.WaitGroup, path string) {
		secret, err := c.Logical().List(path)
		checkErr(err, "error listing path")

		if secret == nil || secret.Data == nil {
			panic(fmt.Sprintf("No value found at %s", path))
		}

		// If the secret is wrapped, return the wrapped response.
		if secret.WrapInfo != nil && secret.WrapInfo.TTL != 0 {
			// _ = vaultcommand.OutputSecret(vaultcommand.KVListCommand.UI, secret)
			fmt.Println("secret wrapped")
		}

		if _, ok := vault.ExtractListData(secret); !ok {
			panic(fmt.Sprintf("No entries found at %s", path))
		}

		for _, p := range secret.Data {
			for _, k := range p.([]interface{}) {
				newPath := path + "/" + k.(string)
				if isDir(k.(string)) { // type assertion
					findVaultSecrets(c, vault.EnsureNoTrailingSlash(newPath), smPointer)
				} else {
					// reconciling v2 secret engine requirement for list operation
					keyPath := strings.Replace(newPath, "metadata", "data", 1)
					debugMsg(fmt.Sprintf("processing a secret at %s", keyPath))

					sec, err := c.Logical().Read(keyPath)
					checkErr(err, "")

					if sec != nil {
						smPointer.Store(keyPath, sec.Data)
					}

				}
			}
		}
		wg.Done()
	}(&wg, path)
}

func getPathFromInput(input string) string {
	if input == "" {
		panic("missing input path from command line")
	}
	return vault.EnsureNoTrailingSlash(vault.SanitizePath(input))
}

func isDir(p string) bool {
	lastChar := p[len(p)-1:]
	if lastChar != "/" {
		return false
	}
	return true
}

func printToStdOut(s *sync.Map) {
	m := make(map[interface{}]interface{})
	s.Range(func(key, val interface{}) bool {
		// for k, v := range val.(map[string]interface{}) {
		// 	fmt.Printf("[%s] = %s : %v \n", key, k, v)
		// }
		m[key] = val

		return true
	})
	fmt.Println(toYaml(m))
}

func toYaml(i interface{}) string {
	y, err := yaml.Marshal(i)
	checkErr(err, "error when marshalling interface into []byte")
	return string(y)
}

func main() {

	if viper.IsSet(debugFlag) {
		debug = true
	}
	config := vaultapi.DefaultConfig()
	client, err := vaultapi.NewClient(config)
	checkErr(err, "failed vault client init")

	if viper.IsSet(vaFlag) {
		debugMsg("flag set: " + vaFlag)
		client.SetAddress(viper.GetString(vaFlag))
	}

	if viper.IsSet(vtFlag) {
		debugMsg("flag set: " + vtFlag)
		client.SetToken(viper.GetString(vtFlag))
	}

	// get inputPath from first non flag argument
	inputPath := getPathFromInput(pflag.Arg(0))
	mountPath, v2, err := vault.IsKVv2(inputPath, client)
	checkErr(err, "error determining KV engine version")
	if v2 {
		inputPath = vault.AddPrefixToVKVPath(inputPath, mountPath, "metadata")
		checkErr(err, "")
	}

	var sm sync.Map
	findVaultSecrets(client, inputPath, &sm)
	wg.Wait()

	printToStdOut(&sm)

}
