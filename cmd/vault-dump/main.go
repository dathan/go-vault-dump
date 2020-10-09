package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/dump"
	vaultapi "github.com/hashicorp/vault/api"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

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

func init() {
	pflag.String(vaFlag, "https://127.0.0.1:8200", "vault url")
	pflag.String(vtFlag, "", "vault token")
	pflag.String("enc", "yaml", "encoding type [json, yaml]")
	pflag.String("o", "stdout", "output type, [stdout, file]")
	pflag.String("kc", "", "location of kube config file")
	pflag.Bool(debugFlag, false, "enables verbose messages")
	pflag.CommandLine.ParseErrorsWhitelist.UnknownFlags = true
	pflag.Parse()
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

}

func main() {

	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	dump.CheckErr(err, "failed vault client init")
	config := &dump.Config{
		Debug:  viper.GetBool(debugFlag),
		Client: client,
	}

	config.Client.SetAddress(viper.GetString(vaFlag))
	config.Client.SetToken(viper.GetString(vtFlag))
	config.SetInput(pflag.Arg(0))
	config.SetOutput(pflag.Arg(1), viper.GetString("enc"), viper.GetString("o"))

	var sm sync.Map
	var wg sync.WaitGroup
	dump.FindVaultSecrets(config, config.GetInput(), &sm, &wg)
	wg.Wait()

	vo, _ := dump.ValidateOutputType(viper.GetString("o"))
	switch vo {
	case "k8s":
		VaultToKube(config, &sm)
	default:
		dump.ProcessOutput(config, &sm)
	}

}

const (
	tokenFile  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	rootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// VaultToKube
func VaultToKube(c *dump.Config, s *sync.Map) {
	var config *rest.Config
	var err error

	if _, err := os.Stat(tokenFile); err == nil {
		fmt.Println("Using in cluster config")
		config, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	} else {
		fmt.Println("Using out of cluster config")
		config, err = clientcmd.BuildConfigFromFlags("", viper.GetString("kc"))
	}
	dump.CheckErr(err, "failed to setup kube config")

	kClient, err := kubernetes.NewForConfig(config)
	dump.CheckErr(err, "failed to setup kube client")

	secrets, _ := kClient.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})

	fmt.Printf("There are %d secrets in the cluster\n", len(secrets.Items))

	m := make(map[interface{}]interface{})
	s.Range(func(key, val interface{}) bool {
		m[key] = val
		return true
	})
	fmt.Printf("There are %d secrets in the mountpath\n", len(m))
	for k, v := range m {

		createOrModifySecret(kClient, k.(string), v.(map[string]interface{})) // type assertion syntax
	}

	// vault path to kubernetes location association will be
	// secret/cluster/namespace/secretName

	// from vault path check if you are in the correct environment, namespace before creating secret
	// if secret already exists, modify it or merge the two
	// if not, create a new secret
	//
}

// type kubeCoord struct {
// 	cluster   string
// 	namespace string
// 	app       string
// }

func createOrModifySecret(client *kubernetes.Clientset, key string, value map[string]interface{}) {
	fmt.Println(key)
	// fmt.Println(value["data"])
	secretMap := make(map[string]string)
	for k, v := range value["data"].(map[string]interface{}) {
		// fmt.Println(fmt.Sprintf("key: %s, value: %s", k, v))
		secretMap[k] = v.(string)
	}
	// fmt.Println(secretMap)
	for i, j := range secretMap {
		fmt.Println(fmt.Sprintf("key: %s, value: %s", i, j))
	}

	kCoord := strings.Split(key, "/")
	kSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: kCoord[len(kCoord)-1],
		},
		StringData: secretMap,
	}
	_, err := client.CoreV1().Secrets("default").Get(context.TODO(), kCoord[len(kCoord)-1], metav1.GetOptions{})
	if errors.IsNotFound(err) {
		fmt.Println("DOESNT EXIST")
		_, err := client.CoreV1().Secrets("default").Create(context.TODO(), &kSecret, metav1.CreateOptions{})
		dump.CheckErr(err, "failed to create new secret")
	} else if err != nil {
		dump.CheckErr(err, "failed to get secret with name "+kCoord[len(kCoord)-1])
	}
	fmt.Println(kSecret)
}
