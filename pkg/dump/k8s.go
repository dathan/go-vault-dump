package dump

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// ToKube
func ToKube(c *Config, s *sync.Map) error {
	var config *rest.Config
	var err error

	if _, err := os.Stat(tokenFile); err == nil {
		log.Println("Using in cluster config")
		config, err = rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	} else {
		log.Println("Using out of cluster config")
		config, err = clientcmd.BuildConfigFromFlags("", viper.GetString("kc"))
	}
	if err != nil {
		return fmt.Errorf("failed to setup kube config: %w", err)
	}

	kClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to setup kube client: %w", err)
	}

	secrets, _ := kClient.CoreV1().Secrets("").List(context.TODO(), metav1.ListOptions{})

	log.Printf("There are %d secrets in the cluster\n", len(secrets.Items))

	m := make(map[interface{}]interface{})
	s.Range(func(key, val interface{}) bool {
		m[key] = val
		return true
	})
	c.DebugMsg(fmt.Sprintf("There are %d secrets in the mountpath\n", len(m)))
	for k, v := range m {

		err := createOrModifySecret(kClient, k.(string), v.(map[string]interface{})) // type assertion syntax
		if err != nil {
			return fmt.Errorf("failed to create or modify secret: %w", err)
		}
	}
	return nil
}

func createOrModifySecret(client *kubernetes.Clientset, key string, value map[string]interface{}) error {
	// fmt.Println(key)
	// fmt.Println(value["data"])
	secretMap := make(map[string]string)
	for k, v := range value["data"].(map[string]interface{}) {
		// convert to map[string]string
		secretMap[strings.ToUpper(k)] = v.(string)
	}
	// fmt.Println(secretMap)
	// for i, j := range secretMap {
	// 	fmt.Println(fmt.Sprintf("key: %s, value: %s", i, j))
	// }

	secretName := strings.Join(strings.Split(key, "/")[1:], ".")
	kSecret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		StringData: secretMap,
	}
	secretExists, err := client.CoreV1().Secrets("default").Get(context.TODO(), secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		fmt.Println(fmt.Sprintf("K8s secret %s not found, creating...", kSecret.Name))
		_, err := client.CoreV1().Secrets("default").Create(context.TODO(), &kSecret, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("failed to create new secret: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get secret with name %s: %w", secretName, err)
	}

	// merge vault secret into kube secret, overriding k8s secrets if force flag is set,
	// otherwise fail due to existing key values that do not match
	// vaultSecret := make(map[string][]byte)
	// for k, v := range value["data"].(map[string]interface{}) {
	// 	// convert to map[string]string
	// 	vaultSecret[strings.ToUpper(k)] = (v.([]byte))
	// }
	// // if vaultSecret != secretExists.Data {

	// // }
	for k, v := range secretMap {
		for i, j := range secretExists.Data {
			if k != i || string(v) != string(j) {
				log.Println(k, string(v))
				log.Println(i, string(j))
			}
		}
	}

	for k1, _ := range secretExists.Data {
		log.Printf("secret: %s,\tkey: %s\n", key, k1)
	}
	log.Println(value)
	return nil
}
