package dump

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

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
func ToKube(c *Config, m map[string]interface{}) error {
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

	// c.DebugMsg(fmt.Sprintf("There are %d secrets in the mountpath\n", len(m)))
	for k, v := range m {
		err := createOrModifySecret(kClient, k, v.(map[string]interface{})) // type assertion syntax
		if err != nil {
			return fmt.Errorf("failed to create or modify secret: %w", err)
		}
	}
	return nil
}

func createOrModifySecret(client *kubernetes.Clientset, key string, value map[string]interface{}) error {
	secretMap := make(map[string]string)
	for k, v := range value {
		// convert to map[string]string
		secretMap[strings.ToUpper(k)] = v.(string)
	}

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
	} else {
		// merge vault secret into kube secret, overriding k8s secrets
		// TODO override if force flag is set, otherwise fail due to existing key values that do not match
		newMap := make(map[string]string)
		for k1, v1 := range secretExists.Data {
			newMap[k1] = string(v1)
		}
		for i, j := range secretMap {
			// TODO log what key when values do not match
			// log.Printf("secret: %s,\tkey: %s\n", i, j)
			newMap[i] = j
		}
		_, err = client.CoreV1().Secrets("default").Update(
			context.TODO(),
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName,
				},
				StringData: newMap,
			},
			metav1.UpdateOptions{},
		)
		if err != nil {
			return fmt.Errorf("failed: %w", err)
		}

	}

	return nil
}
