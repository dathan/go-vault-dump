package dump

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/vault"
	vaultapi "github.com/hashicorp/vault/api"
)

type secret struct {
	path string
	data interface{}
}

type secretPathStream struct {
	secretpath chan string
	wg         *sync.WaitGroup
}
type secretStream struct {
	channel chan secret
	wg      *sync.WaitGroup
}
type SecretScraper struct {
	context context.Context
	find    *secretPathStream
	secrets *secretStream
	vault   *vaultapi.Client
	Data    map[string]interface{}
}

func NewSecretScraper(vault *vaultapi.Client) (*SecretScraper, error) {
	return &SecretScraper{
		context: context.Background(),
		find: &secretPathStream{
			secretpath: make(chan string),
			wg:         new(sync.WaitGroup),
		},
		secrets: &secretStream{
			channel: make(chan secret),
			wg:      new(sync.WaitGroup),
		},
		vault: vault,
		Data:  make(map[string]interface{}),
	}, nil
}

// Run creates n number of workers to secret info from found paths
func (s *SecretScraper) Run(path string, n int) error {
	ctx, cancelFunc := context.WithCancel(context.Background())

	s.find.wg.Add(1)
	go s.secretFinder(ctx, cancelFunc, path)

	s.secrets.wg.Add(n)
	for i := 0; i != n; i++ {
		go s.secretProducer(ctx, cancelFunc, n)
	}

	// once the secretStream is closed
	// convert the stream into a map
	go func() {
		for secret := range s.secrets.channel {
			s.Data[secret.path] = secret.data
		}
	}()

	s.find.wg.Wait()
	close(s.find.secretpath)
	s.secrets.wg.Wait()
	close(s.secrets.channel)
	log.Println("Completed producing secrets from found paths")

	cancelFunc()
	return nil
}

func (s *SecretScraper) secretFinder(ctx context.Context, cancelFunc context.CancelFunc, path string) {
	defer s.find.wg.Done()

	select {
	case <-ctx.Done():
		// close(s.find.secretpath)
		log.Println("Received signal to stop, stopping secretFinder")
		return
	default:
		results, err := s.vault.Logical().List(path)
		if err != nil {
			log.Printf("failed to list on path %s, %s\n", path, err.Error())
		}

		if data, ok := vault.ExtractListData(results); !ok {
			log.Printf("No entries found at %s\n", path) // if a path is a leaf, this will occur
		} else {
			for _, v := range data {
				newpath := vault.EnsureNoTrailingSlash(path + "/" + v.(string))
				if isDir(v.(string)) {
					s.find.wg.Add(1)
					s.secretFinder(ctx, cancelFunc, newpath)
				} else {

					// reconciling v2 secret engine requirement for list operation
					s.find.secretpath <- strings.Replace(newpath, "metadata", "data", 1)
				}
			}
		}
	}
}

// secretProducer takes secretPaths off its stream and converts them into secrets
// and adds those to another stream until an error occurs or the context is shutdown
func (s *SecretScraper) secretProducer(ctx context.Context, cancelFunc context.CancelFunc, id int) {
	defer s.secrets.wg.Done()

	for path := range s.find.secretpath {
		select {
		case <-ctx.Done():
			log.Println("Received signal to stop, stopping, secretProducer")
			return
		default:
			vaultSecret, err := s.vault.Logical().Read(path)
			if err != nil {
				log.Printf("failed to get secrets in %s, %s\n", path, err.Error())
			}

			// secret engine v2 has a different response body
			data := vaultSecret.Data["data"]
			if data == nil {
				// secret engine v1
				data = vaultSecret.Data
			}

			secret := secret{
				path: path,
				data: data,
			}
			s.secrets.channel <- secret
		}
	}
}
