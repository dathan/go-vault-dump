package dump

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/dathan/go-vault-dump/pkg/vault"
)

const (
	bufsize = 1000
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
	context     context.Context
	find        *secretPathStream
	secrets     *secretStream
	Data        map[string]interface{}
	VaultConfig *vault.Config
}

func NewSecretScraper(vc *vault.Config) (*SecretScraper, error) {
	return &SecretScraper{
		context: context.Background(),
		find: &secretPathStream{
			secretpath: make(chan string, bufsize),
			wg:         new(sync.WaitGroup),
		},
		secrets: &secretStream{
			channel: make(chan secret, bufsize),
			wg:      new(sync.WaitGroup),
		},
		VaultConfig: vc,
		Data:        make(map[string]interface{}),
	}, nil
}

// Run creates n number of workers to secret info from found paths
func (s *SecretScraper) Run(path string, wg *sync.WaitGroup, n int) error {
	ctx, cancelFunc := context.WithCancel(context.Background())

	for _, vv := range strings.Split(path, ",") {
		s.find.wg.Add(1)
		go s.secretFinder(ctx, cancelFunc, vv)
	}

	s.secrets.wg.Add(n)
	for i := 0; i != n; i++ {
		go s.secretProducer(ctx, cancelFunc, n)
	}

	// once the secretStream is closed
	// convert the stream into a map
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		for secret := range s.secrets.channel {
			s.Data[secret.path] = secret.data
		}
	}(wg)

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
		results, _ := s.VaultConfig.Client.Logical().List(path)

		if data, ok := vault.ExtractListData(results); !ok {
			// maybe it's leaf node; if not, secretProducer will filter it out
			s.find.secretpath <- strings.Replace(vault.EnsureNoTrailingSlash(path), "metadata", "data", 1)
		} else {
			for _, v := range data {
				newpath := vault.EnsureNoTrailingSlash(path) + "/" + vault.EnsureNoTrailingSlash(v.(string))
				if isDir(v.(string)) {
					s.find.wg.Add(1)
					go s.secretFinder(ctx, cancelFunc, newpath)
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
			ignored := false
			for _, ip := range s.VaultConfig.Ignore.Paths {
				if strings.HasPrefix(path, ip) {
					ignored = true
					break
				}
			}

			for _, ik := range s.VaultConfig.Ignore.Keys {
				if strings.HasSuffix(path, ik) {
					ignored = true
					break
				}
			}

			if !ignored {
				vaultSecret, err := s.VaultConfig.Client.Logical().Read(path)
				if err != nil {
					log.Printf("failed to get secrets in %s, %s\n", path, err.Error())
				}

				// handles case when the path does not have a vault value: No value found at XYZ
				var data interface{}
				if vaultSecret != nil {
					// secret engine v2 has a different response body
					data = vaultSecret.Data["data"]
					if data == nil {
						// secret engine v1
						data = vaultSecret.Data
					}
				}

				if data != nil {
					secret := secret{
						path: path,
						data: data,
					}
					s.secrets.channel <- secret
					log.Println("created secret from:", path)
				} else {
					log.Println("No entries found at:", path)
				}
			}
		}
	}
}
