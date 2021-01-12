package vault

import (
	"strings"
)

// updateIfKVv2 updates the path and secret if the KV engine is version 2
// uses memoization to reduce number of calls to Vault
// this function expects the path to have already been sanitized
func (vc *Config) updateIfKVv2(path string, secret map[string]interface{}) (string, map[string]interface{}, error) {
	var (
		err       error
		mountPath string
		v2        bool
	)

	p := strings.Split(path, "/")
	mount := p[0]

	mp, ok := vc.memo.Load(mount)
	if !ok {
		var version bool
		mountPath, version, err = IsKVv2(path, vc.Client)
		if err != nil {
			return path, secret, err
		}
		vc.memo.Store(mount, version)
		v2 = version
	}

	if mp != nil { // use values stored in memo
		v2 = mp.(bool)
		mountPath = mount + "/"
	}

	if v2 {
		path = AddPrefixToVKVPath(path, mountPath, "data")
		// https://github.com/hashicorp/vault/blob/31ddb809c8e46b2796654f5083cc2ac8b1b3b188/command/kv_put.go#L131
		secret = map[string]interface{}{
			"data":    secret,
			"options": map[string]interface{}{},
		}
	}

	return path, secret, nil
}
