package vault

import vaultapi "github.com/hashicorp/vault/api"

// updateIfKVv2 updates the path and secret if the KV engine is version 2
func updateIfKVv2(c *vaultapi.Client, path string, secret map[string]interface{}) (string, map[string]interface{}, error) {
	mountPath, v2, err := IsKVv2(path, c)
	if err != nil {
		return path, secret, err
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
