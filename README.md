# go-vault-dump
Dump all keys for vault. Use case figure out who is sharing credentials in an organization

## Getting Started
To spin up a local insecure Vault, first set `VAULT_DEV_ROOT_TOKEN_ID` to a value [here](./docker-compose.yml#L12)
You can then execute the following with that value: `go run ./cmd/vault-dump/main.go --vault-addr http://localhost:8200 --vault-token= --debug /secret`

## Usage
```
SECRET_NAME=$(kubectl -n $K8S_NAMESPACE get serviceaccount default -o jsonpath='{.secrets[0].name}')
	kubectl get secret $SECRET_NAME -o jsonpath='{.data.token}' -n $K8S_NAMESPACE | base64 --decode > /tmp/k8s-token
	export VAULT_TOKEN=` + "`vault write auth/$K8S_CLUSTER/login role=$K8S_NAMESPACE-role jwt=@/tmp/k8s-token | sed -n '3 p' | awk '{print $2}'`" + `
	echo -n $VAULT_TOKEN > /tmp/vault-token
	vault login token=$VAULT_TOKEN
	kubectl config set-context $CCONTEXT --namespace=$K8S_NAMESPACE
	./%s [start key path]
```

## [pkg/vault](./pkg/vault)
This stores various helper funcs from [Vault](https://github.com/hashicorp/vault/tree/master/command) which are not exported nor easy to use from it's original location.
