# vault-dump

vault-dump is an export/import tool for HashiCorp Vault deployments; its goal is to provide secure, managed disaster preparedness for vault data, allowing system administrators to easily backup and restore critical vault data. vault-dump communicates directly with a vault via its API, and uses standard AWS workflows to encrypt and store exported data in S3. 

## Command Reference

```
  [dump]      Export vault secrets locally or to S3
  import      Import vault secrets
  purge       Recursively delete one or more paths from vault
  list        Lists vault exports in an S3 bucket
  help        Get help about any command
```

### dump

Downloads the contents of a vault, and stores the data in an encrypted state file in S3.

```
Usage:
  vault-dump [flags] /path[,path,...]
  
Options:
      --config string          config file (default is $HOME/.vault-dump/config.yaml)
  -d, --dest string            output directory or S3 path
  -e, --encoding string        encoding type [json, yaml] (default "json")
  -f, --filename string        output filename (.json or .yaml extension will be added) (default "vault-dump")
      --ignore-keys strings    comma separated list of key names to ignore
      --ignore-paths strings   comma separated list of paths to ignore
      --kms-key string         KMS encryption key ARN (required for S3 uploads)
  -k, --kubeconfig string      location of kube config file
  -o, --output string          output type, [stdout, file, s3] (default "file")
      --vault-addr string      vault url (default "https://127.0.0.1:8200")
      --vault-token string     vault token
```


### import

Downloads a vault state file from S3, and imports the contents into a vault.

```
Usage:
  vault-dump import [flags] <filename>

Options:
      --brute   retry failed indefinitely
      --ignore-keys strings    comma separated list of key names to ignore
      --ignore-paths strings   comma separated list of paths to ignore
      --vault-addr string      vault url (default "https://127.0.0.1:8200")
      --vault-token string     vault token
```


### purge

Deletes the contents of a vault.

**DANGER ZONE** -- _This is a destructive command; even when used with `--force` to disable the confirmation prompt, `purge` will impose a brief sanity-check pause before executing._

```
Usage:
  vault-dump purge [flags] /vault/path[,path,...]

Options:
      --force   Skip confirmation prompt
      --vault-addr string      vault url (default "https://127.0.0.1:8200")
      --vault-token string     vault token
```


### list

Lists vault state files in a bucket matching a given prefix

```
Usage:
  vault-dump list s3://<bucket>/[path] [flags]
```

## Development Quickstart

To bootstrap a local development environment with a local vault and mocked S3/KMS services, run:
```
./scripts/init_env.sh
```

To configure your shell for local services, run: 
```
export VAULT_DUMP_VAULT_ADDR=http://localhost:8200 VAULT_DUMP_VAULT_TOKEN=Test_123 \
       AWS_ENDPOINT=http://localhost:4566 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
```

And to test S3 export/import, generate and store a local mock KMS key:
```
export VAULT_DUMP_KMS_KEY=$(docker-compose exec localstack aws --endpoint-url=http://localhost:4566 --region=us-east-1 kms create-key | jq .KeyMetadata.Arn -rj)
```

The development entrypoint for vault-dump is `go run main.go`, eg:
```
go run main.go --help
go run main.go /secret
go run main.go list s3://test/
```

For direct manual interaction with vault (eg to add some test secrets), run `docker-compose exec vault sh` to get a properly configured shell in the vault container.

A few tests are referenced in `scripts/run_tests.sh`, but coverage is currently far from complete. The export commands in that file may be useful for configuring
