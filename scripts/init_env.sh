docker-compose down
docker-compose up -d vault
echo waiting...
sleep 10
docker-compose exec vault vault secrets disable secret
docker-compose exec vault vault secrets enable -version=1 -path=/secret kv
echo done