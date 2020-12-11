
ssh root@9.30.51.119
dlv debug --headless --listen ":2345" --log --api-version 2 -- server

openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr

openssl req -noout -text -in domain.csr


