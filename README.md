# Instalación y uso

## Instalación
```bash
npm install
npm start


curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"username":"amilcar","password":"Pass1234"}'

curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"amilcar","password":"Pass1234"}'

curl -s -H "Authorization: Bearer TOKEN" \
  http://localhost:8080/me


curl -s -X POST http://localhost:8080/logout \
  -H "Authorization: Bearer TOKEN"
