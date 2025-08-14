INSTALACIÓN
npm install
npm start

<!-- registrar usuario -->
curl -s -X POST http://localhost:8080/register -H "Content-Type: application/json" -d '{"username":"amilcar","password":"Pass1234"}'

<!-- inicio de sesión -->
curl -s -X POST http://localhost:8080/login -H "Content-Type: application/json" -d '{"username":"amilcar","password":"Pass1234"}'

<!-- consulta a ruta protegida por token -->
curl -s -H "Authorization: Bearer TOKEN" http://localhost:8080/me

<!-- logout -->
curl -s -X POST http://localhost:8080/logout -H "Authorization: Bearer TOKEN"
