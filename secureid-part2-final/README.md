# SecureID — Registration + Login Journey

Implements the supplied IAM assignment using HTML, CSS, JavaScript and Node.js/Express.

## Part 1
Registration → Email OTP → SMS OTP → MFA setup → Registration success.

## Part 2
Login → credential validation → MFA method selection → login OTP → authenticated server session → dashboard.

Backend also implements failed-login attempts and temporary lockout, `GET /api/me`, `POST /api/logout`, `POST /api/token`, and JWT-protected `GET /api/protected`. OTPs are generated and verified on the backend, stored only as hashes, expire, have attempt limits, and are simulated via the server console. Authentication tokens are not stored in localStorage.

## Run
```bash
npm install
npm start
```
Open `http://localhost:3000`.
