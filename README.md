# SecureID — Part 1 Registration Journey

Implemented against the supplied Registration Screens and Implementation Guidelines.

Included:
- Registration form with backend validation and bcrypt password hashing
- Email OTP: backend generation, protected hash storage, expiry, attempts, single-use, resend
- SMS OTP: backend generation, protected hash storage, expiry, attempts, single-use, resend
- MFA setup and backend verification (simulated delivery logged to server console)
- Registration success state
- Responsive web/mobile presentation

## Run
```bash
npm install
npm start
```
Open http://localhost:3000.

## Important assignment note
The later "Password Enhancement" (Weak / Medium / Strong strength indicator and minimum-strength frontend blocking) is intentionally NOT pre-implemented here. The assignment explicitly instructs the candidate to proceed only after Internshala admin confirmation and to implement that change by LIVE CODING without AI in the submission video. The baseline show/hide password control remains present because it is already shown in the supplied registration reference screen.
