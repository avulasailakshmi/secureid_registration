# SecureID — Part 1 Registration Journey

## Run locally
1. Install Node.js 18+
2. Run `npm install`
3. Run `npm start`
4. Open http://localhost:3000

## OTP testing
Email and SMS OTPs are generated only on the backend and printed to the server terminal.
Enter those six-digit values in the browser.

For the demo authenticator screen, use: `624111`.

## Implemented
Registration form, email OTP, wrong/expired states, SMS OTP, wrong/max-attempt states,
MFA selection, authenticator setup/verification, success screen, responsive mobile/web UI.

## Deployment
Push this folder to GitHub and import the repository into Vercel.
