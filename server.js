
const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || "secureid-assignment-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production" }
}));

const users = new Map();
const challenges = new Map();
const mfaChallenges = new Map();

const id = () => crypto.randomUUID();
const otp = () => String(Math.floor(100000 + Math.random() * 900000));
const hashOtp = value => crypto.createHash("sha256").update(value).digest("hex");

function createChallenge(userId, channel) {
  const challengeId = id();
  const code = otp();
  challenges.set(challengeId, {
    challengeId, userId, channel, otpHash: hashOtp(code),
    expiresAt: Date.now() + 3 * 60 * 1000, attempts: 0, used: false
  });
  console.log(`\n[SIMULATED ${channel.toUpperCase()}]\nUser: ${userId}\nOTP: ${code}\n`);
  return challengeId;
}
function verifyChallenge(challengeId, code, channel) {
  const c = challenges.get(challengeId);
  if (!c || c.channel !== channel || c.used) return { ok:false, status:400, error:"Invalid challenge." };
  if (Date.now() > c.expiresAt) return { ok:false, status:410, error:"This code has expired.", expired:true };
  if (c.attempts >= 3) return { ok:false, status:429, error:"Maximum attempts reached.", maxAttempts:true };
  if (hashOtp(String(code)) !== c.otpHash) {
    c.attempts++;
    if (c.attempts >= 3) return { ok:false, status:429, error:"Maximum attempts reached.", maxAttempts:true };
    return { ok:false, status:400, error:"Incorrect code. Please try again.", attemptsLeft:3-c.attempts };
  }
  c.used = true;
  return { ok:true, challenge:c };
}

app.post("/api/register", async (req,res) => {
  const {fullName,email,countryCode,mobile,password,terms} = req.body;
  if (!fullName || !email || !mobile || !password || !terms) return res.status(400).json({error:"Please complete all required fields."});
  if (password.length < 8 || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z0-9]/.test(password))
    return res.status(400).json({error:"Password does not meet the minimum requirements."});
  const normalized = email.trim().toLowerCase();
  if (users.has(normalized)) return res.status(409).json({error:"An account with this email already exists."});
  users.set(normalized, {
    id: normalized, fullName, email: normalized, countryCode: countryCode || "+91", mobile,
    passwordHash: await bcrypt.hash(password, 10), emailVerified:false, mobileVerified:false, mfaEnabled:false
  });
  const challengeId = createChallenge(normalized, "email");
  res.json({challengeId, method:"email", masked:normalized});
});

app.post("/api/send-email-otp", (req,res) => {
  const user = users.get(req.body.email?.toLowerCase());
  if (!user) return res.status(404).json({error:"User not found."});
  res.json({challengeId:createChallenge(user.id,"email")});
});
app.post("/api/verify-email-otp", (req,res) => {
  const result = verifyChallenge(req.body.challengeId, req.body.otp, "email");
  if (!result.ok) return res.status(result.status).json(result);
  const user = users.get(result.challenge.userId); user.emailVerified = true;
  const challengeId = createChallenge(user.id, "sms");
  res.json({verified:true, challengeId, masked:`${user.countryCode} ${user.mobile}`});
});
app.post("/api/send-sms-otp", (req,res) => {
  const user = users.get(req.body.email?.toLowerCase());
  if (!user || !user.emailVerified) return res.status(400).json({error:"Email verification is required first."});
  res.json({challengeId:createChallenge(user.id,"sms")});
});
app.post("/api/verify-sms-otp", (req,res) => {
  const result = verifyChallenge(req.body.challengeId, req.body.otp, "sms");
  if (!result.ok) return res.status(result.status).json(result);
  const user = users.get(result.challenge.userId); user.mobileVerified = true;
  res.json({verified:true});
});
app.post("/api/setup-mfa", (req,res) => {
  const user = users.get(req.body.email?.toLowerCase());
  const method = req.body.method;
  if (!user || !user.emailVerified || !user.mobileVerified) return res.status(400).json({error:"Complete email and mobile verification first."});
  if (!["authenticator","sms","email"].includes(method)) return res.status(400).json({error:"Choose a valid MFA method."});
  const challengeId = id();
  const code = otp();
  mfaChallenges.set(challengeId,{userId:user.id,method,otpHash:hashOtp(code),expiresAt:Date.now()+3*60*1000,attempts:0,used:false});
  console.log(`\n[SIMULATED MFA - ${method.toUpperCase()}]\nUser: ${user.id}\nOTP: ${code}\n`);
  res.json({challengeId,method,setupKey:method === "authenticator" ? "SECUREID-DEMO-KEY" : undefined});
});
app.post("/api/verify-mfa", (req,res) => {
  const c = mfaChallenges.get(req.body.challengeId);
  if (!c || c.used) return res.status(400).json({error:"Invalid MFA challenge."});
  if (Date.now() > c.expiresAt) return res.status(410).json({error:"This code has expired."});
  if (c.attempts >= 3) return res.status(429).json({error:"Maximum attempts reached."});
  if (hashOtp(String(req.body.otp)) !== c.otpHash) {
    c.attempts++;
    return res.status(c.attempts >= 3 ? 429 : 400).json({error:c.attempts >= 3 ? "Maximum attempts reached." : "Invalid code. Please try again.", attemptsLeft:Math.max(0,3-c.attempts)});
  }
  c.used = true;
  const user = users.get(c.userId);
  user.mfaEnabled = true;
  user.mfaMethod = c.method;
  res.json({success:true,mfaEnabled:true});
});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port = process.env.PORT || 3000;
app.listen(port,()=>console.log(`SecureID running at http://localhost:${port}`));
