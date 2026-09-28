const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || "secureid-assignment-secret-change-me",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 30 * 60 * 1000 }
}));

const users = new Map();
const challenges = new Map();
const mfaChallenges = new Map();
const loginChallenges = new Map();
const id = () => crypto.randomUUID();
const otp = () => String(Math.floor(100000 + Math.random() * 900000));
const hashOtp = value => crypto.createHash("sha256").update(String(value)).digest("hex");
const JWT_SECRET = process.env.JWT_SECRET || "secureid-jwt-assignment-secret-change-me";
const LOCK_AFTER = 3;
const LOCK_MS = 60 * 1000;

function createChallenge(userId, channel) {
  const challengeId = id(), code = otp();
  challenges.set(challengeId,{challengeId,userId,channel,otpHash:hashOtp(code),expiresAt:Date.now()+3*60*1000,attempts:0,used:false});
  console.log(`\n[SIMULATED ${channel.toUpperCase()}]\nUser: ${userId}\nOTP: ${code}\n`);
  return challengeId;
}
function verifyChallenge(challengeId, code, channel) {
  const c=challenges.get(challengeId);
  if(!c||c.channel!==channel||c.used)return {ok:false,status:400,error:"Invalid challenge."};
  if(Date.now()>c.expiresAt)return {ok:false,status:410,error:"This code has expired.",expired:true};
  if(c.attempts>=3)return {ok:false,status:429,error:"Maximum attempts reached.",maxAttempts:true};
  if(hashOtp(code)!==c.otpHash){c.attempts++;if(c.attempts>=3)return {ok:false,status:429,error:"Maximum attempts reached.",maxAttempts:true};return {ok:false,status:400,error:"Incorrect code. Please try again.",attemptsLeft:3-c.attempts};}
  c.used=true; return {ok:true,challenge:c};
}
function createLoginChallenge(user, method){
  const challengeId=id(), code=otp();
  loginChallenges.set(challengeId,{challengeId,userId:user.id,method,otpHash:hashOtp(code),expiresAt:Date.now()+3*60*1000,attempts:0,used:false});
  console.log(`\n[SIMULATED LOGIN MFA - ${method.toUpperCase()}]\nUser: ${user.email}\nOTP: ${code}\n`);
  return challengeId;
}
function publicUser(u){return {id:u.id,fullName:u.fullName,email:u.email,mobile:`${u.countryCode} ${u.mobile}`,mfaEnabled:u.mfaEnabled,mfaMethod:u.mfaMethod};}

app.post("/api/register",async(req,res)=>{
  const {fullName,email,countryCode,mobile,password,terms}=req.body;
  if(!fullName||!email||!mobile||!password||!terms)return res.status(400).json({error:"Please complete all required fields."});
  if(password.length<8||!/[A-Z]/.test(password)||!/\d/.test(password)||!/[^A-Za-z0-9]/.test(password))return res.status(400).json({error:"Password does not meet the minimum requirements."});
  const normalized=email.trim().toLowerCase();
  if(users.has(normalized))return res.status(409).json({error:"An account with this email already exists."});
  users.set(normalized,{id:normalized,fullName,email:normalized,countryCode:countryCode||"+91",mobile,passwordHash:await bcrypt.hash(password,10),emailVerified:false,mobileVerified:false,mfaEnabled:false,mfaMethod:null,failedLogins:0,lockedUntil:0});
  res.json({challengeId:createChallenge(normalized,"email"),method:"email",masked:normalized});
});
app.post("/api/send-email-otp",(req,res)=>{const u=users.get(req.body.email?.toLowerCase());if(!u)return res.status(404).json({error:"User not found."});res.json({challengeId:createChallenge(u.id,"email")});});
app.post("/api/verify-email-otp",(req,res)=>{const r=verifyChallenge(req.body.challengeId,req.body.otp,"email");if(!r.ok)return res.status(r.status).json(r);const u=users.get(r.challenge.userId);u.emailVerified=true;res.json({verified:true,challengeId:createChallenge(u.id,"sms"),masked:`${u.countryCode} ${u.mobile}`});});
app.post("/api/send-sms-otp",(req,res)=>{const u=users.get(req.body.email?.toLowerCase());if(!u||!u.emailVerified)return res.status(400).json({error:"Email verification is required first."});res.json({challengeId:createChallenge(u.id,"sms")});});
app.post("/api/verify-sms-otp",(req,res)=>{const r=verifyChallenge(req.body.challengeId,req.body.otp,"sms");if(!r.ok)return res.status(r.status).json(r);users.get(r.challenge.userId).mobileVerified=true;res.json({verified:true});});
app.post("/api/setup-mfa",(req,res)=>{const u=users.get(req.body.email?.toLowerCase()),method=req.body.method;if(!u||!u.emailVerified||!u.mobileVerified)return res.status(400).json({error:"Complete email and mobile verification first."});if(!["authenticator","sms","email"].includes(method))return res.status(400).json({error:"Choose a valid MFA method."});const challengeId=id(),code=otp();mfaChallenges.set(challengeId,{userId:u.id,method,otpHash:hashOtp(code),expiresAt:Date.now()+3*60*1000,attempts:0,used:false});console.log(`\n[SIMULATED MFA - ${method.toUpperCase()}]\nUser: ${u.id}\nOTP: ${code}\n`);res.json({challengeId,method,setupKey:method==="authenticator"?"SECUREID-DEMO-KEY":undefined});});
app.post("/api/verify-mfa",(req,res)=>{const c=mfaChallenges.get(req.body.challengeId);if(!c||c.used)return res.status(400).json({error:"Invalid MFA challenge."});if(Date.now()>c.expiresAt)return res.status(410).json({error:"This code has expired."});if(c.attempts>=3)return res.status(429).json({error:"Maximum attempts reached."});if(hashOtp(req.body.otp)!==c.otpHash){c.attempts++;return res.status(c.attempts>=3?429:400).json({error:c.attempts>=3?"Maximum attempts reached.":"Invalid code. Please try again.",attemptsLeft:Math.max(0,3-c.attempts)});}c.used=true;const u=users.get(c.userId);u.mfaEnabled=true;u.mfaMethod=c.method;res.json({success:true,mfaEnabled:true});});

// Part 2 — Login Journey
app.post("/api/login",async(req,res)=>{
  const email=(req.body.email||"").trim().toLowerCase(),password=req.body.password||"";
  const u=users.get(email);
  // Generic response avoids revealing whether an account exists.
  if(!u)return res.status(401).json({error:"Invalid email or password. Please try again."});
  if(u.lockedUntil>Date.now())return res.status(423).json({error:"Account temporarily locked due to failed login attempts.",locked:true,retryAfter:Math.ceil((u.lockedUntil-Date.now())/1000)});
  if(!(await bcrypt.compare(password,u.passwordHash))){
    u.failedLogins=(u.failedLogins||0)+1;
    if(u.failedLogins>=LOCK_AFTER){u.lockedUntil=Date.now()+LOCK_MS;u.failedLogins=0;return res.status(423).json({error:"Account temporarily locked due to failed login attempts.",locked:true,retryAfter:60});}
    return res.status(401).json({error:"Invalid email or password. Please try again.",attemptsLeft:LOCK_AFTER-u.failedLogins});
  }
  u.failedLogins=0;u.lockedUntil=0;
  if(!u.mfaEnabled){req.session.userId=u.id;return res.json({authenticated:true,mfaRequired:false,user:publicUser(u)});}
  // Let frontend display the method chooser. No authenticated session exists yet.
  res.json({authenticated:false,mfaRequired:true,availableMethods:["email","sms","authenticator"],preferredMethod:u.mfaMethod||"email"});
});
app.post("/api/send-login-otp",(req,res)=>{
  const email=(req.body.email||"").trim().toLowerCase(),method=req.body.method;
  const u=users.get(email);
  if(!u||!u.mfaEnabled)return res.status(400).json({error:"Unable to start MFA verification."});
  if(!["email","sms","authenticator"].includes(method))return res.status(400).json({error:"Choose a valid verification method."});
  const challengeId=createLoginChallenge(u,method);
  res.json({challengeId,method,masked:method==="email"?u.email:`${u.countryCode} ${u.mobile}`,expiresIn:180});
});
app.post("/api/verify-login-otp",(req,res)=>{
  const c=loginChallenges.get(req.body.challengeId);
  if(!c||c.used)return res.status(400).json({error:"Invalid login challenge."});
  if(Date.now()>c.expiresAt)return res.status(410).json({error:"Code expired.",expired:true});
  if(c.attempts>=3)return res.status(429).json({error:"Maximum attempts reached.",maxAttempts:true});
  if(hashOtp(req.body.otp)!==c.otpHash){c.attempts++;if(c.attempts>=3)return res.status(429).json({error:"Maximum attempts reached.",maxAttempts:true});return res.status(400).json({error:"Incorrect code. Please try again.",attemptsLeft:3-c.attempts});}
  c.used=true;req.session.userId=c.userId;
  if(req.body.rememberMe)req.session.cookie.maxAge=7*24*60*60*1000;
  res.json({authenticated:true,user:publicUser(users.get(c.userId))});
});
app.get("/api/me",(req,res)=>{if(!req.session.userId)return res.status(401).json({error:"Not authenticated."});const u=users.get(req.session.userId);if(!u)return res.status(401).json({error:"Not authenticated."});res.json({user:publicUser(u)});});
app.post("/api/logout",(req,res)=>{req.session.destroy(err=>{if(err)return res.status(500).json({error:"Could not log out."});res.clearCookie("connect.sid");res.json({success:true});});});
app.post("/api/token",async(req,res)=>{
  const email=(req.body.email||"").trim().toLowerCase(),u=users.get(email);
  if(!u||!(await bcrypt.compare(req.body.password||"",u.passwordHash)))return res.status(401).json({error:"Invalid credentials."});
  const token=jwt.sign({sub:u.id,email:u.email},JWT_SECRET,{expiresIn:"10m"});
  res.json({token,tokenType:"Bearer",expiresIn:600});
});
app.get("/api/protected",(req,res)=>{const h=req.headers.authorization||"";if(!h.startsWith("Bearer "))return res.status(401).json({error:"Bearer token required."});try{const p=jwt.verify(h.slice(7),JWT_SECRET);res.json({message:"Protected API access granted.",user:{id:p.sub,email:p.email}});}catch{return res.status(401).json({error:"Invalid or expired token."});}});

app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
const port=process.env.PORT||3000;
app.listen(port,()=>console.log(`SecureID running at http://localhost:${port}`));
