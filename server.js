require("dotenv").config();
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false });
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = process.env.UPLOAD_DIR || "./uploads";
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

app.set("view engine", "ejs");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.use("/uploads", express.static(UPLOAD_DIR));

app.use(session({
  store: new pgSession({ pool, tableName: "user_sessions", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || "dev-secret-change-me",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", maxAge: 8*60*60*1000 }
}));

const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 15*60*1000, limit: 8, standardHeaders: true, legacyHeaders: false });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${path.extname(file.originalname).toLowerCase()}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 5*1024*1024 },
  fileFilter: (_, file, cb) => cb(null, [".pdf",".jpg",".jpeg",".png"].includes(path.extname(file.originalname).toLowerCase()))
});

async function q(text, params=[]) { return (await pool.query(text, params)).rows; }
async function one(text, params=[]) { return (await pool.query(text, params)).rows[0]; }
function applicationNo() { return `MRFI${new Date().getFullYear()}${crypto.randomBytes(3).toString("hex").toUpperCase()}`; }
function hashCode(code) { return crypto.createHash("sha256").update(code).digest("hex"); }
function adminOnly(req,res,next){ if(!req.session.adminId) return res.redirect("/admin/login"); next(); }

async function init() {
  const schema = fs.readFileSync("schema.sql","utf8");
  await pool.query(schema);
  const admin = await one("SELECT id FROM admins WHERE email=$1",[process.env.ADMIN_EMAIL]);
  if(!admin && process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    await pool.query("INSERT INTO admins(email,password_hash) VALUES($1,$2)",[process.env.ADMIN_EMAIL,bcrypt.hashSync(process.env.ADMIN_PASSWORD,12)]);
  }
}
async function sendOtp(phone, code) {
  if ((process.env.OTP_PROVIDER||"demo") === "demo") return { ok:true, demoCode:code };
  // Provider adapter placeholder: POST your approved OTP provider here.
  return { ok:false, error:"OTP provider is not configured." };
}
async function sendWhatsAppText(to, text) {
  if(!process.env.WHATSAPP_CLOUD_TOKEN || !process.env.WHATSAPP_PHONE_NUMBER_ID) return {ok:false, mode:"click-to-chat"};
  const r = await fetch(`https://graph.facebook.com/v20.0/${process.env.WHATSAPP_PHONE_NUMBER_ID}/messages`,{
    method:"POST", headers:{Authorization:`Bearer ${process.env.WHATSAPP_CLOUD_TOKEN}`,"Content-Type":"application/json"},
    body:JSON.stringify({messaging_product:"whatsapp",to,type:"text",text:{body:text}})
  });
  return {ok:r.ok, body:await r.text()};
}
async function verifyDocument(type, value, applicationId) {
  if((process.env.KYC_PROVIDER||"demo")==="demo") {
    return {status:"Submitted", providerRef:`DEMO-${applicationId}-${type}`};
  }
  // Provider adapter placeholder: connect only to an authorized KYC provider.
  return {status:"Pending Verification", providerRef:null};
}

app.get("/", (req,res)=>res.render("home",{wa:process.env.WHATSAPP_NUMBER||"919864445321"}));
app.get("/apply", (req,res)=>res.render("apply",{error:null}));
app.post("/otp/send", otpLimiter, async (req,res)=>{
  const phone=(req.body.phone||"").replace(/\D/g,"");
  if(phone.length<10) return res.status(400).json({ok:false,error:"Enter a valid mobile number."});
  const code=String(crypto.randomInt(100000,999999));
  await pool.query("INSERT INTO otp_codes(phone,code_hash,expires_at) VALUES($1,$2,NOW()+INTERVAL '5 minutes')",[phone,hashCode(code)]);
  const result=await sendOtp(phone,code);
  // In demo mode, return code for testing only.
  res.json({ok:result.ok, demoCode:result.demoCode||undefined, message:result.ok?"OTP sent.":result.error});
});
app.post("/otp/verify", otpLimiter, async (req,res)=>{
  const phone=(req.body.phone||"").replace(/\D/g,""), code=(req.body.code||"").trim();
  const row=await one("SELECT * FROM otp_codes WHERE phone=$1 AND verified_at IS NULL AND expires_at>NOW() ORDER BY id DESC LIMIT 1",[phone]);
  if(!row) return res.status(400).json({ok:false,error:"OTP expired or not found."});
  if(row.attempts>=5) return res.status(429).json({ok:false,error:"Too many attempts."});
  await pool.query("UPDATE otp_codes SET attempts=attempts+1 WHERE id=$1",[row.id]);
  if(hashCode(code)!==row.code_hash) return res.status(400).json({ok:false,error:"Incorrect OTP."});
  await pool.query("UPDATE otp_codes SET verified_at=NOW() WHERE id=$1",[row.id]);
  req.session.verifiedPhone=phone;
  res.json({ok:true});
});

app.post("/apply", upload.single("document"), async (req,res)=>{
  const phone=(req.body.phone||"").replace(/\D/g,"");
  if(req.session.verifiedPhone!==phone) return res.status(400).render("apply",{error:"Please verify your mobile number with OTP first."});
  const {name,email,address,loan_type,amount,employment,monthly_income,message}=req.body;
  if(!name||!phone||!loan_type||!amount) return res.status(400).render("apply",{error:"Required fields are missing."});
  const appNo=applicationNo();
  const doc=req.file?`/uploads/${req.file.filename}`:null;
  const a=await one(`INSERT INTO applications(application_no,name,phone,email,address,loan_type,amount,employment,monthly_income,message,document_path)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id,application_no`,
    [appNo,name,phone,email||"",address||"",loan_type,Number(amount),employment||"",monthly_income?Number(monthly_income):null,message||"",doc]);
  await pool.query("INSERT INTO audit_logs(application_id,actor,action,details) VALUES($1,$2,$3,$4)",[a.id,"customer","application_created",JSON.stringify({loan_type,amount})]);
  const text=`MrFi application ${a.application_no} received. We will contact you regarding the next steps.`;
  await sendWhatsAppText(phone,text);
  res.render("success",{appNo:a.application_no});
});

app.get("/track",(req,res)=>res.render("track",{result:null,error:null}));
app.post("/track",async(req,res)=>{
  const appNo=(req.body.application_no||"").trim().toUpperCase();
  const phone=(req.body.phone||"").replace(/\D/g,"");
  const result=await one("SELECT application_no,name,loan_type,amount,status,video_kyc_status,created_at,updated_at FROM applications WHERE application_no=$1 AND phone=$2",[appNo,phone]);
  res.render("track",{result,error:result?null:"Application not found. Check your application number and mobile number."});
});

app.get("/admin/login",(req,res)=>res.render("login",{error:null}));
app.post("/admin/login",authLimiter,async(req,res)=>{
  const a=await one("SELECT * FROM admins WHERE email=$1",[req.body.email]);
  if(!a||!bcrypt.compareSync(req.body.password||"",a.password_hash)) return res.status(401).render("login",{error:"Invalid email or password."});
  req.session.adminId=a.id; res.redirect("/admin");
});
app.post("/admin/logout",adminOnly,(req,res)=>req.session.destroy(()=>res.redirect("/admin/login")));

app.get("/admin",adminOnly,async(req,res)=>{
  const counts=await one(`SELECT COUNT(*) total,
    COUNT(*) FILTER(WHERE status='New') new_count,
    COUNT(*) FILTER(WHERE status='Under Review') review_count,
    COUNT(*) FILTER(WHERE status='Approved') approved_count,
    COUNT(*) FILTER(WHERE status='Rejected') rejected_count,
    COALESCE(SUM(amount),0) total_amount FROM applications`);
  const monthly=await q(`SELECT TO_CHAR(DATE_TRUNC('month',created_at),'Mon YYYY') month, COUNT(*) applications,
    COALESCE(SUM(amount),0) amount FROM applications WHERE created_at>=NOW()-INTERVAL '6 months'
    GROUP BY DATE_TRUNC('month',created_at) ORDER BY DATE_TRUNC('month',created_at)`);
  const apps=await q("SELECT * FROM applications ORDER BY id DESC LIMIT 200");
  res.render("dashboard",{counts,monthly,apps});
});
app.post("/admin/application/:id/status",adminOnly,async(req,res)=>{
  const allowed=["New","Under Review","Approved","Rejected"];
  if(!allowed.includes(req.body.status)) return res.status(400).send("Invalid status");
  await pool.query("UPDATE applications SET status=$1,updated_at=NOW() WHERE id=$2",[req.body.status,req.params.id]);
  await pool.query("INSERT INTO audit_logs(application_id,actor,action,details) VALUES($1,$2,$3,$4)",[req.params.id,"admin","status_changed",JSON.stringify({status:req.body.status})]);
  res.redirect("/admin");
});
app.post("/admin/application/:id/kyc",adminOnly,async(req,res)=>{
  const link=`${process.env.BASE_URL||"http://localhost:3000"}/video-kyc/${req.params.id}`;
  await pool.query("UPDATE applications SET video_kyc_status='Scheduled',video_kyc_link=$1,updated_at=NOW() WHERE id=$2",[link,req.params.id]);
  res.redirect("/admin");
});
app.post("/admin/application/:id/verify",adminOnly,async(req,res)=>{
  const a=await one("SELECT * FROM applications WHERE id=$1",[req.params.id]);
  if(!a) return res.status(404).send("Not found");
  if(req.body.type==="aadhaar") {
    const r=await verifyDocument("aadhaar",req.body.value,a.id);
    await pool.query("UPDATE applications SET aadhaar_status=$1,kyc_provider_ref=COALESCE($2,kyc_provider_ref),updated_at=NOW() WHERE id=$3",[r.status,r.providerRef,a.id]);
  } else if(req.body.type==="pan") {
    const r=await verifyDocument("pan",req.body.value,a.id);
    await pool.query("UPDATE applications SET pan_status=$1,kyc_provider_ref=COALESCE($2,kyc_provider_ref),updated_at=NOW() WHERE id=$3",[r.status,r.providerRef,a.id]);
  }
  res.redirect("/admin");
});
app.get("/video-kyc/:id",async(req,res)=>{
  const a=await one("SELECT id,name,video_kyc_status,video_kyc_link FROM applications WHERE id=$1",[req.params.id]);
  if(!a) return res.status(404).send("Application not found.");
  const room=`MrFi-KYC-${a.id}`;
  res.render("kyc",{application:a,room});
});

init().then(()=>app.listen(PORT,()=>console.log(`MrFi V3 on ${PORT}`))).catch(err=>{console.error(err);process.exit(1)});
