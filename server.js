import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pg from "pg";

dotenv.config();
const { Pool } = pg;
const app = express();
app.use(express.static('public'));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized:false } : false });

app.use(helmet({ contentSecurityPolicy:false }));
app.use(express.json({limit:"100kb"}));
app.use(cookieParser());
app.use(rateLimit({windowMs:15*60*1000,max:300}));
app.use(express.static(path.join(__dirname,"../public")));

const sign = u => jwt.sign({id:u.id,role:u.role,username:u.username}, process.env.JWT_SECRET, {expiresIn:"8h"});
const auth = (req,res,next) => {
  try {
    const token=req.cookies.gmes_token || (req.headers.authorization||"").replace("Bearer ","");
    if(!token) return res.status(401).json({error:"Login required"});
    req.user=jwt.verify(token,process.env.JWT_SECRET); next();
  } catch { return res.status(401).json({error:"Invalid or expired session"}); }
};
const adminOnly=(req,res,next)=>req.user?.role==="admin"?next():res.status(403).json({error:"Admin access required"});

app.post("/api/login", async (req,res)=>{
  const {username,password}=req.body||{};
  if(!username||!password) return res.status(400).json({error:"Username and password required"});
  const r=await pool.query("SELECT id,username,password_hash,role FROM users WHERE username=$1",[username.trim()]);
  if(!r.rowCount || !(await bcrypt.compare(password,r.rows[0].password_hash))) return res.status(401).json({error:"Invalid credentials"});
  res.cookie("gmes_token",sign(r.rows[0]),{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",maxAge:8*60*60*1000});
  res.json({role:r.rows[0].role,username:r.rows[0].username});
});
app.post("/api/logout",(req,res)=>{res.clearCookie("gmes_token");res.json({ok:true})});
app.get("/api/me",auth,(req,res)=>res.json(req.user));

app.get("/api/admin/summary",auth,adminOnly,async(req,res)=>{
  const q=await pool.query(`
    SELECT
    (SELECT COUNT(*) FROM students) students,
    (SELECT COUNT(*) FROM staff) staff,
    (SELECT COALESCE(SUM(amount),0) FROM fee_payments) fee_collected,
    (SELECT COALESCE(SUM(annual_fee),0) FROM students) annual_fee,
    (SELECT COALESCE(SUM(amount),0) FROM salary_payments) salary_paid,
    (SELECT COALESCE(SUM(amount),0) FROM expenses) expenses`);
  const x=q.rows[0];
  res.json({...x,fee_due:Number(x.annual_fee)-Number(x.fee_collected),balance:Number(x.fee_collected)-Number(x.salary_paid)-Number(x.expenses)});
});

app.get("/api/students",auth,async(req,res)=>{
  if(req.user.role==="student"){
    const r=await pool.query(`SELECT s.student_id,s.name,s.class_name,s.section,s.parent_name,s.phone,s.annual_fee,
      COALESCE((SELECT SUM(amount) FROM fee_payments f WHERE f.student_id=s.id),0) paid
      FROM students s JOIN users u ON u.id=s.user_id WHERE u.id=$1`,[req.user.id]);
    return res.json(r.rows);
  }
  if(req.user.role!=="admin") return res.status(403).json({error:"Not allowed"});
  const r=await pool.query(`SELECT s.student_id,s.name,s.class_name,s.section,s.parent_name,s.phone,s.annual_fee,
    COALESCE(SUM(f.amount),0) paid, s.annual_fee-COALESCE(SUM(f.amount),0) due
    FROM students s LEFT JOIN fee_payments f ON f.student_id=s.id GROUP BY s.id ORDER BY s.id DESC`);
  res.json(r.rows);
});
app.get("/api/staff",auth,async(req,res)=>{
  if(req.user.role==="staff"){
    const r=await pool.query(`SELECT s.staff_id,s.name,s.role_title,s.phone,s.monthly_salary FROM staff s WHERE s.user_id=$1`,[req.user.id]); return res.json(r.rows);
  }
  if(req.user.role!=="admin") return res.status(403).json({error:"Not allowed"});
  const r=await pool.query(`SELECT staff_id,name,role_title,phone,monthly_salary FROM staff ORDER BY id DESC`);res.json(r.rows);
});

app.post("/api/admin/students",auth,adminOnly,async(req,res)=>{
  const b=req.body||{}; if(!b.name||!b.student_id||!b.class_name||!b.username||!b.password) return res.status(400).json({error:"Required student fields missing"});
  const c=await pool.connect();
  try{await c.query("BEGIN"); const ph=await bcrypt.hash(b.password,12);
    const u=await c.query("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'student') RETURNING id",[b.username.trim(),ph]);
    const s=await c.query(`INSERT INTO students(user_id,student_id,name,class_name,section,parent_name,phone,annual_fee)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[u.rows[0].id,b.student_id,b.name,b.class_name,b.section||null,b.parent_name||null,b.phone||null,Number(b.annual_fee||0)]);
    await c.query("COMMIT");res.json(s.rows[0]);
  }catch(e){await c.query("ROLLBACK");res.status(400).json({error:e.code==="23505"?"Username or Student ID already exists":"Could not create student"});}finally{c.release();}
});
app.post("/api/admin/staff",auth,adminOnly,async(req,res)=>{
  const b=req.body||{};if(!b.name||!b.staff_id||!b.username||!b.password)return res.status(400).json({error:"Required staff fields missing"});
  const c=await pool.connect();
  try{await c.query("BEGIN");const ph=await bcrypt.hash(b.password,12);
    const u=await c.query("INSERT INTO users(username,password_hash,role) VALUES($1,$2,'staff') RETURNING id",[b.username.trim(),ph]);
    const s=await c.query(`INSERT INTO staff(user_id,staff_id,name,role_title,phone,monthly_salary) VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [u.rows[0].id,b.staff_id,b.name,b.role_title||null,b.phone||null,Number(b.monthly_salary||0)]);
    await c.query("COMMIT");res.json(s.rows[0]);
  }catch(e){await c.query("ROLLBACK");res.status(400).json({error:e.code==="23505"?"Username or Staff ID already exists":"Could not create staff"});}finally{c.release();}
});
app.post("/api/admin/fees",auth,adminOnly,async(req,res)=>{
  const b=req.body||{},n=Number(b.amount);if(!b.student_id||n<=0)return res.status(400).json({error:"Invalid payment"});
  const receipt="GMES-"+Date.now();
  const r=await pool.query("INSERT INTO fee_payments(student_id,amount,payment_date,receipt_no,note) VALUES($1,$2,$3,$4,$5) RETURNING *",[b.student_id,n,b.payment_date||new Date(),receipt,b.note||null]);res.json(r.rows[0]);
});
app.post("/api/admin/salaries",auth,adminOnly,async(req,res)=>{
  const n=Number(req.body.amount);if(!req.body.staff_id||n<=0)return res.status(400).json({error:"Invalid salary payment"});
  const r=await pool.query("INSERT INTO salary_payments(staff_id,amount,payment_date,note) VALUES($1,$2,$3,$4) RETURNING *",[req.body.staff_id,n,req.body.payment_date||new Date(),req.body.note||null]);res.json(r.rows[0]);
});
app.post("/api/admin/expenses",auth,adminOnly,async(req,res)=>{
  const n=Number(req.body.amount);if(!req.body.title||n<=0)return res.status(400).json({error:"Invalid expense"});
  const r=await pool.query("INSERT INTO expenses(title,amount,expense_date,note) VALUES($1,$2,$3,$4) RETURNING *",[req.body.title,n,req.body.expense_date||new Date(),req.body.note||null]);res.json(r.rows[0]);
});
app.get("/api/admin/transactions",auth,adminOnly,async(req,res)=>{
  const [f,s,e]=await Promise.all([
    pool.query("SELECT f.payment_date,f.receipt_no,s.name student,f.amount FROM fee_payments f JOIN students s ON s.id=f.student_id ORDER BY f.payment_date DESC"),
    pool.query("SELECT p.payment_date,s.name staff,p.amount FROM salary_payments p JOIN staff s ON s.id=p.staff_id ORDER BY p.payment_date DESC"),
    pool.query("SELECT expense_date,title,amount FROM expenses ORDER BY expense_date DESC")]);
  res.json({fees:f.rows,salaries:s.rows,expenses:e.rows});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"../public/index.html")));
app.listen(process.env.PORT||3000,()=>console.log("GMES server running"));
