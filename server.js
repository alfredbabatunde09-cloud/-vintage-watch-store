const express = require("express");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, "store.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, order_code TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL,
 phone TEXT NOT NULL, product TEXT NOT NULL, price TEXT, message TEXT,
 status TEXT NOT NULL DEFAULT 'new'
);
CREATE TABLE IF NOT EXISTS chat_messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 session_id TEXT NOT NULL,
 sender TEXT NOT NULL CHECK(sender IN ('customer','admin')),
 name TEXT,
 message TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_session ON chat_messages(session_id, id);
`);

app.use(express.json({limit:"100kb"}));
app.use(express.static(__dirname));

function makeToken(username){
  const payload=Buffer.from(JSON.stringify({username,exp:Date.now()+1000*60*60*8})).toString("base64url");
  const sig=crypto.createHmac("sha256",SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function verifyToken(token){
  if(!token) return null;
  const [payload,sig]=token.split(".");
  if(!payload||!sig) return null;
  const expected=crypto.createHmac("sha256",SESSION_SECRET).update(payload).digest("base64url");
  if(sig.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))) return null;
  try{
    const data=JSON.parse(Buffer.from(payload,"base64url").toString());
    if(data.exp<Date.now()||data.username!==ADMIN_USERNAME) return null;
    return data;
  }catch{return null}
}
function requireAdmin(req,res,next){
  const auth=req.headers.authorization||"";
  const bearer=auth.startsWith("Bearer ")?auth.slice(7):null;
  const data=verifyToken(bearer||req.cookies?.admin_token);
  if(!data) return res.status(401).json({error:"Login required."});
  req.admin=data.username;next();
}

// Tiny cookie parser so no extra dependency is needed.
app.use((req,res,next)=>{
  const raw=req.headers.cookie||"";
  req.cookies={};
  raw.split(";").forEach(part=>{
    const i=part.indexOf("=");
    if(i>0) req.cookies[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());
  });
  next();
});

app.post("/api/admin/login",(req,res)=>{
  const {username,password}=req.body||{};
  if(username!==ADMIN_USERNAME||password!==ADMIN_PASSWORD) return res.status(401).json({error:"Wrong username or password."});
  const token=makeToken(username);
  res.setHeader("Set-Cookie",`admin_token=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800${process.env.NODE_ENV==="production"?"; Secure":""}`);
  res.json({ok:true,token});
});
app.post("/api/admin/logout",(req,res)=>{
  res.setHeader("Set-Cookie","admin_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ok:true});
});

app.post("/api/orders",(req,res)=>{
  const {name,email,phone,product,message,price}=req.body||{};
  if(!name||!email||!phone||!product) return res.status(400).json({error:"Name, email, phone and product are required."});
  const orderCode="ORD-"+Date.now().toString(36).toUpperCase(), createdAt=new Date().toISOString();
  db.prepare(`INSERT INTO orders (order_code,created_at,name,email,phone,product,price,message) VALUES (?,?,?,?,?,?,?,?)`)
    .run(orderCode,createdAt,String(name).slice(0,120),String(email).slice(0,180),String(phone).slice(0,60),String(product).slice(0,120),String(price||"").slice(0,60),String(message||"").slice(0,1000));
  res.status(201).json({ok:true,orderId:orderCode});
});
app.get("/api/orders",requireAdmin,(req,res)=>res.json(db.prepare("SELECT * FROM orders ORDER BY id DESC").all()));
app.patch("/api/orders/:id",requireAdmin,(req,res)=>{
  const allowed=["new","contacted","paid","completed","cancelled"], {status}=req.body||{};
  if(!allowed.includes(status)) return res.status(400).json({error:"Invalid status."});
  const result=db.prepare("UPDATE orders SET status=? WHERE id=?").run(status,req.params.id);
  if(!result.changes) return res.status(404).json({error:"Order not found."});
  res.json({ok:true});
});
app.delete("/api/orders/:id",requireAdmin,(req,res)=>{
  const result=db.prepare("DELETE FROM orders WHERE id=?").run(req.params.id);
  if(!result.changes) return res.status(404).json({error:"Order not found."});
  res.json({ok:true});
});

// ---------------- CUSTOMER CHAT ----------------
const streams = new Set();
function cleanSession(v){return String(v||"").replace(/[^a-zA-Z0-9_-]/g,"").slice(0,80)}
function cleanMessage(v){return String(v||"").trim().slice(0,1000)}
function chatBroadcast(message){
  const payload=`data: ${JSON.stringify(message)}\n\n`;
  for(const s of streams){
    if(s.type==="customer" && s.session_id!==message.session_id) continue;
    try{s.res.write(payload)}catch(_){}
  }
}
function saveChat({session_id,sender,name,message}){
  const created_at=new Date().toISOString();
  const info=db.prepare(`INSERT INTO chat_messages(session_id,sender,name,message,created_at) VALUES(?,?,?,?,?)`)
    .run(session_id,sender,name||"",message,created_at);
  const row={id:Number(info.lastInsertRowid),session_id,sender,name:name||"",message,created_at};
  chatBroadcast(row);return row;
}

app.get("/api/chat/messages",(req,res)=>{
  const session_id=cleanSession(req.query.session_id);
  if(!session_id)return res.status(400).json({error:"session_id required"});
  res.json({messages:db.prepare("SELECT * FROM chat_messages WHERE session_id=? ORDER BY id ASC").all(session_id)});
});
app.post("/api/chat/messages",(req,res)=>{
  const session_id=cleanSession(req.body?.session_id);
  const name=String(req.body?.name||"Visitor").slice(0,80);
  const message=cleanMessage(req.body?.message);
  if(!session_id||!message)return res.status(400).json({error:"Message required."});
  const row=saveChat({session_id,sender:"customer",name,message});
  res.status(201).json({ok:true,message:row});
});
app.get("/api/chat/stream",(req,res)=>{
  const session_id=cleanSession(req.query.session_id);
  if(!session_id)return res.status(400).end();
  res.setHeader("Content-Type","text/event-stream");
  res.setHeader("Cache-Control","no-cache");
  res.setHeader("Connection","keep-alive");
  res.flushHeaders?.();
  res.write(": connected\n\n");
  const stream={res,type:"customer",session_id};streams.add(stream);
  req.on("close",()=>streams.delete(stream));
});

// Admin chat list and reply endpoints are protected.
app.get("/api/admin/chats",requireAdmin,(req,res)=>{
  const chats=db.prepare(`
    SELECT c.session_id,c.name,c.message AS last_message,c.created_at
    FROM chat_messages c
    INNER JOIN (SELECT session_id,MAX(id) max_id FROM chat_messages GROUP BY session_id) x
    ON c.id=x.max_id ORDER BY c.id DESC
  `).all();
  res.json({chats});
});
app.get("/api/admin/chats/:session_id",requireAdmin,(req,res)=>{
  const session_id=cleanSession(req.params.session_id);
  res.json({messages:db.prepare("SELECT * FROM chat_messages WHERE session_id=? ORDER BY id ASC").all(session_id)});
});
app.post("/api/admin/chats/:session_id/reply",requireAdmin,(req,res)=>{
  const session_id=cleanSession(req.params.session_id);
  const message=cleanMessage(req.body?.message);
  if(!message)return res.status(400).json({error:"Message required."});
  const row=saveChat({session_id,sender:"admin",name:ADMIN_USERNAME,message});
  res.status(201).json({ok:true,message:row});
});
app.get("/api/admin/chat-stream",requireAdmin,(req,res)=>{
  res.setHeader("Content-Type","text/event-stream");
  res.setHeader("Cache-Control","no-cache");
  res.setHeader("Connection","keep-alive");
  res.flushHeaders?.();
  res.write(": connected\n\n");
  const stream={res,type:"admin"};streams.add(stream);
  req.on("close",()=>streams.delete(stream));
});

app.get("/health",(req,res)=>res.json({ok:true}));
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"admin.html")));
app.get("/admin-chat",(req,res)=>res.sendFile(path.join(__dirname,"admin-chat.html")));

// Express 5 compatible catch-all.
app.get("/{*splat}",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));

app.listen(PORT,()=>console.log(`VINTAGE Watch Store running on port ${PORT}`));
