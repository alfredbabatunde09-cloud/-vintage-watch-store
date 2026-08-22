const express = require("express");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, "store.db"));
db.pragma("journal_mode = WAL");

db.exec(`
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_code TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT NOT NULL,
  product TEXT NOT NULL,
  price TEXT,
  message TEXT,
  status TEXT DEFAULT 'new'
);
`);

app.use(express.json());
app.use(express.static(__dirname));

function makeToken(username) {
  const payload = Buffer.from(JSON.stringify({
    username,
    exp: Date.now() + 8 * 60 * 60 * 1000
  })).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Login required" });
  }

  const parts = auth.substring(7).split(".");
  if (parts.length !== 2) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const [payload, signature] = parts;

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  if (signature !== expected) {
    return res.status(401).json({ error: "Invalid session" });
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (data.username !== ADMIN_USERNAME || data.exp < Date.now()) {
      return res.status(401).json({ error: "Session expired" });
    }

    next();
  } catch {
    res.status(401).json({ error: "Invalid session" });
  }
}

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    username !== ADMIN_USERNAME ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "Wrong username or password"
    });
  }

  res.json({
    ok: true,
    token: makeToken(username)
  });
});

app.post("/api/orders", (req, res) => {
  const {
    name,
    email,
    phone,
    product,
    price,
    message
  } = req.body;

  if (!name || !email || !phone || !product) {
    return res.status(400).json({
      error: "Please fill in all required fields."
    });
  }

  const orderCode =
    "ORD-" + Date.now().toString(36).toUpperCase();

  db.prepare(`
    INSERT INTO orders
    (order_code, created_at, name, email, phone, product, price, message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    orderCode,
    new Date().toISOString(),
    name,
    email,
    phone,
    product,
    price || "",
    message || ""
  );

  res.status(201).json({
    ok: true,
    orderId: orderCode
  });
});

app.get("/api/orders", requireAdmin, (req, res) => {
  const orders = db
    .prepare("SELECT * FROM orders ORDER BY id DESC")
    .all();

  res.json(orders);
});

app.patch("/api/orders/:id", requireAdmin, (req, res) => {
  const allowed = [
    "new",
    "contacted",
    "paid",
    "completed",
    "cancelled"
  ];

  if (!allowed.includes(req.body.status)) {
    return res.status(400).json({
      error: "Invalid status"
    });
  }

  db.prepare(
    "UPDATE orders SET status = ? WHERE id = ?"
  ).run(req.body.status, req.params.id);

  res.json({ ok: true });
});

app.delete("/api/orders/:id", requireAdmin, (req, res) => {
  db.prepare(
    "DELETE FROM orders WHERE id = ?"
  ).run(req.params.id);

  res.json({ ok: true });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.listen(PORT, () => {
  console.log("Vintage Watch Store running on port " + PORT);
});
