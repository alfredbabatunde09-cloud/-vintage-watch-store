const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// Production settings should be supplied as environment variables.
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "ChangeMe123!";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

const db = new Database(path.join(__dirname, "data", "store.db"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_code TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    product TEXT NOT NULL,
    price TEXT,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'new'
  );
`);

app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

function makeToken(username) {
  const payload = Buffer.from(JSON.stringify({
    username,
    exp: Date.now() + 1000 * 60 * 60 * 8
  })).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return res.status(401).json({ error: "Login required." });

  const token = auth.slice(7);
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return res.status(401).json({ error: "Invalid session." });

  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    return res.status(401).json({ error: "Invalid session." });
  }

  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString());
    if (data.exp < Date.now() || data.username !== ADMIN_USERNAME) {
      return res.status(401).json({ error: "Session expired." });
    }
    req.admin = data.username;
    next();
  } catch {
    return res.status(401).json({ error: "Invalid session." });
  }
}

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body || {};
  if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "Wrong username or password." });
  }
  res.json({ ok: true, token: makeToken(username) });
});

app.post("/api/orders", (req, res) => {
  const { name, email, phone, product, message, price } = req.body || {};
  if (!name || !email || !phone || !product) {
    return res.status(400).json({ error: "Name, email, phone and product are required." });
  }

  const orderCode = "ORD-" + Date.now().toString(36).toUpperCase();
  const createdAt = new Date().toISOString();

  const stmt = db.prepare(`
    INSERT INTO orders
      (order_code, created_at, name, email, phone, product, price, message)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    orderCode, createdAt,
    String(name).slice(0, 120),
    String(email).slice(0, 180),
    String(phone).slice(0, 60),
    String(product).slice(0, 120),
    String(price || "").slice(0, 60),
    String(message || "").slice(0, 1000)
  );

  console.log(`New order ${orderCode} from ${name}`);
  res.status(201).json({ ok: true, orderId: orderCode });
});

app.get("/api/orders", requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM orders ORDER BY id DESC").all();
  res.json(rows);
});

app.patch("/api/orders/:id", requireAdmin, (req, res) => {
  const allowed = ["new", "contacted", "paid", "completed", "cancelled"];
  const { status } = req.body || {};
  if (!allowed.includes(status)) return res.status(400).json({ error: "Invalid status." });

  const result = db.prepare("UPDATE orders SET status = ? WHERE id = ?").run(status, req.params.id);
  if (!result.changes) return res.status(404).json({ error: "Order not found." });
  res.json({ ok: true });
});

app.delete("/api/orders/:id", requireAdmin, (req, res) => {
  const result = db.prepare("DELETE FROM orders WHERE id = ?").run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: "Order not found." });
  res.json({ ok: true });
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => {
  console.log(`VINTAGE Watch Store running at http://localhost:${PORT}`);
  console.log(`Admin dashboard: http://localhost:${PORT}/admin`);
});