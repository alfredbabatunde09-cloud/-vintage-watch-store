const express = require("express");
const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const session = require("express-session");
const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000
  }
}));


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

CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  name TEXT,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chat_session
ON chat_messages(session_id, id);
`);

app.use(express.json({ limit: "100kb" }));
app.use(express.static(__dirname));

/* ---------------- AUTHENTICATION ---------------- */

function makeToken(username) {
  const payload = Buffer.from(
    JSON.stringify({
      username,
      exp: Date.now() + 8 * 60 * 60 * 1000
    })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  return payload + "." + signature;
}

function verifyToken(token) {
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 2) return null;

  const payload = parts[0];
  const signature = parts[1];

  const expected = crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  if (signature !== expected) return null;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (
      data.username !== ADMIN_USERNAME ||
      data.exp < Date.now()
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Login required"
    });
  }

  const token = auth.substring(7);
  const admin = verifyToken(token);

  if (!admin) {
    return res.status(401).json({
      error: "Invalid or expired session"
    });
  }

  req.admin = admin.username;
  next();
}

/* ---------------- ADMIN LOGIN ---------------- */

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

/* ---------------- ORDERS ---------------- */

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
      error: "Please fill in all required fields"
    });
  }

  const orderCode =
    "ORD-" +
    Date.now().toString(36).toUpperCase();

  db.prepare(`
    INSERT INTO orders
    (
      order_code,
      created_at,
      name,
      email,
      phone,
      product,
      price,
      message
    )
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
    .prepare(
      "SELECT * FROM orders ORDER BY id DESC"
    )
    .all();

  res.json(orders);
});

app.patch(
  "/api/orders/:id",
  requireAdmin,
  (req, res) => {
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
    ).run(
      req.body.status,
      req.params.id
    );

    res.json({
      ok: true
    });
  }
);

app.delete(
  "/api/orders/:id",
  requireAdmin,
  (req, res) => {
    db.prepare(
      "DELETE FROM orders WHERE id = ?"
    ).run(req.params.id);

    res.json({
      ok: true
    });
  }
);

/* ---------------- CHAT ---------------- */

const streams = new Set();

function cleanSession(value) {
  return String(value || "")
    .replace(/[^a-zA-Z0-9_-]/g, "")
    .slice(0, 80);
}

function cleanMessage(value) {
  return String(value || "")
    .trim()
    .slice(0, 1000);
}

function broadcast(message) {
  const data =
    "data: " +
    JSON.stringify(message) +
    "\n\n";

  for (const stream of streams) {
    if (
      stream.type === "customer" &&
      stream.session_id !== message.session_id
    ) {
      continue;
    }

    try {
      stream.res.write(data);
    } catch {}
  }
}

function saveMessage({
  session_id,
  sender,
  name,
  message
}) {
  const created_at =
    new Date().toISOString();

  const result = db
    .prepare(`
      INSERT INTO chat_messages
      (
        session_id,
        sender,
        name,
        message,
        created_at
      )
      VALUES (?, ?, ?, ?, ?)
    `)
    .run(
      session_id,
      sender,
      name || "",
      message,
      created_at
    );

  const row = {
    id: Number(result.lastInsertRowid),
    session_id,
    sender,
    name: name || "",
    message,
    created_at
  };

  broadcast(row);

  return row;
}

/* CUSTOMER GET MESSAGES */

app.get(
  "/api/chat/messages",
  (req, res) => {
    const session_id =
      cleanSession(req.query.session_id);

    if (!session_id) {
      return res.status(400).json({
        error: "session_id required"
      });
    }

    const messages = db
      .prepare(`
        SELECT *
        FROM chat_messages
        WHERE session_id = ?
        ORDER BY id ASC
      `)
      .all(session_id);

    res.json({
      messages
    });
  }
);

/* CUSTOMER SEND MESSAGE */

app.post(
  "/api/chat/messages",
  (req, res) => {
    const session_id =
      cleanSession(req.body.session_id);

    const name =
      String(req.body.name || "Visitor")
        .slice(0, 80);

    const message =
      cleanMessage(req.body.message);

    if (!session_id || !message) {
      return res.status(400).json({
        error: "Message required"
      });
    }

    const row = saveMessage({
      session_id,
      sender: "customer",
      name,
      message
    });

    res.status(201).json({
      ok: true,
      message: row
    });
  }
);

/* CUSTOMER REAL-TIME CONNECTION */

app.get(
  "/api/chat/stream",
  (req, res) => {
    const session_id =
      cleanSession(req.query.session_id);

    if (!session_id) {
      return res.status(400).end();
    }

    res.setHeader(
      "Content-Type",
      "text/event-stream"
    );

    res.setHeader(
      "Cache-Control",
      "no-cache"
    );

    res.setHeader(
      "Connection",
      "keep-alive"
    );

    res.flushHeaders();

    res.write(": connected\n\n");

    const stream = {
      res,
      type: "customer",
      session_id
    };

    streams.add(stream);

    req.on("close", () => {
      streams.delete(stream);
    });
  }
);

/* ---------------- ADMIN CHAT ---------------- */

app.get(
  "/api/admin/chats",
  requireAdmin,
  (req, res) => {
    const chats = db
      .prepare(`
        SELECT
          c.session_id,
          c.name,
          c.message AS last_message,
          c.created_at
        FROM chat_messages c

        INNER JOIN (
          SELECT
            session_id,
            MAX(id) AS max_id
          FROM chat_messages
          GROUP BY session_id
        ) x

        ON c.id = x.max_id

        ORDER BY c.id DESC
      `)
      .all();

    res.json({
      chats
    });
  }
);

app.get(
  "/api/admin/chats/:session_id",
  requireAdmin,
  (req, res) => {
    const session_id =
      cleanSession(req.params.session_id);

    const messages = db
      .prepare(`
        SELECT *
        FROM chat_messages
        WHERE session_id = ?
        ORDER BY id ASC
      `)
      .all(session_id);

    res.json({
      messages
    });
  }
);

app.post(
  "/api/admin/chats/:session_id/reply",
  requireAdmin,
  (req, res) => {
    const session_id =
      cleanSession(req.params.session_id);

    const message =
      cleanMessage(req.body.message);

    if (!message) {
      return res.status(400).json({
        error: "Message required"
      });
    }

    const row = saveMessage({
      session_id,
      sender: "admin",
      name: ADMIN_USERNAME,
      message
    });

    res.status(201).json({
      ok: true,
      message: row
    });
  }
);

/* ADMIN REAL-TIME CONNECTION */

app.get(
  "/api/admin/chat-stream",
  requireAdmin,
  (req, res) => {
    res.setHeader(
      "Content-Type",
      "text/event-stream"
    );

    res.setHeader(
      "Cache-Control",
      "no-cache"
    );

    res.setHeader(
      "Connection",
      "keep-alive"
    );

    res.flushHeaders();

    res.write(": connected\n\n");

    const stream = {
      res,
      type: "admin"
    };

    streams.add(stream);

    req.on("close", () => {
      streams.delete(stream);
    });
  }
);

/* ---------------- PAGES ---------------- */

app.get("/health", (req, res) => {
  res.json({
    ok: true
  });
});

app.get("/admin", (req, res) => {
  res.sendFile(
    path.join(__dirname, "admin.html")
  );
});

app.get("/admin-chat", (req, res) => {
  res.sendFile(
    path.join(__dirname, "admin-chat.html")
  );
});

/* Express 5 compatible catch-all */// ================= CUSTOMER CHAT =================

const chatMessages = [];

app.get("/api/chat/messages", (req, res) => {
  res.json(chatMessages);
});

app.post("/api/chat/messages", (req, res) => {
  const { name, message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({
      error: "Message is required"
    });
  }

  const chatMessage = {
    id: Date.now(),
    name: name || "Customer",
    message: message.trim(),
    sender: "customer",
    time: new Date().toISOString()
  };

  chatMessages.push(chatMessage);

  res.json({
    ok: true,
    message: chatMessage
  });
});

app.post("/api/chat/reply", (req, res) => {
  const { message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({
      error: "Message is required"
    });
  }

  const chatMessage = {
    id: Date.now(),
    name: "Admin",
    message: message.trim(),
    sender: "admin",
    time: new Date().toISOString()
  };

  chatMessages.push(chatMessage);

  res.json({
    ok: true,
    message: chatMessage
  });
});

app.get("/{*splat}", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

/* ---------------- START SERVER ---------------- */

app.listen(PORT, () => {
  console.log(
    "VINTAGE Watch Store running on port " +
    PORT
  );
});
