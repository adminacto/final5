const express = require("express")
const http = require("http")
const socketIo = require("socket.io")
const cors = require("cors")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const rateLimit = require("express-rate-limit")
const helmet = require("helmet")
const { v4: uuidv4 } = require("uuid")
const path = require("path")
const mongoose = require("mongoose")
const { Schema, model } = require("mongoose")
const fs = require("fs")
const multer = require("multer")
const cookieParser = require("cookie-parser")

// ÐÐ½Ð¸ÑÐ¸Ð°Ð»Ð¸Ð·Ð°ÑÐ¸Ñ Ð¿ÑÐ¸Ð»Ð¾Ð¶ÐµÐ½Ð¸Ña
const app = express()
const server = http.createServer(app)

// ÐÐ°ÑÑÑÐ¾Ð¹ÐºÐ° trust proxy Ð´Ð»Ñ ÑÐ°Ð±Ð¾ÑÑ Ð·Ð° Ð¿ÑÐ¾ÐºÑÐ¸ (Render.com)
app.set('trust proxy', 1)

// ÐÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾ÑÑÑ
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
)

// Rate limiting Ñ Ð¿ÑÐ°Ð²Ð¸Ð»ÑÐ½Ð¾Ð¹ Ð½Ð°ÑÑÑÐ¾Ð¹ÐºÐ¾Ð¹ Ð´Ð»Ñ Ð¿ÑÐ¾ÐºÑÐ¸
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Ð¼Ð¸Ð½ÑÑ
  max: 100, // Ð¼Ð°ÐºÑÐ¸Ð¼ÑÐ¼ 100 Ð·Ð°Ð¿ÑÐ¾ÑÐ¾Ð²
  message: "Ð¡Ð»Ð¸ÑÐºÐ¾Ð¼ Ð¼Ð½Ð¾Ð³Ð¾ Ð·Ð°Ð¿ÑÐ¾ÑÐ¾Ð², Ð¿Ð¾Ð¿ÑÐ¾Ð±ÑÐ¹ÑÐµ Ð¿Ð¾Ð·Ð¶Ðµ",
  standardHeaders: true,
  legacyHeaders: false,
  // ÐÐ°ÑÑÑÐ¾Ð¹ÐºÐ° Ð´Ð»Ñ ÑÐ°Ð±Ð¾ÑÑ Ð·Ð° Ð¿ÑÐ¾ÐºÑÐ¸
  skip: (req) => req.ip === '127.0.0.1' || req.ip === '::1',
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // Ð¼Ð°ÐºÑÐ¸Ð¼ÑÐ¼ 5 Ð¿Ð¾Ð¿ÑÑÐ¾Ðº Ð²ÑÐ¾Ð´Ð°
  message: "Ð¡Ð»Ð¸ÑÐºÐ¾Ð¼ Ð¼Ð½Ð¾Ð³Ð¾ Ð¿Ð¾Ð¿ÑÑÐ¾Ðº Ð²ÑÐ¾Ð´Ð°, Ð¿Ð¾Ð´Ð¾Ð¶Ð´Ð¸ÑÐµ 15 Ð¼Ð¸Ð½ÑÑ",
  standardHeaders: true,
  legacyHeaders: false,
  // ÐÐ°ÑÑÑÐ¾Ð¹ÐºÐ° Ð´Ð»Ñ ÑÐ°Ð±Ð¾ÑÑ Ð·Ð° Ð¿ÑÐ¾ÐºÑÐ¸
  skip: (req) => req.ip === '127.0.0.1' || req.ip === '::1',
})

// Ð¡Ð¾Ð·Ð´Ð°ÑÑ Ð¿Ð°Ð¿ÐºÑ avatars, ÐµÑÐ»Ð¸ Ð½Ðµ ÑÑÑÐµÑÑÐ²ÑÐµÑ
const avatarsDir = path.join(__dirname, "public", "avatars")
if (!fs.existsSync(avatarsDir)) {
  fs.mkdirSync(avatarsDir, { recursive: true })
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, avatarsDir)
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname)
    const uniqueName = `${Date.now()}_${Math.round(Math.random() * 1e9)}${ext}`
    cb(null, uniqueName)
  },
})
const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (req, file, cb) => {
    if (["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)) {
      cb(null, true)
    } else {
      cb(new Error("Ð¢Ð¾Ð»ÑÐºÐ¾ Ð¸Ð·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ñ (jpg, png, webp)"))
    }
  },
})

// ÐÐ¾Ð½ÑÐ¸Ð³ÑÑÐ°ÑÐ¸Ñ
const JWT_SECRET = process.env.JWT_SECRET || "actogram_ultra_secure_key_2024_v3"
const PORT = process.env.PORT || 3001

// Ð Ð°Ð·ÑÐµÑÐµÐ½Ð½ÑÐµ Ð´Ð¾Ð¼ÐµÐ½Ñ
const allowedOrigins = [
  "https://acto-uimuz.vercel.app",
  "https://actogr.onrender.com",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  /\.vercel\.app$/,
  /\.render\.com$/,
]

// CORS Ð½Ð°ÑÑÑÐ¾Ð¹ÐºÐ¸
const corsOptions = {
  origin: (origin, callback) => {
    if (!origin) return callback(null, true)

    const isAllowed = allowedOrigins.some((allowed) => {
      if (typeof allowed === "string") {
        return origin === allowed || origin.includes(allowed.replace(/https?:\/\//, ""))
      }
      return allowed.test(origin)
    })

    if (isAllowed) {
      callback(null, true)
    } else {
      callback(new Error("CORS: ÐÐ¾Ð¼ÐµÐ½ Ð½Ðµ ÑÐ°Ð·ÑÐµÑÐµÐ½"))
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
  exposedHeaders: ["Set-Cookie"],
}

app.use(cors(corsOptions))
app.use(express.json({ limit: "10mb" }))
app.use(express.static(path.join(__dirname, "public")))
app.use(cookieParser())

// Socket.IO Ð½Ð°ÑÑÑÐ¾Ð¹ÐºÐ¸
const io = socketIo(server, {
  cors: corsOptions,
  transports: ["websocket", "polling"],
  pingTimeout: 60000,
  pingInterval: 25000,
})

// Ð¥ÑÐ°Ð½Ð¸Ð»Ð¸ÑÐµ Ð´Ð°Ð½Ð½ÑÑ (Ð² Ð¿ÑÐ¾Ð´Ð°ÐºÑÐµÐ½Ðµ Ð¸ÑÐ¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÑ Ð±Ð°Ð·Ñ Ð´Ð°Ð½Ð½ÑÑ)
const activeConnections = new Map() // socketId -> userId
const typingUsers = new Map() // chatId -> Set of userIds
const blockedUsers = new Map() // userId -> Set of blocked userIds
const userHeartbeats = new Map() // userId -> lastHeartbeat timestamp
// Rate limiting Ð´Ð»Ñ Ð¾Ð±ÑÐµÐ³Ð¾ ÑÐ°ÑÐ°
const globalChatRateLimit = new Map(); // userId -> lastTimestamp
const globalChatOnline = new Set(); // socket.id

// Middleware Ð´Ð»Ñ Ð¿ÑÐ¾Ð²ÐµÑÐºÐ¸ JWT
const authenticateToken = (req, res, next) => {
  let token = null;
  const authHeader = req.headers["authorization"];
  console.log("ð ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼ Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ñ Ð´Ð»Ñ Ð·Ð°Ð¿ÑÐ¾ÑÐ°:", req.path);
  console.log("ð ÐÐ°Ð³Ð¾Ð»Ð¾Ð²ÐºÐ¸:", Object.keys(req.headers));
  console.log("ð Cookie:", req.cookies);
  console.log("ð Origin:", req.headers.origin);
  console.log("ð Host:", req.headers.host);
  
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
    console.log("ð Ð¢Ð¾ÐºÐµÐ½ Ð¿Ð¾Ð»ÑÑÐµÐ½ Ð¸Ð· Ð·Ð°Ð³Ð¾Ð»Ð¾Ð²ÐºÐ° Authorization");
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
    console.log("ðª Ð¢Ð¾ÐºÐµÐ½ Ð¿Ð¾Ð»ÑÑÐµÐ½ Ð¸Ð· cookie");
  } else {
    console.log("â Ð¢Ð¾ÐºÐµÐ½ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½ Ð½Ð¸ Ð² Ð·Ð°Ð³Ð¾Ð»Ð¾Ð²ÐºÐµ, Ð½Ð¸ Ð² cookie");
    console.log("ð ÐÑÐµ cookie:", JSON.stringify(req.cookies, null, 2));
  }

  if (!token) {
    console.log("â Ð¢Ð¾ÐºÐµÐ½ Ð¾ÑÑÑÑÑÑÐ²ÑÐµÑ, Ð²Ð¾Ð·Ð²ÑÐ°ÑÐ°ÐµÐ¼ 401");
    return res.status(401).json({ error: "Ð¢Ð¾ÐºÐµÐ½ Ð´Ð¾ÑÑÑÐ¿Ð° Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÐµÐ½" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("â ÐÑÐ¸Ð±ÐºÐ° Ð²ÐµÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ð¸ ÑÐ¾ÐºÐµÐ½Ð°:", err.message);
      return res.status(403).json({ error: "ÐÐµÐ´ÐµÐ¹ÑÑÐ²Ð¸ÑÐµÐ»ÑÐ½ÑÐ¹ Ð¸Ð»Ð¸ Ð¸ÑÑÐµÐºÑÐ¸Ð¹ ÑÐ¾ÐºÐµÐ½" });
    }
    console.log("â ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÑÐ¸ÑÐ¾Ð²Ð°Ð½:", user.userId, user.username);
    req.user = user;
    next();
  });
}

// ÐÐ°Ð»Ð¸Ð´Ð°ÑÐ¸Ñ
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
const validatePassword = (password) => password && password.length >= 8
const validateUsername = (username) => /^@[a-zA-Z0-9_]{3,20}$/.test(username)

// Ð£ÑÐ¸Ð»Ð¸ÑÑ
const encryptMessage = (message) => {
  return btoa(unescape(encodeURIComponent(message)))
}

const decryptMessage = (encrypted) => {
  try {
    return decodeURIComponent(escape(atob(encrypted)))
  } catch {
    return encrypted
  }
}

// ÐÐ¼Ð¾Ð´Ð·Ð¸ Ð´Ð»Ñ ÑÐµÐ°ÐºÑÐ¸Ð¹
const reactionEmojis = ["â¤ï¸", "ð", "ð", "ð", "ð®", "ð¢", "ð¡", "ð¥", "ð", "ð"]

// Ð¡Ð¾Ð·Ð´Ð°Ð½Ð¸Ðµ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ-Ð±Ð¾ÑÐ° Ð¿ÑÐ¸ Ð·Ð°Ð¿ÑÑÐºÐµ
const BOT_USERNAME = "@actogram_bot"
const BOT_ID_KEY = "actogram_bot_id"
let botUserId = null

async function ensureBotUser() {
  let bot = await User.findOne({ username: BOT_USERNAME })
  if (!bot) {
    bot = await User.create({
      email: "bot@actogram.app",
      username: BOT_USERNAME,
      fullName: "Actogram Bot",
      bio: "ÐÑÐ¸ÑÐ¸Ð°Ð»ÑÐ½ÑÐ¹ Ð±Ð¾Ñ Actogram. ÐÐ¾Ð²Ð¾ÑÑÐ¸ Ð¸ Ð¾Ð±Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ñ.",
      password: "bot_password_12345678", // Ð½Ðµ Ð¸ÑÐ¿Ð¾Ð»ÑÐ·ÑÐµÑÑÑ
      createdAt: new Date(),
      isVerified: true,
      isOnline: false,
      lastSeen: new Date(),
      avatar: null,
      status: "online",
    })
    console.log("ð¤ Actogram Bot ÑÐ¾Ð·Ð´Ð°Ð½!")
  }
  botUserId = bot._id.toString()
  return botUserId
}

// Ð¡Ð¾Ð·Ð´Ð°Ð½Ð¸Ðµ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° (ÐµÑÐ»Ð¸ ÐµÐ³Ð¾ Ð½ÐµÑ)
async function ensureGlobalChat() {
  const globalChatId = "global";
  let chat = await Chat.findById(globalChatId);
  if (!chat) {
    chat = await Chat.create({
      _id: globalChatId,
      name: "ACTO â ÐÐ±ÑÐ¸Ð¹ ÑÐ°Ñ",
      avatar: null,
      description: "ÐÐ»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð´Ð»Ñ Ð²ÑÐµÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹",
      isGroup: true,
      participants: [], // ÐÐ¾Ð¶Ð½Ð¾ Ð¾ÑÑÐ°Ð²Ð¸ÑÑ Ð¿ÑÑÑÑÐ¼, ÑÑÐ¾Ð±Ñ Ð½Ðµ Ð±ÑÐ»Ð¾ Ð¾Ð³ÑÐ°Ð½Ð¸ÑÐµÐ½Ð¸Ð¹
      createdAt: new Date(),
      type: "group",
      isEncrypted: false,
      createdBy: null,
      theme: "default",
      isPinned: true,
      isMuted: false,
    });
    console.log("ð ÐÐ»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ ÑÐ¾Ð·Ð´Ð°Ð½!");
  }
}

// ÐÐ»Ð°Ð²Ð½Ð°Ñ ÑÑÑÐ°Ð½Ð¸ÑÐ°
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ACTOGRAM Server v3.0</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                max-width: 800px;
                width: 100%;
                background: rgba(255,255,255,0.1);
                backdrop-filter: blur(20px);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 25px 50px rgba(0,0,0,0.2);
                border: 1px solid rgba(255,255,255,0.2);
            }
            .header {
                text-align: center;
                margin-bottom: 40px;
            }
            .logo {
                width: 80px;
                height: 80px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                border-radius: 20px;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 20px;
                font-size: 32px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            }
            h1 {
                font-size: 2.5rem;
                margin-bottom: 10px;
                background: linear-gradient(135deg, #fff, #e0e7ff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }
            .status {
                background: rgba(34, 197, 94, 0.2);
                padding: 15px 25px;
                border-radius: 15px;
                margin: 20px 0;
                text-align: center;
                font-size: 18px;
                border: 1px solid rgba(34, 197, 94, 0.3);
            }
            .stats {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            .stat-card {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 15px;
                text-align: center;
                border: 1px solid rgba(255,255,255,0.2);
                transition: transform 0.3s ease;
            }
            .stat-card:hover {
                transform: translateY(-5px);
            }
            .stat-number {
                font-size: 2rem;
                font-weight: bold;
                color: #60a5fa;
                display: block;
            }
            .features {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin: 30px 0;
            }
            .feature {
                background: rgba(255,255,255,0.1);
                padding: 20px;
                border-radius: 15px;
                border: 1px solid rgba(255,255,255,0.2);
            }
            .feature-icon {
                font-size: 24px;
                margin-bottom: 10px;
            }
            .client-link {
                display: inline-block;
                background: linear-gradient(135deg, #10b981, #059669);
                color: white;
                padding: 15px 30px;
                border-radius: 15px;
                text-decoration: none;
                font-weight: bold;
                font-size: 18px;
                margin: 20px 10px;
                transition: all 0.3s ease;
                box-shadow: 0 10px 25px rgba(16, 185, 129, 0.3);
            }
            .client-link:hover {
                transform: translateY(-3px);
                box-shadow: 0 15px 35px rgba(16, 185, 129, 0.4);
            }
            .version-badge {
                background: linear-gradient(135deg, #f59e0b, #d97706);
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: bold;
                display: inline-block;
                margin: 10px 0;
            }
            @media (max-width: 768px) {
                .container { padding: 20px; }
                h1 { font-size: 2rem; }
                .stats { grid-template-columns: 1fr; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">ð¬</div>
                <h1>ACTOGRAM</h1>
                <div class="version-badge">Server v3.0 - Ultra Secure</div>
                <p>Ð¡Ð¾Ð²ÑÐµÐ¼ÐµÐ½Ð½ÑÐ¹ Ð¼ÐµÑÑÐµÐ½Ð´Ð¶ÐµÑ Ñ end-to-end ÑÐ¸ÑÑÐ¾Ð²Ð°Ð½Ð¸ÐµÐ¼</p>
            </div>
            
            <div class="status">
                â Ð¡ÐµÑÐ²ÐµÑ ÑÐ°Ð±Ð¾ÑÐ°ÐµÑ ÑÑÐ°Ð±Ð¸Ð»ÑÐ½Ð¾ Ð¸ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <span class="stat-number">0</span>
                    <div>ÐÐ°ÑÐµÐ³Ð¸ÑÑÑÐ¸ÑÐ¾Ð²Ð°Ð½Ð½ÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">${activeConnections.size}</span>
                    <div>ÐÐºÑÐ¸Ð²Ð½ÑÑ Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ð¹</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">0</span>
                    <div>ÐÐºÑÐ¸Ð²Ð½ÑÑ ÑÐ°ÑÐ¾Ð²</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">0</span>
                    <div>Ð¡Ð¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹ Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÐµÐ½Ð¾</div>
                </div>
            </div>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">ð</div>
                    <h3>End-to-End ÑÐ¸ÑÑÐ¾Ð²Ð°Ð½Ð¸Ðµ</h3>
                    <p>ÐÑÐµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ Ð·Ð°ÑÐ¸ÑÐµÐ½Ñ ÑÐ¾Ð²ÑÐµÐ¼ÐµÐ½Ð½ÑÐ¼ ÑÐ¸ÑÑÐ¾Ð²Ð°Ð½Ð¸ÐµÐ¼</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">â¡</div>
                    <h3>ÐÐ³Ð½Ð¾Ð²ÐµÐ½Ð½Ð°Ñ Ð´Ð¾ÑÑÐ°Ð²ÐºÐ°</h3>
                    <p>WebSocket ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ðµ Ð´Ð»Ñ Ð±ÑÑÑÑÐ¾Ð³Ð¾ Ð¾Ð±Ð¼ÐµÐ½Ð° ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸ÑÐ¼Ð¸</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">ð±</div>
                    <h3>ÐÐ´Ð°Ð¿ÑÐ¸Ð²Ð½ÑÐ¹ Ð´Ð¸Ð·Ð°Ð¹Ð½</h3>
                    <p>ÐÑÐ»Ð¸ÑÐ½Ð¾ ÑÐ°Ð±Ð¾ÑÐ°ÐµÑ Ð½Ð° Ð²ÑÐµÑ ÑÑÑÑÐ¾Ð¹ÑÑÐ²Ð°Ñ</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">ð¡ï¸</div>
                    <h3>ÐÐ°ÐºÑÐ¸Ð¼Ð°Ð»ÑÐ½Ð°Ñ Ð±ÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾ÑÑÑ</h3>
                    <p>JWT Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ñ, rate limiting, CORS Ð·Ð°ÑÐ¸ÑÐ°</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">ð</div>
                    <h3>ÐÐ½Ð¾Ð³Ð¾ÑÐ·ÑÑÐ½Ð¾ÑÑÑ</h3>
                    <p>ÐÐ¾Ð´Ð´ÐµÑÐ¶ÐºÐ° ÑÐ·Ð±ÐµÐºÑÐºÐ¾Ð³Ð¾, ÑÑÑÑÐºÐ¾Ð³Ð¾ Ð¸ Ð°Ð½Ð³Ð»Ð¸Ð¹ÑÐºÐ¾Ð³Ð¾ ÑÐ·ÑÐºÐ¾Ð²</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">ð¨</div>
                    <h3>Ð¡Ð¾Ð²ÑÐµÐ¼ÐµÐ½Ð½ÑÐ¹ UI</h3>
                    <p>ÐÑÐ°ÑÐ¸Ð²ÑÐ¹ Ð¸Ð½ÑÐµÑÑÐµÐ¹Ñ Ñ ÑÐµÐ¼Ð½Ð¾Ð¹ Ð¸ ÑÐ²ÐµÑÐ»Ð¾Ð¹ ÑÐµÐ¼Ð°Ð¼Ð¸</p>
                </div>
            </div>
            
            <div style="text-align: center; margin: 40px 0;">
                <h2>ð ÐÐ°ÑÐ°ÑÑ Ð¸ÑÐ¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°Ð½Ð¸Ðµ</h2>
                <a href="https://acto-uimuz.vercel.app" class="client-link" target="_blank">
                    ÐÑÐºÑÑÑÑ ACTOGRAM
                </a>
                <p style="margin-top: 20px; opacity: 0.8;">
                    ÐÐµÐ·Ð¾Ð¿Ð°ÑÐ½ÑÐ¹ Ð¼ÐµÑÑÐµÐ½Ð´Ð¶ÐµÑ Ð½Ð¾Ð²Ð¾Ð³Ð¾ Ð¿Ð¾ÐºÐ¾Ð»ÐµÐ½Ð¸Ñ
                </p>
            </div>
            
            <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.2);">
                <p style="opacity: 0.7;">
                    ÐÑÐµÐ¼Ñ ÑÐ°Ð±Ð¾ÑÑ: ${Math.floor(process.uptime() / 60)} Ð¼Ð¸Ð½ÑÑ | 
                    ÐÐµÑÑÐ¸Ñ: 3.0.0 | 
                    Node.js ${process.version}
                </p>
            </div>
        </div>
        
        <script src="/socket.io/socket.io.js"></script>
        <script>
            const socket = io();
            socket.on('connect', () => {
                console.log('ð¢ WebSocket Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½:', socket.id);
            });
            socket.on('disconnect', () => {
                console.log('ð´ WebSocket Ð¾ÑÐºÐ»ÑÑÐµÐ½');
            });
        </script>
    </body>
    </html>
  `)
})

// API Routes
app.get("/api/health", async (req, res) => {
  try {
    const userCount = await User.countDocuments()
    const chatCount = await Chat.countDocuments()
    const messageCount = await Message.countDocuments()
    
    res.json({
      status: "ACTOGRAM Server v3.0 ÑÐ°Ð±Ð¾ÑÐ°ÐµÑ Ð¾ÑÐ»Ð¸ÑÐ½Ð¾",
      timestamp: new Date().toISOString(),
      stats: {
        users: userCount,
        activeConnections: activeConnections.size,
        chats: chatCount,
        totalMessages: messageCount,
        uptime: process.uptime(),
      },
      version: "3.0.0",
      features: {
        endToEndEncryption: true,
        realTimeMessaging: true,
        multiLanguage: true,
        adaptiveDesign: true,
        secureAuth: true,
        rateLimiting: true,
      },
    })
  } catch (error) {
    console.error("Health check error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° ÑÐµÑÐ²ÐµÑÐ°" })
  }
})

// Endpoint Ð´Ð»Ñ Ð·Ð°Ð³ÑÑÐ·ÐºÐ¸ Ð°Ð²Ð°ÑÐ°ÑÐ°
app.post("/api/upload-avatar", authenticateToken, upload.single("avatar"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "Ð¤Ð°Ð¹Ð» Ð½Ðµ Ð·Ð°Ð³ÑÑÐ¶ÐµÐ½" })
    }
    const userId = req.user.userId
    const avatarUrl = `/avatars/${req.file.filename}`
    await User.findByIdAndUpdate(userId, { avatar: avatarUrl })
    res.json({ success: true, avatar: avatarUrl })
  } catch (error) {
    console.error("upload-avatar error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° Ð·Ð°Ð³ÑÑÐ·ÐºÐ¸ Ð°Ð²Ð°ÑÐ°ÑÐ°" })
  }
})

// Endpoint Ð´Ð»Ñ ÑÐ¾Ð·Ð´Ð°Ð½Ð¸Ñ Ð³ÑÑÐ¿Ð¿Ñ/ÐºÐ°Ð½Ð°Ð»Ð° Ñ Ð°Ð²Ð°ÑÐ°ÑÐ¾Ð¼
app.post("/api/create-group", authenticateToken, upload.single("avatar"), async (req, res) => {
  try {
    const userId = req.user.userId
    const { name, description, type, participants } = req.body
    if (!name || !type || !["group", "channel"].includes(type)) {
      return res.status(400).json({ error: "ÐÐµÐºÐ¾ÑÑÐµÐºÑÐ½ÑÐµ Ð´Ð°Ð½Ð½ÑÐµ" })
    }
    let avatarUrl = null
    if (req.file) {
      avatarUrl = `/avatars/${req.file.filename}`
    }
    // Ð£ÑÐ°ÑÑÐ½Ð¸ÐºÐ¸: Ð²ÑÐµÐ³Ð´Ð° Ð´Ð¾Ð±Ð°Ð²Ð»ÑÑÑ ÑÐ¾Ð·Ð´Ð°ÑÐµÐ»Ñ
    let members = [userId]
    if (participants) {
      try {
        const parsed = JSON.parse(participants)
        if (Array.isArray(parsed)) {
          members = Array.from(new Set([...members, ...parsed]))
        }
      } catch {}
    }
    // ÐÐµÐ½ÐµÑÐ¸ÑÑÐµÐ¼ ÑÐ½Ð¸ÐºÐ°Ð»ÑÐ½ÑÐ¹ id Ð´Ð»Ñ Ð³ÑÑÐ¿Ð¿Ñ/ÐºÐ°Ð½Ð°Ð»Ð°
    const chatId = `${type}_${Date.now()}_${Math.round(Math.random() * 1e9)}`
    const chat = await Chat.create({
      _id: chatId,
      name,
      avatar: avatarUrl,
      description: description || "",
      isGroup: true,
      participants: members,
      createdAt: new Date(),
      type,
      isEncrypted: true,
      createdBy: userId,
      theme: "default",
      isPinned: false,
      isMuted: false,
    })
    // ÐÐ¾Ð»ÑÑÐ¸ÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð² Ð´Ð»Ñ Ð¾ÑÐ²ÐµÑÐ°
    const populatedChat = await Chat.findById(chat._id)
      .populate("participants", "_id username fullName avatar isOnline isVerified status")
      .lean()
    res.json({ success: true, chat: {
      ...populatedChat,
      id: populatedChat._id?.toString() || populatedChat._id,
      participants: populatedChat.participants.filter(p => p !== null),
    } })
  } catch (error) {
    console.error("create-group error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° ÑÐ¾Ð·Ð´Ð°Ð½Ð¸Ñ Ð³ÑÑÐ¿Ð¿Ñ/ÐºÐ°Ð½Ð°Ð»Ð°" })
  }
})

// ÐÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ñ
app.post("/api/auth", authLimiter, async (req, res) => {
  try {
    const { action, email, password, username, fullName, bio } = req.body

    if (!email || !password) {
      return res.status(400).json({ error: "Email Ð¸ Ð¿Ð°ÑÐ¾Ð»Ñ Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÑÐ½Ñ" })
    }

    if (!validateEmail(email)) {
      return res.status(400).json({ error: "ÐÐµÐ²ÐµÑÐ½ÑÐ¹ ÑÐ¾ÑÐ¼Ð°Ñ email" })
    }

    if (!validatePassword(password)) {
      return res.status(400).json({ error: "ÐÐ°ÑÐ¾Ð»Ñ Ð´Ð¾Ð»Ð¶ÐµÐ½ ÑÐ¾Ð´ÐµÑÐ¶Ð°ÑÑ Ð¼Ð¸Ð½Ð¸Ð¼ÑÐ¼ 8 ÑÐ¸Ð¼Ð²Ð¾Ð»Ð¾Ð²" })
    }

    if (action === "register") {
      if (!username || !fullName) {
        return res.status(400).json({ error: "Username Ð¸ Ð¿Ð¾Ð»Ð½Ð¾Ðµ Ð¸Ð¼Ñ Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÑÐ½Ñ" })
      }

      if (!validateUsername(username)) {
        return res.status(400).json({ error: "Username Ð´Ð¾Ð»Ð¶ÐµÐ½ Ð½Ð°ÑÐ¸Ð½Ð°ÑÑÑÑ Ñ @ Ð¸ ÑÐ¾Ð´ÐµÑÐ¶Ð°ÑÑ 3-20 ÑÐ¸Ð¼Ð²Ð¾Ð»Ð¾Ð²" })
      }

      const existingUser = await User.findOne({ $or: [{ email }, { username }] })
      if (existingUser) {
        return res.status(400).json({ error: "ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ñ ÑÐ°ÐºÐ¸Ð¼ email Ð¸Ð»Ð¸ username ÑÐ¶Ðµ ÑÑÑÐµÑÑÐ²ÑÐµÑ" })
      }

      const hashedPassword = await bcrypt.hash(password, 12)
      const user = await User.create({
        email,
        username,
        fullName,
        bio: bio || "",
        password: hashedPassword,
        createdAt: new Date(),
        isVerified: Math.random() > 0.5,
        isOnline: false,
        lastSeen: new Date(),
        avatar: null,
        status: "offline",
      })

      const token = jwt.sign({ userId: user._id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: "30d" })
      const userResponse = user.toObject()
      delete userResponse.password
      userResponse.id = user._id.toString()
      // --- Ð£ÑÑÐ°Ð½Ð°Ð²Ð»Ð¸Ð²Ð°ÐµÐ¼ cookie Ñ ÑÐ¾ÐºÐµÐ½Ð¾Ð¼ ---
      res.cookie('token', token, {
        httpOnly: false, // ÐÐ·Ð¼ÐµÐ½ÐµÐ½Ð¾ Ð½Ð° false Ð´Ð»Ñ Ð¾ÑÐ»Ð°Ð´ÐºÐ¸
        secure: false,
        sameSite: 'Lax', // ÐÐµÑÐ½ÑÐ»Ð¸ Ð¾Ð±ÑÐ°ÑÐ½Ð¾
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
      })
      console.log("ðª Cookie ÑÑÑÐ°Ð½Ð¾Ð²Ð»ÐµÐ½ Ð´Ð»Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ:", user.username)
      // ---
      res.json({
        success: true,
        message: "Ð ÐµÐ³Ð¸ÑÑÑÐ°ÑÐ¸Ñ ÑÑÐ¿ÐµÑÐ½Ð°",
        user: userResponse,
        token,
      })
      console.log(`â ÐÐ¾Ð²ÑÐ¹ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ: ${username} (${email})`)
    } else if (action === "login") {
      const user = await User.findOne({ email })
      if (!user) {
        return res.status(401).json({ error: "ÐÐµÐ²ÐµÑÐ½ÑÐ¹ email Ð¸Ð»Ð¸ Ð¿Ð°ÑÐ¾Ð»Ñ" })
      }
      const isValidPassword = await bcrypt.compare(password, user.password)
      if (!isValidPassword) {
        return res.status(401).json({ error: "ÐÐµÐ²ÐµÑÐ½ÑÐ¹ email Ð¸Ð»Ð¸ Ð¿Ð°ÑÐ¾Ð»Ñ" })
      }
      user.isOnline = true
      user.lastSeen = new Date()
      user.status = "online"
      await user.save()
      const token = jwt.sign({ userId: user._id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: "30d" })
      const userResponse = user.toObject()
      delete userResponse.password
      userResponse.id = user._id.toString()
      // --- Ð£ÑÑÐ°Ð½Ð°Ð²Ð»Ð¸Ð²Ð°ÐµÐ¼ cookie Ñ ÑÐ¾ÐºÐµÐ½Ð¾Ð¼ ---
      res.cookie('token', token, {
        httpOnly: false, // ÐÐ·Ð¼ÐµÐ½ÐµÐ½Ð¾ Ð½Ð° false Ð´Ð»Ñ Ð¾ÑÐ»Ð°Ð´ÐºÐ¸
        secure: false,
        sameSite: 'Lax', // ÐÐµÑÐ½ÑÐ»Ð¸ Ð¾Ð±ÑÐ°ÑÐ½Ð¾
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
      })
      console.log("ðª Cookie ÑÑÑÐ°Ð½Ð¾Ð²Ð»ÐµÐ½ Ð´Ð»Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ:", user.username)
      // ---
      res.json({
        success: true,
        message: "ÐÑÐ¾Ð´ Ð²ÑÐ¿Ð¾Ð»Ð½ÐµÐ½ ÑÑÐ¿ÐµÑÐ½Ð¾",
        user: userResponse,
        token,
      })
      console.log(`â ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð²Ð¾ÑÐµÐ»: ${user.username}`)
    } else {
      res.status(400).json({ error: "ÐÐµÐ²ÐµÑÐ½Ð¾Ðµ Ð´ÐµÐ¹ÑÑÐ²Ð¸Ðµ" })
    }
  } catch (error) {
    console.error("Auth error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° ÑÐµÑÐ²ÐµÑÐ°" })
  }
})

// ÐÐ¾Ð»ÑÑÐµÐ½Ð¸Ðµ ÑÐ°ÑÐ¾Ð² Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ (MongoDB)
app.get("/api/chats", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    console.log("ð ÐÐ°Ð¿ÑÐ¾Ñ ÑÐ°ÑÐ¾Ð² Ð´Ð»Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ:", userId, req.user.username)
    
    // ÐÐ°Ð¹ÑÐ¸ Ð²ÑÐµ ÑÐ°ÑÑ, Ð³Ð´Ðµ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ â ÑÑÐ°ÑÑÐ½Ð¸Ðº
    const chats = await Chat.find({ participants: userId })
      .populate("participants", "_id username fullName avatar isOnline isVerified status")
      .sort({ updatedAt: -1 }) // Ð¡Ð¾ÑÑÐ¸ÑÑÐµÐ¼ Ð¿Ð¾ Ð²ÑÐµÐ¼ÐµÐ½Ð¸ Ð¾Ð±Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ñ
      .lean()
    
    console.log("ð ÐÐ°Ð¹Ð´ÐµÐ½Ð¾ ÑÐ°ÑÐ¾Ð²:", chats.length)
    
    // ÐÐ»Ñ ÐºÐ°Ð¶Ð´Ð¾Ð³Ð¾ ÑÐ°ÑÐ° Ð¿Ð¾Ð»ÑÑÐ¸ÑÑ Ð¿Ð¾ÑÐ»ÐµÐ´Ð½ÐµÐµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð¸ ÐºÐ¾Ð»Ð¸ÑÐµÑÑÐ²Ð¾ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹
    const chatList = await Promise.all(
      chats.map(async (chat) => {
        const lastMessage = await Message.findOne({ chat: chat._id })
          .sort({ timestamp: -1 })
          .lean()
        const messageCount = await Message.countDocuments({ chat: chat._id })
        return {
          ...chat,
          id: chat._id?.toString() || chat._id,
          participants: chat.participants.filter(p => p !== null),
          lastMessage: lastMessage
            ? {
                ...lastMessage,
                id: lastMessage._id?.toString() || lastMessage._id,
                senderId: lastMessage.sender?.toString() || lastMessage.sender,
                chatId: lastMessage.chat?.toString() || lastMessage.chat,
              }
            : null,
          messageCount,
          unreadCount: 0, // TODO: ÑÐµÐ°Ð»Ð¸Ð·Ð¾Ð²Ð°ÑÑ
        }
      })
    )
    
    // ÐÑÐµÐ³Ð´Ð° Ð´Ð¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð² Ð½Ð°ÑÐ°Ð»Ð¾ ÑÐ¿Ð¸ÑÐºÐ°
    const globalChat = await Chat.findById("global").lean();
    if (globalChat) {
      // ÐÐ¾Ð»ÑÑÐ°ÐµÐ¼ Ð¿Ð¾ÑÐ»ÐµÐ´Ð½ÐµÐµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð¸ ÐºÐ¾Ð»Ð¸ÑÐµÑÑÐ²Ð¾ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹ Ð´Ð»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°
      const globalLastMessage = await Message.findOne({ chat: "global" })
        .sort({ timestamp: -1 })
        .lean()
      const globalMessageCount = await Message.countDocuments({ chat: "global" })
      
      // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð² Ð½Ð°ÑÐ°Ð»Ð¾ ÑÐ¿Ð¸ÑÐºÐ°
      chatList.unshift({
        ...globalChat,
        id: globalChat._id?.toString() || globalChat._id,
        participants: globalChat.participants || [],
        lastMessage: globalLastMessage
          ? {
              ...globalLastMessage,
              id: globalLastMessage._id?.toString() || globalLastMessage._id,
              senderId: globalLastMessage.sender?.toString() || globalLastMessage.sender,
              chatId: globalLastMessage.chat?.toString() || globalLastMessage.chat,
            }
          : null,
        messageCount: globalMessageCount,
        unreadCount: 0,
      });
      console.log("ð ÐÐ»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð´Ð¾Ð±Ð°Ð²Ð»ÐµÐ½ Ð² ÑÐ¿Ð¸ÑÐ¾Ðº");
    }
    
    console.log("ð ÐÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ ÑÐ¿Ð¸ÑÐ¾Ðº ÑÐ°ÑÐ¾Ð²:", chatList.length, "ÑÐ°ÑÐ¾Ð²");
    res.json(chatList)
  } catch (error) {
    console.error("/api/chats error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° ÑÐµÑÐ²ÐµÑÐ°" })
  }
})

// ÐÐ¾Ð»ÑÑÐµÐ½Ð¸Ðµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹ ÑÐ°ÑÐ° (MongoDB) Ñ Ð¿Ð°Ð³Ð¸Ð½Ð°ÑÐ¸ÐµÐ¹
app.get("/api/messages/:chatId", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params
    const userId = req.user.userId
    const page = parseInt(req.query.page) || 0
    const limit = parseInt(req.query.limit) || 50
    const skip = page * limit
    const chat = await Chat.findById(chatId).lean()
    if (!chat) return res.status(404).json({ error: "Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½" })
    
    // ÐÐ»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° ÑÐ°Ð·ÑÐµÑÐ°ÐµÐ¼ Ð²ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÑÐ¼ Ð¿Ð¾Ð»ÑÑÐ°ÑÑ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ
    const isGlobalChat = chatId === "global"
    const isParticipant = isGlobalChat || chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(userId)
    if (!isParticipant) {
      return res.status(403).json({ error: "ÐÐµÑ Ð´Ð¾ÑÑÑÐ¿Ð° Ðº ÑÑÐ¾Ð¼Ñ ÑÐ°ÑÑ" })
    }
    
    const chatMessages = await Message.find({ chat: chatId })
      .populate("sender", "username fullName") // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¸Ð½ÑÐ¾ÑÐ¼Ð°ÑÐ¸Ñ Ð¾Ð± Ð¾ÑÐ¿ÑÐ°Ð²Ð¸ÑÐµÐ»Ðµ
      .sort({ timestamp: 1 })
      .skip(skip)
      .limit(limit)
      .lean()

    // ÐÐ»Ñ ÐºÐ°Ð¶Ð´Ð¾Ð³Ð¾ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ Ñ replyTo Ð¿Ð¾Ð´Ð³ÑÑÐ¶Ð°ÐµÐ¼ Ð¾ÑÐ¸Ð³Ð¸Ð½Ð°Ð»
    const messagesWithReply = await Promise.all(chatMessages.map(async (msg) => {
      let replyTo = null
      if (msg.replyTo) {
        const originalMsg = await Message.findById(msg.replyTo).populate("sender", "username fullName").lean()
        if (originalMsg) {
          let senderName = "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾"
          if (originalMsg.sender) {
            senderName = originalMsg.sender.username || originalMsg.sender.fullName || "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾"
          }
          replyTo = {
            id: originalMsg._id?.toString() || originalMsg._id,
            content: originalMsg.isEncrypted ? decryptMessage(originalMsg.content) : originalMsg.content,
            senderName,
          }
        }
      }
      return {
        ...msg,
        id: msg._id?.toString() || msg._id,
        senderId: msg.sender?._id?.toString() || msg.sender?.toString() || msg.sender,
        senderName: msg.sender?.username || msg.sender?.fullName || "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾", // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¸Ð¼Ñ Ð¾ÑÐ¿ÑÐ°Ð²Ð¸ÑÐµÐ»Ñ
        chatId: msg.chat?.toString() || msg.chat,
        content: msg.isEncrypted ? decryptMessage(msg.content) : msg.content,
        replyTo, // ÑÐµÐ¿ÐµÑÑ ÑÑÐ¾ Ð¾Ð±ÑÐµÐºÑ, Ð° Ð½Ðµ id
      }
    }))
    res.json(messagesWithReply)
  } catch (error) {
    console.error("/api/messages/:chatId error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° ÑÐµÑÐ²ÐµÑÐ°" })
  }
})

// Socket.IO Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ñ (MongoDB)
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token
    console.log("ð Socket.IO Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ðµ, ÑÐ¾ÐºÐµÐ½:", token ? "ÐµÑÑÑ" : "Ð½ÐµÑ")

    if (!token) {
      console.log("â Socket.IO: ÑÐ¾ÐºÐµÐ½ Ð¾ÑÑÑÑÑÑÐ²ÑÐµÑ")
      return next(new Error("Ð¢Ð¾ÐºÐµÐ½ Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ð¸ Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÐµÐ½"))
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.log("â Socket.IO: Ð¾ÑÐ¸Ð±ÐºÐ° Ð²ÐµÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ð¸ ÑÐ¾ÐºÐµÐ½Ð°:", err.message)
        return next(new Error("ÐÐµÐ´ÐµÐ¹ÑÑÐ²Ð¸ÑÐµÐ»ÑÐ½ÑÐ¹ Ð¸Ð»Ð¸ Ð¸ÑÑÐµÐºÑÐ¸Ð¹ ÑÐ¾ÐºÐµÐ½"))
      }

      try {
        const user = await User.findById(decoded.userId).lean()
        if (!user) {
          console.log("â Socket.IO: Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½ Ð² ÐÐ")
          return next(new Error("ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½"))
        }

        socket.userId = user._id.toString()
        socket.user = {
          ...user,
          id: user._id.toString() // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¿Ð¾Ð»Ðµ id Ð´Ð»Ñ ÑÐ¾Ð²Ð¼ÐµÑÑÐ¸Ð¼Ð¾ÑÑÐ¸
        }
        console.log("â Socket.IO: Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÑÐ¸ÑÐ¾Ð²Ð°Ð½:", user.username, user._id)
        next()
      } catch (error) {
        console.error("Socket auth error:", error)
        return next(new Error("ÐÑÐ¸Ð±ÐºÐ° Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ð¸"))
      }
    })
  } catch (error) {
    console.error("Socket auth error:", error)
    return next(new Error("ÐÑÐ¸Ð±ÐºÐ° Ð°ÑÑÐµÐ½ÑÐ¸ÑÐ¸ÐºÐ°ÑÐ¸Ð¸"))
  }
})

// Socket.IO Ð¾Ð±ÑÐ°Ð±Ð¾ÑÑÐ¸ÐºÐ¸
io.on("connection", async (socket) => {
  const user = socket.user
  console.log(`ð ÐÐ¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ðµ: ${user.username} (${socket.id})`)

  activeConnections.set(socket.id, user.id)
  // ÐÑÐ¸ Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ð¸ Ð¾Ð±Ð½Ð¾Ð²Ð»ÑÑÑ ÑÑÐ°ÑÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð² MongoDB
  await User.findByIdAndUpdate(user.id, { isOnline: true, lastSeen: new Date(), status: "online" })
  userHeartbeats.set(user.id, Date.now())

      // ÐÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ÐºÐ¾ Ð²ÑÐµÐ¼ ÐµÐ³Ð¾ ÑÐ°ÑÐ°Ð¼ (MongoDB)
    try {
      const userChats = await Chat.find({ participants: user.id }).lean()
      for (const chat of userChats) {
        socket.join(chat._id.toString())
      }
      
      // ÐÑÐµÐ³Ð´Ð° Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÑÐµÐ¼ Ðº Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð¼Ñ ÑÐ°ÑÑ Ð¸ Ð´Ð¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð² ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¸
      socket.join("global")
      globalChatOnline.add(socket.id);
      io.to('global').emit('global_online_count', globalChatOnline.size);
      
      // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð² ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¸ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° ÐµÑÐ»Ð¸ ÐµÐ³Ð¾ ÑÐ°Ð¼ Ð½ÐµÑ
      const globalChat = await Chat.findById("global");
      if (globalChat && !globalChat.participants.includes(user.id)) {
        globalChat.participants.push(user.id);
        await globalChat.save();
        console.log(`ð ${user.username} Ð´Ð¾Ð±Ð°Ð²Ð»ÐµÐ½ Ð² ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¸ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°`)
      }
      
      console.log(`ð ${user.username} Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½ Ðº Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð¼Ñ ÑÐ°ÑÑ`)
    } catch (error) {
      console.error("Error joining user chats:", error)
    }

  // ÐÐ¾Ð»ÑÑÐµÐ½Ð¸Ðµ ÑÐ°ÑÐ¾Ð² Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ (MongoDB)
  socket.on("get_my_chats", async (userId) => {
    try {
      if (userId === user.id) {
        const chats = await Chat.find({ participants: user.id })
          .populate("participants", "_id username fullName avatar isOnline isVerified status")
          .lean()
        
        const chatList = await Promise.all(
          chats.map(async (chat) => {
            const lastMessage = await Message.findOne({ chat: chat._id })
              .sort({ timestamp: -1 })
              .lean()
            const messageCount = await Message.countDocuments({ chat: chat._id })
            return {
              ...chat,
              id: chat._id?.toString() || chat._id,
              participants: chat.participants.filter(p => p !== null),
              lastMessage: lastMessage
                ? {
                    ...lastMessage,
                    id: lastMessage._id?.toString() || lastMessage._id,
                    senderId: lastMessage.sender?.toString() || lastMessage.sender,
                    chatId: lastMessage.chat?.toString() || lastMessage.chat,
                  }
                : null,
              messageCount,
              unreadCount: 0,
            }
          })
        )
        
        // ÐÑÐµÐ³Ð´Ð° Ð´Ð¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð² Ð½Ð°ÑÐ°Ð»Ð¾ ÑÐ¿Ð¸ÑÐºÐ°
        const globalChat = await Chat.findById("global").lean();
        if (globalChat) {
          // ÐÐ¾Ð»ÑÑÐ°ÐµÐ¼ Ð¿Ð¾ÑÐ»ÐµÐ´Ð½ÐµÐµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð¸ ÐºÐ¾Ð»Ð¸ÑÐµÑÑÐ²Ð¾ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹ Ð´Ð»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°
          const globalLastMessage = await Message.findOne({ chat: "global" })
            .sort({ timestamp: -1 })
            .lean()
          const globalMessageCount = await Message.countDocuments({ chat: "global" })
          
          // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð² Ð½Ð°ÑÐ°Ð»Ð¾ ÑÐ¿Ð¸ÑÐºÐ°
          chatList.unshift({
            ...globalChat,
            id: globalChat._id?.toString() || globalChat._id,
            participants: globalChat.participants || [],
            lastMessage: globalLastMessage
              ? {
                  ...globalLastMessage,
                  id: globalLastMessage._id?.toString() || globalLastMessage._id,
                  senderId: globalLastMessage.sender?.toString() || globalLastMessage.sender,
                  chatId: globalLastMessage.chat?.toString() || globalLastMessage.chat,
                }
              : null,
            messageCount: globalMessageCount,
            unreadCount: 0,
          });
          console.log("ð ÐÐ»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð´Ð¾Ð±Ð°Ð²Ð»ÐµÐ½ Ð² ÑÐ¿Ð¸ÑÐ¾Ðº");
        }
        
        socket.emit("my_chats", chatList)
      }
    } catch (error) {
      console.error("get_my_chats error:", error)
      socket.emit("my_chats", [])
    }
  })

      // ÐÐ¾Ð»ÑÑÐµÐ½Ð¸Ðµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹ (MongoDB)
    socket.on("get_messages", async (data) => {
      try {
        const { chatId, userId } = data
        const page = 0
        const limit = 50
        const skip = page * limit
        
        console.log(`ð¨ ÐÐ°Ð¿ÑÐ¾Ñ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ð¹ Ð´Ð»Ñ ÑÐ°ÑÐ°: ${chatId}`)
        
        // ÐÐ»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° ÑÐ°Ð·ÑÐµÑÐ°ÐµÐ¼ Ð²ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÑÐ¼ Ð¿Ð¾Ð»ÑÑÐ°ÑÑ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ
        const isGlobalChat = chatId === "global"
        if (!isGlobalChat) {
          const chat = await Chat.findById(chatId).lean()
          if (!chat) {
            console.log(`â Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½: ${chatId}`)
            socket.emit("chat_messages", { chatId, messages: [] })
            return
          }
          
          const isParticipant = chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)
          if (!isParticipant) {
            console.log(`â ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð½Ðµ ÑÐ²Ð»ÑÐµÑÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÐ°ÑÐ°: ${chatId}`)
            socket.emit("chat_messages", { chatId, messages: [] })
            return
          }
        }

        const chatMessages = await Message.find({ chat: chatId })
          .populate("sender", "username fullName") // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¸Ð½ÑÐ¾ÑÐ¼Ð°ÑÐ¸Ñ Ð¾Ð± Ð¾ÑÐ¿ÑÐ°Ð²Ð¸ÑÐµÐ»Ðµ
          .sort({ timestamp: 1 })
          .skip(skip)
          .limit(limit)
          .lean()

        const decryptedMessages = chatMessages.map((msg) => ({
          ...msg,
          id: msg._id?.toString() || msg._id,
          senderId: msg.sender?._id?.toString() || msg.sender?.toString() || msg.sender,
          senderName: msg.sender?.username || msg.sender?.fullName || "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾", // ÐÐ¾Ð±Ð°Ð²Ð»ÑÐµÐ¼ Ð¸Ð¼Ñ Ð¾ÑÐ¿ÑÐ°Ð²Ð¸ÑÐµÐ»Ñ
          chatId: msg.chat?.toString() || msg.chat,
          content: msg.isEncrypted ? decryptMessage(msg.content) : msg.content,
        }))

        socket.emit("chat_messages", { chatId, messages: decryptedMessages })
      } catch (error) {
        console.error("get_messages error:", error)
        socket.emit("chat_messages", { chatId: data?.chatId || "unknown", messages: [] })
      }
    })

  // ÐÐ¾Ð¸ÑÐº Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹ (MongoDB)
  socket.on("search_users", async (query) => {
    try {
      if (!query || typeof query !== 'string' || query.length < 2) {
        socket.emit("search_results", [])
        return
      }
      const searchTerm = query.toLowerCase()
      const usersFound = await User.find({
        $or: [
          { username: { $regex: searchTerm, $options: "i" } },
          { fullName: { $regex: searchTerm, $options: "i" } },
          { email: { $regex: searchTerm, $options: "i" } },
        ],
        _id: { $ne: user.id },
      })
        .limit(10)
        .lean()
      const results = usersFound.map((u) => ({
        id: u._id.toString(),
        username: u.username,
        fullName: u.fullName,
        email: u.email,
        avatar: u.avatar,
        bio: u.bio,
        isOnline: u.isOnline,
        isVerified: u.isVerified,
        status: u.status,
      }))
      socket.emit("search_results", results)
    } catch (error) {
      console.error("search_users error:", error)
      socket.emit("search_results", [])
    }
  })

  // Ð¡Ð¾Ð·Ð´Ð°Ð½Ð¸Ðµ Ð¿ÑÐ¸Ð²Ð°ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° (MongoDB)
  socket.on("create_private_chat", async (data) => {
    try {
      console.log(`ð¬ ÐÐ¾Ð¿ÑÑÐºÐ° ÑÐ¾Ð·Ð´Ð°Ð½Ð¸Ñ Ð¿ÑÐ¸Ð²Ð°ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°: ${user.username} -> ${data.userId}`)
      console.log(`ð¬ ÐÐ°Ð½Ð½ÑÐµ ÑÐ°ÑÐ°:`, data)
      
      const { userId, chatId, createdBy } = data
      console.log(`ð ÐÑÐ¾Ð²ÐµÑÐºÐ° ÑÐ¾Ð·Ð´Ð°ÑÐµÐ»Ñ ÑÐ°ÑÐ°: createdBy=${createdBy}, user.id=${user.id}`)
      
      // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼, ÑÑÐ¾ ÑÐ¾Ð·Ð´Ð°ÑÐµÐ»Ñ ÑÐ°ÑÐ° - ÑÑÐ¾ ÑÐµÐºÑÑÐ¸Ð¹ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ
      if (createdBy && createdBy !== user.id) {
        console.log(`â ÐÐµÐ²ÐµÑÐ½ÑÐ¹ ÑÐ¾Ð·Ð´Ð°ÑÐµÐ»Ñ ÑÐ°ÑÐ°: ${createdBy} != ${user.id}`)
        return
      }
      
      // ÐÑÐ¾Ð²ÐµÑÐ¸ÑÑ, ÑÑÑÐµÑÑÐ²ÑÐµÑ Ð»Ð¸ ÑÐ¶Ðµ ÑÐ°ÐºÐ¾Ð¹ ÑÐ°Ñ
      let chat = await Chat.findById(chatId)
      if (!chat) {
        console.log(`ð Ð¡Ð¾Ð·Ð´Ð°Ð½Ð¸Ðµ Ð½Ð¾Ð²Ð¾Ð³Ð¾ ÑÐ°ÑÐ°: ${chatId}`)
        
        // ÐÐ¾Ð»ÑÑÐ¸ÑÑ Ð¸Ð½ÑÐ¾ÑÐ¼Ð°ÑÐ¸Ñ Ð¾ ÑÐ¾Ð±ÐµÑÐµÐ´Ð½Ð¸ÐºÐµ
        const otherUser = await User.findById(userId).lean()
        const otherUserName = otherUser ? otherUser.username : "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾"
        
        // Ð¡Ð¾Ð·Ð´Ð°ÑÑ Ð½Ð¾Ð²ÑÐ¹ ÑÐ°Ñ
        chat = await Chat.create({
          _id: chatId, // ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐµÐ¼ ÑÑÑÐ¾ÐºÐ¾Ð²ÑÐ¹ ID
          name: otherUserName, // ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐµÐ¼ Ð¸Ð¼Ñ ÑÐ¾Ð±ÐµÑÐµÐ´Ð½Ð¸ÐºÐ°
          avatar: otherUser?.avatar || null,
          description: `ÐÑÐ¸Ð²Ð°ÑÐ½ÑÐ¹ ÑÐ°Ñ Ñ ${otherUserName}`,
          isGroup: false,
          participants: [user.id, userId],
          createdAt: new Date(),
          type: "private",
          isEncrypted: true,
          createdBy: user.id,
          theme: "default",
          isPinned: false,
          isMuted: false,
        })
        console.log(`â Ð§Ð°Ñ ÑÐ¾Ð·Ð´Ð°Ð½: ${chat._id} Ñ ÑÐ¾Ð±ÐµÑÐµÐ´Ð½Ð¸ÐºÐ¾Ð¼: ${otherUserName}`)
      } else {
        console.log(`ð Ð§Ð°Ñ ÑÐ¶Ðµ ÑÑÑÐµÑÑÐ²ÑÐµÑ: ${chat._id}`)
      }
      
      // ÐÐ¾Ð»ÑÑÐ¸ÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð²
      const populatedChat = await Chat.findById(chat._id)
        .populate("participants", "_id username fullName avatar isOnline isVerified status")
        .lean()
      
      console.log(`ð Ð£ÑÐ°ÑÑÐ½Ð¸ÐºÐ¸ ÑÐ°ÑÐ°:`, populatedChat.participants)
      
      // ÐÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÑÐµÐ¼ ÑÐµÐºÑÑÐµÐ³Ð¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ðº ÑÐ°ÑÑ
      socket.join(chatId)
      console.log(`â ${user.username} Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½ Ðº ÑÐ°ÑÑ: ${chatId}`)
      
      // ÐÐ°ÑÐ¾Ð´Ð¸Ð¼ Ð¸ Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÑÐµÐ¼ Ð²ÑÐ¾ÑÐ¾Ð³Ð¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ
      const targetSocket = Array.from(io.sockets.sockets.values()).find((s) => s.userId === userId)
      if (targetSocket) {
        targetSocket.join(chatId)
        console.log(`â ÐÑÐ¾ÑÐ¾Ð¹ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½ Ðº ÑÐ°ÑÑ: ${chatId}`)
        targetSocket.emit("new_private_chat", {
          ...populatedChat,
          id: populatedChat._id?.toString() || populatedChat._id,
          participants: populatedChat.participants.filter(p => p !== null),
        })
      } else {
        console.log(`â ï¸ ÐÑÐ¾ÑÐ¾Ð¹ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½ Ð¾Ð½Ð»Ð°Ð¹Ð½: ${userId}`)
      }
      
      // ÐÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ ÑÐ¾Ð±ÑÑÐ¸Ðµ ÑÐµÐºÑÑÐµÐ¼Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ
      socket.emit("new_private_chat", {
        ...populatedChat,
        id: populatedChat._id?.toString() || populatedChat._id,
        participants: populatedChat.participants.filter(p => p !== null),
      })
      
      console.log(`ð¬ Ð¡Ð¾Ð·Ð´Ð°Ð½ Ð¿ÑÐ¸Ð²Ð°ÑÐ½ÑÐ¹ ÑÐ°Ñ: ${user.username} â ${userId}`)
    } catch (error) {
      console.error("create_private_chat error:", error)
    }
  })

  // ÐÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ðµ Ðº ÑÐ°ÑÑ (MongoDB)
  socket.on("join_chat", async (chatId) => {
    try {
      console.log(`ð¥ ÐÐ¾Ð¿ÑÑÐºÐ° Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ñ Ðº ÑÐ°ÑÑ: ${user.username} -> ${chatId}`)
      
      // ÐÐ»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° Ð½Ðµ Ð¿ÑÐ¾Ð²ÐµÑÑÐµÐ¼ ÑÑÑÐµÑÑÐ²Ð¾Ð²Ð°Ð½Ð¸Ðµ
      if (chatId === "global") {
        socket.join(chatId)
        globalChatOnline.add(socket.id)
        io.to('global').emit('global_online_count', globalChatOnline.size)
        console.log(`â ${user.username} Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½Ð¸Ð»ÑÑ Ðº Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð¼Ñ ÑÐ°ÑÑ`)
        return
      }
      
      const chat = await Chat.findById(chatId)
      if (!chat) {
        console.log(`â Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½: ${chatId}`)
        socket.emit("error", { message: "Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½" })
        return
      }

      console.log(`ð Ð£ÑÐ°ÑÑÐ½Ð¸ÐºÐ¸ ÑÐ°ÑÐ°:`, chat.participants)
      console.log(`ð¤ Ð¢ÐµÐºÑÑÐ¸Ð¹ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ: ${user.id}`)
      
      // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼, ÑÐ²Ð»ÑÐµÑÑÑ Ð»Ð¸ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÐ°ÑÐ°
      const isParticipant = chat.participants.some(p => p && p.toString() === user.id)
      if (!isParticipant) {
        console.log(`â ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ${user.username} Ð½Ðµ ÑÐ²Ð»ÑÐµÑÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÐ°ÑÐ° ${chatId}`)
        socket.emit("error", { message: "ÐÑ Ð½Ðµ ÑÐ²Ð»ÑÐµÑÐµÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÑÐ¾Ð³Ð¾ ÑÐ°ÑÐ°" })
        return
      }

      socket.join(chatId)
      console.log(`â ${user.username} Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½Ð¸Ð»ÑÑ Ðº ÑÐ°ÑÑ: ${chatId}`)
    } catch (error) {
      console.error("join_chat error:", error)
      socket.emit("error", { message: "ÐÑÐ¸Ð±ÐºÐ° Ð¿ÑÐ¸ÑÐ¾ÐµÐ´Ð¸Ð½ÐµÐ½Ð¸Ñ Ðº ÑÐ°ÑÑ" })
    }
  })

  // ÐÑÐ¿ÑÐ°Ð²ÐºÐ° ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ (MongoDB)
  socket.on("send_message", async (messageData) => {
    try {
      console.log(`ð¤ ÐÐ¾Ð¿ÑÑÐºÐ° Ð¾ÑÐ¿ÑÐ°Ð²ÐºÐ¸ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ: ${user.username} -> ${messageData.chatId}`)
      console.log(`ð¤ ÐÐ°Ð½Ð½ÑÐµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ:`, messageData)
    
      let chat = await Chat.findById(messageData.chatId)
      if (!chat) {
        console.log(`â Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½: ${messageData.chatId}`)
        
        // ÐÐ¾Ð¿ÑÐ¾Ð±ÑÐµÐ¼ ÑÐ¾Ð·Ð´Ð°ÑÑ ÑÐ°Ñ, ÐµÑÐ»Ð¸ Ð¾Ð½ Ð½Ðµ ÑÑÑÐµÑÑÐ²ÑÐµÑ
        if (messageData.chatId.startsWith('private_')) {
          const participantIds = messageData.chatId.replace('private_', '').split('_')
          if (participantIds.length >= 2) {
            console.log(`ð ÐÐ¾Ð¿ÑÑÐºÐ° ÑÐ¾Ð·Ð´Ð°Ð½Ð¸Ñ ÑÐ°ÑÐ°: ${messageData.chatId}`)
            
            // ÐÐ°Ð¹ÑÐ¸ ÑÐ¾Ð±ÐµÑÐµÐ´Ð½Ð¸ÐºÐ° (Ð½Ðµ ÑÐµÐºÑÑÐµÐ³Ð¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ)
            const otherUserId = participantIds.find(id => id !== user.id)
            const otherUser = otherUserId ? await User.findById(otherUserId).lean() : null
            const otherUserName = otherUser ? otherUser.username : "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾"
            
            chat = await Chat.create({
              _id: messageData.chatId,
              name: otherUserName, // ÐÑÐ¿Ð¾Ð»ÑÐ·ÑÐµÐ¼ Ð¸Ð¼Ñ ÑÐ¾Ð±ÐµÑÐµÐ´Ð½Ð¸ÐºÐ°
              avatar: otherUser?.avatar || null,
              description: `ÐÑÐ¸Ð²Ð°ÑÐ½ÑÐ¹ ÑÐ°Ñ Ñ ${otherUserName}`,
              isGroup: false,
              participants: participantIds,
              createdAt: new Date(),
              type: "private",
              isEncrypted: true,
              createdBy: user.id,
              theme: "default",
              isPinned: false,
              isMuted: false,
            })
            console.log(`â Ð§Ð°Ñ ÑÐ¾Ð·Ð´Ð°Ð½ Ð°Ð²ÑÐ¾Ð¼Ð°ÑÐ¸ÑÐµÑÐºÐ¸: ${chat._id} Ñ ÑÐ¾Ð±ÐµÑÐµÐ´Ð½Ð¸ÐºÐ¾Ð¼: ${otherUserName}`)
          }
        }
        
        if (!chat) {
          console.log(`â ÐÐµ ÑÐ´Ð°Ð»Ð¾ÑÑ ÑÐ¾Ð·Ð´Ð°ÑÑ ÑÐ°Ñ: ${messageData.chatId}`)
          socket.emit("error", { message: "Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½ Ð¸ Ð½Ðµ Ð¼Ð¾Ð¶ÐµÑ Ð±ÑÑÑ ÑÐ¾Ð·Ð´Ð°Ð½" })
          return
        }
      }
      
      console.log(`ð Ð£ÑÐ°ÑÑÐ½Ð¸ÐºÐ¸ ÑÐ°ÑÐ°:`, chat.participants)
      console.log(`ð¤ Ð¢ÐµÐºÑÑÐ¸Ð¹ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ: ${user.id}`)
      
      // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼, ÑÐ²Ð»ÑÐµÑÑÑ Ð»Ð¸ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÐ°ÑÐ°
      // ÐÐ»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° ÑÐ°Ð·ÑÐµÑÐ°ÐµÐ¼ Ð²ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÑÐ¼ Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÑÑÑ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ
      const isGlobalChat = messageData.chatId === "global"
      const isParticipant = isGlobalChat || chat.participants.some(p => p && p.toString() === user.id)
      if (!isParticipant) {
        console.log(`â ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ${user.username} Ð½Ðµ ÑÐ²Ð»ÑÐµÑÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÐ°ÑÐ° ${messageData.chatId}`)
        socket.emit("error", { message: "ÐÑ Ð½Ðµ ÑÐ²Ð»ÑÐµÑÐµÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÑÐ¾Ð³Ð¾ ÑÐ°ÑÐ°" })
        return
      }
      
      // Rate limiting Ð´Ð»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° (5 ÑÐµÐºÑÐ½Ð´ Ð¼ÐµÐ¶Ð´Ñ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸ÑÐ¼Ð¸)
      if (isGlobalChat) {
        const now = Date.now();
        const lastTimestamp = globalChatRateLimit.get(user.id) || 0;
        if (now - lastTimestamp < 5000) { // 5 ÑÐµÐºÑÐ½Ð´
          socket.emit("error", { message: "Ð Ð¾Ð±ÑÐ¸Ð¹ ÑÐ°Ñ Ð¼Ð¾Ð¶Ð½Ð¾ Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÑÑÑ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ ÑÐ°Ð· Ð² 5 ÑÐµÐºÑÐ½Ð´!" });
          return;
        }
        globalChatRateLimit.set(user.id, now);
      }

      // ÐÐ³ÑÐ°Ð½Ð¸ÑÐµÐ½Ð¸Ðµ Ð½Ð° ÐºÐ¾Ð»Ð¸ÑÐµÑÑÐ²Ð¾ ÑÐ»Ð¾Ð² (100 ÑÐ»Ð¾Ð² Ð´Ð»Ñ Ð²ÑÐµÑ ÑÐ°ÑÐ¾Ð²)
      const originalContent = messageData.isEncrypted ? decryptMessage(messageData.content) : messageData.content;
      const wordCount = originalContent.split(/\s+/).filter(Boolean).length;
      if (wordCount > 100) {
        socket.emit("error", { message: "Ð¡Ð¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð½Ðµ Ð´Ð¾Ð»Ð¶Ð½Ð¾ ÑÐ¾Ð´ÐµÑÐ¶Ð°ÑÑ Ð±Ð¾Ð»ÐµÐµ 100 ÑÐ»Ð¾Ð²!" });
        return;
      }
      
      // ÐÐ°Ð»Ð¸Ð´Ð°ÑÐ¸Ñ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ
      if (!messageData.content || typeof messageData.content !== 'string' || messageData.content.trim().length === 0) {
        console.log(`â ÐÐµÐ²ÐµÑÐ½Ð¾Ðµ ÑÐ¾Ð´ÐµÑÐ¶Ð¸Ð¼Ð¾Ðµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ`)
        socket.emit("error", { message: "Ð¡Ð¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð½Ðµ Ð¼Ð¾Ð¶ÐµÑ Ð±ÑÑÑ Ð¿ÑÑÑÑÐ¼" })
        return
      }
      
      if (messageData.content.length > 1000) {
        socket.emit("error", { message: "Ð¡Ð¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ ÑÐ»Ð¸ÑÐºÐ¾Ð¼ Ð´Ð»Ð¸Ð½Ð½Ð¾Ðµ" })
        return
      }
      
      // Ð¡Ð¾Ð·Ð´Ð°ÑÑ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ - ÑÐ¾ÑÑÐ°Ð½ÑÐµÐ¼ ÐºÐ°Ðº ÐµÑÑÑ (ÑÐ¶Ðµ Ð·Ð°ÑÐ¸ÑÑÐ¾Ð²Ð°Ð½Ð½Ð¾Ðµ Ñ ÐºÐ»Ð¸ÐµÐ½ÑÐ°)
      const message = await Message.create({
        sender: user.id,
        chat: chat._id.toString(), // ÐÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ - ÑÐ¾ÑÑÐ°Ð½ÑÐµÐ¼ ÐºÐ°Ðº ÑÑÑÐ¾ÐºÑ
        content: messageData.content, // Ð¡Ð¾ÑÑÐ°Ð½ÑÐµÐ¼ Ð·Ð°ÑÐ¸ÑÑÐ¾Ð²Ð°Ð½Ð½Ð¾Ðµ ÑÐ¾Ð´ÐµÑÐ¶Ð¸Ð¼Ð¾Ðµ
        timestamp: new Date(),
        type: messageData.type || "text",
        fileUrl: messageData.fileUrl,
        fileName: messageData.fileName,
        fileSize: messageData.fileSize,
        isEncrypted: messageData.isEncrypted || false,
        replyTo: messageData.replyTo?.id,
        reactions: [],
        readBy: [user.id],
        isEdited: false,
      })
      
      console.log(`â Ð¡Ð¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ ÑÐ¾Ð·Ð´Ð°Ð½Ð¾ Ð² ÐÐ: ${message._id}`)
      
      // Ð¤Ð¾ÑÐ¼Ð¸ÑÑÐµÐ¼ replyTo Ð´Ð»Ñ UI, ÐµÑÐ»Ð¸ ÑÑÐ¾ Ð¾ÑÐ²ÐµÑ
      let replyToData = null;
      if (message.replyTo) {
        const originalMsg = await Message.findById(message.replyTo).lean();
        if (originalMsg) {
          let senderName = "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾";
          if (originalMsg.sender) {
            const senderUser = await User.findById(originalMsg.sender).lean();
            senderName = senderUser?.username || senderUser?.fullName || "ÐÐµÐ¸Ð·Ð²ÐµÑÑÐ½Ð¾";
          }
          replyToData = {
            id: originalMsg._id?.toString() || originalMsg._id,
            content: originalMsg.isEncrypted ? decryptMessage(originalMsg.content) : originalMsg.content,
            senderName,
          };
        }
      }
      
      const msgObj = {
        ...message.toObject(),
        id: message._id?.toString() || message._id,
        senderId: user.id,
        senderName: user.username,
        chatId: chat._id?.toString() || chat._id,
        content: messageData.content, // ÐÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ ÐºÐ°Ðº ÐµÑÑÑ - ÐºÐ»Ð¸ÐµÐ½Ñ ÑÐ°Ð¼ ÑÐ°ÑÑÐ¸ÑÑÑÐµÑ
        replyTo: replyToData,
      }
      
      console.log(`ð¤ ÐÑÐ¿ÑÐ°Ð²ÐºÐ° ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ Ð² ÐºÐ¾Ð¼Ð½Ð°ÑÑ: ${chat._id}`)
      console.log(`ð¤ Ð¡Ð¾Ð´ÐµÑÐ¶Ð¸Ð¼Ð¾Ðµ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ:`, msgObj)
      
      // ÐÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð²ÑÐµÐ¼ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ°Ð¼ ÑÐ°ÑÐ°
      io.to(chat._id.toString()).emit("new_message", msgObj)
      
      // ÐÐ»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ° ÑÐ°ÐºÐ¶Ðµ Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ Ð²ÑÐµÐ¼ Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð½ÑÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÑÐ¼
      if (isGlobalChat) {
        console.log(`ð ÐÑÐ¿ÑÐ°Ð²ÐºÐ° ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ Ð²Ð¾ Ð²ÑÐµ Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ñ Ð´Ð»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°`)
        io.emit("new_message", msgObj)
      }
      
      // ÐÑÐ»Ð¸ ÑÐ°Ñ Ð¿ÑÐ¸Ð²Ð°ÑÐ½ÑÐ¹, Ð¾ÑÐ¿ÑÐ°Ð²Ð¸ÑÑ ÑÐ¾Ð±ÑÑÐ¸Ðµ 'new_private_chat' Ð²ÑÐ¾ÑÐ¾Ð¼Ñ ÑÑÐ°ÑÑÐ½Ð¸ÐºÑ
      if (chat.type === "private") {
        console.log(`ð¬ ÐÑÐ¸Ð²Ð°ÑÐ½ÑÐ¹ ÑÐ°Ñ, ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¸:`, chat.participants)
        chat.participants.forEach((participantId) => {
          if (participantId.toString() !== user.id) {
            console.log(`ð ÐÑÐµÐ¼ ÑÐ¾ÐºÐµÑ Ð´Ð»Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ: ${participantId}`)
            const targetSocket = Array.from(io.sockets.sockets.values()).find((s) => s.userId === participantId.toString());
            if (targetSocket) {
              console.log(`â ÐÐ°Ð¹Ð´ÐµÐ½ ÑÐ¾ÐºÐµÑ Ð´Ð»Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ${participantId}, Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ ÑÐ²ÐµÐ´Ð¾Ð¼Ð»ÐµÐ½Ð¸Ðµ Ð¾ Ð½Ð¾Ð²Ð¾Ð¼ ÑÐ°ÑÐµ`)
              // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼, ÐµÑÑÑ Ð»Ð¸ Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ÑÑÐ¾Ñ ÑÐ°Ñ (Ð¼Ð¾Ð¶Ð½Ð¾ Ð´Ð¾Ð±Ð°Ð²Ð¸ÑÑ Ð¿ÑÐ¾Ð²ÐµÑÐºÑ, ÐµÑÐ»Ð¸ Ð½ÑÐ¶Ð½Ð¾)
              targetSocket.emit("new_private_chat", {
                ...chat,
                id: chat._id?.toString() || chat._id,
                participants: chat.participants,
              });
            } else {
              console.log(`â ï¸ Ð¡Ð¾ÐºÐµÑ Ð´Ð»Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ${participantId} Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½`)
            }
          }
        });
      }
      
      console.log(`ð¬ Ð¡Ð¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð¾Ñ ${user.username} Ð² ÑÐ°Ñ ${chat._id} Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÐµÐ½Ð¾ ÑÑÐ¿ÐµÑÐ½Ð¾`)
    } catch (error) {
      console.error("send_message error:", error)
      socket.emit("error", { message: "ÐÑÐ¸Ð±ÐºÐ° Ð¾ÑÐ¿ÑÐ°Ð²ÐºÐ¸ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ" })
    }
  })

  // Ð ÐµÐ°ÐºÑÐ¸Ð¸ Ð½Ð° ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ñ (MongoDB)
  socket.on("add_reaction", async (data) => {
    try {
      const { messageId, emoji, userId, username } = data
      if (userId !== user.id) return
      if (!emoji || !reactionEmojis.includes(emoji)) return
      // ÐÐ°Ð¹ÑÐ¸ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ
      const message = await Message.findById(messageId)
      if (!message) return
      // ÐÑÐ¾Ð²ÐµÑÐ¸ÑÑ, ÐµÑÑÑ Ð»Ð¸ ÑÐ¶Ðµ ÑÐµÐ°ÐºÑÐ¸Ñ Ð¾Ñ ÑÑÐ¾Ð³Ð¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ
      const existing = message.reactions.find(
        (r) => r.userId === userId && r.emoji === emoji
      )
      if (existing) {
        // Ð£Ð´Ð°Ð»Ð¸ÑÑ ÑÐµÐ°ÐºÑÐ¸Ñ
        message.reactions = message.reactions.filter(
          (r) => !(r.userId === userId && r.emoji === emoji)
        )
      } else {
        // ÐÐ¾Ð±Ð°Ð²Ð¸ÑÑ ÑÐµÐ°ÐºÑÐ¸Ñ
        message.reactions.push({ emoji, userId, username })
      }
      await message.save()
      const chatId = message.chat?.toString() || message.chat
      io.to(chatId).emit("message_reaction", {
        messageId: message._id?.toString() || message._id,
        reactions: message.reactions,
      })
    } catch (error) {
      console.error("add_reaction error:", error)
    }
  })

  // ÐÐµÑÐ°ÑÐ°ÐµÑ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ (MongoDB check)
  socket.on("typing", async (data) => {
    try {
      const { chatId, userId, username } = data
      const chat = await Chat.findById(chatId)
      if (!chat) return
      if (!chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)) return
      if (!typingUsers.has(chatId)) {
        typingUsers.set(chatId, new Set())
      }
      typingUsers.get(chatId).add(userId)
      socket.to(chatId).emit("user_typing", { userId, username, chatId })
    } catch (error) {
      console.error("typing error:", error)
    }
  })

  // ÐÐµÑÐµÑÑÐ°Ð» Ð¿ÐµÑÐ°ÑÐ°ÑÑ (MongoDB check)
  socket.on("stop_typing", async (data) => {
    try {
      const { chatId } = data
      const chat = await Chat.findById(chatId)
      if (!chat) return
      if (!chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)) return
      if (typingUsers.has(chatId)) {
        typingUsers.get(chatId).delete(user.id)
        if (typingUsers.get(chatId).size === 0) {
          typingUsers.delete(chatId)
        }
      }
      socket.to(chatId).emit("user_stop_typing", { userId: user.id, chatId })
    } catch (error) {
      console.error("stop_typing error:", error)
    }
  })

  // ÐÑÐ¸ÑÑÐºÐ° ÑÐ°ÑÐ° (MongoDB)
  socket.on("clear_chat", async (chatId) => {
    try {
      const chat = await Chat.findById(chatId)
      if (!chat) return
      
      // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼ Ð¿ÑÐ°Ð²Ð° Ð´Ð»Ñ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°
      const isGlobalChat = chatId === "global"
      const isAdmin = user.isAdmin
      const isParticipant = chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)
      const isCreator = chat.createdBy?.toString() === user.id
      
      if (isGlobalChat && !isAdmin) {
        socket.emit("error", { message: "Ð¢Ð¾Ð»ÑÐºÐ¾ Ð°Ð´Ð¼Ð¸Ð½Ð¸ÑÑÑÐ°ÑÐ¾Ñ Ð¼Ð¾Ð¶ÐµÑ Ð¾ÑÐ¸ÑÐ°ÑÑ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ" })
        return
      }
      
      if (!isParticipant && !isCreator && !isGlobalChat) {
        socket.emit("error", { message: "ÐÐµÑ Ð¿ÑÐ°Ð² Ð´Ð»Ñ Ð¾ÑÐ¸ÑÑÐºÐ¸ ÑÑÐ¾Ð³Ð¾ ÑÐ°ÑÐ°" })
        return
      }
      
      await Message.deleteMany({ chat: chatId })
      io.to(chatId).emit("chat_cleared", { chatId })
      console.log(`ð§¹ Ð§Ð°Ñ ${chatId} Ð¾ÑÐ¸ÑÐµÐ½ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¼ ${user.username}`)
    } catch (error) {
      console.error("clear_chat error:", error)
    }
  })

  // ÐÐ±Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ðµ Ð½Ð°ÑÑÑÐ¾ÐµÐº ÑÐ°ÑÐ°
  socket.on("update_chat_settings", async (data) => {
    try {
      const { chatId, isPinned, isMuted } = data
      const chat = await Chat.findById(chatId)
      if (!chat) return
      
      // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼ Ð¿ÑÐ°Ð²Ð°
      const isParticipant = chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)
      const isCreator = chat.createdBy?.toString() === user.id
      
      if (!isParticipant && !isCreator) {
        socket.emit("error", { message: "ÐÐµÑ Ð¿ÑÐ°Ð² Ð´Ð»Ñ Ð¸Ð·Ð¼ÐµÐ½ÐµÐ½Ð¸Ñ Ð½Ð°ÑÑÑÐ¾ÐµÐº ÑÐ°ÑÐ°" })
        return
      }
      
      const updateData = {}
      if (isPinned !== undefined) updateData.isPinned = isPinned
      if (isMuted !== undefined) updateData.isMuted = isMuted
      
      await Chat.findByIdAndUpdate(chatId, updateData)
      
      // Ð£Ð²ÐµÐ´Ð¾Ð¼Ð»ÑÐµÐ¼ Ð²ÑÐµÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð² ÑÐ°ÑÐ° Ð¾Ð± Ð¸Ð·Ð¼ÐµÐ½ÐµÐ½Ð¸Ð¸
      io.to(chatId).emit("chat_settings_updated", {
        chatId,
        isPinned,
        isMuted
      })
      
      console.log(`âï¸ ÐÐ°ÑÑÑÐ¾Ð¹ÐºÐ¸ ÑÐ°ÑÐ° ${chatId} Ð¾Ð±Ð½Ð¾Ð²Ð»ÐµÐ½Ñ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¼ ${user.username}`)
    } catch (error) {
      console.error("update_chat_settings error:", error)
    }
  })

  // Heartbeat Ð´Ð»Ñ Ð¾ÑÑÐ»ÐµÐ¶Ð¸Ð²Ð°Ð½Ð¸Ñ Ð°ÐºÑÐ¸Ð²Ð½Ð¾ÑÑÐ¸
  socket.on("heartbeat", () => {
    userHeartbeats.set(user.id, Date.now())
  })

  // ÐÐ±Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ðµ Ð¿ÑÐ¾ÑÐ¸Ð»Ñ (MongoDB)
  socket.on("update_profile", async (userData) => {
    try {
      // ÐÐ°Ð»Ð¸Ð´Ð°ÑÐ¸Ñ Ð´Ð°Ð½Ð½ÑÑ Ð¿ÑÐ¾ÑÐ¸Ð»Ñ
      const allowedFields = ['fullName', 'bio', 'avatar']
      const sanitizedData = {}
      for (const field of allowedFields) {
        if (userData[field] !== undefined) {
          if (field === 'fullName' && userData[field]) {
            sanitizedData[field] = userData[field].trim().substring(0, 50)
          } else if (field === 'bio' && userData[field]) {
            sanitizedData[field] = userData[field].trim().substring(0, 200)
          } else {
            sanitizedData[field] = userData[field]
          }
        }
      }
      await User.findByIdAndUpdate(user.id, sanitizedData)
      // ÐÐ±Ð½Ð¾Ð²Ð»ÑÐµÐ¼ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð²Ð¾ Ð²ÑÐµÑ ÑÐ°ÑÐ°Ñ (MongoDB Ð½Ðµ ÑÑÐµÐ±ÑÐµÑ ÑÑÐ¾Ð³Ð¾, Ð½Ð¾ Ð¼Ð¾Ð¶Ð½Ð¾ Ð¾Ð±Ð½Ð¾Ð²Ð¸ÑÑ Ð² Ð¿Ð°Ð¼ÑÑÐ¸)
      // Ð£Ð²ÐµÐ´Ð¾Ð¼Ð»ÑÐµÐ¼ Ð²ÑÐµÑ Ð¾Ð± Ð¾Ð±Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ð¸
      const activeUsers = await User.find({ isOnline: true }).lean()
      io.emit("users_update", activeUsers.map((u) => ({
        id: u._id.toString(),
        username: u.username,
        fullName: u.fullName,
        email: u.email,
        avatar: u.avatar,
        isOnline: u.isOnline,
        isVerified: u.isVerified,
        status: u.status,
      })))
      console.log(`ð¤ ${user.username} Ð¾Ð±Ð½Ð¾Ð²Ð¸Ð» Ð¿ÑÐ¾ÑÐ¸Ð»Ñ`)
    } catch (error) {
      console.error("update_profile error:", error)
    }
  })

  // ÐÑÐºÐ»ÑÑÐµÐ½Ð¸Ðµ
  socket.on("disconnect", async () => {
    activeConnections.delete(socket.id)
    // Ð£Ð´Ð°Ð»ÑÐµÐ¼ Ð¸Ð· Ð²ÑÐµÑ typing lists
    for (const [chatId, typingSet] of typingUsers.entries()) {
      if (typingSet.has(user.id)) {
        typingSet.delete(user.id)
        if (typingSet.size === 0) {
          typingUsers.delete(chatId)
        }
        socket.to(chatId).emit("user_stop_typing", { userId: user.id, chatId })
      }
    }
    // ÐÐ±Ð½Ð¾Ð²Ð¸ÑÑ ÑÑÐ°ÑÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð² MongoDB
    await User.findByIdAndUpdate(user.id, { isOnline: false, lastSeen: new Date(), status: "offline" })
    // Ð£Ð´Ð°Ð»ÑÐµÐ¼ Ð¸Ð· heartbeat tracking
    userHeartbeats.delete(user.id)
    globalChatOnline.delete(socket.id);
    io.to('global').emit('global_online_count', globalChatOnline.size);
    // ÐÐ±Ð½Ð¾Ð²Ð»ÑÐµÐ¼ ÑÐ¿Ð¸ÑÐ¾Ðº Ð°ÐºÑÐ¸Ð²Ð½ÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹
    const activeUsers = await User.find({ isOnline: true }).lean()
    io.emit("users_update", activeUsers.map((u) => ({
      id: u._id.toString(),
      username: u.username,
      fullName: u.fullName,
      email: u.email,
      avatar: u.avatar,
      isOnline: u.isOnline,
      isVerified: u.isVerified,
      status: u.status,
    })))
    console.log(`ð ÐÑÐºÐ»ÑÑÐµÐ½Ð¸Ðµ: ${user.username}`)
  })
})

// Ð¤ÑÐ½ÐºÑÐ¸Ñ Ð¾ÑÐ¸ÑÑÐºÐ¸ Ð½ÐµÐ°ÐºÑÐ¸Ð²Ð½ÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹
const cleanupInactiveUsers = async () => {
  try {
    const now = Date.now()
    const inactiveThreshold = 30000 // 30 ÑÐµÐºÑÐ½Ð´ Ð±ÐµÐ· Ð°ÐºÑÐ¸Ð²Ð½Ð¾ÑÑÐ¸
    
    for (const [userId, lastHeartbeat] of userHeartbeats.entries()) {
      if (now - lastHeartbeat > inactiveThreshold) {
        // ÐÐ¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ Ð½ÐµÐ°ÐºÑÐ¸Ð²ÐµÐ½, Ð¾Ð±Ð½Ð¾Ð²Ð»ÑÐµÐ¼ ÑÑÐ°ÑÑÑ
        await User.findByIdAndUpdate(userId, { 
          isOnline: false, 
          lastSeen: new Date(), 
          status: "offline" 
        })
        userHeartbeats.delete(userId)
        activeConnections.delete(userId)
        console.log(`ð ÐÐ²ÑÐ¾Ð¼Ð°ÑÐ¸ÑÐµÑÐºÐ¾Ðµ Ð¾ÑÐºÐ»ÑÑÐµÐ½Ð¸Ðµ Ð½ÐµÐ°ÐºÑÐ¸Ð²Ð½Ð¾Ð³Ð¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ: ${userId}`)
      }
    }
    
    // ÐÐ±Ð½Ð¾Ð²Ð»ÑÐµÐ¼ ÑÐ¿Ð¸ÑÐ¾Ðº Ð°ÐºÑÐ¸Ð²Ð½ÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹
    const activeUsers = await User.find({ isOnline: true }).lean()
    io.emit("users_update", activeUsers.map((u) => ({
      id: u._id.toString(),
      username: u.username,
      fullName: u.fullName,
      email: u.email,
      avatar: u.avatar,
      isOnline: u.isOnline,
      isVerified: u.isVerified,
      status: u.status,
    })))
  } catch (error) {
    console.error("cleanupInactiveUsers error:", error)
  }
}

// ÐÐ°Ð¿ÑÑÐºÐ°ÐµÐ¼ Ð¾ÑÐ¸ÑÑÐºÑ ÐºÐ°Ð¶Ð´ÑÐµ 30 ÑÐµÐºÑÐ½Ð´
setInterval(cleanupInactiveUsers, 30000)

// ÐÐ²ÑÐ¾Ð¾ÑÐ¸ÑÑÐºÐ° Ð¾Ð±ÑÐµÐ³Ð¾ ÑÐ°ÑÐ° Ð¾ÑÐºÐ»ÑÑÐµÐ½Ð° - ÑÐ°Ñ ÑÐµÐ¿ÐµÑÑ Ð¿Ð¾ÑÑÐ¾ÑÐ½Ð½ÑÐ¹
// let lastGlobalChatCleanupDay = null;
// setInterval(async () => {
//   const now = new Date();
//   if (now.getHours() === 4 && now.getMinutes() === 0) {
//     const today = now.toISOString().slice(0, 10);
//     if (lastGlobalChatCleanupDay !== today) {
//       await Message.deleteMany({ chat: 'global' });
//       io.to('global').emit('chat_cleared', { chatId: 'global' });
//       lastGlobalChatCleanupDay = today;
//       console.log('ð ÐÐ±ÑÐ¸Ð¹ ÑÐ°Ñ Ð°Ð²ÑÐ¾Ð¼Ð°ÑÐ¸ÑÐµÑÐºÐ¸ Ð¾ÑÐ¸ÑÐµÐ½ Ð² 4:00 ÑÑÑÐ°');
//     }
//   }
// }, 60 * 1000);

// ÐÐ°Ð¿ÑÑÐº ÑÐµÑÐ²ÐµÑÐ°
server.listen(PORT, async () => {
  // ÐÑÐ¸ÑÐ°ÐµÐ¼ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð¿ÑÐ¸ Ð·Ð°Ð¿ÑÑÐºÐµ
  try {
    await Message.deleteMany({ chat: 'global' });
    console.log('ð ÐÐ»Ð¾Ð±Ð°Ð»ÑÐ½ÑÐ¹ ÑÐ°Ñ Ð¾ÑÐ¸ÑÐµÐ½ Ð¿ÑÐ¸ Ð·Ð°Ð¿ÑÑÐºÐµ ÑÐµÑÐ²ÐµÑÐ°');
  } catch (error) {
    console.error('ÐÑÐ¸Ð±ÐºÐ° Ð¾ÑÐ¸ÑÑÐºÐ¸ Ð³Ð»Ð¾Ð±Ð°Ð»ÑÐ½Ð¾Ð³Ð¾ ÑÐ°ÑÐ°:', error);
  }
  
  console.log(`
ð ACTOGRAM Server v3.0 Ð·Ð°Ð¿ÑÑÐµÐ½ Ð½Ð° Ð¿Ð¾ÑÑÑ ${PORT}
ð± ÐÐ»Ð¸ÐµÐ½Ñ: https://acto-uimuz.vercel.app  
ð Ð¡ÐµÑÐ²ÐµÑ: https://actogr.onrender.com
ð ÐÐµÐ·Ð¾Ð¿Ð°ÑÐ½Ð¾ÑÑÑ: JWT + Bcrypt + Rate Limiting + E2E Encryption
â¨ ÐÐ¾Ð²ÑÐµ ÑÑÐ½ÐºÑÐ¸Ð¸: Ð ÐµÐ°ÐºÑÐ¸Ð¸, ÑÐ»ÑÑÑÐµÐ½Ð½ÑÐ¹ UI, Ð¼Ð½Ð¾Ð³Ð¾ÑÐ·ÑÑÐ½Ð¾ÑÑÑ
ð¡ï¸ Ð¡ÑÐ°ÑÑÑ: ÐÐ¾Ð»Ð½Ð¾ÑÑÑÑ Ð·Ð°ÑÐ¸ÑÐµÐ½ Ð¸ Ð³Ð¾ÑÐ¾Ð² Ðº ÑÐ°Ð±Ð¾ÑÐµ
  `)
})

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM Ð¿Ð¾Ð»ÑÑÐµÐ½, Ð·Ð°Ð²ÐµÑÑÐ°ÐµÐ¼ ÑÐ°Ð±Ð¾ÑÑ ÑÐµÑÐ²ÐµÑÐ°...")
  server.close(() => {
    console.log("Ð¡ÐµÑÐ²ÐµÑ ÑÑÐ¿ÐµÑÐ½Ð¾ Ð·Ð°Ð²ÐµÑÑÐ¸Ð» ÑÐ°Ð±Ð¾ÑÑ")
    process.exit(0)
  })
})

process.on("SIGINT", () => {
  console.log("SIGINT Ð¿Ð¾Ð»ÑÑÐµÐ½, Ð·Ð°Ð²ÐµÑÑÐ°ÐµÐ¼ ÑÐ°Ð±Ð¾ÑÑ ÑÐµÑÐ²ÐµÑÐ°...")
  server.close(() => {
    console.log("Ð¡ÐµÑÐ²ÐµÑ ÑÑÐ¿ÐµÑÐ½Ð¾ Ð·Ð°Ð²ÐµÑÑÐ¸Ð» ÑÐ°Ð±Ð¾ÑÑ")
    process.exit(0)
  })
})

// ÐÐ¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ðµ Ðº MongoDB Ñ Ð¾Ð±ÑÐ°Ð±Ð¾ÑÐºÐ¾Ð¹ Ð¾ÑÐ¸Ð±Ð¾Ðº
let connectionAttempts = 0
const maxConnectionAttempts = 5

const connectToMongoDB = async () => {
  try {
    connectionAttempts++;
    console.log(`ð ÐÐ¾Ð¿ÑÑÐºÐ° Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ñ Ðº MongoDB (${connectionAttempts}/${maxConnectionAttempts})`);
    await mongoose.connect("mongodb+srv://actogol:actogolsila@actogramuz.6ogftpx.mongodb.net/actogram?retryWrites=true&w=majority&appName=actogramUZ", {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    });
    console.log("â MongoDB Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½ ÑÑÐ¿ÐµÑÐ½Ð¾");
    connectionAttempts = 0; // Ð¡Ð±ÑÐ¾Ñ ÑÑÐµÑÑÐ¸ÐºÐ° Ð¿ÑÐ¸ ÑÑÐ¿ÐµÑÐ½Ð¾Ð¼ Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ð¸
    await ensureGlobalChat(); // <-- ÐÑÐ·Ð¾Ð² Ð·Ð´ÐµÑÑ!
  } catch (err) {
    console.error(`â ÐÑÐ¸Ð±ÐºÐ° Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ñ Ðº MongoDB (Ð¿Ð¾Ð¿ÑÑÐºÐ° ${connectionAttempts}):`, err.message);
    if (connectionAttempts >= maxConnectionAttempts) {
      console.error("ð« ÐÑÐµÐ²ÑÑÐµÐ½Ð¾ Ð¼Ð°ÐºÑÐ¸Ð¼Ð°Ð»ÑÐ½Ð¾Ðµ ÐºÐ¾Ð»Ð¸ÑÐµÑÑÐ²Ð¾ Ð¿Ð¾Ð¿ÑÑÐ¾Ðº Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ñ");
      console.log("ð¡ ÐÑÐ¾Ð²ÐµÑÑÑÐµ Ð½Ð°ÑÑÑÐ¾Ð¹ÐºÐ¸ MongoDB Atlas:");
      console.log("   1. IP Ð°Ð´ÑÐµÑÐ° Ð² Network Access");
      console.log("   2. ÐÑÐ°Ð²Ð¸Ð»ÑÐ½Ð¾ÑÑÑ ÑÑÑÐ¾ÐºÐ¸ Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ñ");
      console.log("   3. Ð¡ÑÐ°ÑÑÑ ÐºÐ»Ð°ÑÑÐµÑÐ°");
      return;
    }
    console.log(`â³ ÐÐ¾Ð²ÑÐ¾ÑÐ½Ð°Ñ Ð¿Ð¾Ð¿ÑÑÐºÐ° ÑÐµÑÐµÐ· 5 ÑÐµÐºÑÐ½Ð´...`);
    setTimeout(connectToMongoDB, 5000);
  }
};

connectToMongoDB();

// ÐÐ±ÑÐ°Ð±Ð¾ÑÐºÐ° Ð¾ÑÐ¸Ð±Ð¾Ðº Ð¿Ð¾Ð´ÐºÐ»ÑÑÐµÐ½Ð¸Ñ
mongoose.connection.on('error', (err) => {
  console.error('â MongoDB connection error:', err.message)
})

mongoose.connection.on('disconnected', () => {
  console.log('ð MongoDB disconnected')
  // ÐÐ¾Ð¿ÑÐ¾Ð±Ð¾Ð²Ð°ÑÑ Ð¿ÐµÑÐµÐ¿Ð¾Ð´ÐºÐ»ÑÑÐ¸ÑÑÑÑ
  if (connectionAttempts < maxConnectionAttempts) {
    setTimeout(connectToMongoDB, 5000)
  }
})

mongoose.connection.on('connected', () => {
  console.log('â MongoDB connected')
})

mongoose.connection.on('reconnected', () => {
  console.log('ð MongoDB reconnected')
})

const UserSchema = new Schema({
  email: { type: String, unique: true },
  username: { type: String, unique: true },
  fullName: String,
  bio: String,
  password: String,
  createdAt: { type: Date, default: Date.now },
  isVerified: Boolean,
  isOnline: Boolean,
  lastSeen: Date,
  avatar: String,
  status: String,
  isAdmin: { type: Boolean, default: false }, // <-- Ð½Ð¾Ð²Ð¾Ðµ Ð¿Ð¾Ð»Ðµ
});

const ChatSchema = new Schema({
  _id: { type: String, required: true },
  name: String,
  avatar: String,
  description: String,
  isGroup: Boolean,
  participants: [{ type: Schema.Types.ObjectId, ref: "User" }],
  createdAt: { type: Date, default: Date.now },
  type: String,
  isEncrypted: Boolean,
  createdBy: { type: Schema.Types.ObjectId, ref: "User" },
  theme: String,
  isPinned: Boolean,
  isMuted: Boolean,
});

const MessageSchema = new Schema({
  sender: { type: Schema.Types.ObjectId, ref: "User" },
  chat: { type: String, required: true }, // ÐÐ·Ð¼ÐµÐ½ÐµÐ½Ð¾ Ñ ObjectId Ð½Ð° String
  content: String,
  timestamp: { type: Date, default: Date.now },
  type: String,
  fileUrl: String,
  fileName: String,
  fileSize: Number,
  isEncrypted: Boolean,
  replyTo: { type: Schema.Types.ObjectId, ref: "Message" },
  reactions: [{ emoji: String, userId: String, username: String }],
  readBy: [String],
  isEdited: Boolean,
});

const User = model("User", UserSchema);
const Chat = model("Chat", ChatSchema);
const Message = model("Message", MessageSchema);

// Endpoint Ð´Ð»Ñ Ð¾ÑÐ¿ÑÐ°Ð²ÐºÐ¸ Ð½Ð¾Ð²Ð¾ÑÑÐ¸ Ð¾Ñ Ð±Ð¾ÑÐ° Ð²Ð¾ Ð²ÑÐµ ÑÐ°ÑÑ (ÑÐ¾Ð»ÑÐºÐ¾ Ð´Ð»Ñ Ð°Ð´Ð¼Ð¸Ð½Ð°)
app.post("/api/bot-news", authenticateToken, async (req, res) => {
  try {
    const { userId, username } = req.user
    if (username !== "@adminstator") {
      return res.status(403).json({ error: "Ð¢Ð¾Ð»ÑÐºÐ¾ Ð°Ð´Ð¼Ð¸Ð½ Ð¼Ð¾Ð¶ÐµÑ Ð¾ÑÐ¿ÑÐ°Ð²Ð»ÑÑÑ Ð½Ð¾Ð²Ð¾ÑÑÐ¸" })
    }
    const { text } = req.body
    if (!text || typeof text !== "string" || !text.trim()) {
      return res.status(400).json({ error: "Ð¢ÐµÐºÑÑ Ð½Ð¾Ð²Ð¾ÑÑÐ¸ Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÐµÐ½" })
    }
    await ensureBotUser()
    // ÐÐ°Ð¹ÑÐ¸ Ð²ÑÐµ Ð¿ÑÐ¸Ð²Ð°ÑÐ½ÑÐµ ÑÐ°ÑÑ Ð±Ð¾ÑÐ°
    const botChats = await Chat.find({
      isGroup: false,
      type: "private",
      participants: botUserId,
    })
    for (const chat of botChats) {
      await Message.create({
        sender: botUserId,
        chat: chat._id,
        content: text,
        timestamp: new Date(),
        type: "text",
        isEncrypted: false,
        readBy: [botUserId],
        isEdited: false,
      })
      // ÐÑÐ¿ÑÐ°Ð²Ð¸ÑÑ ÑÐµÑÐµÐ· Socket.IO
      io.to(chat._id.toString()).emit("new_message", {
        id: Date.now() + Math.random(),
        senderId: botUserId,
        senderName: "Actogram Bot",
        chatId: chat._id.toString(),
        content: text,
        timestamp: new Date(),
        type: "text",
        isEncrypted: false,
      })
    }
    res.json({ success: true, count: botChats.length })
  } catch (error) {
    console.error("bot-news error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° ÑÐ°ÑÑÑÐ»ÐºÐ¸ Ð½Ð¾Ð²Ð¾ÑÑÐ¸" })
  }
})

// Endpoint Ð´Ð»Ñ Ð±Ð°Ð½Ð° Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ (ÑÐ¾Ð»ÑÐºÐ¾ Ð´Ð»Ñ Ð°Ð´Ð¼Ð¸Ð½Ð°)
app.post("/api/ban-user", authenticateToken, async (req, res) => {
  try {
    const { username } = req.user
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: "Ð¢Ð¾Ð»ÑÐºÐ¾ Ð°Ð´Ð¼Ð¸Ð½ Ð¼Ð¾Ð¶ÐµÑ Ð±Ð°Ð½Ð¸ÑÑ" })
    }
    const { userId } = req.body
    if (!userId) return res.status(400).json({ error: "userId Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÐµÐ½" })
    await User.findByIdAndUpdate(userId, { status: "banned" })
    // ÐÑÐºÐ»ÑÑÐ¸ÑÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ, ÐµÑÐ»Ð¸ Ð¾Ð½ Ð¾Ð½Ð»Ð°Ð¹Ð½
    for (const [socketId, uid] of activeConnections.entries()) {
      if (uid === userId) {
        const s = io.sockets.sockets.get(socketId)
        if (s) s.disconnect(true)
      }
    }
    res.json({ success: true })
  } catch (error) {
    console.error("ban-user error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° Ð±Ð°Ð½Ð° Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ" })
  }
})

// Endpoint Ð´Ð»Ñ Ð¾ÑÐ¸ÑÑÐºÐ¸ Ð¾Ð±ÑÐµÐ³Ð¾ ÑÐ°ÑÐ° (Ð´Ð»Ñ Ð²ÑÐµÑ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»ÐµÐ¹)
app.post("/api/clear-global-chat", authenticateToken, async (req, res) => {
  try {
    await Message.deleteMany({ chat: 'global' });
    io.to('global').emit('chat_cleared', { chatId: 'global' });
    
    console.log('ð ÐÐ±ÑÐ¸Ð¹ ÑÐ°Ñ Ð¿Ð¾Ð»Ð½Ð¾ÑÑÑÑ Ð¾ÑÐ¸ÑÐµÐ½');
    res.json({ success: true, message: "ÐÐ±ÑÐ¸Ð¹ ÑÐ°Ñ Ð¿Ð¾Ð»Ð½Ð¾ÑÑÑÑ Ð¾ÑÐ¸ÑÐµÐ½" });
  } catch (error) {
    console.error("clear-global-chat error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° Ð¾ÑÐ¸ÑÑÐºÐ¸ Ð¾Ð±ÑÐµÐ³Ð¾ ÑÐ°ÑÐ°" })
  }
})

// Endpoint Ð´Ð»Ñ Ð·Ð°Ð³ÑÑÐ·ÐºÐ¸ Ð¸Ð·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ñ Ð² ÑÐ°Ñ
app.post("/api/upload-image", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    console.log("ð· ÐÐ°Ð¿ÑÐ¾Ñ Ð½Ð° Ð·Ð°Ð³ÑÑÐ·ÐºÑ Ð¸Ð·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ñ (Ð»Ð¾ÐºÐ°Ð»ÑÐ½Ð¾)")
    console.log("ð· Ð¤Ð°Ð¹Ð»:", req.file)
    console.log("ð· Body:", req.body)
    console.log("ð· User:", req.user)
    
    if (!req.file) {
      console.log("â Ð¤Ð°Ð¹Ð» Ð½Ðµ Ð·Ð°Ð³ÑÑÐ¶ÐµÐ½")
      return res.status(400).json({ error: "Ð¤Ð°Ð¹Ð» Ð½Ðµ Ð·Ð°Ð³ÑÑÐ¶ÐµÐ½" })
    }
    
    const userId = req.user.userId
    const { chatId } = req.body
    
    console.log("ð· ÐÐ°Ð½Ð½ÑÐµ:", { userId, chatId })
    
    if (!chatId) {
      console.log("â chatId Ð¾ÑÑÑÑÑÑÐ²ÑÐµÑ")
      return res.status(400).json({ error: "chatId Ð¾Ð±ÑÐ·Ð°ÑÐµÐ»ÐµÐ½" })
    }
    
    // ÐÑÐ¾Ð²ÐµÑÑÐµÐ¼, ÑÑÐ¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ñ ÑÐ²Ð»ÑÐµÑÑÑ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ¾Ð¼ ÑÐ°ÑÐ°
    const chat = await Chat.findById(chatId)
    if (!chat) {
      return res.status(404).json({ error: "Ð§Ð°Ñ Ð½Ðµ Ð½Ð°Ð¹Ð´ÐµÐ½" })
    }
    
    const isGlobalChat = chatId === "global"
    const isParticipant = isGlobalChat || chat.participants.some(p => p && p.toString() === userId)
    if (!isParticipant) {
      return res.status(403).json({ error: "ÐÐµÑ Ð´Ð¾ÑÑÑÐ¿Ð° Ðº ÑÑÐ¾Ð¼Ñ ÑÐ°ÑÑ" })
    }
    
    const imageUrl = `/avatars/${req.file.filename}`
    
    // Ð¡Ð¾Ð·Ð´Ð°ÐµÐ¼ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ñ Ð¸Ð·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸ÐµÐ¼
    const message = await Message.create({
      sender: userId,
      chat: chatId,
      content: `ð· ÐÐ·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ðµ`,
      timestamp: new Date(),
      type: "image",
      fileUrl: imageUrl,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      isEncrypted: false,
      reactions: [],
      readBy: [userId],
      isEdited: false,
    })
    
    // ÐÐ¾Ð»ÑÑÐ°ÐµÐ¼ Ð¸Ð½ÑÐ¾ÑÐ¼Ð°ÑÐ¸Ñ Ð¾ Ð¿Ð¾Ð»ÑÐ·Ð¾Ð²Ð°ÑÐµÐ»Ðµ
    const user = await User.findById(userId).lean()
    
    const msgObj = {
      ...message.toObject(),
      id: message._id?.toString() || message._id,
      senderId: userId,
      senderName: user.username,
      chatId: chatId,
      content: `ð· ÐÐ·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ðµ`,
      fileUrl: imageUrl,
      fileName: req.file.originalname,
      fileSize: req.file.size,
    }
    
    // ÐÑÐ¿ÑÐ°Ð²Ð»ÑÐµÐ¼ ÑÐ¾Ð¾Ð±ÑÐµÐ½Ð¸Ðµ Ð²ÑÐµÐ¼ ÑÑÐ°ÑÑÐ½Ð¸ÐºÐ°Ð¼ ÑÐ°ÑÐ°
    io.to(chatId).emit("new_message", msgObj)
    
    res.json({ 
      success: true, 
      message: msgObj,
      imageUrl: imageUrl 
    })
    
    console.log(`ð· ÐÐ·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ðµ Ð·Ð°Ð³ÑÑÐ¶ÐµÐ½Ð¾ (Ð»Ð¾ÐºÐ°Ð»ÑÐ½Ð¾): ${user.username} -> ${chatId}`)
  } catch (error) {
    console.error("upload-image error:", error)
    res.status(500).json({ error: "ÐÑÐ¸Ð±ÐºÐ° Ð·Ð°Ð³ÑÑÐ·ÐºÐ¸ Ð¸Ð·Ð¾Ð±ÑÐ°Ð¶ÐµÐ½Ð¸Ñ" })
  }
})
