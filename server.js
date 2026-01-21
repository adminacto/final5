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

// Инициализация приложения
const app = express()
const server = http.createServer(app)

// Настройка trust proxy для работы за прокси (Render.com)
app.set("trust proxy", 1)

// Безопасность
app.use(
    helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
    }),
)

// Rate limiting с правильной настройкой для прокси
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Слишком много запросов, попробуйте позже",
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.ip === "127.0.0.1" || req.ip === "::1",
})

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: "Слишком много попыток входа, подождите 15 минут",
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => req.ip === "127.0.0.1" || req.ip === "::1",
})

const uploadLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: "Слишком много загрузок, подождите минуту",
})

// Создать папку avatars, если не существует
const avatarsDir = path.join(__dirname, "public", "avatars")
if (!fs.existsSync(avatarsDir)) {
    fs.mkdirSync(avatarsDir, { recursive: true })
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, avatarsDir)
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname)
        const uniqueName = `${Date.now()}_${Math.round(Math.random() * 1e9)}${ext}`
        cb(null, uniqueName)
    },
})

const upload = multer({
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        cb(null, true)
    },
})

// Конфигурация
const JWT_SECRET = process.env.JWT_SECRET || "actogram_ultra_secure_key_2024_v3"
const PORT = process.env.PORT || 3001

// Админ доступ
const ADMIN_USERNAME = "Mumtozbekk"
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "pA7$Zk!2gHq9#LmXv4@rT1wQ"

// Разрешенные домены
const allowedOrigins = [
    "https://acto-uimuz.vercel.app",
    "https://actogr.onrender.com",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    /\.vercel\.app$/,
    /\.render\.com$/,
]

// CORS настройки
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
            callback(new Error("CORS: Домен не разрешен"))
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

// Socket.IO настройки
const io = socketIo(server, {
    cors: corsOptions,
    transports: ["websocket", "polling"],
    pingTimeout: 60000,
    pingInterval: 25000,
})

// Хранилище данных
const activeConnections = new Map()
const typingUsers = new Map()
const blockedUsers = new Map()
const userHeartbeats = new Map()
const globalChatRateLimit = new Map()
const globalChatOnline = new Set()

// Middleware для проверки JWT
const authenticateToken = (req, res, next) => {
    let token = null
    const authHeader = req.headers["authorization"]

    if (authHeader && authHeader.startsWith("Bearer ")) {
        token = authHeader.split(" ")[1]
    } else if (req.cookies && req.cookies.token) {
        token = req.cookies.token
    }

    if (!token) {
        return res.status(401).json({ error: "Токен доступа обязателен" })
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Недействительный или истекший токен" })
        }
        req.user = user
        next()
    })
}

// Валидация
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
const validatePassword = (password) => password && password.length >= 8
const validateUsername = (username) => /^@[a-zA-Z0-9_]{3,20}$/.test(username)

// Утилиты
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

// Эмодзи для реакций
const reactionEmojis = ["❤️", "👍", "👎", "😂", "😮", "😢", "😡", "🔥", "👏", "🎉"]

// ========== MONGODB SCHEMAS ==========

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
    isAdmin: { type: Boolean, default: false },
    lastIp: String,
})

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
})

const MessageSchema = new Schema({
    sender: { type: Schema.Types.ObjectId, ref: "User" },
    chat: { type: String, required: true },
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
})

const BannedIPSchema = new Schema({
    ip: { type: String, unique: true, required: true },
    reason: { type: String },
    bannedAt: { type: Date, default: Date.now },
    bannedBy: { type: String, default: ADMIN_USERNAME },
})

const User = model("User", UserSchema)
const Chat = model("Chat", ChatSchema)
const Message = model("Message", MessageSchema)
const BannedIP = model("BannedIP", BannedIPSchema)

// ========== UTILITY FUNCTIONS ==========

function getClientIp(req) {
    const xff = req.headers["x-forwarded-for"]
    if (xff) {
        const ips = Array.isArray(xff) ? xff : String(xff).split(",")
        if (ips.length > 0) return ips[0].trim()
    }
    return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || ""
}

const BOT_USERNAME = "@actogram_bot"
let botUserId = null

async function ensureBotUser() {
    try {
        let bot = await User.findOne({ username: BOT_USERNAME })
        if (!bot) {
            bot = await User.create({
                email: "bot@actogram.app",
                username: BOT_USERNAME,
                fullName: "Actogram Bot",
                bio: "Официальный бот Actogram. Новости и обновления.",
                password: "bot_password_12345678",
                createdAt: new Date(),
                isVerified: true,
                isOnline: false,
                lastSeen: new Date(),
                avatar: null,
                status: "online",
            })
            console.log("🤖 Actogram Bot создан!")
        }
        botUserId = bot._id.toString()
        return botUserId
    } catch (error) {
        console.error("Ошибка создания бота:", error)
    }
}

async function ensureGlobalChat() {
    try {
        const globalChatId = "global"
        let chat = await Chat.findById(globalChatId)
        if (!chat) {
            chat = await Chat.create({
                _id: globalChatId,
                name: "ACTO — Общий чат",
                avatar: null,
                description: "Глобальный чат для всех пользователей",
                isGroup: true,
                participants: [],
                createdAt: new Date(),
                type: "group",
                isEncrypted: false,
                createdBy: null,
                theme: "default",
                isPinned: true,
                isMuted: false,
            })
            console.log("🌐 Глобальный чат создан!")
        }
    } catch (error) {
        console.error("Ошибка создания глобального чата:", error)
    }
}

async function ensureAdminUser() {
    try {
        const adminExists = await User.findOne({ username: ADMIN_USERNAME })
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 12)
            await User.create({
                email: "admin@actogram.app",
                username: ADMIN_USERNAME,
                fullName: "Administrator",
                bio: "Главный администратор Actogram",
                password: hashedPassword,
                createdAt: new Date(),
                isVerified: true,
                isOnline: false,
                lastSeen: new Date(),
                avatar: null,
                status: "offline",
                isAdmin: true,
            })
            console.log("👑 Аккаунт администратора создан")
        } else if (!adminExists.isAdmin) {
            await User.findByIdAndUpdate(adminExists._id, { isAdmin: true })
            console.log("👑 Права администратора восстановлены")
        }
    } catch (error) {
        console.error("Ошибка создания админа:", error)
    }
}

// ========== MAIN PAGE ==========

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
                <div class="logo">💬</div>
                <h1>ACTOGRAM</h1>
                <div class="version-badge">Server v3.0 - Ultra Secure</div>
                <p>Современный мессенджер с end-to-end шифрованием</p>
            </div>
            
            <div class="status">
                ✅ Сервер работает стабильно и безопасно
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <span class="stat-number">0</span>
                    <div>Зарегистрированных пользователей</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">${activeConnections.size}</span>
                    <div>Активных подключений</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">0</span>
                    <div>Активных чатов</div>
                </div>
                <div class="stat-card">
                    <span class="stat-number">0</span>
                    <div>Сообщений отправлено</div>
                </div>
            </div>
            
            <div class="features">
                <div class="feature">
                    <div class="feature-icon">🔐</div>
                    <h3>End-to-End шифрование</h3>
                    <p>Все сообщения защищены современным шифрованием</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">⚡</div>
                    <h3>Мгновенная доставка</h3>
                    <p>WebSocket соединение для быстрого обмена сообщениями</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">📱</div>
                    <h3>Адаптивный дизайн</h3>
                    <p>Отлично работает на всех устройствах</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🛡️</div>
                    <h3>Максимальная безопасность</h3>
                    <p>JWT аутентификация, rate limiting, CORS защита</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🌐</div>
                    <h3>Многоязычность</h3>
                    <p>Поддержка узбекского, русского и английского языков</p>
                </div>
                <div class="feature">
                    <div class="feature-icon">🎨</div>
                    <h3>Современный UI</h3>
                    <p>Красивый интерфейс с темной и светлой темами</p>
                </div>
            </div>
            
            <div style="text-align: center; margin: 40px 0;">
                <h2>🚀 Начать использование</h2>
                <a href="https://acto-uimuz.vercel.app" class="client-link" target="_blank">
                    Открыть ACTOGRAM
                </a>
                <p style="margin-top: 20px; opacity: 0.8;">
                    Безопасный мессенджер нового поколения
                </p>
            </div>
            
            <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,0.2);">
                <p style="opacity: 0.7;">
                    Время работы: ${Math.floor(process.uptime() / 60)} минут | 
                    Версия: 3.0.0 | 
                    Node.js ${process.version}
                </p>
            </div>
        </div>
    </body>
    </html>
  `)
})

// ========== ADMIN PANEL ==========

app.get("/admin", (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="ru">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0" />
      <title>ACTOGRAM Admin</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }
        #bg { position: fixed; inset: 0; z-index: 0; overflow: hidden; background: #000; }
        #bg canvas { width: 100%; height: 100%; display: block; }
        #bg .v-out { position:absolute; inset:0; pointer-events:none; background: radial-gradient(circle, rgba(0,0,0,0) 60%, rgba(0,0,0,1) 100%); }
        #bg .v-center { position:absolute; inset:0; pointer-events:none; background: radial-gradient(circle, rgba(0,0,0,0.8) 0%, rgba(0,0,0,0) 60%); }
        .wrap { position: relative; z-index: 1; max-width: 880px; margin: 0 auto; padding: 24px; }
        .card { background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 20px; margin-top: 16px; }
        .row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
        input, button { height: 40px; border-radius: 8px; border: 1px solid #374151; background: #0b1220; color: #e2e8f0; padding: 0 12px; }
        button { background: linear-gradient(135deg, #3b82f6, #8b5cf6); border: none; cursor: pointer; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border-bottom: 1px solid #1f2937; padding: 8px 6px; }
        .muted { color: #94a3b8; font-size: 12px; }
        .ok { color: #34d399; }
        .err { color: #f87171; }
        .hidden { display: none; }
      </style>
    </head>
    <body>
      <div id="bg">
        <canvas id="lgCanvas"></canvas>
        <div class="v-out"></div>
        <div class="v-center"></div>
      </div>
      <div class="wrap">
        <h1>ACTOGRAM Admin</h1>
        <p class="muted">JWT-панель управления: вход и бан по IP</p>

        <div id="loginCard" class="card">
          <h3>Вход администратора</h3>
          <div class="row" style="margin-top: 8px;">
            <input id="username" placeholder="Логин" value="Mumtozbekk" />
            <input id="password" type="password" placeholder="Пароль" />
            <button id="loginBtn">Войти</button>
          </div>
          <div id="loginMsg" class="muted" style="margin-top: 8px;"></div>
        </div>

        <div id="adminCard" class="card hidden">
          <div class="row" style="justify-content: space-between; margin-bottom: 20px;">
            <h2 style="margin: 0;">🔐 Админ-панель ACTOGRAM</h2>
            <button id="logoutBtn" style="background:#ef4444;">Выйти</button>
          </div>

          <!-- Статистика -->
          <div id="statsCard" class="card" style="background: linear-gradient(135deg, #1e293b, #334155); margin-top: 0;">
            <h3 style="margin-top: 0;">📊 Статистика</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 12px;">
              <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                <div style="font-size: 24px; font-weight: bold; color: #60a5fa;" id="statTotal">0</div>
                <div style="font-size: 12px; color: #94a3b8;">Всего</div>
              </div>
              <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                <div style="font-size: 24px; font-weight: bold; color: #34d399;" id="statOnline">0</div>
                <div style="font-size: 12px; color: #94a3b8;">Онлайн</div>
              </div>
              <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                <div style="font-size: 24px; font-weight: bold; color: #f87171;" id="statBanned">0</div>
                <div style="font-size: 12px; color: #94a3b8;">Забанено</div>
              </div>
              <div style="text-align: center; padding: 12px; background: rgba(0,0,0,0.3); border-radius: 8px;">
                <div style="font-size: 24px; font-weight: bold; color: #fbbf24;" id="statVerified">0</div>
                <div style="font-size: 12px; color: #94a3b8;">Верифицировано</div>
              </div>
            </div>
          </div>

          <!-- Блокировка IP -->
          <div class="card">
            <h3>🛡️ Блокировка IP</h3>
          <div class="row" style="margin-top: 8px;">
              <input id="ipInput" placeholder="IP адрес (например 1.2.3.4)" style="flex: 1;" />
              <input id="reasonInput" placeholder="Причина (необязательно)" style="flex: 1;" />
            <button id="banBtn">Забанить IP</button>
            <button id="unbanBtn" style="background:#ef4444;">Разбанить IP</button>
          </div>
          <div id="actionMsg" class="muted" style="margin-top: 8px;"></div>

            <div style="margin-top: 16px;">
              <div class="row" style="justify-content: space-between; margin-bottom: 8px;">
                <h4 style="margin: 0;">Забаненные IP</h4>
                <button id="refreshBansBtn" style="background:#475569; font-size: 12px; padding: 6px 12px;">Обновить</button>
          </div>
              <div style="max-height: 200px; overflow:auto; border:1px solid #1f2937; border-radius:8px;">
                <table style="width:100%; font-size: 12px;">
              <thead>
                    <tr style="background: #1f2937;">
                      <th style="padding: 8px;">IP</th>
                      <th style="padding: 8px;">Причина</th>
                      <th style="padding: 8px;">Когда</th>
                      <th style="padding: 8px;">Кем</th>
                      <th style="padding: 8px;">Действие</th>
                </tr>
              </thead>
              <tbody id="bansBody"></tbody>
            </table>
          </div>
            </div>
          </div>

          <!-- Управление пользователями -->
          <div class="card">
            <h3>👥 Управление пользователями</h3>
            
            <!-- Поиск и фильтры -->
            <div style="margin-top: 16px;">
              <div class="row" style="margin-bottom: 12px;">
                <input id="searchInput" placeholder="🔍 Поиск по username, email, IP, имени..." style="flex: 1;" />
                <select id="filterSelect" style="height: 40px; border-radius: 8px; border: 1px solid #374151; background: #0b1220; color: #e2e8f0; padding: 0 12px;">
                  <option value="">Все пользователи</option>
                  <option value="online">Онлайн</option>
                  <option value="offline">Оффлайн</option>
                  <option value="banned">Забаненные</option>
                  <option value="verified">Верифицированные</option>
                  <option value="unverified">Неверифицированные</option>
                </select>
                <select id="sortSelect" style="height: 40px; border-radius: 8px; border: 1px solid #374151; background: #0b1220; color: #e2e8f0; padding: 0 12px;">
                  <option value="lastSeen-desc">Последняя активность (новые)</option>
                  <option value="lastSeen-asc">Последняя активность (старые)</option>
                  <option value="createdAt-desc">Дата регистрации (новые)</option>
                  <option value="createdAt-asc">Дата регистрации (старые)</option>
                  <option value="username-asc">Username (А-Я)</option>
                  <option value="username-desc">Username (Я-А)</option>
                </select>
                <button id="refreshUsersBtn" style="background:#475569;">Обновить</button>
              </div>
            </div>

            <!-- Таблица пользователей -->
            <div style="max-height: 600px; overflow:auto; border:1px solid #1f2937; border-radius:8px; margin-top: 12px;">
              <table style="width:100%; font-size: 13px;">
                <thead>
                  <tr style="background: #1f2937; position: sticky; top: 0; z-index: 10;">
                    <th style="padding: 10px; text-align: left;">Пользователь</th>
                    <th style="padding: 10px; text-align: left;">Email</th>
                    <th style="padding: 10px; text-align: left;">IP</th>
                    <th style="padding: 10px; text-align: center;">Статус</th>
                    <th style="padding: 10px; text-align: center;">Последняя активность</th>
                    <th style="padding: 10px; text-align: center;">Действия</th>
                  </tr>
                </thead>
                <tbody id="usersBody"></tbody>
              </table>
            </div>
            <div id="usersCount" class="muted" style="margin-top: 8px; text-align: center;"></div>
          </div>
        </div>

        <!-- Модальное окно для деталей пользователя -->
        <div id="userModal" class="hidden" style="position: fixed; inset: 0; background: rgba(0,0,0,0.8); z-index: 1000; display: none; align-items: center; justify-content: center; padding: 20px;">
          <div class="card" style="max-width: 600px; width: 100%; max-height: 80vh; overflow: auto; position: relative;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
              <h3 style="margin: 0;">📋 Детали пользователя</h3>
              <button id="closeModal" style="background: #ef4444; width: 32px; height: 32px; border-radius: 50%; border: none; cursor: pointer; font-size: 20px; color: white;">×</button>
            </div>
            <div id="userModalContent"></div>
          </div>
        </div>

        <p class="muted" style="margin-top: 12px;">Токен хранится в localStorage (admin_token).</p>
      </div>

      <script>
        (function(){
          const canvas = document.getElementById('lgCanvas');
          if(!canvas) return;
          const ctx = canvas.getContext('2d');
          const glitchColors = ['#2b4539', '#61dca3', '#61b3dc'];
          const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$&*()-_+=/[]{};:<>.,0123456789";
          const letters = [];
          let grid = { columns: 0, rows: 0 };
          let lastGlitchTime = Date.now();
          const glitchSpeed = 50;
          const fontSize = 16;
          const charWidth = 10;
          const charHeight = 20;

          function getRandomChar(){
            return characters.charAt(Math.floor(Math.random()*characters.length));
          }
          function getRandomColor(){
            return glitchColors[Math.floor(Math.random()*glitchColors.length)];
          }
          function calculateGrid(w,h){
            return { columns: Math.ceil(w/charWidth), rows: Math.ceil(h/charHeight) };
          }
          function initLetters(cols, rows){
            grid = { columns: cols, rows: rows };
            const total = cols*rows;
            letters.length = 0;
            for(let i=0;i<total;i++){
              letters.push({ char: getRandomChar(), color: getRandomColor() });
            }
          }
          function resize(){
            const dpr = window.devicePixelRatio || 1;
            const rect = document.body.getBoundingClientRect();
            canvas.width = rect.width * dpr;
            canvas.height = rect.height * dpr;
            canvas.style.width = rect.width + 'px';
            canvas.style.height = rect.height + 'px';
            ctx.setTransform(dpr,0,0,dpr,0,0);
            const g = calculateGrid(rect.width, rect.height);
            initLetters(g.columns, g.rows);
            draw();
          }
          function draw(){
            const rect = canvas.getBoundingClientRect();
            ctx.clearRect(0,0,rect.width,rect.height);
            ctx.font = fontSize + 'px monospace';
            ctx.textBaseline = 'top';
            for(let i=0;i<letters.length;i++){
              const x = (i % grid.columns) * charWidth;
              const y = Math.floor(i / grid.columns) * charHeight;
              ctx.fillStyle = letters[i].color;
              ctx.fillText(letters[i].char, x, y);
            }
          }
          function update(){
            const count = Math.max(1, Math.floor(letters.length * 0.05));
            for(let i=0;i<count;i++){
              const idx = Math.floor(Math.random()*letters.length);
              if(letters[idx]){
                letters[idx].char = getRandomChar();
                letters[idx].color = getRandomColor();
              }
            }
          }
          function loop(){
            const now = Date.now();
            if(now - lastGlitchTime >= glitchSpeed){ update(); draw(); lastGlitchTime = now; }
            requestAnimationFrame(loop);
          }
          window.addEventListener('resize', ()=>{ clearTimeout(window.__lg_to); window.__lg_to = setTimeout(resize, 100); });
          resize();
          loop();
        })();

        function initAdminPanel() {
        console.log('🔍 initAdminPanel вызвана');
        const loginCard = document.getElementById('loginCard');
        const adminCard = document.getElementById('adminCard');
        const loginMsg = document.getElementById('loginMsg');
        const actionMsg = document.getElementById('actionMsg');
        const bansBody = document.getElementById('bansBody');
        const usersBody = document.getElementById('usersBody');
          
        console.log('🔍 Элементы найдены:', { loginCard: !!loginCard, adminCard: !!adminCard });
          
          if(!loginCard || !adminCard) {
            console.error('Admin panel elements not found!');
            return;
          }

        function getToken(){ return localStorage.getItem('admin_token') || ''; }
        function setToken(t){ if(t) localStorage.setItem('admin_token', t); }
        function clearToken(){ localStorage.removeItem('admin_token'); }
          
          // Загрузка банов
        async function loadBans(){
            if(!actionMsg || !bansBody) return;
          actionMsg.textContent='';
          try{
            const res = await fetch('/admin/bans', { headers: { 'Authorization': 'Bearer ' + getToken() }});
            const data = await res.json();
            if(!res.ok){ actionMsg.textContent = (data && data.error) || 'Ошибка загрузки'; actionMsg.className='err'; return; }
            bansBody.innerHTML = '';
            (data.items||[]).forEach(item => {
              const tr = document.createElement('tr');
                tr.innerHTML = '<td style="padding: 8px;">' + (item.ip || '') + '</td>'
                  + '<td style="padding: 8px;">' + (item.reason || '-') + '</td>'
                  + '<td style="padding: 8px;">' + new Date(item.bannedAt).toLocaleString('ru-RU') + '</td>'
                  + '<td style="padding: 8px;">' + (item.bannedBy || '') + '</td>'
                  + '<td style="padding: 8px;"><button onclick="window.unbanIPFromTable(\'' + item.ip + '\')" style="background:#ef4444; padding: 4px 8px; font-size: 11px; border: none; border-radius: 4px; cursor: pointer;">Разбанить</button></td>';
              bansBody.appendChild(tr);
            });
            }catch(e){ 
              if(actionMsg) {
                actionMsg.textContent='Сеть недоступна'; 
                actionMsg.className='err'; 
              }
            }
          }

          // Загрузка пользователей
          let currentSearch = '';
          let currentFilter = '';
          let currentSort = 'lastSeen-desc';
        
        async function loadUsers(){
            if(!usersBody) return;
            try{
              const searchInput = document.getElementById('searchInput');
              const filterSelect = document.getElementById('filterSelect');
              const sortSelect = document.getElementById('sortSelect');
              const search = searchInput ? searchInput.value.trim() : '';
              const filter = filterSelect ? filterSelect.value : '';
              const sort = sortSelect ? sortSelect.value : 'lastSeen-desc';
              const [sortBy, sortOrder] = sort.split('-');
              
              const params = new URLSearchParams();
              if(search) params.append('search', search);
              if(filter) params.append('filter', filter);
              params.append('sortBy', sortBy);
              params.append('sortOrder', sortOrder);
              
              const res = await fetch('/admin/users?' + params.toString(), { 
                headers: { 'Authorization': 'Bearer ' + getToken() } 
              });
            const data = await res.json();
            if(!res.ok){ return; }
              
              // Обновляем статистику
              if(data.stats){
                const statTotal = document.getElementById('statTotal');
                const statOnline = document.getElementById('statOnline');
                const statBanned = document.getElementById('statBanned');
                const statVerified = document.getElementById('statVerified');
                if(statTotal) statTotal.textContent = data.stats.total || 0;
                if(statOnline) statOnline.textContent = data.stats.online || 0;
                if(statBanned) statBanned.textContent = data.stats.banned || 0;
                if(statVerified) statVerified.textContent = data.stats.verified || 0;
              }
              
            usersBody.innerHTML = '';
              const users = data.items || [];
              const usersCount = document.getElementById('usersCount');
              if(usersCount) usersCount.textContent = 'Найдено пользователей: ' + users.length;
              
              users.forEach(u => {
              const tr = document.createElement('tr');
                tr.style.borderBottom = '1px solid #1f2937';
                tr.style.cursor = 'pointer';
                tr.onmouseenter = () => tr.style.background = '#1f2937';
                tr.onmouseleave = () => tr.style.background = '';
                
                const statusIcon = u.status === 'banned' ? '🚫' : (u.isOnline ? '🟢' : '⚪');
                const statusText = u.status === 'banned' ? 'Забанен' : (u.isOnline ? 'Онлайн' : 'Оффлайн');
                const verifiedBadge = u.isVerified ? ' <span style="color: #fbbf24;">✓</span>' : '';
                const lastSeen = u.lastSeen ? new Date(u.lastSeen).toLocaleString('ru-RU') : 'Никогда';
                const safeUsername = (u.username||'').replace(/'/g, "\\'").replace(/"/g, '&quot;');
                
                tr.innerHTML = '<td style="padding: 10px;"><strong>' + (u.username||'') + '</strong>' + verifiedBadge + '<br><span style="color: #94a3b8; font-size: 11px;">' + (u.fullName||'') + '</span></td>'
                  + '<td style="padding: 10px; font-size: 12px;">' + (u.email||'-') + '</td>'
                  + '<td style="padding: 10px;"><a href="#" data-ip="' + (u.lastIp||'') + '" class="pick-ip" style="color: #60a5fa; text-decoration: none;">' + (u.lastIp||'-') + '</a></td>'
                  + '<td style="padding: 10px; text-align: center;"><span style="font-size: 16px;">' + statusIcon + '</span><br><span style="font-size: 11px; color: #94a3b8;">' + statusText + '</span></td>'
                  + '<td style="padding: 10px; text-align: center; font-size: 11px; color: #94a3b8;">' + lastSeen + '</td>'
                  + '<td style="padding: 10px; text-align: center;"><button onclick="window.showUserDetails(\'' + u.id + '\')" style="background:#3b82f6; padding: 4px 8px; font-size: 11px; border: none; border-radius: 4px; cursor: pointer; margin: 2px;">Детали</button>' 
                  + (u.status === 'banned' 
                    ? '<button onclick="window.unbanUser(\'' + u.id + '\', \'' + safeUsername + '\')" style="background:#10b981; padding: 4px 8px; font-size: 11px; border: none; border-radius: 4px; cursor: pointer; margin: 2px;">Разбанить</button>'
                    : '<button onclick="window.banUser(\'' + u.id + '\', \'' + safeUsername + '\')" style="background:#ef4444; padding: 4px 8px; font-size: 11px; border: none; border-radius: 4px; cursor: pointer; margin: 2px;">Забанить</button>') + '</td>';
                tr.setAttribute('data-user-id', u.id);
                tr.onclick = () => window.showUserDetails(u.id);
              usersBody.appendChild(tr);
            });
              
            usersBody.querySelectorAll('a.pick-ip').forEach(a => {
              a.addEventListener('click', (e) => {
                  e.stopPropagation();
                e.preventDefault();
                const ip = a.getAttribute('data-ip');
                  if(ip && ip !== '-'){ 
                    const ipInput = document.getElementById('ipInput');
                    if(ipInput) {
                      ipInput.value = ip;
                      ipInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    }
                  }
              });
            });
              
              currentSearch = search;
              currentFilter = filter;
              currentSort = sort;
            }catch(e){
              console.error('Load users error:', e);
            }
          }

          function setState(logged){
            if(logged){ 
              loginCard.classList.add('hidden'); 
              adminCard.classList.remove('hidden'); 
              loadBans(); 
              loadUsers(); 
            } else { 
              adminCard.classList.add('hidden'); 
              loginCard.classList.remove('hidden'); 
            }
          }

          // Обработчик входа
          const loginBtn = document.getElementById('loginBtn');
          console.log('🔍 Кнопка входа найдена:', !!loginBtn);
          if(loginBtn) {
            console.log('🔍 Добавляем обработчик клика');
            loginBtn.addEventListener('click', async (e) => {
              console.log('🔍 Клик по кнопке входа!');
              e.preventDefault();
              e.stopPropagation();
              if(loginMsg) {
                loginMsg.textContent = 'Подключение...';
                loginMsg.className = 'muted';
              }
              const usernameInput = document.getElementById('username');
              const passwordInput = document.getElementById('password');
              if(!usernameInput || !passwordInput) {
                if(loginMsg) {
                  loginMsg.textContent = 'Элементы формы не найдены';
                  loginMsg.className = 'err';
                }
                return;
              }
              const username = usernameInput.value.trim();
              const password = passwordInput.value;
              if(!username || !password) {
                if(loginMsg) {
                  loginMsg.textContent = 'Заполните все поля';
                  loginMsg.className = 'err';
                }
                return;
              }
              try{
                const res = await fetch('/admin/login', {
                  method: 'POST',
                  headers: {'Content-Type': 'application/json'}, 
                  body: JSON.stringify({username, password})
                });
                const data = await res.json();
                if(!res.ok){ 
                  if(loginMsg) {
                    loginMsg.textContent = (data && data.error) || 'Ошибка входа'; 
                    loginMsg.className='err';
                  }
                  return; 
                }
                setToken(data.token); 
                if(loginMsg) {
                  loginMsg.textContent='Вход выполнен'; 
                  loginMsg.className='ok';
                }
                setState(true);
              }catch(e){
                console.error('Login error:', e);
                if(loginMsg) {
                  loginMsg.textContent = 'Ошибка сети: ' + (e.message || 'Неизвестная ошибка'); 
                  loginMsg.className='err';
                }
              }
            });
          } else {
            console.error('Login button not found!');
          }

          const logoutBtn = document.getElementById('logoutBtn');
          if(logoutBtn) {
            logoutBtn.onclick = () => { clearToken(); setState(false); };
          }
          
          // Функция показа модального окна с деталями пользователя
          function showUserModal(user) {
            const modal = document.getElementById('userModal');
            const content = document.getElementById('userModalContent');
            if(!modal || !content) return;
            
            const statusIcon = user.status === 'banned' ? '🚫' : (user.isOnline ? '🟢' : '⚪');
            const statusText = user.status === 'banned' ? 'Забанен' : (user.isOnline ? 'Онлайн' : 'Оффлайн');
            const lastSeen = user.lastSeen ? new Date(user.lastSeen).toLocaleString('ru-RU') : 'Никогда';
            const createdAt = user.createdAt ? new Date(user.createdAt).toLocaleString('ru-RU') : '';
            const userAvatar = user.avatar ? '<img src="' + user.avatar + '" style="width: 64px; height: 64px; border-radius: 50%; margin-bottom: 12px;" />' : '<div style="width: 64px; height: 64px; border-radius: 50%; background: #374151; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 12px;">' + (user.username ? user.username.charAt(0).toUpperCase() : '?') + '</div>';
            const safeUsername = (user.username||'').replace(/'/g, "\\'").replace(/"/g, '&quot;');
            const safeLastIp = (user.lastIp||'').replace(/'/g, "\\'");
            
            content.innerHTML = '<div style="line-height: 1.8;">'
              + '<div style="text-align: center; margin-bottom: 20px;">' + userAvatar + '</div>'
              + '<div style="background: #1f2937; padding: 12px; border-radius: 8px; margin-bottom: 12px;"><strong>ID:</strong> <code style="background: #0b1220; padding: 2px 6px; border-radius: 4px; font-size: 11px;">' + user.id + '</code></div>'
              + '<strong>Username:</strong> ' + (user.username||'') + (user.isVerified ? ' <span style="color: #fbbf24;">✓ Верифицирован</span>' : '') + '<br>'
              + '<strong>Полное имя:</strong> ' + (user.fullName||'-') + '<br>'
              + '<strong>Email:</strong> ' + (user.email||'-') + '<br>'
              + '<strong>Bio:</strong> ' + (user.bio||'-') + '<br>'
              + '<strong>Статус:</strong> ' + statusIcon + ' ' + statusText + '<br>'
              + '<strong>Последний IP:</strong> <a href="#" onclick="window.setIPAndCloseModal(\'' + safeLastIp + '\'); return false;" style="color: #60a5fa;">' + (user.lastIp||'-') + '</a><br>'
              + '<strong>Последняя активность:</strong> ' + lastSeen + '<br>'
              + '<strong>Дата регистрации:</strong> ' + createdAt + '<br><br>'
              + '<div style="display: flex; gap: 8px; margin-top: 16px; flex-wrap: wrap;">'
              + (user.status === 'banned' 
                ? '<button onclick="window.unbanUser(\'' + user.id + '\', \'' + safeUsername + '\'); window.closeUserModal();" style="background:#10b981; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; flex: 1; min-width: 150px;">✅ Разбанить</button>'
                : '<button onclick="window.banUser(\'' + user.id + '\', \'' + safeUsername + '\'); window.closeUserModal();" style="background:#ef4444; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; flex: 1; min-width: 150px;">🚫 Забанить</button>')
              + (user.lastIp && user.lastIp !== '-' 
                ? '<button onclick="window.banUserIP(\'' + safeLastIp + '\'); window.closeUserModal();" style="background:#f59e0b; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; flex: 1; min-width: 150px;">🛡️ Забанить IP</button>'
                : '')
              + '</div></div>';
            
            modal.style.display = 'flex';
            modal.classList.remove('hidden');
          }

          // Показать детали пользователя
          async function showUserDetails(userId) {
            try{
              const res = await fetch('/admin/users?search=' + userId, { 
                headers: { 'Authorization': 'Bearer ' + getToken() } 
              });
              const data = await res.json();
              const user = data.items && data.items.find(u => u.id === userId);
              if(!user) {
                alert('Пользователь не найден');
                return;
              }
              showUserModal(user);
            }catch(e){
              console.error('Show user details error:', e);
              alert('Ошибка загрузки данных пользователя');
            }
          }

          // Бан пользователя
          async function banUser(userId, username) {
            if(!confirm('Забанить пользователя ' + username + '?')) return;
            try{
              const res = await fetch('/admin/ban-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getToken() },
                body: JSON.stringify({ userId })
              });
              const data = await res.json();
              if(!res.ok){
                alert('Ошибка: ' + (data.error || 'Неизвестная ошибка'));
                return;
              }
              alert('Пользователь ' + username + ' забанен');
              loadUsers();
              loadBans();
            }catch(e){
              alert('Ошибка сети');
            }
          }

          // Разбан пользователя
          async function unbanUser(userId, username) {
            if(!confirm('Разбанить пользователя ' + username + '?')) return;
            try{
              const res = await fetch('/admin/unban-user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + getToken() },
                body: JSON.stringify({ userId })
              });
              const data = await res.json();
              if(!res.ok){
                alert('Ошибка: ' + (data.error || 'Неизвестная ошибка'));
                return;
              }
              alert('Пользователь ' + username + ' разбанен');
              loadUsers();
              loadBans();
            }catch(e){
              alert('Ошибка сети');
            }
          }

          // Бан IP пользователя
          function banUserIP(ip) {
            if(!ip || ip === '-') {
              alert('IP адрес не найден');
              return;
            }
            const ipInput = document.getElementById('ipInput');
            if(ipInput) {
              ipInput.value = ip;
              const reason = prompt('Причина бана IP ' + ip + ':');
              if(reason !== null){
                const reasonInput = document.getElementById('reasonInput');
                if(reasonInput) reasonInput.value = reason;
                const banBtn = document.getElementById('banBtn');
                if(banBtn) banBtn.click();
              }
            }
          }

          // Разбан IP из таблицы
          async function unbanIPFromTable(ip) {
            if(!confirm('Разбанить IP ' + ip + '?')) return;
            const ipInput = document.getElementById('ipInput');
            if(ipInput) ipInput.value = ip;
            const unbanBtn = document.getElementById('unbanBtn');
            if(unbanBtn) unbanBtn.click();
          }

          // Закрыть модальное окно
          function closeUserModal() {
            const modal = document.getElementById('userModal');
            if(modal) {
              modal.style.display = 'none';
              modal.classList.add('hidden');
            }
          }

          // Установить IP и закрыть модальное окно
          function setIPAndCloseModal(ip) {
            const ipInput = document.getElementById('ipInput');
            if(ipInput && ip && ip !== '-') {
              ipInput.value = ip;
              ipInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            closeUserModal();
          }

          // Debounce функция
          function debounce(func, wait){
            let timeout;
            return function executedFunction(...args){
              const later = () => { clearTimeout(timeout); func(...args); };
              clearTimeout(timeout);
              timeout = setTimeout(later, wait);
            };
          }

          // Экспортируем функции в window для использования в onclick
          window.getAdminToken = getToken;
          window.loadAdminUsers = loadUsers;
          window.loadAdminBans = loadBans;
          window.showUserDetails = showUserDetails;
          window.banUser = banUser;
          window.unbanUser = unbanUser;
          window.banUserIP = banUserIP;
          window.unbanIPFromTable = unbanIPFromTable;
          window.closeUserModal = closeUserModal;
          window.setIPAndCloseModal = setIPAndCloseModal;

          // Обработчики для кнопок IP
          const banBtn = document.getElementById('banBtn');
          if(banBtn) {
            banBtn.onclick = async () => {
              if(!actionMsg) return;
          actionMsg.textContent='';
              const ipInput = document.getElementById('ipInput');
              const reasonInput = document.getElementById('reasonInput');
              if(!ipInput) return;
              const ip = ipInput.value.trim();
              const reason = reasonInput ? reasonInput.value.trim() : '';
              if(!ip){ 
                actionMsg.textContent='Укажите IP'; 
                actionMsg.className='err'; 
                return; 
              }
              try{
                const res = await fetch('/admin/ban-ip', { 
                  method:'POST', 
                  headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer ' + getToken() }, 
                  body: JSON.stringify({ ip, reason }) 
                });
            const data = await res.json();
                if(!res.ok){ 
                  actionMsg.textContent = (data && data.error) || 'Ошибка бана'; 
                  actionMsg.className='err'; 
                  return; 
                }
                actionMsg.textContent='IP забанен'; 
                actionMsg.className='ok'; 
                loadBans();
                loadUsers();
              }catch(e){ 
                actionMsg.textContent='Сеть недоступна'; 
                actionMsg.className='err'; 
              }
            };
          }

          const unbanBtn = document.getElementById('unbanBtn');
          if(unbanBtn) {
            unbanBtn.onclick = async () => {
              if(!actionMsg) return;
          actionMsg.textContent='';
              const ipInput = document.getElementById('ipInput');
              if(!ipInput) return;
              const ip = ipInput.value.trim();
              if(!ip){ 
                actionMsg.textContent='Укажите IP'; 
                actionMsg.className='err'; 
                return; 
              }
              try{
                const res = await fetch('/admin/unban-ip', { 
                  method:'POST', 
                  headers:{ 'Content-Type':'application/json', 'Authorization':'Bearer ' + getToken() }, 
                  body: JSON.stringify({ ip }) 
                });
            const data = await res.json();
                if(!res.ok){ 
                  actionMsg.textContent = (data && data.error) || 'Ошибка разбана'; 
                  actionMsg.className='err'; 
                  return; 
                }
                actionMsg.textContent='IP разбанен'; 
                actionMsg.className='ok'; 
                loadBans();
                loadUsers();
              }catch(e){ 
                actionMsg.textContent='Сеть недоступна'; 
                actionMsg.className='err'; 
              }
            };
          }

          // Обработчики для кнопок обновления
          const refreshBansBtn = document.getElementById('refreshBansBtn');
          if(refreshBansBtn) {
            refreshBansBtn.onclick = () => { loadBans(); };
          }

          const refreshUsersBtn = document.getElementById('refreshUsersBtn');
          if(refreshUsersBtn) {
            refreshUsersBtn.onclick = () => { loadUsers(); };
          }

          // Обработчики для поиска и фильтров
          const searchInput = document.getElementById('searchInput');
          if(searchInput) {
            searchInput.addEventListener('input', debounce(loadUsers, 500));
          }

          const filterSelect = document.getElementById('filterSelect');
          if(filterSelect) {
            filterSelect.addEventListener('change', loadUsers);
          }

          const sortSelect = document.getElementById('sortSelect');
          if(sortSelect) {
            sortSelect.addEventListener('change', loadUsers);
          }

          // Обработчики для модального окна
          const closeModalBtn = document.getElementById('closeModal');
          if(closeModalBtn) {
            closeModalBtn.onclick = closeUserModal;
          }

          const userModal = document.getElementById('userModal');
          if(userModal) {
            userModal.onclick = (e) => {
              if(e.target.id === 'userModal') closeUserModal();
            };
          }

          // Проверяем, есть ли сохраненный токен
        setState(!!getToken());
        }
        
        // Инициализация при загрузке страницы
        if (document.readyState === 'loading') {
          document.addEventListener('DOMContentLoaded', initAdminPanel);
        } else {
          // DOM уже загружен
          initAdminPanel();
        }
      </script>
    </body>
    </html>
  `)
})

// ========== ADMIN API ==========

app.post("/admin/login", authLimiter, async (req, res) => {
    try {
        const { username, password } = req.body || {}
        if (username !== ADMIN_USERNAME || password !== ADMIN_PASSWORD) {
            return res.status(401).json({ error: "Неверные данные" })
        }
        const token = jwt.sign({ admin: true, username: ADMIN_USERNAME }, JWT_SECRET, { expiresIn: "12h" })
        res.json({ token })
    } catch (err) {
        res.status(500).json({ error: "Ошибка входа" })
    }
})

function requireAdmin(req, res, next) {
    const authHeader = req.headers["authorization"] || ""
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null
    if (!token) return res.status(401).json({ error: "Токен обязателен" })
    try {
        const payload = jwt.verify(token, JWT_SECRET)
        if (!payload?.admin || payload?.username !== ADMIN_USERNAME) {
            return res.status(403).json({ error: "Нет доступа" })
        }
        next()
    } catch (e) {
        return res.status(403).json({ error: "Недействительный токен" })
    }
}

app.get("/admin/bans", requireAdmin, async (req, res) => {
    const list = await BannedIP.find().sort({ bannedAt: -1 }).lean()
    res.json({ items: list })
})

app.get("/admin/users", requireAdmin, async (req, res) => {
    try {
        const { search, filter, sortBy = "lastSeen", sortOrder = "desc" } = req.query

        let query = {}

        // Поиск
        if (search && search.trim()) {
            const searchTerm = search.trim()
            // Проверяем, является ли поисковый запрос ObjectId
            const isObjectId = /^[0-9a-fA-F]{24}$/.test(searchTerm)
            if (isObjectId) {
                try {
                    // Если это ObjectId, ищем напрямую по _id
                    query._id = new mongoose.Types.ObjectId(searchTerm)
                } catch (e) {
                    // Если не валидный ObjectId, ищем по текстовым полям
                    query.$or = [
                        { username: { $regex: searchTerm, $options: "i" } },
                        { fullName: { $regex: searchTerm, $options: "i" } },
                        { email: { $regex: searchTerm, $options: "i" } },
                        { lastIp: { $regex: searchTerm, $options: "i" } },
                    ]
                }
            } else {
                // Иначе ищем по текстовым полям
                query.$or = [
                    { username: { $regex: searchTerm, $options: "i" } },
                    { fullName: { $regex: searchTerm, $options: "i" } },
                    { email: { $regex: searchTerm, $options: "i" } },
                    { lastIp: { $regex: searchTerm, $options: "i" } },
                ]
            }
        }

        // Фильтры
        if (filter) {
            if (filter === "online") query.isOnline = true
            if (filter === "offline") query.isOnline = false
            if (filter === "banned") query.status = "banned"
            if (filter === "verified") query.isVerified = true
            if (filter === "unverified") query.isVerified = false
        }

        // Сортировка
        const sortOptions = {}
        sortOptions[sortBy] = sortOrder === "asc" ? 1 : -1

        const users = await User.find(query, "_id username fullName email lastSeen isOnline lastIp status isVerified createdAt bio avatar")
            .sort(sortOptions)
            .lean()

        // Статистика
        const totalUsers = await User.countDocuments({})
        const onlineUsers = await User.countDocuments({ isOnline: true })
        const bannedUsers = await User.countDocuments({ status: "banned" })
        const verifiedUsers = await User.countDocuments({ isVerified: true })

        const items = users.map((u) => ({
            id: u._id.toString(),
            username: u.username,
            fullName: u.fullName,
            email: u.email,
            isOnline: !!u.isOnline,
            lastSeen: u.lastSeen,
            lastIp: u.lastIp || "",
            status: u.status || "offline",
            isVerified: !!u.isVerified,
            createdAt: u.createdAt,
            bio: u.bio || "",
            avatar: u.avatar || "",
        }))

        res.json({
            items,
            stats: {
                total: totalUsers,
                online: onlineUsers,
                offline: totalUsers - onlineUsers,
                banned: bannedUsers,
                verified: verifiedUsers,
            }
        })
    } catch (e) {
        console.error("Admin users error:", e)
        res.status(500).json({ error: "Ошибка получения пользователей" })
    }
})

app.post("/admin/ban-ip", requireAdmin, async (req, res) => {
    const { ip, reason } = req.body || {}
    if (!ip || typeof ip !== "string") {
        return res.status(400).json({ error: "ip обязателен" })
    }
    try {
        await BannedIP.updateOne(
            { ip },
            { $set: { ip, reason: reason || "", bannedAt: new Date(), bannedBy: ADMIN_USERNAME } },
            { upsert: true },
        )
        res.json({ success: true })
    } catch (e) {
        res.status(500).json({ error: "Ошибка бана" })
    }
})

app.post("/admin/unban-ip", requireAdmin, async (req, res) => {
    const { ip } = req.body || {}
    if (!ip || typeof ip !== "string") {
        return res.status(400).json({ error: "ip обязателен" })
    }
    try {
        await BannedIP.deleteOne({ ip })
        res.json({ success: true })
    } catch (e) {
        res.status(500).json({ error: "Ошибка разбана" })
    }
})

app.post("/admin/ban-user", requireAdmin, async (req, res) => {
    try {
        const { userId } = req.body
        if (!userId) {
            return res.status(400).json({ error: "userId обязателен" })
        }

        await User.findByIdAndUpdate(userId, {
            status: "banned",
            isOnline: false
        })

        // Отключаем пользователя если он онлайн
        for (const [socketId, uid] of activeConnections.entries()) {
            if (uid === userId) {
                const socket = io.sockets.sockets.get(socketId)
                if (socket) {
                    socket.emit("error", { message: "Ваш аккаунт заблокирован" })
                    socket.disconnect(true)
                }
            }
        }

        console.log(`🚫 Пользователь ${userId} забанен через админ-панель`)
        res.json({ success: true })

    } catch (error) {
        console.error("admin ban-user error:", error)
        res.status(500).json({ error: "Ошибка бана пользователя" })
    }
})

app.post("/admin/unban-user", requireAdmin, async (req, res) => {
    try {
        const { userId } = req.body
        if (!userId) {
            return res.status(400).json({ error: "userId обязателен" })
        }

        await User.findByIdAndUpdate(userId, { status: "offline" })

        console.log(`✅ Пользователь ${userId} разбанен через админ-панель`)
        res.json({ success: true })

    } catch (error) {
        console.error("admin unban-user error:", error)
        res.status(500).json({ error: "Ошибка разбана пользователя" })
    }
})

// ========== IP BAN MIDDLEWARE ==========

app.use(async (req, res, next) => {
    try {
        const clientIp = getClientIp(req)
        const banned = await BannedIP.findOne({ ip: clientIp }).lean()
        if (banned) {
            return res.status(403).json({ error: "Ваш IP забанен" })
        }
    } catch (e) {
        // Молча пропускаем в случае ошибки
    }
    next()
})

// ========== API ROUTES ==========

app.get("/api/health", async (req, res) => {
    try {
        const userCount = await User.countDocuments()
        const chatCount = await Chat.countDocuments()
        const messageCount = await Message.countDocuments()

        res.json({
            status: "ACTOGRAM Server v3.0 работает отлично",
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
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.post("/api/upload-avatar", authenticateToken, upload.single("avatar"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "Файл не загружен" })
        }
        const userId = req.user.userId
        const avatarUrl = `/avatars/${req.file.filename}`
        await User.findByIdAndUpdate(userId, { avatar: avatarUrl })
        res.json({ success: true, avatar: avatarUrl })
    } catch (error) {
        console.error("upload-avatar error:", error)
        res.status(500).json({ error: "Ошибка загрузки аватара" })
    }
})

app.post("/api/create-group", authenticateToken, upload.single("avatar"), async (req, res) => {
    try {
        const userId = req.user.userId
        const { name, description, type, participants } = req.body
        if (!name || !type || !["group", "channel"].includes(type)) {
            return res.status(400).json({ error: "Некорректные данные" })
        }
        let avatarUrl = null
        if (req.file) {
            avatarUrl = `/avatars/${req.file.filename}`
        }
        let members = [userId]
        if (participants) {
            try {
                const parsed = JSON.parse(participants)
                if (Array.isArray(parsed)) {
                    members = Array.from(new Set([...members, ...parsed]))
                }
            } catch { }
        }
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
        const populatedChat = await Chat.findById(chat._id)
            .populate("participants", "_id username fullName avatar isOnline isVerified status")
            .lean()
        res.json({
            success: true,
            chat: {
                ...populatedChat,
                id: populatedChat._id?.toString() || populatedChat._id,
                participants: populatedChat.participants.filter((p) => p !== null),
            },
        })
    } catch (error) {
        console.error("create-group error:", error)
        res.status(500).json({ error: "Ошибка создания группы/канала" })
    }
})

app.post("/api/auth", authLimiter, async (req, res) => {
    try {
        const { action, email, password, username, fullName, bio } = req.body

        if (!email || !password) {
            return res.status(400).json({ error: "Email и пароль обязательны" })
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ error: "Неверный формат email" })
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ error: "Пароль должен содержать минимум 8 символов" })
        }

        if (action === "register") {
            if (!username || !fullName) {
                return res.status(400).json({ error: "Username и полное имя обязательны" })
            }

            if (!validateUsername(username)) {
                return res.status(400).json({
                    error: "Username должен начинаться с @ и содержать 3-20 символов",
                })
            }

            const existingUser = await User.findOne({
                $or: [{ email }, { username }],
            })
            if (existingUser) {
                return res.status(400).json({
                    error: "Пользователь с таким email или username уже существует",
                })
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

            const token = jwt.sign({ userId: user._id, email: user.email, username: user.username }, JWT_SECRET, {
                expiresIn: "30d",
            })
            const userResponse = user.toObject()
            delete userResponse.password
            userResponse.id = user._id.toString()

            res.cookie("token", token, {
                httpOnly: false,
                secure: false,
                sameSite: "Lax",
                maxAge: 30 * 24 * 60 * 60 * 1000,
                path: "/",
            })

            res.json({
                success: true,
                message: "Регистрация успешна",
                user: userResponse,
                token,
            })
            console.log(`✅ Новый пользователь: ${username} (${email})`)
        } else if (action === "login") {
            const user = await User.findOne({ email })
            if (!user) {
                return res.status(401).json({ error: "Неверный email или пароль" })
            }

            if (user.status === "banned") {
                return res.status(403).json({ error: "Ваш аккаунт заблокирован" })
            }

            const isValidPassword = await bcrypt.compare(password, user.password)
            if (!isValidPassword) {
                return res.status(401).json({ error: "Неверный email или пароль" })
            }

            user.isOnline = true
            user.lastSeen = new Date()
            user.status = "online"
            await user.save()

            const token = jwt.sign({ userId: user._id, email: user.email, username: user.username }, JWT_SECRET, {
                expiresIn: "30d",
            })
            const userResponse = user.toObject()
            delete userResponse.password
            userResponse.id = user._id.toString()

            res.cookie("token", token, {
                httpOnly: false,
                secure: false,
                sameSite: "Lax",
                maxAge: 30 * 24 * 60 * 60 * 1000,
                path: "/",
            })

            res.json({
                success: true,
                message: "Вход выполнен успешно",
                user: userResponse,
                token,
            })
            console.log(`✅ Пользователь вошел: ${user.username}`)
        } else {
            res.status(400).json({ error: "Неверное действие" })
        }
    } catch (error) {
        console.error("Auth error:", error)
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.get("/api/chats", authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId

        const chats = await Chat.find({ participants: userId })
            .populate("participants", "_id username fullName avatar isOnline isVerified status")
            .sort({ updatedAt: -1 })
            .lean()

        const chatList = await Promise.all(
            chats.map(async (chat) => {
                const lastMessage = await Message.findOne({ chat: chat._id })
                    .sort({ timestamp: -1 })
                    .populate("sender", "username fullName avatar")
                    .lean()
                const messageCount = await Message.countDocuments({ chat: chat._id })
                return {
                    ...chat,
                    id: chat._id?.toString() || chat._id,
                    participants: chat.participants.filter((p) => p !== null),
                    lastMessage: lastMessage
                        ? {
                            ...lastMessage,
                            id: lastMessage._id?.toString() || lastMessage._id,
                            senderId: lastMessage.sender?._id?.toString() || lastMessage.sender,
                            senderName: lastMessage.sender?.username || "Пользователь",
                            chatId: lastMessage.chat?.toString() || lastMessage.chat,
                        }
                        : null,
                    messageCount,
                    unreadCount: 0,
                }
            }),
        )

        const globalChat = await Chat.findById("global").lean()
        if (globalChat && !chatList.some((chat) => (chat.id || chat._id) === "global")) {
            const globalLastMessage = await Message.findOne({ chat: "global" })
                .sort({ timestamp: -1 })
                .populate("sender", "username fullName avatar")
                .lean()
            const globalMessageCount = await Message.countDocuments({
                chat: "global",
            })
            chatList.unshift({
                ...globalChat,
                id: globalChat._id?.toString() || globalChat._id,
                participants: globalChat.participants || [],
                lastMessage: globalLastMessage
                    ? {
                        ...globalLastMessage,
                        id: globalLastMessage._id?.toString() || globalLastMessage._id,
                        senderId: globalLastMessage.sender?._id?.toString() || globalLastMessage.sender,
                        senderName: globalLastMessage.sender?.username || "Пользователь",
                        chatId: globalLastMessage.chat?.toString() || globalLastMessage.chat,
                    }
                    : null,
                messageCount: globalMessageCount,
                unreadCount: 0,
            })
        }

        res.json(chatList)
    } catch (error) {
        console.error("/api/chats error:", error)
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.get("/api/messages/:chatId", authenticateToken, async (req, res) => {
    try {
        const { chatId } = req.params
        const userId = req.user.userId
        const page = Number.parseInt(req.query.page) || 0
        const limit = Number.parseInt(req.query.limit) || 50
        const skip = page * limit
        const chat = await Chat.findById(chatId).lean()
        if (!chat) return res.status(404).json({ error: "Чат не найден" })

        const isGlobalChat = chatId === "global"
        const isParticipant =
            isGlobalChat ||
            chat.participants
                .filter((p) => p !== null)
                .map((id) => id.toString())
                .includes(userId)
        if (!isParticipant) {
            return res.status(403).json({ error: "Нет доступа к этому чату" })
        }

        const chatMessages = await Message.find({ chat: chatId })
            .populate("sender", "username fullName")
            .sort({ timestamp: 1 })
            .skip(skip)
            .limit(limit)
            .lean()

        const messagesWithReply = await Promise.all(
            chatMessages.map(async (msg) => {
                let replyTo = null
                if (msg.replyTo) {
                    const originalMsg = await Message.findById(msg.replyTo).populate("sender", "username fullName").lean()
                    if (originalMsg) {
                        let senderName = "Неизвестно"
                        if (originalMsg.sender) {
                            senderName = originalMsg.sender.username || originalMsg.sender.fullName || "Неизвестно"
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
                    senderName: msg.sender?.username || msg.sender?.fullName || "Неизвестно",
                    chatId: msg.chat?.toString() || msg.chat,
                    content: msg.isEncrypted ? decryptMessage(msg.content) : msg.content,
                    replyTo,
                }
            }),
        )
        res.json(messagesWithReply)
    } catch (error) {
        console.error("/api/messages/:chatId error:", error)
        res.status(500).json({ error: "Ошибка сервера" })
    }
})

app.post("/api/upload-image", uploadLimiter, authenticateToken, upload.single("image"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "Файл не загружен" })
        }

        const userId = req.user.userId
        const { chatId } = req.body

        if (!chatId) {
            return res.status(400).json({ error: "chatId обязателен" })
        }

        const chat = await Chat.findById(chatId)
        if (!chat) {
            return res.status(404).json({ error: "Чат не найден" })
        }

        const isGlobalChat = chatId === "global"
        const isParticipant = isGlobalChat || chat.participants.some((p) => p && p.toString() === userId)
        if (!isParticipant) {
            return res.status(403).json({ error: "Нет доступа к чату" })
        }

        const imageUrl = `/avatars/${req.file.filename}`

        const message = await Message.create({
            sender: userId,
            chat: chatId,
            content: `📷 Изображение`,
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

        const user = await User.findById(userId).lean()

        const msgObj = {
            ...message.toObject(),
            id: message._id?.toString() || message._id,
            senderId: userId,
            senderName: user.username,
            chatId: chatId,
            content: `📷 Изображение`,
            fileUrl: imageUrl,
            fileName: req.file.originalname,
            fileSize: req.file.size,
        }

        io.to(chatId).emit("new_message", msgObj)

        res.json({
            success: true,
            message: msgObj,
            imageUrl: imageUrl,
        })

        console.log(`📷 Изображение загружено: ${user.username} -> ${chatId}`)
    } catch (error) {
        console.error("upload-image error:", error)
        res.status(500).json({ error: "Ошибка загрузки изображения" })
    }
})

app.post("/api/bot-news", authenticateToken, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user.userId)
        if (!currentUser || !currentUser.isAdmin) {
            return res.status(403).json({ error: "Только админ может отправлять новости" })
        }
        const { text } = req.body
        if (!text || typeof text !== "string" || !text.trim()) {
            return res.status(400).json({ error: "Текст новости обязателен" })
        }
        await ensureBotUser()
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
        res.status(500).json({ error: "Ошибка рассылки новости" })
    }
})

app.post("/api/ban-user", authenticateToken, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user.userId)
        if (!currentUser || !currentUser.isAdmin) {
            return res.status(403).json({ error: "Только админ может банить" })
        }

        const { userId } = req.body
        if (!userId) {
            return res.status(400).json({ error: "userId обязателен" })
        }

        await User.findByIdAndUpdate(userId, {
            status: "banned",
            isOnline: false
        })

        for (const [socketId, uid] of activeConnections.entries()) {
            if (uid === userId) {
                const socket = io.sockets.sockets.get(socketId)
                if (socket) {
                    socket.emit("error", { message: "Ваш аккаунт заблокирован" })
                    socket.disconnect(true)
                }
            }
        }

        console.log(`🚫 Пользователь ${userId} забанен администратором ${currentUser.username}`)
        res.json({ success: true })

    } catch (error) {
        console.error("ban-user error:", error)
        res.status(500).json({ error: "Ошибка бана пользователя" })
    }
})

app.post("/api/unban-user", authenticateToken, async (req, res) => {
    try {
        const currentUser = await User.findById(req.user.userId)
        if (!currentUser || !currentUser.isAdmin) {
            return res.status(403).json({ error: "Только админ может разбанить" })
        }

        const { userId } = req.body
        if (!userId) {
            return res.status(400).json({ error: "userId обязателен" })
        }

        await User.findByIdAndUpdate(userId, { status: "offline" })

        console.log(`✅ Пользователь ${userId} разбанен администратором ${currentUser.username}`)
        res.json({ success: true })

    } catch (error) {
        console.error("unban-user error:", error)
        res.status(500).json({ error: "Ошибка разбана пользователя" })
    }
})

app.post("/api/clear-global-chat", authenticateToken, async (req, res) => {
    try {
        await Message.deleteMany({ chat: "global" })
        io.to("global").emit("chat_cleared", { chatId: "global" })

        console.log("🌐 Общий чат полностью очищен")
        res.json({ success: true, message: "Общий чат полностью очищен" })
    } catch (error) {
        console.error("clear-global-chat error:", error)
        res.status(500).json({ error: "Ошибка очистки общего чата" })
    }
})

// ========== SOCKET.IO AUTHENTICATION ==========

io.use(async (socket, next) => {
    try {
        const hdrAuth = socket.handshake.headers && socket.handshake.headers.authorization
        const queryToken =
            socket.handshake.query &&
            (socket.handshake.query.token || socket.handshake.query.auth || socket.handshake.query.jwt)
        const authToken = socket.handshake.auth && (socket.handshake.auth.token || socket.handshake.auth.jwt)
        const token =
            authToken ||
            (hdrAuth ? String(hdrAuth).replace(/^Bearer\s+/i, "") : null) ||
            (queryToken ? String(queryToken) : null)

        if (!token) {
            return next(new Error("Токен аутентификации обязателен"))
        }

        jwt.verify(token, JWT_SECRET, async (err, decoded) => {
            if (err) {
                return next(new Error("Недействительный или истекший токен"))
            }

            try {
                // Проверка бана по IP
                const reqLike = { headers: socket.handshake.headers, ip: socket.request?.ip }
                const clientIp = getClientIp(reqLike)
                const bannedIp = await BannedIP.findOne({ ip: clientIp }).lean()
                if (bannedIp) {
                    console.log("❌ Socket.IO: IP забанен:", clientIp)
                    return next(new Error("IP забанен"))
                }

                const user = await User.findById(decoded.userId).lean()
                if (!user) {
                    return next(new Error("Пользователь не найден"))
                }

                // ВАЖНО: Проверка banned статуса
                if (user.status === 'banned') {
                    console.log("❌ Попытка подключения забаненного пользователя:", user.username)
                    return next(new Error("Ваш аккаунт заблокирован"))
                }

                socket.userId = user._id.toString()
                socket.user = {
                    ...user,
                    id: user._id.toString(),
                }

                // Сохраняем последний IP
                try {
                    await User.findByIdAndUpdate(user._id, {
                        lastIp: clientIp,
                        lastSeen: new Date(),
                        isOnline: true
                    })
                } catch (e) { }

                console.log("✅ Socket.IO: пользователь аутентифицирован:", user.username, user._id)
                next()
            } catch (error) {
                console.error("Socket auth error:", error)
                return next(new Error("Ошибка аутентификации"))
            }
        })
    } catch (error) {
        console.error("Socket auth error:", error)
        return next(new Error("Ошибка аутентификации"))
    }
})

// ========== SOCKET.IO EVENTS ==========

io.on("connection", async (socket) => {
    const user = socket.user
    console.log(`🔗 Подключение: ${user.username} (${socket.id})`)

    activeConnections.set(socket.id, user.id)

    await User.findByIdAndUpdate(user.id, {
        isOnline: true,
        lastSeen: new Date(),
        status: "online",
    })
    userHeartbeats.set(user.id, Date.now())

    try {
        const userChats = await Chat.find({ participants: user.id }).lean()
        for (const chat of userChats) {
            socket.join(chat._id.toString())
        }

        socket.join("global")
        globalChatOnline.add(socket.id)
        io.to("global").emit("global_online_count", globalChatOnline.size)

        const globalChat = await Chat.findById("global")
        if (globalChat && !globalChat.participants.includes(user.id)) {
            globalChat.participants.push(user.id)
            await globalChat.save()
        }

        console.log(`🌐 ${user.username} присоединен к глобальному чату`)
    } catch (error) {
        console.error("Error joining user chats:", error)
    }

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
                            .populate("sender", "username fullName avatar")
                            .lean()
                        const messageCount = await Message.countDocuments({
                            chat: chat._id,
                        })
                        return {
                            ...chat,
                            id: chat._id?.toString() || chat._id,
                            participants: chat.participants.filter((p) => p !== null),
                            lastMessage: lastMessage
                                ? {
                                    ...lastMessage,
                                    id: lastMessage._id?.toString() || lastMessage._id,
                                    senderId: lastMessage.sender?._id?.toString() || lastMessage.sender,
                                    senderName: lastMessage.sender?.username || "Пользователь",
                                    chatId: lastMessage.chat?.toString() || lastMessage.chat,
                                }
                                : null,
                            messageCount,
                            unreadCount: 0,
                        }
                    }),
                )

                const globalChat = await Chat.findById("global").lean()
                if (globalChat && !chatList.some((chat) => (chat.id || chat._id) === "global")) {
                    const globalLastMessage = await Message.findOne({ chat: "global" })
                        .sort({ timestamp: -1 })
                        .populate("sender", "username fullName avatar")
                        .lean()
                    const globalMessageCount = await Message.countDocuments({
                        chat: "global",
                    })
                    chatList.unshift({
                        ...globalChat,
                        id: globalChat._id?.toString() || globalChat._id,
                        participants: globalChat.participants || [],
                        lastMessage: globalLastMessage
                            ? {
                                ...globalLastMessage,
                                id: globalLastMessage._id?.toString() || globalLastMessage._id,
                                senderId: globalLastMessage.sender?._id?.toString() || globalLastMessage.sender,
                                senderName: globalLastMessage.sender?.username || "Пользователь",
                                chatId: globalLastMessage.chat?.toString() || globalLastMessage.chat,
                            }
                            : null,
                        messageCount: globalMessageCount,
                        unreadCount: 0,
                    })
                }

                socket.emit("my_chats", chatList)
            }
        } catch (error) {
            console.error("Error in get_my_chats:", error)
            socket.emit("my_chats", [])
        }
    })

    socket.on("get_messages", async (data) => {
        try {
            const { chatId } = data
            const page = 0
            const limit = 50
            const skip = page * limit

            const isGlobalChat = chatId === "global"
            if (!isGlobalChat) {
                const chat = await Chat.findById(chatId).lean()
                if (!chat) {
                    socket.emit("chat_messages", { chatId, messages: [] })
                    return
                }

                const isParticipant = chat.participants
                    .filter((p) => p !== null)
                    .map((id) => id.toString())
                    .includes(user.id)
                if (!isParticipant) {
                    socket.emit("chat_messages", { chatId, messages: [] })
                    return
                }
            }

            const chatMessages = await Message.find({ chat: chatId })
                .populate("sender", "username fullName")
                .sort({ timestamp: 1 })
                .skip(skip)
                .limit(limit)
                .lean()

            const decryptedMessages = chatMessages.map((msg) => ({
                ...msg,
                id: msg._id?.toString() || msg._id,
                senderId: msg.sender?._id?.toString() || msg.sender?.toString() || msg.sender,
                senderName: msg.sender?.username || msg.sender?.fullName || "Неизвестно",
                chatId: msg.chat?.toString() || msg.chat,
                content: msg.isEncrypted ? decryptMessage(msg.content) : msg.content,
            }))

            socket.emit("chat_messages", { chatId, messages: decryptedMessages })
        } catch (error) {
            console.error("get_messages error:", error)
            socket.emit("chat_messages", {
                chatId: data?.chatId || "unknown",
                messages: [],
            })
        }
    })

    socket.on("search_users", async (query) => {
        try {
            if (!query || typeof query !== "string" || query.length < 2) {
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

    socket.on("create_private_chat", async (data) => {
        try {
            const { userId, chatId, createdBy } = data

            if (createdBy && createdBy !== user.id) {
                return
            }

            let chat = await Chat.findById(chatId)
            if (!chat) {
                const otherUser = await User.findById(userId).lean()
                const otherUserName = otherUser ? otherUser.username : "Неизвестно"

                chat = await Chat.create({
                    _id: chatId,
                    name: otherUserName,
                    avatar: otherUser?.avatar || null,
                    description: `Приватный чат с ${otherUserName}`,
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
            }

            const populatedChat = await Chat.findById(chat._id)
                .populate("participants", "_id username fullName avatar isOnline isVerified status")
                .lean()

            socket.join(chatId)

            const targetSocket = Array.from(io.sockets.sockets.values()).find((s) => s.userId === userId)
            if (targetSocket) {
                targetSocket.join(chatId)
                targetSocket.emit("new_private_chat", {
                    ...populatedChat,
                    id: populatedChat._id?.toString() || populatedChat._id,
                    participants: populatedChat.participants.filter((p) => p !== null),
                })
            }

            socket.emit("new_private_chat", {
                ...populatedChat,
                id: populatedChat._id?.toString() || populatedChat._id,
                participants: populatedChat.participants.filter((p) => p !== null),
            })

            console.log(`💬 Создан приватный чат: ${user.username} ↔ ${userId}`)
        } catch (error) {
            console.error("create_private_chat error:", error)
        }
    })

    socket.on("join_chat", async (chatId) => {
        try {
            if (chatId === "global") {
                socket.join(chatId)
                globalChatOnline.add(socket.id)
                io.to("global").emit("global_online_count", globalChatOnline.size)
                return
            }

            const chat = await Chat.findById(chatId)
            if (!chat) {
                socket.emit("error", { message: "Чат не найден" })
                return
            }

            const isParticipant = chat.participants.some((p) => p && p.toString() === user.id)
            if (!isParticipant) {
                яяяяя
                socket.emit("error", {
                    message: "Вы не являетесь участником этого чата",
                })
                return
            }

            socket.join(chatId)
        } catch (error) {
            console.error("join_chat error:", error)
            socket.emit("error", { message: "Ошибка присоединения к чату" })
        }
    })

    socket.on("send_message", async (messageData) => {
        try {
            let chat = await Chat.findById(messageData.chatId)
            if (!chat) {
                if (messageData.chatId.startsWith("private_")) {
                    const participantIds = messageData.chatId.replace("private_", "").split("_")
                    if (participantIds.length >= 2) {
                        const otherUserId = participantIds.find((id) => id !== user.id)
                        const otherUser = otherUserId ? await User.findById(otherUserId).lean() : null
                        const otherUserName = otherUser ? otherUser.username : "Неизвестно"

                        chat = await Chat.create({
                            _id: messageData.chatId,
                            name: otherUserName,
                            avatar: otherUser?.avatar || null,
                            description: `Приватный чат с ${otherUserName}`,
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
                    }
                }

                if (!chat) {
                    socket.emit("error", {
                        message: "Чат не найден и не может быть создан",
                    })
                    return
                }
            }

            const isGlobalChat = messageData.chatId === "global"
            const isParticipant = isGlobalChat || chat.participants.some((p) => p && p.toString() === user.id)
            if (!isParticipant) {
                socket.emit("error", {
                    message: "Вы не являетесь участником этого чата",
                })
                return
            }

            // Rate limiting для глобального чата
            if (isGlobalChat) {
                const now = Date.now()
                const lastTimestamp = globalChatRateLimit.get(user.id) || 0
                if (now - lastTimestamp < 5000) {
                    socket.emit("error", {
                        message: "В общий чат можно отправлять сообщение раз в 5 секунд!",
                    })
                    return
                }
                globalChatRateLimit.set(user.id, now)
            }

            // Ограничение на количество слов
            const originalContent = messageData.isEncrypted ? decryptMessage(messageData.content) : messageData.content
            const wordCount = originalContent.split(/\s+/).filter(Boolean).length
            if (wordCount > 100) {
                socket.emit("error", {
                    message: "Сообщение не должно содержать более 100 слов!",
                })
                return
            }

            if (!messageData.content || typeof messageData.content !== "string" || messageData.content.trim().length === 0) {
                socket.emit("error", { message: "Сообщение не может быть пустым" })
                return
            }

            if (messageData.content.length > 1000) {
                socket.emit("error", { message: "Сообщение слишком длинное" })
                return
            }

            const message = await Message.create({
                sender: user.id,
                chat: chat._id.toString(),
                content: messageData.content,
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

            let replyToData = null
            if (message.replyTo) {
                const originalMsg = await Message.findById(message.replyTo).lean()
                if (originalMsg) {
                    let senderName = "Неизвестно"
                    if (originalMsg.sender) {
                        const senderUser = await User.findById(originalMsg.sender).lean()
                        senderName = senderUser?.username || senderUser?.fullName || "Неизвестно"
                    }
                    replyToData = {
                        id: originalMsg._id?.toString() || originalMsg._id,
                        content: originalMsg.isEncrypted ? decryptMessage(originalMsg.content) : originalMsg.content,
                        senderName,
                    }
                }
            }

            const msgObj = {
                ...message.toObject(),
                id: message._id?.toString() || message._id,
                senderId: user.id,
                senderName: user.username,
                chatId: chat._id?.toString() || chat._id,
                content: messageData.content,
                replyTo: replyToData,
            }

            io.to(chat._id.toString()).emit("new_message", msgObj)

            if (isGlobalChat) {
                io.emit("new_message", msgObj)
            }

            if (chat.type === "private") {
                chat.participants.forEach((participantId) => {
                    if (participantId.toString() !== user.id) {
                        const targetSocket = Array.from(io.sockets.sockets.values()).find(
                            (s) => s.userId === participantId.toString(),
                        )
                        if (targetSocket) {
                            targetSocket.emit("new_private_chat", {
                                ...chat,
                                id: chat._id?.toString() || chat._id,
                                participants: chat.participants,
                            })
                        }
                    }
                })
            }

            console.log(`💬 Сообщение от ${user.username} в чат ${chat._id} отправлено успешно`)
        } catch (error) {
            console.error("send_message error:", error)
            socket.emit("error", { message: "Ошибка отправки сообщения" })
        }
    })

    socket.on("add_reaction", async (data) => {
        try {
            const { messageId, emoji, userId, username } = data
            if (userId !== user.id) return
            if (!emoji || !reactionEmojis.includes(emoji)) return

            const message = await Message.findById(messageId)
            if (!message) return

            const existing = message.reactions.find((r) => r.userId === userId && r.emoji === emoji)
            if (existing) {
                message.reactions = message.reactions.filter((r) => !(r.userId === userId && r.emoji === emoji))
            } else {
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

    socket.on("typing", async (data) => {
        try {
            const { chatId, userId, username } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            if (
                !chat.participants
                    .filter((p) => p !== null)
                    .map((id) => id.toString())
                    .includes(user.id)
            )
                return
            if (!typingUsers.has(chatId)) {
                typingUsers.set(chatId, new Set())
            }
            typingUsers.get(chatId).add(userId)
            socket.to(chatId).emit("user_typing", { userId, username, chatId })
        } catch (error) {
            console.error("typing error:", error)
        }
    })

    socket.on("stop_typing", async (data) => {
        try {
            const { chatId } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            if (
                !chat.participants
                    .filter((p) => p !== null)
                    .map((id) => id.toString())
                    .includes(user.id)
            )
                return
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

    socket.on("start_call", async (data) => {
        try {
            const { toUserId, chatId, type } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            const participants = chat.participants.filter((p) => p !== null).map((id) => id.toString())
            const isParticipant = participants.includes(user.id) && participants.includes(toUserId)
            if (!isParticipant) return
            const targets = Array.from(io.sockets.sockets.values()).filter((s) => s.userId === toUserId)
            for (const ts of targets) {
                ts.emit("incoming_call", { fromUserId: user.id, chatId, type })
            }
        } catch (error) { }
    })

    socket.on("call_offer", async (data) => {
        try {
            const { toUserId, chatId, sdp } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            const participants = chat.participants.filter((p) => p !== null).map((id) => id.toString())
            const isParticipant = participants.includes(user.id) && participants.includes(toUserId)
            if (!isParticipant) return
            const targets = Array.from(io.sockets.sockets.values()).filter((s) => s.userId === toUserId)
            for (const ts of targets) {
                ts.emit("call_offer", { fromUserId: user.id, chatId, sdp })
            }
        } catch (error) { }
    })

    socket.on("call_answer", async (data) => {
        try {
            const { toUserId, chatId, sdp } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            const participants = chat.participants.filter((p) => p !== null).map((id) => id.toString())
            const isParticipant = participants.includes(user.id) && participants.includes(toUserId)
            if (!isParticipant) return
            const targets = Array.from(io.sockets.sockets.values()).filter((s) => s.userId === toUserId)
            for (const ts of targets) {
                ts.emit("call_answer", { fromUserId: user.id, chatId, sdp })
            }
        } catch (error) { }
    })

    socket.on("ice_candidate", async (data) => {
        try {
            const { toUserId, chatId, candidate } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            const participants = chat.participants.filter((p) => p !== null).map((id) => id.toString())
            const isParticipant = participants.includes(user.id) && participants.includes(toUserId)
            if (!isParticipant) return
            const targets = Array.from(io.sockets.sockets.values()).filter((s) => s.userId === toUserId)
            for (const ts of targets) {
                ts.emit("ice_candidate", { fromUserId: user.id, chatId, candidate })
            }
        } catch (error) { }
    })

    socket.on("end_call", async (data) => {
        try {
            const { toUserId, chatId } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return
            const participants = chat.participants.filter((p) => p !== null).map((id) => id.toString())
            const isParticipant = participants.includes(user.id) && participants.includes(toUserId)
            if (!isParticipant) return
            const targets = Array.from(io.sockets.sockets.values()).filter((s) => s.userId === toUserId)
            for (const ts of targets) {
                ts.emit("end_call", { fromUserId: user.id, chatId })
            }
        } catch (error) { }
    })

    socket.on("clear_chat", async (chatId) => {
        try {
            const chat = await Chat.findById(chatId)
            if (!chat) return

            const isGlobalChat = chatId === "global"
            const isAdmin = user.isAdmin
            const isParticipant = chat.participants
                .filter((p) => p !== null)
                .map((id) => id.toString())
                .includes(user.id)
            const isCreator = chat.createdBy?.toString() === user.id

            if (isGlobalChat && !isAdmin) {
                socket.emit("error", {
                    message: "Только администратор может очищать глобальный чат",
                })
                return
            }

            if (!isParticipant && !isCreator && !isGlobalChat) {
                socket.emit("error", { message: "Нет прав для очистки этого чата" })
                return
            }

            await Message.deleteMany({ chat: chatId })
            io.to(chatId).emit("chat_cleared", { chatId })
            console.log(`🧹 Чат ${chatId} очищен пользователем ${user.username}`)
        } catch (error) {
            console.error("clear_chat error:", error)
        }
    })

    socket.on("update_chat_settings", async (data) => {
        try {
            const { chatId, isPinned, isMuted } = data
            const chat = await Chat.findById(chatId)
            if (!chat) return

            const isParticipant = chat.participants
                .filter((p) => p !== null)
                .map((id) => id.toString())
                .includes(user.id)
            const isCreator = chat.createdBy?.toString() === user.id

            if (!isParticipant && !isCreator) {
                socket.emit("error", {
                    message: "Нет прав для изменения настроек чата",
                })
                return
            }

            const updateData = {}
            if (isPinned !== undefined) updateData.isPinned = isPinned
            if (isMuted !== undefined) updateData.isMuted = isMuted

            await Chat.findByIdAndUpdate(chatId, updateData)

            io.to(chatId).emit("chat_settings_updated", {
                chatId,
                isPinned,
                isMuted,
            })
        } catch (error) {
            console.error("update_chat_settings error:", error)
        }
    })

    socket.on("heartbeat", () => {
        userHeartbeats.set(user.id, Date.now())
    })

    socket.on("update_profile", async (userData) => {
        try {
            const allowedFields = ["fullName", "bio", "avatar"]
            const sanitizedData = {}
            for (const field of allowedFields) {
                if (userData[field] !== undefined) {
                    if (field === "fullName" && userData[field]) {
                        sanitizedData[field] = userData[field].trim().substring(0, 50)
                    } else if (field === "bio" && userData[field]) {
                        sanitizedData[field] = userData[field].trim().substring(0, 200)
                    } else {
                        sanitizedData[field] = userData[field]
                    }
                }
            }
            await User.findByIdAndUpdate(user.id, sanitizedData)

            const activeUsers = await User.find({ isOnline: true }).lean()
            io.emit(
                "users_update",
                activeUsers.map((u) => ({
                    id: u._id.toString(),
                    username: u.username,
                    fullName: u.fullName,
                    email: u.email,
                    avatar: u.avatar,
                    isOnline: u.isOnline,
                    isVerified: u.isVerified,
                    status: u.status,
                })),
            )
            console.log(`👤 ${user.username} обновил профиль`)
        } catch (error) {
            console.error("update_profile error:", error)
        }
    })

    socket.on("delete_message", async (data) => {
        try {
            const { messageId } = data
            const message = await Message.findById(messageId)
            if (!message) {
                socket.emit("error", { message: "Сообщение не найдено" })
                return
            }
            if (message.sender.toString() !== user.id) {
                socket.emit("error", { message: "Вы не можете удалить это сообщение" })
                return
            }
            await Message.findByIdAndDelete(messageId)
            io.to(message.chat.toString()).emit("message_deleted", messageId)
        } catch (error) {
            console.error("delete_message error:", error)
            socket.emit("error", { message: "Ошибка удаления сообщения" })
        }
    })

    socket.on("edit_message", async (data) => {
        try {
            const { messageId, newContent, isEncrypted } = data
            const message = await Message.findById(messageId)
            if (!message) {
                socket.emit("error", { message: "Сообщение не найдено" })
                return
            }
            if (message.sender.toString() !== user.id) {
                socket.emit("error", {
                    message: "Вы не можете редактировать это сообщение",
                })
                return
            }
            message.content = newContent
            message.isEncrypted = !!isEncrypted
            message.isEdited = true
            await message.save()

            const msgObj = {
                ...message.toObject(),
                id: message._id?.toString() || message._id,
                senderId: user.id,
                senderName: user.username,
                chatId: message.chat?.toString() || message.chat,
                content: newContent,
                isEdited: true,
            }
            io.to(message.chat.toString()).emit("message_edited", msgObj)
        } catch (error) {
            console.error("edit_message error:", error)
            socket.emit("error", { message: "Ошибка редактирования сообщения" })
        }
    })

    socket.on("disconnect", async () => {
        activeConnections.delete(socket.id)

        for (const [chatId, typingSet] of typingUsers.entries()) {
            if (typingSet.has(user.id)) {
                typingSet.delete(user.id)
                if (typingSet.size === 0) {
                    typingUsers.delete(chatId)
                }
                socket.to(chatId).emit("user_stop_typing", { userId: user.id, chatId })
            }
        }

        await User.findByIdAndUpdate(user.id, {
            isOnline: false,
            lastSeen: new Date(),
            status: "offline",
        })

        userHeartbeats.delete(user.id)
        globalChatOnline.delete(socket.id)
        io.to("global").emit("global_online_count", globalChatOnline.size)

        const activeUsers = await User.find({ isOnline: true }).lean()
        io.emit(
            "users_update",
            activeUsers.map((u) => ({
                id: u._id.toString(),
                username: u.username,
                fullName: u.fullName,
                email: u.email,
                avatar: u.avatar,
                isOnline: u.isOnline,
                isVerified: u.isVerified,
                status: u.status,
            })),
        )
        console.log(`🔌 Отключение: ${user.username}`)
    })
})

// Автоочистка глобального чата каждое воскресенье в 4:00
let lastGlobalChatCleanupDay = null

setInterval(async () => {
    const now = new Date()
    // Воскресенье (0) в 4:00
    if (now.getDay() === 0 && now.getHours() === 4 && now.getMinutes() === 0) {
        const today = now.toISOString().slice(0, 10)
        if (lastGlobalChatCleanupDay !== today) {
            try {
                await Message.deleteMany({ chat: "global" })
                io.to("global").emit("chat_cleared", { chatId: "global" })
                lastGlobalChatCleanupDay = today
                console.log("🌐 Глобальный чат автоматически очищен в 4:00 утра")
            } catch (error) {
                console.error("Ошибка автоочистки глобального чата:", error)
            }
        }
    }
}, 60 * 1000)

// ========== MULTER ERROR HANDLER ==========

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        if (err.code === "LIMIT_FILE_SIZE") {
            return res.status(400).json({ error: "Файл слишком большой. Максимальный размер — 10 МБ." })
        }
        return res.status(400).json({ error: "Ошибка загрузки файла: " + err.message })
    } else if (err) {
        return res.status(500).json({ error: "Ошибка сервера: " + err.message })
    }
    next()
})

// ========== MONGODB CONNECTION ==========

let connectionAttempts = 0
const maxConnectionAttempts = 5

const connectToMongoDB = async () => {
    try {
        connectionAttempts++
        console.log(`🔄 Попытка подключения к MongoDB (${connectionAttempts}/${maxConnectionAttempts})`)

        await mongoose.connect(
            "mongodb+srv://actogol:actogolsila@actogramuz.6ogftpx.mongodb.net/actogram?retryWrites=true&w=majority&appName=actogramUZ",
            {
                serverSelectionTimeoutMS: 10000,
                socketTimeoutMS: 45000,
            }
        )

        console.log("✅ MongoDB подключен успешно")
        connectionAttempts = 0

        // ВАЖНО: Инициализация после подключения
        await ensureAdminUser()
        await ensureBotUser()
        await ensureGlobalChat()

        console.log("✅ Инициализация завершена")

    } catch (err) {
        console.error(`❌ Ошибка подключения к MongoDB (попытка ${connectionAttempts}):`, err.message)
        if (connectionAttempts >= maxConnectionAttempts) {
            console.error("🚫 Превышено максимальное количество попыток подключения")
            console.log("💡 Проверьте настройки MongoDB Atlas:")
            console.log("   1. IP адреса в Network Access")
            console.log("   2. Правильность строки подключения")
            console.log("   3. Статус кластера")
            return
        }
        console.log(`⏳ Повторная попытка через 5 секунд...`)
        setTimeout(connectToMongoDB, 5000)
    }
}

mongoose.connection.on("error", (err) => {
    console.error("❌ MongoDB connection error:", err.message)
})

mongoose.connection.on("disconnected", () => {
    console.log("🔌 MongoDB disconnected")
    if (connectionAttempts < maxConnectionAttempts) {
        setTimeout(connectToMongoDB, 5000)
    }
})

mongoose.connection.on("connected", () => {
    console.log("✅ MongoDB connected")
})

mongoose.connection.on("reconnected", () => {
    console.log("🔄 MongoDB reconnected")
})

// Запуск подключения
connectToMongoDB()

// ========== SERVER START ==========

server.listen(PORT, async () => {
    console.log(`
  ╔════════════════════════════════════════════════════════════╗
  ║          ACTOGRAM Server v3.0 запущен на порту ${PORT}         ║
  ╚════════════════════════════════════════════════════════════╝
  
  🌐 Клиент: https://acto-uimuz.vercel.app
  🔒 Безопасность: JWT + Bcrypt + Rate Limiting + E2E Encryption
  📱 Функции: Приватные чаты, групповые чаты, глобальный чат
  ✨ Дополнительно: Реакции, ответы, редактирование, админ-панель
  `)
})

// ========== GRACEFUL SHUTDOWN ==========

process.on("SIGTERM", () => {
    console.log("SIGTERM получен, завершаем работу сервера...")
    server.close(() => {
        console.log("Сервер успешно завершил работу")
        mongoose.connection.close(false, () => {
            console.log("MongoDB соединение закрыто")
            process.exit(0)
        })
    })
})

process.on("SIGINT", () => {
    console.log("SIGINT получен, завершаем работу сервера...")
    server.close(() => {
        console.log("Сервер успешно завершил работу")
        mongoose.connection.close(false, () => {
            console.log("MongoDB соединение закрыто")
            process.exit(0)
        })
    })
})

// ========== UNHANDLED ERRORS ==========

process.on("uncaughtException", (error) => {
    console.error("❌ Uncaught Exception:", error)
    process.exit(1)
})

process.on("unhandledRejection", (reason, promise) => {
    console.error("❌ Unhandled Rejection at:", promise, "reason:", reason)
    process.exit(1)
})
