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

// Инициализация приложенияa
const app = express()
const server = http.createServer(app)

// Настройка trust proxy для работы за прокси (Render.com)
app.set('trust proxy', 1)

// Безопасность
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }),
)

// Rate limiting с правильной настройкой для прокси
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 минут
  max: 100, // максимум 100 запросов
  message: "Слишком много запросов, попробуйте позже",
  standardHeaders: true,
  legacyHeaders: false,
  // Настройка для работы за прокси
  skip: (req) => req.ip === '127.0.0.1' || req.ip === '::1',
})

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // максимум 5 попыток входа
  message: "Слишком много попыток входа, подождите 15 минут",
  standardHeaders: true,
  legacyHeaders: false,
  // Настройка для работы за прокси
  skip: (req) => req.ip === '127.0.0.1' || req.ip === '::1',
})

// Создать папку avatars, если не существует
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
      cb(new Error("Только изображения (jpg, png, webp)"))
    }
  },
})

// Конфигурация
const JWT_SECRET = process.env.JWT_SECRET || "actogram_ultra_secure_key_2024_v3"
const PORT = process.env.PORT || 3001

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

// Хранилище данных (в продакшене использовать базу данных)
const activeConnections = new Map() // socketId -> userId
const typingUsers = new Map() // chatId -> Set of userIds
const blockedUsers = new Map() // userId -> Set of blocked userIds
const userHeartbeats = new Map() // userId -> lastHeartbeat timestamp
// Rate limiting для общего чата
const globalChatRateLimit = new Map(); // userId -> lastTimestamp
const globalChatOnline = new Set(); // socket.id

// Middleware для проверки JWT
const authenticateToken = (req, res, next) => {
  let token = null;
  const authHeader = req.headers["authorization"];
  console.log("🔍 Проверяем аутентификацию для запроса:", req.path);
  console.log("🔍 Заголовки:", Object.keys(req.headers));
  console.log("🔍 Cookie:", req.cookies);
  console.log("🔍 Origin:", req.headers.origin);
  console.log("🔍 Host:", req.headers.host);
  
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
    console.log("🔑 Токен получен из заголовка Authorization");
  } else if (req.cookies && req.cookies.token) {
    token = req.cookies.token;
    console.log("🍪 Токен получен из cookie");
  } else {
    console.log("❌ Токен не найден ни в заголовке, ни в cookie");
    console.log("🔍 Все cookie:", JSON.stringify(req.cookies, null, 2));
  }

  if (!token) {
    console.log("❌ Токен отсутствует, возвращаем 401");
    return res.status(401).json({ error: "Токен доступа обязателен" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.log("❌ Ошибка верификации токена:", err.message);
      return res.status(403).json({ error: "Недействительный или истекший токен" });
    }
    console.log("✅ Пользователь аутентифицирован:", user.userId, user.username);
    req.user = user;
    next();
  });
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

// Создание пользователя-бота при запуске
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
      bio: "Официальный бот Actogram. Новости и обновления.",
      password: "bot_password_12345678", // не используется
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
}

// Создание глобального чата (если его нет)
async function ensureGlobalChat() {
  const globalChatId = "global";
  let chat = await Chat.findById(globalChatId);
  if (!chat) {
    chat = await Chat.create({
      _id: globalChatId,
      name: "ACTO — Общий чат",
      avatar: null,
      description: "Глобальный чат для всех пользователей",
      isGroup: true,
      participants: [], // Можно оставить пустым, чтобы не было ограничений
      createdAt: new Date(),
      type: "group",
      isEncrypted: false,
      createdBy: null,
      theme: "default",
      isPinned: true,
      isMuted: false,
    });
    console.log("🌍 Глобальный чат создан!");
  }
}

// Главная страница
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
                    <div class="feature-icon">🌍</div>
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
        
        <script src="/socket.io/socket.io.js"></script>
        <script>
            const socket = io();
            socket.on('connect', () => {
                console.log('🟢 WebSocket подключен:', socket.id);
            });
            socket.on('disconnect', () => {
                console.log('🔴 WebSocket отключен');
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

// Endpoint для загрузки аватара
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

// Endpoint для создания группы/канала с аватаром
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
    // Участники: всегда добавлять создателя
    let members = [userId]
    if (participants) {
      try {
        const parsed = JSON.parse(participants)
        if (Array.isArray(parsed)) {
          members = Array.from(new Set([...members, ...parsed]))
        }
      } catch {}
    }
    // Генерируем уникальный id для группы/канала
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
    // Получить участников для ответа
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
    res.status(500).json({ error: "Ошибка создания группы/канала" })
  }
})

// Аутентификация
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
        return res.status(400).json({ error: "Username должен начинаться с @ и содержать 3-20 символов" })
      }

      const existingUser = await User.findOne({ $or: [{ email }, { username }] })
      if (existingUser) {
        return res.status(400).json({ error: "Пользователь с таким email или username уже существует" })
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
      // --- Устанавливаем cookie с токеном ---
      res.cookie('token', token, {
        httpOnly: false, // Изменено на false для отладки
        secure: false,
        sameSite: 'Lax', // Вернули обратно
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
      })
      console.log("🍪 Cookie установлен для пользователя:", user.username)
      // ---
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
      const isValidPassword = await bcrypt.compare(password, user.password)
      if (!isValidPassword) {
        return res.status(401).json({ error: "Неверный email или пароль" })
      }
      user.isOnline = true
      user.lastSeen = new Date()
      user.status = "online"
      await user.save()
      const token = jwt.sign({ userId: user._id, email: user.email, username: user.username }, JWT_SECRET, { expiresIn: "30d" })
      const userResponse = user.toObject()
      delete userResponse.password
      userResponse.id = user._id.toString()
      // --- Устанавливаем cookie с токеном ---
      res.cookie('token', token, {
        httpOnly: false, // Изменено на false для отладки
        secure: false,
        sameSite: 'Lax', // Вернули обратно
        maxAge: 30 * 24 * 60 * 60 * 1000,
        path: '/'
      })
      console.log("🍪 Cookie установлен для пользователя:", user.username)
      // ---
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

// Получение чатов пользователя (MongoDB)
app.get("/api/chats", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId
    console.log("📋 Запрос чатов для пользователя:", userId, req.user.username)
    
    // Найти все чаты, где пользователь — участник
    const chats = await Chat.find({ participants: userId })
      .populate("participants", "_id username fullName avatar isOnline isVerified status")
      .sort({ updatedAt: -1 }) // Сортируем по времени обновления
      .lean()
    
    console.log("📋 Найдено чатов:", chats.length)
    
    // Для каждого чата получить последнее сообщение и количество сообщений
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
          unreadCount: 0, // TODO: реализовать
        }
      })
    )
    
    // Всегда добавляем глобальный чат в начало списка
    const globalChat = await Chat.findById("global").lean();
    if (globalChat) {
      // Получаем последнее сообщение и количество сообщений для глобального чата
      const globalLastMessage = await Message.findOne({ chat: "global" })
        .sort({ timestamp: -1 })
        .lean()
      const globalMessageCount = await Message.countDocuments({ chat: "global" })
      
      // Добавляем глобальный чат в начало списка
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
      console.log("🌍 Глобальный чат добавлен в список");
    }
    
    console.log("📋 Отправляем список чатов:", chatList.length, "чатов");
    res.json(chatList)
  } catch (error) {
    console.error("/api/chats error:", error)
    res.status(500).json({ error: "Ошибка сервера" })
  }
})

// Получение сообщений чата (MongoDB) с пагинацией
app.get("/api/messages/:chatId", authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params
    const userId = req.user.userId
    const page = parseInt(req.query.page) || 0
    const limit = parseInt(req.query.limit) || 50
    const skip = page * limit
    const chat = await Chat.findById(chatId).lean()
    if (!chat) return res.status(404).json({ error: "Чат не найден" })
    
    // Для глобального чата разрешаем всем пользователям получать сообщения
    const isGlobalChat = chatId === "global"
    const isParticipant = isGlobalChat || chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(userId)
    if (!isParticipant) {
      return res.status(403).json({ error: "Нет доступа к этому чату" })
    }
    
    const chatMessages = await Message.find({ chat: chatId })
      .populate("sender", "username fullName") // Добавляем информацию об отправителе
      .sort({ timestamp: 1 })
      .skip(skip)
      .limit(limit)
      .lean()

    // Для каждого сообщения с replyTo подгружаем оригинал
    const messagesWithReply = await Promise.all(chatMessages.map(async (msg) => {
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
        senderName: msg.sender?.username || msg.sender?.fullName || "Неизвестно", // Добавляем имя отправителя
        chatId: msg.chat?.toString() || msg.chat,
        content: msg.isEncrypted ? decryptMessage(msg.content) : msg.content,
        replyTo, // теперь это объект, а не id
      }
    }))
    res.json(messagesWithReply)
  } catch (error) {
    console.error("/api/messages/:chatId error:", error)
    res.status(500).json({ error: "Ошибка сервера" })
  }
})

// Socket.IO аутентификация (MongoDB)
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token
    console.log("🔌 Socket.IO подключение, токен:", token ? "есть" : "нет")

    if (!token) {
      console.log("❌ Socket.IO: токен отсутствует")
      return next(new Error("Токен аутентификации обязателен"))
    }

    jwt.verify(token, JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.log("❌ Socket.IO: ошибка верификации токена:", err.message)
        return next(new Error("Недействительный или истекший токен"))
      }

      try {
        const user = await User.findById(decoded.userId).lean()
        if (!user) {
          console.log("❌ Socket.IO: пользователь не найден в БД")
          return next(new Error("Пользователь не найден"))
        }

        socket.userId = user._id.toString()
        socket.user = {
          ...user,
          id: user._id.toString() // Добавляем поле id для совместимости
        }
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

// Socket.IO обработчики
io.on("connection", async (socket) => {
  const user = socket.user
  console.log(`🔗 Подключение: ${user.username} (${socket.id})`)

  activeConnections.set(socket.id, user.id)
  // При подключении обновлять статус пользователя в MongoDB
  await User.findByIdAndUpdate(user.id, { isOnline: true, lastSeen: new Date(), status: "online" })
  userHeartbeats.set(user.id, Date.now())

      // Присоединяем пользователя ко всем его чатам (MongoDB)
    try {
      const userChats = await Chat.find({ participants: user.id }).lean()
      for (const chat of userChats) {
        socket.join(chat._id.toString())
      }
      
      // Всегда присоединяем к глобальному чату и добавляем пользователя в участники
      socket.join("global")
      globalChatOnline.add(socket.id);
      io.to('global').emit('global_online_count', globalChatOnline.size);
      
      // Добавляем пользователя в участники глобального чата если его там нет
      const globalChat = await Chat.findById("global");
      if (globalChat && !globalChat.participants.includes(user.id)) {
        globalChat.participants.push(user.id);
        await globalChat.save();
        console.log(`🌍 ${user.username} добавлен в участники глобального чата`)
      }
      
      console.log(`🌍 ${user.username} присоединен к глобальному чату`)
    } catch (error) {
      console.error("Error joining user chats:", error)
    }

  // Получение чатов пользователя (MongoDB)
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
        
        // Всегда добавляем глобальный чат в начало списка
        const globalChat = await Chat.findById("global").lean();
        if (globalChat) {
          // Получаем последнее сообщение и количество сообщений для глобального чата
          const globalLastMessage = await Message.findOne({ chat: "global" })
            .sort({ timestamp: -1 })
            .lean()
          const globalMessageCount = await Message.countDocuments({ chat: "global" })
          
          // Добавляем глобальный чат в начало списка
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
          console.log("🌍 Глобальный чат добавлен в список");
        }
        
        socket.emit("my_chats", chatList)
      }
    } catch (error) {
      console.error("get_my_chats error:", error)
      socket.emit("my_chats", [])
    }
  })

      // Получение сообщений (MongoDB)
    socket.on("get_messages", async (data) => {
      try {
        const { chatId, userId } = data
        const page = 0
        const limit = 50
        const skip = page * limit
        
        console.log(`📨 Запрос сообщений для чата: ${chatId}`)
        
        // Для глобального чата разрешаем всем пользователям получать сообщения
        const isGlobalChat = chatId === "global"
        if (!isGlobalChat) {
          const chat = await Chat.findById(chatId).lean()
          if (!chat) {
            console.log(`❌ Чат не найден: ${chatId}`)
            socket.emit("chat_messages", { chatId, messages: [] })
            return
          }
          
          const isParticipant = chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)
          if (!isParticipant) {
            console.log(`❌ Пользователь не является участником чата: ${chatId}`)
            socket.emit("chat_messages", { chatId, messages: [] })
            return
          }
        }

        const chatMessages = await Message.find({ chat: chatId })
          .populate("sender", "username fullName") // Добавляем информацию об отправителе
          .sort({ timestamp: 1 })
          .skip(skip)
          .limit(limit)
          .lean()

        const decryptedMessages = chatMessages.map((msg) => ({
          ...msg,
          id: msg._id?.toString() || msg._id,
          senderId: msg.sender?._id?.toString() || msg.sender?.toString() || msg.sender,
          senderName: msg.sender?.username || msg.sender?.fullName || "Неизвестно", // Добавляем имя отправителя
          chatId: msg.chat?.toString() || msg.chat,
          content: msg.isEncrypted ? decryptMessage(msg.content) : msg.content,
        }))

        socket.emit("chat_messages", { chatId, messages: decryptedMessages })
      } catch (error) {
        console.error("get_messages error:", error)
        socket.emit("chat_messages", { chatId: data?.chatId || "unknown", messages: [] })
      }
    })

  // Поиск пользователей (MongoDB)
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

  // Создание приватного чата (MongoDB)
  socket.on("create_private_chat", async (data) => {
    try {
      console.log(`💬 Попытка создания приватного чата: ${user.username} -> ${data.userId}`)
      console.log(`💬 Данные чата:`, data)
      
      const { userId, chatId, createdBy } = data
      console.log(`🔍 Проверка создателя чата: createdBy=${createdBy}, user.id=${user.id}`)
      
      // Проверяем, что создатель чата - это текущий пользователь
      if (createdBy && createdBy !== user.id) {
        console.log(`❌ Неверный создатель чата: ${createdBy} != ${user.id}`)
        return
      }
      
      // Проверить, существует ли уже такой чат
      let chat = await Chat.findById(chatId)
      if (!chat) {
        console.log(`📝 Создание нового чата: ${chatId}`)
        
        // Получить информацию о собеседнике
        const otherUser = await User.findById(userId).lean()
        const otherUserName = otherUser ? otherUser.username : "Неизвестно"
        
        // Создать новый чат
        chat = await Chat.create({
          _id: chatId, // Используем строковый ID
          name: otherUserName, // Используем имя собеседника
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
        console.log(`✅ Чат создан: ${chat._id} с собеседником: ${otherUserName}`)
      } else {
        console.log(`📋 Чат уже существует: ${chat._id}`)
      }
      
      // Получить участников
      const populatedChat = await Chat.findById(chat._id)
        .populate("participants", "_id username fullName avatar isOnline isVerified status")
        .lean()
      
      console.log(`📋 Участники чата:`, populatedChat.participants)
      
      // Присоединяем текущего пользователя к чату
      socket.join(chatId)
      console.log(`✅ ${user.username} присоединен к чату: ${chatId}`)
      
      // Находим и присоединяем второго пользователя
      const targetSocket = Array.from(io.sockets.sockets.values()).find((s) => s.userId === userId)
      if (targetSocket) {
        targetSocket.join(chatId)
        console.log(`✅ Второй пользователь присоединен к чату: ${chatId}`)
        targetSocket.emit("new_private_chat", {
          ...populatedChat,
          id: populatedChat._id?.toString() || populatedChat._id,
          participants: populatedChat.participants.filter(p => p !== null),
        })
      } else {
        console.log(`⚠️ Второй пользователь не найден онлайн: ${userId}`)
      }
      
      // Отправляем событие текущему пользователю
      socket.emit("new_private_chat", {
        ...populatedChat,
        id: populatedChat._id?.toString() || populatedChat._id,
        participants: populatedChat.participants.filter(p => p !== null),
      })
      
      console.log(`💬 Создан приватный чат: ${user.username} ↔ ${userId}`)
    } catch (error) {
      console.error("create_private_chat error:", error)
    }
  })

  // Присоединение к чату (MongoDB)
  socket.on("join_chat", async (chatId) => {
    try {
      console.log(`📥 Попытка присоединения к чату: ${user.username} -> ${chatId}`)
      
      // Для глобального чата не проверяем существование
      if (chatId === "global") {
        socket.join(chatId)
        globalChatOnline.add(socket.id)
        io.to('global').emit('global_online_count', globalChatOnline.size)
        console.log(`✅ ${user.username} присоединился к глобальному чату`)
        return
      }
      
      const chat = await Chat.findById(chatId)
      if (!chat) {
        console.log(`❌ Чат не найден: ${chatId}`)
        socket.emit("error", { message: "Чат не найден" })
        return
      }

      console.log(`📋 Участники чата:`, chat.participants)
      console.log(`👤 Текущий пользователь: ${user.id}`)
      
      // Проверяем, является ли пользователь участником чата
      const isParticipant = chat.participants.some(p => p && p.toString() === user.id)
      if (!isParticipant) {
        console.log(`❌ Пользователь ${user.username} не является участником чата ${chatId}`)
        socket.emit("error", { message: "Вы не являетесь участником этого чата" })
        return
      }

      socket.join(chatId)
      console.log(`✅ ${user.username} присоединился к чату: ${chatId}`)
    } catch (error) {
      console.error("join_chat error:", error)
      socket.emit("error", { message: "Ошибка присоединения к чату" })
    }
  })

  // Отправка сообщения (MongoDB)
  socket.on("send_message", async (messageData) => {
    try {
      console.log(`📤 Попытка отправки сообщения: ${user.username} -> ${messageData.chatId}`)
      console.log(`📤 Данные сообщения:`, messageData)
    
      let chat = await Chat.findById(messageData.chatId)
      if (!chat) {
        console.log(`❌ Чат не найден: ${messageData.chatId}`)
        
        // Попробуем создать чат, если он не существует
        if (messageData.chatId.startsWith('private_')) {
          const participantIds = messageData.chatId.replace('private_', '').split('_')
          if (participantIds.length >= 2) {
            console.log(`📝 Попытка создания чата: ${messageData.chatId}`)
            
            // Найти собеседника (не текущего пользователя)
            const otherUserId = participantIds.find(id => id !== user.id)
            const otherUser = otherUserId ? await User.findById(otherUserId).lean() : null
            const otherUserName = otherUser ? otherUser.username : "Неизвестно"
            
            chat = await Chat.create({
              _id: messageData.chatId,
              name: otherUserName, // Используем имя собеседника
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
            console.log(`✅ Чат создан автоматически: ${chat._id} с собеседником: ${otherUserName}`)
          }
        }
        
        if (!chat) {
          console.log(`❌ Не удалось создать чат: ${messageData.chatId}`)
          socket.emit("error", { message: "Чат не найден и не может быть создан" })
          return
        }
      }
      
      console.log(`📋 Участники чата:`, chat.participants)
      console.log(`👤 Текущий пользователь: ${user.id}`)
      
      // Проверяем, является ли пользователь участником чата
      // Для глобального чата разрешаем всем пользователям отправлять сообщения
      const isGlobalChat = messageData.chatId === "global"
      const isParticipant = isGlobalChat || chat.participants.some(p => p && p.toString() === user.id)
      if (!isParticipant) {
        console.log(`❌ Пользователь ${user.username} не является участником чата ${messageData.chatId}`)
        socket.emit("error", { message: "Вы не являетесь участником этого чата" })
        return
      }
      
      // Rate limiting для глобального чата (5 секунд между сообщениями)
      if (isGlobalChat) {
        const now = Date.now();
        const lastTimestamp = globalChatRateLimit.get(user.id) || 0;
        if (now - lastTimestamp < 5000) { // 5 секунд
          socket.emit("error", { message: "В общий чат можно отправлять сообщение раз в 5 секунд!" });
          return;
        }
        globalChatRateLimit.set(user.id, now);
      }

      // Ограничение на количество слов (100 слов для всех чатов)
      const originalContent = messageData.isEncrypted ? decryptMessage(messageData.content) : messageData.content;
      const wordCount = originalContent.split(/\s+/).filter(Boolean).length;
      if (wordCount > 100) {
        socket.emit("error", { message: "Сообщение не должно содержать более 100 слов!" });
        return;
      }
      
      // Валидация сообщения
      if (!messageData.content || typeof messageData.content !== 'string' || messageData.content.trim().length === 0) {
        console.log(`❌ Неверное содержимое сообщения`)
        socket.emit("error", { message: "Сообщение не может быть пустым" })
        return
      }
      
      if (messageData.content.length > 1000) {
        socket.emit("error", { message: "Сообщение слишком длинное" })
        return
      }
      
      // Создать сообщение - сохраняем как есть (уже зашифрованное с клиента)
      const message = await Message.create({
        sender: user.id,
        chat: chat._id.toString(), // Исправляем - сохраняем как строку
        content: messageData.content, // Сохраняем зашифрованное содержимое
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
      
      console.log(`✅ Сообщение создано в БД: ${message._id}`)
      
      // Формируем replyTo для UI, если это ответ
      let replyToData = null;
      if (message.replyTo) {
        const originalMsg = await Message.findById(message.replyTo).lean();
        if (originalMsg) {
          let senderName = "Неизвестно";
          if (originalMsg.sender) {
            const senderUser = await User.findById(originalMsg.sender).lean();
            senderName = senderUser?.username || senderUser?.fullName || "Неизвестно";
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
        content: messageData.content, // Отправляем как есть - клиент сам расшифрует
        replyTo: replyToData,
      }
      
      console.log(`📤 Отправка сообщения в комнату: ${chat._id}`)
      console.log(`📤 Содержимое сообщения:`, msgObj)
      
      // Отправляем сообщение всем участникам чата
      io.to(chat._id.toString()).emit("new_message", msgObj)
      
      // Для глобального чата также отправляем всем подключенным пользователям
      if (isGlobalChat) {
        console.log(`🌍 Отправка сообщения во все подключения для глобального чата`)
        io.emit("new_message", msgObj)
      }
      
      // Если чат приватный, отправить событие 'new_private_chat' второму участнику
      if (chat.type === "private") {
        console.log(`💬 Приватный чат, участники:`, chat.participants)
        chat.participants.forEach((participantId) => {
          if (participantId.toString() !== user.id) {
            console.log(`🔍 Ищем сокет для пользователя: ${participantId}`)
            const targetSocket = Array.from(io.sockets.sockets.values()).find((s) => s.userId === participantId.toString());
            if (targetSocket) {
              console.log(`✅ Найден сокет для пользователя ${participantId}, отправляем уведомление о новом чате`)
              // Проверяем, есть ли у пользователя этот чат (можно добавить проверку, если нужно)
              targetSocket.emit("new_private_chat", {
                ...chat,
                id: chat._id?.toString() || chat._id,
                participants: chat.participants,
              });
            } else {
              console.log(`⚠️ Сокет для пользователя ${participantId} не найден`)
            }
          }
        });
      }
      
      console.log(`💬 Сообщение от ${user.username} в чат ${chat._id} отправлено успешно`)
    } catch (error) {
      console.error("send_message error:", error)
      socket.emit("error", { message: "Ошибка отправки сообщения" })
    }
  })

  // Реакции на сообщения (MongoDB)
  socket.on("add_reaction", async (data) => {
    try {
      const { messageId, emoji, userId, username } = data
      if (userId !== user.id) return
      if (!emoji || !reactionEmojis.includes(emoji)) return
      // Найти сообщение
      const message = await Message.findById(messageId)
      if (!message) return
      // Проверить, есть ли уже реакция от этого пользователя
      const existing = message.reactions.find(
        (r) => r.userId === userId && r.emoji === emoji
      )
      if (existing) {
        // Удалить реакцию
        message.reactions = message.reactions.filter(
          (r) => !(r.userId === userId && r.emoji === emoji)
        )
      } else {
        // Добавить реакцию
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

  // Печатает сообщение (MongoDB check)
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

  // Перестал печатать (MongoDB check)
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

  // Очистка чата (MongoDB)
  socket.on("clear_chat", async (chatId) => {
    try {
      const chat = await Chat.findById(chatId)
      if (!chat) return
      
      // Проверяем права для глобального чата
      const isGlobalChat = chatId === "global"
      const isAdmin = user.isAdmin
      const isParticipant = chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)
      const isCreator = chat.createdBy?.toString() === user.id
      
      if (isGlobalChat && !isAdmin) {
        socket.emit("error", { message: "Только администратор может очищать глобальный чат" })
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

  // Обновление настроек чата
  socket.on("update_chat_settings", async (data) => {
    try {
      const { chatId, isPinned, isMuted } = data
      const chat = await Chat.findById(chatId)
      if (!chat) return
      
      // Проверяем права
      const isParticipant = chat.participants.filter(p => p !== null).map((id) => id.toString()).includes(user.id)
      const isCreator = chat.createdBy?.toString() === user.id
      
      if (!isParticipant && !isCreator) {
        socket.emit("error", { message: "Нет прав для изменения настроек чата" })
        return
      }
      
      const updateData = {}
      if (isPinned !== undefined) updateData.isPinned = isPinned
      if (isMuted !== undefined) updateData.isMuted = isMuted
      
      await Chat.findByIdAndUpdate(chatId, updateData)
      
      // Уведомляем всех участников чата об изменении
      io.to(chatId).emit("chat_settings_updated", {
        chatId,
        isPinned,
        isMuted
      })
      
      console.log(`⚙️ Настройки чата ${chatId} обновлены пользователем ${user.username}`)
    } catch (error) {
      console.error("update_chat_settings error:", error)
    }
  })

  // Heartbeat для отслеживания активности
  socket.on("heartbeat", () => {
    userHeartbeats.set(user.id, Date.now())
  })

  // Обновление профиля (MongoDB)
  socket.on("update_profile", async (userData) => {
    try {
      // Валидация данных профиля
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
      // Обновляем пользователя во всех чатах (MongoDB не требует этого, но можно обновить в памяти)
      // Уведомляем всех об обновлении
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
      console.log(`👤 ${user.username} обновил профиль`)
    } catch (error) {
      console.error("update_profile error:", error)
    }
  })

  // Отключение
  socket.on("disconnect", async () => {
    activeConnections.delete(socket.id)
    // Удаляем из всех typing lists
    for (const [chatId, typingSet] of typingUsers.entries()) {
      if (typingSet.has(user.id)) {
        typingSet.delete(user.id)
        if (typingSet.size === 0) {
          typingUsers.delete(chatId)
        }
        socket.to(chatId).emit("user_stop_typing", { userId: user.id, chatId })
      }
    }
    // Обновить статус пользователя в MongoDB
    await User.findByIdAndUpdate(user.id, { isOnline: false, lastSeen: new Date(), status: "offline" })
    // Удаляем из heartbeat tracking
    userHeartbeats.delete(user.id)
    globalChatOnline.delete(socket.id);
    io.to('global').emit('global_online_count', globalChatOnline.size);
    // Обновляем список активных пользователей
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
    console.log(`🔌 Отключение: ${user.username}`)
  })
})

// Функция очистки неактивных пользователей
const cleanupInactiveUsers = async () => {
  try {
    const now = Date.now()
    const inactiveThreshold = 30000 // 30 секунд без активности
    
    for (const [userId, lastHeartbeat] of userHeartbeats.entries()) {
      if (now - lastHeartbeat > inactiveThreshold) {
        // Пользователь неактивен, обновляем статус
        await User.findByIdAndUpdate(userId, { 
          isOnline: false, 
          lastSeen: new Date(), 
          status: "offline" 
        })
        userHeartbeats.delete(userId)
        activeConnections.delete(userId)
        console.log(`🔌 Автоматическое отключение неактивного пользователя: ${userId}`)
      }
    }
    
    // Обновляем список активных пользователей
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

// Запускаем очистку каждые 30 секунд
setInterval(cleanupInactiveUsers, 30000)

// Автоочистка общего чата отключена - чат теперь постоянный
// let lastGlobalChatCleanupDay = null;
// setInterval(async () => {
//   const now = new Date();
//   if (now.getHours() === 4 && now.getMinutes() === 0) {
//     const today = now.toISOString().slice(0, 10);
//     if (lastGlobalChatCleanupDay !== today) {
//       await Message.deleteMany({ chat: 'global' });
//       io.to('global').emit('chat_cleared', { chatId: 'global' });
//       lastGlobalChatCleanupDay = today;
//       console.log('🌍 Общий чат автоматически очищен в 4:00 утра');
//     }
//   }
// }, 60 * 1000);

// Запуск сервера
server.listen(PORT, async () => {
  // Очищаем глобальный чат при запуске
  try {
    await Message.deleteMany({ chat: 'global' });
    console.log('🌍 Глобальный чат очищен при запуске сервера');
  } catch (error) {
    console.error('Ошибка очистки глобального чата:', error);
  }
  
  console.log(`
🚀 ACTOGRAM Server v3.0 запущен на порту ${PORT}
📱 Клиент: https://acto-uimuz.vercel.app  
🌐 Сервер: https://actogr.onrender.com
🔐 Безопасность: JWT + Bcrypt + Rate Limiting + E2E Encryption
✨ Новые функции: Реакции, улучшенный UI, многоязычность
🛡️ Статус: Полностью защищен и готов к работе
  `)
})

// Graceful shutdown
process.on("SIGTERM", () => {
  console.log("SIGTERM получен, завершаем работу сервера...")
  server.close(() => {
    console.log("Сервер успешно завершил работу")
    process.exit(0)
  })
})

process.on("SIGINT", () => {
  console.log("SIGINT получен, завершаем работу сервера...")
  server.close(() => {
    console.log("Сервер успешно завершил работу")
    process.exit(0)
  })
})

// Подключение к MongoDB с обработкой ошибок
let connectionAttempts = 0
const maxConnectionAttempts = 5

const connectToMongoDB = async () => {
  try {
    connectionAttempts++;
    console.log(`🔄 Попытка подключения к MongoDB (${connectionAttempts}/${maxConnectionAttempts})`);
    await mongoose.connect("mongodb+srv://actogol:actogolsila@actogramuz.6ogftpx.mongodb.net/actogram?retryWrites=true&w=majority&appName=actogramUZ", {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
    });
    console.log("✅ MongoDB подключен успешно");
    connectionAttempts = 0; // Сброс счетчика при успешном подключении
    await ensureGlobalChat(); // <-- Вызов здесь!
  } catch (err) {
    console.error(`❌ Ошибка подключения к MongoDB (попытка ${connectionAttempts}):`, err.message);
    if (connectionAttempts >= maxConnectionAttempts) {
      console.error("🚫 Превышено максимальное количество попыток подключения");
      console.log("💡 Проверьте настройки MongoDB Atlas:");
      console.log("   1. IP адреса в Network Access");
      console.log("   2. Правильность строки подключения");
      console.log("   3. Статус кластера");
      return;
    }
    console.log(`⏳ Повторная попытка через 5 секунд...`);
    setTimeout(connectToMongoDB, 5000);
  }
};

connectToMongoDB();

// Обработка ошибок подключения
mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message)
})

mongoose.connection.on('disconnected', () => {
  console.log('🔌 MongoDB disconnected')
  // Попробовать переподключиться
  if (connectionAttempts < maxConnectionAttempts) {
    setTimeout(connectToMongoDB, 5000)
  }
})

mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB connected')
})

mongoose.connection.on('reconnected', () => {
  console.log('🔄 MongoDB reconnected')
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
  isAdmin: { type: Boolean, default: false }, // <-- новое поле
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
  chat: { type: String, required: true }, // Изменено с ObjectId на String
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

// Endpoint для отправки новости от бота во все чаты (только для админа)
app.post("/api/bot-news", authenticateToken, async (req, res) => {
  try {
    const { userId, username } = req.user
    if (username !== "@adminstator") {
      return res.status(403).json({ error: "Только админ может отправлять новости" })
    }
    const { text } = req.body
    if (!text || typeof text !== "string" || !text.trim()) {
      return res.status(400).json({ error: "Текст новости обязателен" })
    }
    await ensureBotUser()
    // Найти все приватные чаты бота
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
      // Отправить через Socket.IO
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

// Endpoint для бана пользователя (только для админа)
app.post("/api/ban-user", authenticateToken, async (req, res) => {
  try {
    const { username } = req.user
    if (!req.user.isAdmin) {
      return res.status(403).json({ error: "Только админ может банить" })
    }
    const { userId } = req.body
    if (!userId) return res.status(400).json({ error: "userId обязателен" })
    await User.findByIdAndUpdate(userId, { status: "banned" })
    // Отключить пользователя, если он онлайн
    for (const [socketId, uid] of activeConnections.entries()) {
      if (uid === userId) {
        const s = io.sockets.sockets.get(socketId)
        if (s) s.disconnect(true)
      }
    }
    res.json({ success: true })
  } catch (error) {
    console.error("ban-user error:", error)
    res.status(500).json({ error: "Ошибка бана пользователя" })
  }
})

// Endpoint для очистки общего чата (для всех пользователей)
app.post("/api/clear-global-chat", authenticateToken, async (req, res) => {
  try {
    await Message.deleteMany({ chat: 'global' });
    io.to('global').emit('chat_cleared', { chatId: 'global' });
    
    console.log('🌍 Общий чат полностью очищен');
    res.json({ success: true, message: "Общий чат полностью очищен" });
  } catch (error) {
    console.error("clear-global-chat error:", error)
    res.status(500).json({ error: "Ошибка очистки общего чата" })
  }
})

// Endpoint для загрузки изображения в чат
app.post("/api/upload-image", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    console.log("📷 Запрос на загрузку изображения (локально)")
    console.log("📷 Файл:", req.file)
    console.log("📷 Body:", req.body)
    console.log("📷 User:", req.user)
    
    if (!req.file) {
      console.log("❌ Файл не загружен")
      return res.status(400).json({ error: "Файл не загружен" })
    }
    
    const userId = req.user.userId
    const { chatId } = req.body
    
    console.log("📷 Данные:", { userId, chatId })
    
    if (!chatId) {
      console.log("❌ chatId отсутствует")
      return res.status(400).json({ error: "chatId обязателен" })
    }
    
    // Проверяем, что пользователь является участником чата
    const chat = await Chat.findById(chatId)
    if (!chat) {
      return res.status(404).json({ error: "Чат не найден" })
    }
    
    const isGlobalChat = chatId === "global"
    const isParticipant = isGlobalChat || chat.participants.some(p => p && p.toString() === userId)
    if (!isParticipant) {
      return res.status(403).json({ error: "Нет доступа к этому чату" })
    }
    
    const imageUrl = `/avatars/${req.file.filename}`
    
    // Создаем сообщение с изображением
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
    
    // Получаем информацию о пользователе
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
    
    // Отправляем сообщение всем участникам чата
    io.to(chatId).emit("new_message", msgObj)
    
    res.json({ 
      success: true, 
      message: msgObj,
      imageUrl: imageUrl 
    })
    
    console.log(`📷 Изображение загружено (локально): ${user.username} -> ${chatId}`)
  } catch (error) {
    console.error("upload-image error:", error)
    res.status(500).json({ error: "Ошибка загрузки изображения" })
  }
})
