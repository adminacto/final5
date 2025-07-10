"use client"

import React from "react"
import { useState, useEffect, useRef } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu"
import {
  MessageCircle,
  Users,
  Settings,
  Search,
  Send,
  Phone,
  Video,
  MoreVertical,
  Wifi,
  WifiOff,
  Paperclip,
  UserPlus,
  Eye,
  EyeOff,
  Shield,
  Lock,
  Mail,
  Trash2,
  Bell,
  Copy,
  Reply,
  X,
  Info,
  Menu,
  ArrowLeft,
  Star,
  Smile,
  Zap,
} from "lucide-react"
import { io, type Socket } from "socket.io-client"

// Интерфейсы
interface User {
  id: string
  username: string
  email: string
  fullName: string
  avatar?: string
  bio?: string
  isOnline: boolean
  lastSeen: Date
  isVerified: boolean
  status: "online" | "away" | "busy" | "offline"
}

interface Message {
  id: string
  senderId: string
  senderName: string
  content: string
  chatId: string
  timestamp: Date
  type: "text" | "image" | "file" | "audio" | "video"
  fileUrl?: string
  fileName?: string
  fileSize?: number
  isEncrypted: boolean
  reactions?: { emoji: string; userId: string; username: string }[]
  replyTo?: {
    id: string
    content: string
    senderName: string
  }
  isEdited?: boolean
  readBy?: string[]
}

interface Chat {
  id: string
  name: string
  avatar?: string
  description?: string
  lastMessage?: Message
  unreadCount: number
  isGroup: boolean
  participants: User[]
  messageCount: number
  type: "private" | "group" | "channel"
  isEncrypted: boolean
  createdBy: string
  createdAt: Date
  isPinned?: boolean
  isMuted?: boolean
  theme?: string
}

// Языки
const languages = [
  { code: "uz", name: "O'zbek", flag: "🇺🇿" },
  { code: "ru", name: "Русский", flag: "🇷🇺" },
  { code: "en", name: "English", flag: "🇺🇸" },
]

const translations = {
  uz: {
    appName: "ACTOGRAM",
    welcome: "Xush kelibsiz",
    login: "Kirish",
    register: "Ro'yxatdan o'tish",
    email: "Email",
    password: "Parol",
    username: "Foydalanuvchi nomi",
    fullName: "To'liq ism",
    bio: "Haqida",
    online: "Onlayn",
    offline: "Oflayn",
    typing: "yozmoqda...",
    send: "Yuborish",
    search: "Qidirish...",
    newChat: "Yangi chat",
    settings: "Sozlamalar",
    profile: "Profil",
    darkMode: "Tungi rejim",
    notifications: "Bildirishnomalar",
    language: "Til",
    save: "Saqlash",
    cancel: "Bekor qilish",
    delete: "O'chirish",
    edit: "Tahrirlash",
    reply: "Javob berish",
    copy: "Nusxalash",
    forward: "Yuborish",
    pin: "Mahkamlash",
    mute: "Ovozsiz",
    archive: "Arxiv",
    block: "Bloklash",
    report: "Shikoyat",
    logout: "Chiqish",
    connecting: "Ulanmoqda...",
    connected: "Ulandi",
    disconnected: "Uzildi",
    encrypted: "Shifrlangan",
    verified: "Tasdiqlangan",
    members: "a'zolar",
    messages: "xabarlar",
    noMessages: "Xabarlar yo'q",
    startChat: "Suhbatni boshlang",
    searchUsers: "Foydalanuvchilarni qidiring",
    addMembers: "A'zolar qo'shish",
    createGroup: "Guruh yaratish",
    groupName: "Guruh nomi",
    groupDescription: "Guruh tavsifi",
    selectPhoto: "Rasm tanlash",
    takePhoto: "Rasm olish",
    chooseFromGallery: "Galereyadan tanlash",
    uploadFile: "Fayl yuklash",
    recording: "Yozib olish...",
    playback: "Ijro etish",
    fileSize: "Fayl hajmi",
    downloading: "Yuklab olish...",
    uploaded: "Yuklandi",
    failed: "Xatolik",
    retry: "Qayta urinish",
    comingSoon: "Tez orada...",
    beta: "Beta",
    pro: "Pro",
    premium: "Premium",
    free: "Bepul",
  },
  ru: {
    appName: "ACTOGRAM",
    welcome: "Добро пожаловать",
    login: "Войти",
    register: "Регистрация",
    email: "Email",
    password: "Пароль",
    username: "Имя пользователя",
    fullName: "Полное имя",
    bio: "О себе",
    online: "Онлайн",
    offline: "Оффлайн",
    typing: "печатает...",
    send: "Отправить",
    search: "Поиск...",
    newChat: "Новый чат",
    settings: "Настройки",
    profile: "Профиль",
    darkMode: "Темная тема",
    notifications: "Уведомления",
    language: "Язык",
    save: "Сохранить",
    cancel: "Отмена",
    delete: "Удалить",
    edit: "Редактировать",
    reply: "Ответить",
    copy: "Копировать",
    forward: "Переслать",
    pin: "Закрепить",
    mute: "Без звука",
    archive: "Архив",
    block: "Заблокировать",
    report: "Пожаловаться",
    logout: "Выйти",
    connecting: "Подключение...",
    connected: "Подключено",
    disconnected: "Отключено",
    encrypted: "Зашифровано",
    verified: "Подтвержден",
    members: "участников",
    messages: "сообщений",
    noMessages: "Нет сообщений",
    startChat: "Начните общение",
    searchUsers: "Поиск пользователей",
    addMembers: "Добавить участников",
    createGroup: "Создать группу",
    groupName: "Название группы",
    groupDescription: "Описание группы",
    selectPhoto: "Выбрать фото",
    takePhoto: "Сделать фото",
    chooseFromGallery: "Выбрать из галереи",
    uploadFile: "Загрузить файл",
    recording: "Запись...",
    playback: "Воспроизведение",
    fileSize: "Размер файла",
    downloading: "Загрузка...",
    uploaded: "Загружено",
    failed: "Ошибка",
    retry: "Повторить",
    comingSoon: "Скоро...",
    beta: "Бета",
    pro: "Про",
    premium: "Премиум",
    free: "Бесплатно",
  },
  en: {
    appName: "ACTOGRAM",
    welcome: "Welcome",
    login: "Login",
    register: "Register",
    email: "Email",
    password: "Password",
    username: "Username",
    fullName: "Full Name",
    bio: "Bio",
    online: "Online",
    offline: "Offline",
    typing: "typing...",
    send: "Send",
    search: "Search...",
    newChat: "New Chat",
    settings: "Settings",
    profile: "Profile",
    darkMode: "Dark Mode",
    notifications: "Notifications",
    language: "Language",
    save: "Save",
    cancel: "Cancel",
    delete: "Delete",
    edit: "Edit",
    reply: "Reply",
    copy: "Copy",
    forward: "Forward",
    pin: "Pin",
    mute: "Mute",
    archive: "Archive",
    block: "Block",
    report: "Report",
    logout: "Logout",
    connecting: "Connecting...",
    connected: "Connected",
    disconnected: "Disconnected",
    encrypted: "Encrypted",
    verified: "Verified",
    members: "members",
    messages: "messages",
    noMessages: "No messages",
    startChat: "Start chatting",
    searchUsers: "Search users",
    addMembers: "Add members",
    createGroup: "Create group",
    groupName: "Group name",
    groupDescription: "Group description",
    selectPhoto: "Select photo",
    takePhoto: "Take photo",
    chooseFromGallery: "Choose from gallery",
    uploadFile: "Upload file",
    recording: "Recording...",
    playback: "Playback",
    fileSize: "File size",
    downloading: "Downloading...",
    uploaded: "Uploaded",
    failed: "Failed",
    retry: "Retry",
    comingSoon: "Coming soon...",
    beta: "Beta",
    pro: "Pro",
    premium: "Premium",
    free: "Free",
  },
}

// Эмодзи для реакций
const reactionEmojis = ["❤️", "👍", "👎", "😂", "😮", "😢", "😡", "🔥", "👏", "🎉"]

// Темы чата
const chatThemes = [
  { id: "default", name: "Default", colors: ["#3B82F6", "#1E40AF"] },
  { id: "purple", name: "Purple", colors: ["#8B5CF6", "#5B21B6"] },
  { id: "green", name: "Green", colors: ["#10B981", "#047857"] },
  { id: "pink", name: "Pink", colors: ["#EC4899", "#BE185D"] },
  { id: "orange", name: "Orange", colors: ["#F59E0B", "#D97706"] },
]

// Утилиты шифрования
const encryptMessage = (message: string): string => {
  return btoa(unescape(encodeURIComponent(message)))
}

const decryptMessage = (encrypted: string): string => {
  try {
    return decodeURIComponent(escape(atob(encrypted)))
  } catch {
    return encrypted
  }
}

// Основной компонент
export default function ActogramChat() {
  // Состояния
  const [currentUser, setCurrentUser] = useState<User | null>(null)
  const [chats, setChats] = useState<Chat[]>([])
  const [selectedChat, setSelectedChat] = useState<Chat | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [newMessage, setNewMessage] = useState("")
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isLoginMode, setIsLoginMode] = useState(true)
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    confirmPassword: "",
    username: "",
    fullName: "",
    bio: "",
  })
  const [showPassword, setShowPassword] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [searchResults, setSearchResults] = useState<User[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [activeUsers, setActiveUsers] = useState<User[]>([])
  const [typingUsers, setTypingUsers] = useState<string[]>([])
  const [language, setLanguage] = useState<"uz" | "ru" | "en">("uz")
  const [darkMode, setDarkMode] = useState(true)
  const [notifications, setNotifications] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [success, setSuccess] = useState("")
  const [isMobile, setIsMobile] = useState(false)
  const [showSidebar, setShowSidebar] = useState(true)
  const [showSettings, setShowSettings] = useState(false)
  const [showUserSearch, setShowUserSearch] = useState(false)
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)
  const [replyingTo, setReplyingTo] = useState<Message | null>(null)
  const [editingMessage, setEditingMessage] = useState<Message | null>(null)
  const [selectedTheme, setSelectedTheme] = useState("default")
  const [uploadProgress, setUploadProgress] = useState(0)
  const [isRecording, setIsRecording] = useState(false)
  const [showChatInfoDialog, setShowChatInfoDialog] = useState(false)
  const [selectedChatForInfo, setSelectedChatForInfo] = useState<Chat | null>(null)

  // Refs
  const socketRef = useRef<Socket | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const messageInputRef = useRef<HTMLInputElement>(null)

  const t = translations[language]

  // Проверка мобильного устройства
  useEffect(() => {
    const checkMobile = () => {
      const mobile = window.innerWidth < 768
      setIsMobile(mobile)
      setShowSidebar(!mobile)
    }
    checkMobile()
    window.addEventListener("resize", checkMobile)
    return () => window.removeEventListener("resize", checkMobile)
  }, [])

  // Загрузка настроек
  useEffect(() => {
    const savedSettings = localStorage.getItem("actogram_settings")
    if (savedSettings) {
      const settings = JSON.parse(savedSettings)
      setDarkMode(settings.darkMode !== undefined ? settings.darkMode : true)
      setLanguage(settings.language || "uz")
      setNotifications(settings.notifications !== false)
      setSelectedTheme(settings.theme || "default")
    }

    const savedUser = localStorage.getItem("actogram_user")
    if (savedUser) {
      const user = JSON.parse(savedUser)
      console.log("🔍 Загружен пользователь из localStorage:", user)
      setCurrentUser(user)
      setIsAuthenticated(true)
    }
  }, [])

  // Применение темной темы
  useEffect(() => {
    document.documentElement.classList.toggle("dark", darkMode)
  }, [darkMode])

  // Подключение к серверу
  useEffect(() => {
    if (!isAuthenticated || !currentUser) return

    const serverUrl = "https://actogr.onrender.com"
    socketRef.current = io(serverUrl, {
      transports: ["websocket", "polling"],
      auth: {
        token: localStorage.getItem("actogram_token"),
        userId: currentUser.id,
      },
    })

    const socket = socketRef.current

    socket.on("connect", () => {
      setIsConnected(true)
      loadChats()
      
      // Отправляем heartbeat каждые 10 секунд
      const heartbeatInterval = setInterval(() => {
        if (socket.connected) {
          socket.emit("heartbeat")
        }
      }, 10000)
      
      // Очищаем интервал при отключении
      socket.on("disconnect", () => {
        clearInterval(heartbeatInterval)
      })
    })

    socket.on("disconnect", () => {
      setIsConnected(false)
    })

    socket.on("new_message", (message: Message) => {
      console.log("📨 Получено новое сообщение:", message)
      if (message.isEncrypted) {
        message.content = decryptMessage(message.content)
        console.log("🔓 Расшифрованное сообщение:", message.content)
      }
      
      // Проверяем, не является ли это дубликатом оптимистичного сообщения
      setMessages((prev) => {
        const isDuplicate = prev.some(m => 
          m.id === message.id || 
          (m.senderId === message.senderId && 
           m.content === message.content && 
           Math.abs(new Date(m.timestamp).getTime() - new Date(message.timestamp).getTime()) < 5000)
        )
        
        if (isDuplicate) {
          console.log("🔄 Пропускаем дубликат сообщения")
          return prev
        }
        
        return [...prev, message]
      })
      
      updateChatLastMessage(message)
      if (notifications && message.senderId !== currentUser.id) {
        showNotification(message.senderName, message.content)
      }
    })

    socket.on("message_edited", (message: Message) => {
      setMessages((prev) => prev.map((m) => (m.id === message.id ? message : m)))
    })

    socket.on("message_deleted", (messageId: string) => {
      setMessages((prev) => prev.filter((m) => m.id !== messageId))
    })

    socket.on("chat_cleared", (data: { chatId: string }) => {
      if (selectedChat?.id === data.chatId) {
        setMessages([])
        setSuccess("Чат очищен")
      }
    })

    socket.on("chat_settings_updated", (data: { chatId: string; isPinned?: boolean; isMuted?: boolean }) => {
      setChats(prev => prev.map(chat => {
        if (chat.id === data.chatId) {
          return {
            ...chat,
            isPinned: data.isPinned !== undefined ? data.isPinned : chat.isPinned,
            isMuted: data.isMuted !== undefined ? data.isMuted : chat.isMuted
          }
        }
        return chat
      }))
    })

    socket.on("error", (data: { message: string }) => {
      setError(data.message)
    })

    socket.on("user_typing", (data: { userId: string; username: string; chatId: string }) => {
      if (data.chatId === selectedChat?.id && data.userId !== currentUser.id) {
        setTypingUsers((prev) => [...prev.filter((u) => u !== data.username), data.username])
        setTimeout(() => {
          setTypingUsers((prev) => prev.filter((u) => u !== data.username))
        }, 3000)
      }
    })

    socket.on("user_stop_typing", (data: { userId: string; chatId: string }) => {
      setTypingUsers((prev) => prev.filter((u) => u !== data.userId))
    })

    socket.on("users_update", (users: User[]) => {
      setActiveUsers(users)
    })

    socket.on("search_results", (results: User[]) => {
      setSearchResults(results)
    })

    socket.on("my_chats", (userChats: Chat[]) => {
      // Расшифровываем последние сообщения в чатах
      const decryptedChats = userChats.map(chat => ({
        ...chat,
        lastMessage: chat.lastMessage ? {
          ...chat.lastMessage,
          content: chat.lastMessage.isEncrypted ? decryptMessage(chat.lastMessage.content) : chat.lastMessage.content
        } : undefined
      }))
      setChats(decryptedChats)
    })

    socket.on("chat_messages", (data: { chatId: string; messages: Message[] }) => {
      if (data.chatId === selectedChat?.id) {
        setMessages(data.messages)
      }
    })

    socket.on("new_private_chat", (chat: Chat) => {
      console.log("🔍 Получен новый приватный чат:", chat)
      setChats((prev) => {
        const existingChat = prev.find((c) => c.id === chat.id)
        if (!existingChat) {
          return [...prev, chat]
        }
        return prev
      })
    })

          return () => {
        socket.disconnect()
      }
  }, [isAuthenticated, currentUser, selectedChat?.id, notifications])

  // Автоскролл
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [messages])

  // Сохраняем настройки при каждом изменении
  useEffect(() => {
    localStorage.setItem(
      "actogram_settings",
      JSON.stringify({
        darkMode,
        language,
        notifications,
        theme: selectedTheme,
      })
    )
  }, [darkMode, language, notifications, selectedTheme])

  // Функции
  const showNotification = (title: string, body: string) => {
    if ("Notification" in window && Notification.permission === "granted") {
      new Notification(title, { body, icon: "/favicon.ico" })
    }
  }

  const updateChatLastMessage = (message: Message) => {
    setChats((prev) => prev.map((chat) => {
      if (chat.id === message.chatId) {
        return {
          ...chat,
          lastMessage: {
            ...message,
            content: message.isEncrypted ? decryptMessage(message.content) : message.content
          }
        }
      }
      return chat
    }))
  }

  const handleAuth = async () => {
    setLoading(true)
    setError("")

    try {
      const response = await fetch("https://actogr.onrender.com/api/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: isLoginMode ? "login" : "register",
          ...formData,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.error)
        return
      }

      console.log("🔍 Ответ сервера при аутентификации:", data)
      
      const user: User = {
        id: data.user.id,
        username: data.user.username,
        email: data.user.email,
        fullName: data.user.fullName,
        avatar: data.user.avatar,
        bio: data.user.bio,
        isOnline: true,
        lastSeen: new Date(),
        isVerified: data.user.isVerified,
        status: "online",
      }

      console.log("🔍 Созданный пользователь:", user)
      
      setCurrentUser(user)
      setIsAuthenticated(true)
      setSuccess(isLoginMode ? "Успешный вход!" : "Регистрация завершена!")

      localStorage.setItem("actogram_user", JSON.stringify(user))
      localStorage.setItem("actogram_token", data.token)

      if ("Notification" in window) {
        Notification.requestPermission()
      }
    } catch (error) {
      setError("Ошибка подключения к серверу")
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    localStorage.removeItem("actogram_user")
    localStorage.removeItem("actogram_token")
    setCurrentUser(null)
    setIsAuthenticated(false)
    setChats([])
    setMessages([])
    setSelectedChat(null)
    socketRef.current?.disconnect()
  }

  const loadChats = async () => {
    if (!currentUser) return
    
    try {
      // Загружаем чаты через REST API
      const token = localStorage.getItem("actogram_token")
      const response = await fetch("https://actogr.onrender.com/api/chats", {
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        }
      })
      
      if (response.ok) {
        const chats = await response.json()
        console.log("🔍 Загружены чаты из API:", chats)
        
        // Расшифровываем последние сообщения в чатах
        const decryptedChats = chats.map((chat: Chat) => ({
          ...chat,
          lastMessage: chat.lastMessage ? {
            ...chat.lastMessage,
            content: chat.lastMessage.isEncrypted ? decryptMessage(chat.lastMessage.content) : chat.lastMessage.content
          } : undefined
        }))
        
        setChats(decryptedChats)
      } else {
        console.error("❌ Ошибка загрузки чатов:", response.status)
      }
    } catch (error) {
      console.error("❌ Ошибка загрузки чатов:", error)
    }
    
    // Также запрашиваем через Socket.IO для обновления в реальном времени
    if (socketRef.current && currentUser) {
      socketRef.current.emit("get_my_chats", currentUser.id)
    }
  }

  const loadMessages = async (chatId: string) => {
    if (!currentUser) return
    
    try {
      // Загружаем сообщения через REST API
      const token = localStorage.getItem("actogram_token")
      const response = await fetch(`https://actogr.onrender.com/api/messages/${chatId}`, {
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        }
      })
      
      if (response.ok) {
        const messages = await response.json()
        console.log("🔍 Загружены сообщения из API:", messages)
        setMessages(messages)
      } else {
        console.error("❌ Ошибка загрузки сообщений:", response.status)
      }
    } catch (error) {
      console.error("❌ Ошибка загрузки сообщений:", error)
    }
    
    // Также запрашиваем через Socket.IO для обновления в реальном времени
    if (socketRef.current && currentUser) {
      socketRef.current.emit("get_messages", { chatId, userId: currentUser.id })
    }
  }

  const sendMessage = () => {
    console.log("🔍 Отладка sendMessage:", {
      currentUser: currentUser,
      currentUserId: currentUser?.id,
      selectedChat: selectedChat,
      newMessage: newMessage.trim(),
      socketRef: !!socketRef.current
    })
    
    if (!newMessage.trim() || !selectedChat || !currentUser || !socketRef.current) {
      console.log("❌ Не удается отправить сообщение:", {
        hasMessage: !!newMessage.trim(),
        hasChat: !!selectedChat,
        hasUser: !!currentUser,
        hasSocket: !!socketRef.current
      })
      return
    }

    console.log("📤 Отправка сообщения:", {
      content: newMessage.trim(),
      chatId: selectedChat.id,
      userId: currentUser.id,
      username: currentUser.username
    })

    const messageData = {
      content: encryptMessage(newMessage.trim()),
      chatId: selectedChat.id,
      type: "text",
      isEncrypted: true,
      replyTo: replyingTo
        ? {
            id: replyingTo.id,
            content: replyingTo.content,
            senderName: replyingTo.senderName,
          }
        : undefined,
    }

    console.log("📤 Данные сообщения для отправки:", messageData)
    
    // Для глобального чата добавляем оптимистичное обновление
    if (selectedChat.id === "global") {
      const optimisticMessage = {
        id: Date.now().toString(),
        senderId: currentUser.id,
        senderName: currentUser.username,
        content: newMessage.trim(),
        chatId: selectedChat.id,
        timestamp: new Date(),
        type: "text",
        isEncrypted: false, // Не шифруем для отображения
        replyTo: replyingTo
          ? {
              id: replyingTo.id,
              content: replyingTo.content,
              senderName: replyingTo.senderName,
            }
          : undefined,
      }
      
      // Добавляем сообщение сразу в UI
      setMessages((prev) => [...prev, optimisticMessage])
      
      // Обновляем последнее сообщение в списке чатов
      updateChatLastMessage(optimisticMessage)
    }
    
    socketRef.current.emit("send_message", messageData)
    setNewMessage("")
    setReplyingTo(null)
    stopTyping()
  }

  const selectChat = (chat: Chat) => {
    setSelectedChat(chat)
    setReplyingTo(null)
    setEditingMessage(null)
    loadMessages(chat.id)
    if (isMobile) setShowSidebar(false)
    if (socketRef.current) {
      socketRef.current.emit("join_chat", chat.id)
    }
    // ВАЖНО: выводим участников в консоль для отладки
    console.log("Участники выбранного чата:", chat.participants)
  }

  const startTyping = () => {
    if (selectedChat && socketRef.current && currentUser) {
      socketRef.current.emit("typing", {
        chatId: selectedChat.id,
        userId: currentUser.id,
        username: currentUser.username,
      })

      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current)
      }

      typingTimeoutRef.current = setTimeout(stopTyping, 1000)
    }
  }

  const stopTyping = () => {
    if (selectedChat && socketRef.current) {
      socketRef.current.emit("stop_typing", { chatId: selectedChat.id })
    }
  }

  const searchUsers = (query: string) => {
    if (!query.trim() || !socketRef.current) {
      setSearchResults([])
      return
    }
    socketRef.current.emit("search_users", query)
  }

  const startPrivateChat = (user: User) => {
    if (!currentUser || !socketRef.current) return
    if (user.id === currentUser.id) return // Нельзя создавать чат с самим собой!

    const chatId = `private_${[currentUser.id, user.id].sort().join("_")}`
    const existingChat = chats.find((chat) => chat.id === chatId)

    if (existingChat) {
      selectChat(existingChat)
      setShowUserSearch(false)
      return
    }

    const newChat: Chat = {
      id: chatId,
      name: user.username,
      avatar: user.avatar,
      isGroup: false,
      participants: [currentUser, user],
      unreadCount: 0,
      messageCount: 0,
      type: "private",
      isEncrypted: true,
      createdBy: currentUser.id,
      createdAt: new Date(),
    }

    setChats((prev) => [...prev, newChat])
    selectChat(newChat)
    setShowUserSearch(false)

    console.log("🔍 Создание приватного чата:", {
      userId: user.id,
      chatId,
      createdBy: currentUser.id,
    })
    
    socketRef.current.emit("create_private_chat", {
      userId: user.id,
      chatId,
      createdBy: currentUser.id,
    })

    // Автоматически отправляем приветственное сообщение, чтобы чат появился у обоих
    socketRef.current.emit("send_message", {
      content: encryptMessage("Salom!"),
      chatId,
      type: "text",
      isEncrypted: true,
    })
  }

  const addReaction = (messageId: string, emoji: string) => {
    if (!currentUser || !socketRef.current) return

    socketRef.current.emit("add_reaction", {
      messageId,
      emoji,
      userId: currentUser.id,
      username: currentUser.username,
    })
  }

  // Функции для работы с чатами
  const showChatInfo = (chat: Chat | null) => {
    if (!chat) return
    setSelectedChatForInfo(chat)
    setShowChatInfoDialog(true)
  }

  const togglePinChat = (chat: Chat | null) => {
    if (!chat || !socketRef.current) return
    
    const newPinnedState = !chat.isPinned
    setChats(prev => prev.map(c => 
      c.id === chat.id ? { ...c, isPinned: newPinnedState } : c
    ))
    
    // Отправляем на сервер
    socketRef.current.emit("update_chat_settings", {
      chatId: chat.id,
      isPinned: newPinnedState
    })
  }

  const toggleMuteChat = (chat: Chat | null) => {
    if (!chat || !socketRef.current) return
    
    const newMutedState = !chat.isMuted
    setChats(prev => prev.map(c => 
      c.id === chat.id ? { ...c, isMuted: newMutedState } : c
    ))
    
    // Отправляем на сервер
    socketRef.current.emit("update_chat_settings", {
      chatId: chat.id,
      isMuted: newMutedState
    })
  }

  const clearChat = (chat: Chat | null) => {
    if (!chat || !socketRef.current) return
    
    // Проверяем права для глобального чата
    if (chat.id === "global" && currentUser?.username !== "@adminstator") {
      setError("Только администратор может очищать глобальный чат")
      return
    }
    
    if (confirm("Вы уверены, что хотите очистить этот чат? Это действие нельзя отменить.")) {
      socketRef.current.emit("clear_chat", chat.id)
      setMessages([])
      setSuccess("Чат очищен")
    }
  }

  // Функция для сохранения настроек
  const saveSettings = () => {
    localStorage.setItem(
      "actogram_settings",
      JSON.stringify({
        darkMode,
        language,
        notifications,
        theme: selectedTheme,
      })
    )
  }

  const handleInputChange = (field: string, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    setError("")
  }

  const filteredChats = chats.filter((chat) => chat.name.toLowerCase().includes(searchQuery.toLowerCase()))

  // Стили
  const gradientBg = `bg-gradient-to-br from-blue-50 via-indigo-50 to-purple-50 dark:from-gray-900 dark:via-blue-900 dark:to-purple-900`
  const cardStyle = `backdrop-blur-lg bg-white/80 dark:bg-gray-800/80 border border-white/20 dark:border-gray-700/50 shadow-xl`
  const buttonStyle = `transition-all duration-300 hover:scale-105 active:scale-95 shadow-lg hover:shadow-xl`
  const inputStyle = `backdrop-blur-sm bg-white/50 dark:bg-gray-800/50 border-2 border-transparent focus:border-blue-500 dark:focus:border-blue-400`

  // Проверка домена
  const hostname = typeof window !== "undefined" ? window.location.hostname : ""
  const allowedDomains = ["vercel.app", "render.com", "localhost"]
  const isDomainAllowed = allowedDomains.some((domain) => hostname.includes(domain) || hostname === "localhost")

  if (!isDomainAllowed) {
    return (
      <div className={`min-h-screen ${gradientBg} flex items-center justify-center p-4`}>
        <Card className={`max-w-md ${cardStyle}`}>
          <CardHeader>
            <CardTitle className="text-red-600 flex items-center gap-2">
              <Shield className="h-6 w-6" />
              Доступ ограничен
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p>ACTOGRAM доступен только с разрешенных доменов</p>
            <p className="text-sm text-gray-500 mt-2">Проверка безопасности домена</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Экран аутентификации
  if (!isAuthenticated) {
    return (
      <div className={`min-h-screen ${gradientBg} flex items-center justify-center p-4`}>
        <Card className={`w-full max-w-md ${cardStyle} animate-in fade-in-50 duration-500`}>
          <CardHeader className="text-center space-y-4">
            <div className="mx-auto w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-2xl">
              <MessageCircle className="h-10 w-10 text-white" />
            </div>
            <div>
              <CardTitle className="text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                {t.appName}
              </CardTitle>
              <p className="text-gray-600 dark:text-gray-300 mt-2">{t.welcome}</p>
            </div>
            <div className="flex items-center justify-center gap-2 text-sm">
              <Lock className="h-4 w-4 text-green-500" />
              <span className="text-green-600 dark:text-green-400">End-to-End Encrypted</span>
            </div>
          </CardHeader>

          <CardContent className="space-y-6">
            <Tabs value={isLoginMode ? "login" : "register"} className="w-full">
              <TabsList className={`grid w-full grid-cols-2 ${cardStyle}`}>
                <TabsTrigger value="login" onClick={() => setIsLoginMode(true)} className={buttonStyle}>
                  {t.login}
                </TabsTrigger>
                <TabsTrigger value="register" onClick={() => setIsLoginMode(false)} className={buttonStyle}>
                  {t.register}
                </TabsTrigger>
              </TabsList>

              <TabsContent value="login" className="space-y-4 mt-6">
                <div className="space-y-2">
                  <Label htmlFor="email" className="flex items-center gap-2 text-sm font-medium">
                    <Mail className="h-4 w-4" />
                    {t.email}
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="your@email.com"
                    value={formData.email}
                    onChange={(e) => handleInputChange("email", e.target.value)}
                    className={inputStyle}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password" className="flex items-center gap-2 text-sm font-medium">
                    <Lock className="h-4 w-4" />
                    {t.password}
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      value={formData.password}
                      onChange={(e) => handleInputChange("password", e.target.value)}
                      className={`${inputStyle} pr-10`}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      className="absolute right-0 top-0 h-full px-3"
                      onClick={() => setShowPassword(!showPassword)}
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="register" className="space-y-4 mt-6">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="fullName" className="text-sm font-medium">
                      {t.fullName}
                    </Label>
                    <Input
                      id="fullName"
                      placeholder="John Doe"
                      value={formData.fullName}
                      onChange={(e) => handleInputChange("fullName", e.target.value)}
                      className={inputStyle}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="username" className="text-sm font-medium">
                      {t.username}
                    </Label>
                    <Input
                      id="username"
                      placeholder="@username"
                      value={formData.username}
                      onChange={(e) => {
                        let value = e.target.value
                        if (!value.startsWith("@") && value.length > 0) {
                          value = "@" + value
                        }
                        handleInputChange("username", value)
                      }}
                      className={inputStyle}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="email-reg" className="flex items-center gap-2 text-sm font-medium">
                    <Mail className="h-4 w-4" />
                    {t.email}
                  </Label>
                  <Input
                    id="email-reg"
                    type="email"
                    placeholder="your@email.com"
                    value={formData.email}
                    onChange={(e) => handleInputChange("email", e.target.value)}
                    className={inputStyle}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password-reg" className="flex items-center gap-2 text-sm font-medium">
                    <Lock className="h-4 w-4" />
                    {t.password}
                  </Label>
                  <Input
                    id="password-reg"
                    type="password"
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => handleInputChange("password", e.target.value)}
                    className={inputStyle}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="bio" className="text-sm font-medium">
                    {t.bio}
                  </Label>
                  <Input
                    id="bio"
                    placeholder="Tell us about yourself..."
                    value={formData.bio}
                    onChange={(e) => handleInputChange("bio", e.target.value)}
                    className={inputStyle}
                  />
                </div>
              </TabsContent>
            </Tabs>

            <div className="flex items-center justify-between">
              <Label className="text-sm font-medium">{t.language}</Label>
              <div className="flex gap-1">
                {languages.map((lang) => (
                  <Button
                    key={lang.code}
                    variant={language === lang.code ? "default" : "outline"}
                    size="sm"
                    onClick={() => setLanguage(lang.code as "uz" | "ru" | "en")}
                    className={buttonStyle}
                  >
                    {lang.flag}
                  </Button>
                ))}
              </div>
            </div>

            {error && (
              <Alert className="border-red-200 bg-red-50 dark:border-red-800 dark:bg-red-900/50">
                <AlertDescription className="text-red-600 dark:text-red-400">{error}</AlertDescription>
              </Alert>
            )}

            {success && (
              <Alert className="border-green-200 bg-green-50 dark:border-green-800 dark:bg-green-900/50">
                <AlertDescription className="text-green-600 dark:text-green-400">{success}</AlertDescription>
              </Alert>
            )}

            <Button
              onClick={handleAuth}
              className={`w-full ${buttonStyle} bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700`}
              disabled={loading}
            >
              {loading ? (
                <div className="flex items-center gap-2">
                  <div className="animate-spin rounded-full h-4 w-4 border-2 border-white border-t-transparent" />
                  {t.connecting}
                </div>
              ) : isLoginMode ? (
                t.login
              ) : (
                t.register
              )}
            </Button>

            <div className="text-center text-sm text-gray-500 dark:text-gray-400">
              <p>
                {isLoginMode ? "Нет аккаунта?" : "Есть аккаунт?"}{" "}
                <button
                  onClick={() => setIsLoginMode(!isLoginMode)}
                  className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
                >
                  {isLoginMode ? t.register : t.login}
                </button>
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  // Основной интерфейс чата
  return (
    <div className={`h-screen flex ${darkMode ? "dark" : ""}`}>
      <div className={`h-screen flex ${gradientBg} w-full relative overflow-hidden`}>
        {/* Боковая панель */}
        <div
          className={`${
            isMobile ? "fixed inset-y-0 left-0 z-50 w-full" : "w-80 min-w-80"
          } ${cardStyle} border-r flex flex-col transition-all duration-300 ${
            isMobile && !showSidebar ? "-translate-x-full" : "translate-x-0"
          }`}
        >
          {/* Заголовок */}
          <div className="p-4 bg-gradient-to-r from-blue-600 to-purple-600 text-white">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-white/20 rounded-xl flex items-center justify-center">
                  <MessageCircle className="h-6 w-6" />
                </div>
                <div>
                  <h1 className="text-xl font-bold">{t.appName}</h1>
                  <p className="text-xs text-blue-100">
                    {isConnected ? (
                      <span className="flex items-center gap-1">
                        <Wifi className="h-3 w-3" />
                        {t.connected}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1">
                        <WifiOff className="h-3 w-3" />
                        {t.disconnected}
                      </span>
                    )}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant="secondary" className="bg-white/20 text-white border-0">
                  {currentUser?.username}
                </Badge>
                <Dialog open={showSettings} onOpenChange={setShowSettings}>
                  <DialogTrigger asChild>
                    <Button variant="ghost" size="icon" className="text-white hover:bg-white/20">
                      <Settings className="h-4 w-4" />
                    </Button>
                  </DialogTrigger>
                  <DialogContent className={`${cardStyle} max-w-md`}>
                    <DialogHeader>
                      <DialogTitle className="flex items-center gap-2">
                        <Settings className="h-5 w-5" />
                        {t.settings}
                      </DialogTitle>
                    </DialogHeader>
                    <Tabs defaultValue="profile" className="w-full">
                      <TabsList className="grid w-full grid-cols-2">
                        <TabsTrigger value="profile">{t.profile}</TabsTrigger>
                        <TabsTrigger value="settings">{t.settings}</TabsTrigger>
                      </TabsList>
                      <TabsContent value="profile" className="space-y-4">
                        <div className="flex items-center gap-4">
                          <Avatar className="h-16 w-16">
                            {currentUser?.avatar ? (
                              <AvatarImage src={currentUser.avatar} />
                            ) : (
                              <AvatarFallback className="text-lg bg-gradient-to-br from-blue-500 to-purple-600 text-white">
                                {currentUser?.username?.charAt(1) || currentUser?.fullName?.charAt(0) || "?"}
                              </AvatarFallback>
                            )}
                          </Avatar>
                          <div className="flex-1">
                            <h3 className="font-semibold">{currentUser?.fullName}</h3>
                            <p className="text-sm text-gray-500">{currentUser?.username}</p>
                            <p className="text-sm text-green-500 flex items-center gap-1">
                              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                              {t.online}
                            </p>
                          </div>
                        </div>
                        <Button onClick={handleLogout} variant="destructive" className="w-full">
                          {t.logout}
                        </Button>
                      </TabsContent>
                      <TabsContent value="settings" className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>{t.darkMode}</Label>
                            <p className="text-sm text-gray-500">Переключить тему</p>
                          </div>
                          <Switch
                            checked={darkMode}
                            onCheckedChange={(checked) => {
                              setDarkMode(checked)
                              saveSettings()
                            }}
                          />
                        </div>
                        <div className="flex items-center justify-between">
                          <div>
                            <Label>{t.notifications}</Label>
                            <p className="text-sm text-gray-500">Уведомления о сообщениях</p>
                          </div>
                          <Switch
                            checked={notifications}
                            onCheckedChange={(checked) => {
                              setNotifications(checked)
                              saveSettings()
                            }}
                          />
                        </div>
                        <div className="space-y-2">
                          <Label>{t.language}</Label>
                          <div className="flex gap-2">
                            {languages.map((lang) => (
                              <Button
                                key={lang.code}
                                variant={language === lang.code ? "default" : "outline"}
                                size="sm"
                                onClick={() => {
                                  setLanguage(lang.code as "uz" | "ru" | "en")
                                  saveSettings()
                                }}
                              >
                                {lang.flag} {lang.name}
                              </Button>
                            ))}
                          </div>
                        </div>
                      </TabsContent>
                    </Tabs>
                  </DialogContent>
                </Dialog>
              </div>
            </div>
          </div>

          {/* Поиск */}
          <div className="p-3 border-b space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder={t.search}
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`pl-10 ${inputStyle}`}
              />
            </div>
            <Dialog open={showUserSearch} onOpenChange={setShowUserSearch}>
              <DialogTrigger asChild>
                <Button variant="outline" className={`w-full ${buttonStyle}`}>
                  <UserPlus className="h-4 w-4 mr-2" />
                  {t.newChat}
                </Button>
              </DialogTrigger>
              <DialogContent className={cardStyle}>
                <DialogHeader>
                  <DialogTitle className="flex items-center gap-2">
                    <UserPlus className="h-5 w-5" />
                    {t.searchUsers}
                  </DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
                    <Input
                      placeholder="@username или имя"
                      onChange={(e) => searchUsers(e.target.value)}
                      className={`pl-10 ${inputStyle}`}
                    />
                  </div>
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {searchResults.map((user) => (
                      <div
                        key={user.id}
                        onClick={() => startPrivateChat(user)}
                        className={`flex items-center gap-3 p-3 rounded-xl hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer transition-all duration-200 ${buttonStyle}`}
                      >
                        <Avatar>
                          {user.avatar ? (
                            <AvatarImage src={user.avatar} />
                          ) : (
                            <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white">
                              {user.username?.charAt(1) || user.fullName?.charAt(0) || "?"}
                            </AvatarFallback>
                          )}
                        </Avatar>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-medium">{user.username}</h4>
                            {user.isVerified && <Star className="h-3 w-3 text-yellow-500" />}
                          </div>
                          <p className="text-sm text-gray-500">{user.username}</p>
                          {user.bio && <p className="text-xs text-gray-400 truncate">{user.bio}</p>}
                        </div>
                        <div className={`w-3 h-3 rounded-full ${user.isOnline ? "bg-green-500" : "bg-gray-300"}`} />
                      </div>
                    ))}
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>

          {/* Список чатов */}
          <div className="flex-1 overflow-y-auto">
            {filteredChats.map((chat) => (
              <div
                key={chat.id}
                onClick={() => selectChat(chat)}
                className={`p-4 border-b cursor-pointer transition-all duration-200 hover:bg-gray-50 dark:hover:bg-gray-700/50 ${
                  selectedChat?.id === chat.id
                    ? "bg-gradient-to-r from-blue-50 to-purple-50 dark:from-blue-900/30 dark:to-purple-900/30 border-l-4 border-l-blue-500"
                    : ""
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className="relative">
                    <Avatar className="h-12 w-12">
                      {chat.avatar ? (
                        <AvatarImage src={chat.avatar} />
                      ) : (
                        <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white">
                          {chat.isGroup ? <Users className="h-5 w-5" /> : chat.name.charAt(0)}
                        </AvatarFallback>
                      )}
                    </Avatar>
                    {!chat.isGroup && (() => {
                      // Найти собеседника
                      const otherUser = chat.participants.find(
                        (u) => u.id !== currentUser?.id && u.username !== currentUser?.username
                      );
                      return otherUser?.isOnline ? (
                        <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-2 border-white dark:border-gray-800 rounded-full" />
                      ) : null;
                    })()}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        {/* Для приватного чата показывай имя собеседника */}
                        {(() => {
                          const isPrivate = chat.type === "private"
                          const otherUser = isPrivate
                            ? chat.participants.find((u) =>
                                u.id !== currentUser?.id && u.username !== currentUser?.username
                              )
                            : null
                          const chatDisplayName = isPrivate
                            ? otherUser?.username || otherUser?.fullName || chat.name || "Неизвестно"
                            : chat.name
                          return <h3 className="font-medium truncate">{chatDisplayName}</h3>
                        })()}
                        {chat.isEncrypted && <Lock className="h-3 w-3 text-green-500" />}
                        {chat.isPinned && <Star className="h-3 w-3 text-yellow-500" />}
                      </div>
                      {chat.lastMessage && (
                        <span className="text-xs text-gray-500">
                          {new Date(chat.lastMessage.timestamp).toLocaleTimeString([], {
                            hour: "2-digit",
                            minute: "2-digit",
                          })}
                        </span>
                      )}
                    </div>
                    {chat.lastMessage && (
                      <p className="text-sm text-gray-600 dark:text-gray-300 truncate">
                        {chat.lastMessage.senderName}: {chat.lastMessage.isEncrypted ? decryptMessage(chat.lastMessage.content) : chat.lastMessage.content}
                      </p>
                    )}
                    <div className="flex items-center justify-between mt-1">
                      <div className="text-xs text-gray-500 flex items-center gap-2">
                        <span>
                          {chat.messageCount} {t.messages}
                        </span>
                      </div>
                      {chat.unreadCount > 0 && (
                        <Badge className="bg-blue-500 text-white animate-pulse">{chat.unreadCount}</Badge>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Область чата */}
        <div className={`flex-1 flex flex-col min-w-0 ${isMobile && showSidebar ? "hidden" : "flex"}`}>
          {selectedChat ? (
            <>
              {/* Заголовок чата */}
              <div className={`p-4 ${cardStyle} border-b flex items-center justify-between`}>
                <div className="flex items-center gap-3">
                  {isMobile && (
                    <Button variant="ghost" size="icon" onClick={() => setShowSidebar(true)}>
                      <ArrowLeft className="h-4 w-4" />
                    </Button>
                  )}
                  <Avatar className="h-10 w-10">
                    {(() => {
                      const avatarSrc = selectedChat.type === "private" 
                        ? (() => {
                            const otherUser = selectedChat.participants.find(
                              (u) => u.id !== currentUser?.id && u.username !== currentUser?.username
                            )
                            return otherUser?.avatar
                          })()
                        : selectedChat.avatar
                      
                      if (avatarSrc) {
                        return <AvatarImage src={avatarSrc} />
                      } else {
                        return (
                          <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white">
                            {selectedChat.isGroup ? (
                              <Users className="h-5 w-5" />
                            ) : (
                              (() => {
                                const otherUser = selectedChat.participants.find(
                                  (u) => u.id !== currentUser?.id && u.username !== currentUser?.username
                                )
                                const displayName = otherUser?.username || otherUser?.fullName || selectedChat.name
                                return displayName.charAt(0)
                              })()
                            )}
                          </AvatarFallback>
                        )
                      }
                    })()}
                  </Avatar>
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="font-semibold">
                        {selectedChat.type === "private" 
                          ? (() => {
                              const otherUser = selectedChat.participants.find(
                                (u) => u.id !== currentUser?.id && u.username !== currentUser?.username
                              )
                              return otherUser?.username || otherUser?.fullName || selectedChat.name
                            })()
                          : selectedChat.name
                        }
                      </h2>
                      {selectedChat.isEncrypted && <Lock className="h-4 w-4 text-green-500" />}
                    </div>
                    <p className="text-sm text-gray-500">
                      {selectedChat.isGroup
                        ? typingUsers.length > 0
                          ? `${typingUsers.join(", ")} ${t.typing}`
                          : t.online
                        : typingUsers.length > 0
                          ? `${typingUsers.join(", ")} ${t.typing}`
                          : t.online}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" size="icon" className={buttonStyle}>
                    <Phone className="h-4 w-4" />
                  </Button>
                  <Button variant="ghost" size="icon" className={buttonStyle}>
                    <Video className="h-4 w-4" />
                  </Button>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon" className={buttonStyle}>
                        <MoreVertical className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className={cardStyle}>
                      <DropdownMenuItem onClick={() => showChatInfo(selectedChat)}>
                        <Info className="h-4 w-4 mr-2" />
                        Информация о чате
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => togglePinChat(selectedChat)}>
                        <Star className="h-4 w-4 mr-2" />
                        {selectedChat?.isPinned ? "Открепить чат" : "Закрепить чат"}
                      </DropdownMenuItem>
                      <DropdownMenuItem onClick={() => toggleMuteChat(selectedChat)}>
                        <Bell className="h-4 w-4 mr-2" />
                        {selectedChat?.isMuted ? "Включить уведомления" : "Отключить уведомления"}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      {(selectedChat?.id !== "global" || currentUser?.username === "@adminstator") && (
                        <DropdownMenuItem 
                          className="text-red-600"
                          onClick={() => clearChat(selectedChat)}
                        >
                          <Trash2 className="h-4 w-4 mr-2" />
                          Очистить чат
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </div>
              </div>

              {/* Сообщения */}
              <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {messages.length === 0 ? (
                  <div className="flex-1 flex items-center justify-center">
                    <div className="text-center space-y-4">
                      <div className="w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center mx-auto">
                        <MessageCircle className="h-10 w-10 text-white" />
                      </div>
                      <div>
                        <h3 className="text-lg font-semibold">{t.noMessages}</h3>
                        <p className="text-gray-500">{t.startChat}</p>
                      </div>
                    </div>
                  </div>
                ) : (
                  messages.map((message, index) => (
                    <div
                      key={message.id}
                      className={`flex ${message.senderId === currentUser?.id ? "justify-end" : "justify-start"}`}
                    >
                      <div
                        className={`max-w-xs lg:max-w-md px-4 py-2 rounded-2xl shadow-lg transition-all duration-200 hover:shadow-xl group ${
                          message.senderId === currentUser?.id
                            ? "bg-gradient-to-r from-blue-500 to-purple-600 text-white"
                            : `${cardStyle}`
                        }`}
                      >
                        {message.replyTo && (
                          <div className="mb-2 p-2 rounded-xl bg-black/10 border-l-2 border-white/30">
                            <p className="text-xs font-medium">{message.replyTo.senderName}</p>
                            <p className="text-xs opacity-80 truncate">{message.replyTo.content}</p>
                          </div>
                        )}

                        {message.senderId !== currentUser?.id && (
                          <p className="text-xs font-medium mb-1 opacity-70">{message.senderName}</p>
                        )}

                        <p className="break-words">{message.content}</p>

                        <div className="flex items-center justify-between mt-2">
                          <div className="flex items-center gap-1">
                            {message.reactions && message.reactions.length > 0 && (
                              <div className="flex gap-1">
                                {message.reactions.slice(0, 3).map((reaction, idx) => (
                                  <span key={idx} className="text-xs">
                                    {reaction.emoji}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs opacity-70">
                              {new Date(message.timestamp).toLocaleTimeString([], {
                                hour: "2-digit",
                                minute: "2-digit",
                              })}
                            </span>
                            {message.isEncrypted && <Lock className="h-3 w-3 opacity-70" />}
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                                >
                                  <MoreVertical className="h-3 w-3" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end" className={cardStyle}>
                                <DropdownMenuItem onClick={() => setReplyingTo(message)}>
                                  <Reply className="h-4 w-4 mr-2" />
                                  {t.reply}
                                </DropdownMenuItem>
                                <DropdownMenuItem onClick={() => navigator.clipboard.writeText(message.content)}>
                                  <Copy className="h-4 w-4 mr-2" />
                                  {t.copy}
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <div className="flex gap-1 p-2">
                                  {reactionEmojis.slice(0, 5).map((emoji) => (
                                    <button
                                      key={emoji}
                                      onClick={() => addReaction(message.id, emoji)}
                                      className="hover:scale-125 transition-transform"
                                    >
                                      {emoji}
                                    </button>
                                  ))}
                                </div>
                              </DropdownMenuContent>
                            </DropdownMenu>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))
                )}

                {typingUsers.length > 0 && (
                  <div className="flex justify-start">
                    <div className={`px-4 py-2 rounded-2xl ${cardStyle}`}>
                      <div className="flex items-center gap-2">
                        <div className="flex space-x-1">
                          <div className="w-2 h-2 bg-gray-500 rounded-full animate-bounce" />
                          <div
                            className="w-2 h-2 bg-gray-500 rounded-full animate-bounce"
                            style={{ animationDelay: "0.1s" }}
                          />
                          <div
                            className="w-2 h-2 bg-gray-500 rounded-full animate-bounce"
                            style={{ animationDelay: "0.2s" }}
                          />
                        </div>
                        <span className="text-sm text-gray-600">
                          {typingUsers.join(", ")} {t.typing}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>

              {/* Поле ответа */}
              {replyingTo && (
                <div className={`px-4 py-2 ${cardStyle} border-t`}>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Reply className="h-4 w-4 text-blue-500" />
                      <div className="text-sm">
                        <p className="font-medium text-blue-600">Ответ для {replyingTo.senderName}</p>
                        <p className="text-gray-600 truncate max-w-xs">{replyingTo.content}</p>
                      </div>
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => setReplyingTo(null)}>
                      <X className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}

              {/* Поле ввода */}
              <div className={`p-4 ${cardStyle} border-t`}>
                <div className="flex items-center gap-2">
                  <input type="file" ref={fileInputRef} className="hidden" accept="*/*" />
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => fileInputRef.current?.click()}
                    className={buttonStyle}
                  >
                    <Paperclip className="h-4 w-4" />
                  </Button>
                  <div className="flex-1 relative">
                    <Input
                      ref={messageInputRef}
                      placeholder={`${t.send}...`}
                      value={newMessage}
                      onChange={(e) => {
                        setNewMessage(e.target.value)
                        if (e.target.value.length > 0) {
                          startTyping()
                        }
                      }}
                      onKeyPress={(e) => e.key === "Enter" && sendMessage()}
                      className={`${inputStyle} pr-20`}
                      disabled={!isConnected}
                    />
                    <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex items-center gap-1">
                      <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                        <Smile className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                  <Button
                    onClick={sendMessage}
                    disabled={!newMessage.trim() || !isConnected}
                    className={`${buttonStyle} bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700`}
                  >
                    <Send className="h-4 w-4" />
                  </Button>
                </div>
                <div className="flex items-center justify-between mt-2 text-xs text-gray-500">
                  <div className="flex items-center gap-2">
                    {isConnected ? (
                      <span className="flex items-center gap-1 text-green-600">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                        {t.connected}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 text-red-600">
                        <div className="w-2 h-2 bg-red-500 rounded-full" />
                        {t.disconnected}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <Lock className="h-3 w-3 text-green-500" />
                    <span>{t.encrypted}</span>
                  </div>
                </div>
              </div>
            </>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center space-y-6">
                {isMobile && (
                  <Button onClick={() => setShowSidebar(true)} className={`mb-4 ${buttonStyle}`}>
                    <Menu className="h-4 w-4 mr-2" />
                    Чаты
                  </Button>
                )}
                <div className="w-32 h-32 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center mx-auto shadow-2xl">
                  <MessageCircle className="h-16 w-16 text-white" />
                </div>
                <div>
                  <h3 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                    {t.welcome} в {t.appName}
                  </h3>
                  <p className="text-gray-500 mt-2">{t.startChat}</p>
                </div>
                <div className="flex items-center justify-center gap-4 text-sm text-gray-400">
                  <div className="flex items-center gap-2">{isConnected ? "🟢 Подключено" : "🔴 Отключено"}</div>
                  <div className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-green-500" />
                    <span>End-to-End шифрование</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-yellow-500" />
                    <span>Быстрая доставка</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Диалог информации о чате */}
      <Dialog open={showChatInfoDialog} onOpenChange={setShowChatInfoDialog}>
        <DialogContent className={cardStyle}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Info className="h-5 w-5" />
              Информация о чате
            </DialogTitle>
          </DialogHeader>
          {selectedChatForInfo && (
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <Avatar className="h-16 w-16">
                  {selectedChatForInfo.avatar ? (
                    <AvatarImage src={selectedChatForInfo.avatar} />
                  ) : (
                    <AvatarFallback className="bg-gradient-to-br from-blue-500 to-purple-600 text-white">
                      {selectedChatForInfo.isGroup ? (
                        <Users className="h-6 w-6" />
                      ) : selectedChatForInfo.name.charAt(0)}
                    </AvatarFallback>
                  )}
                </Avatar>
                <div>
                  <h3 className="font-semibold text-lg">{selectedChatForInfo.name}</h3>
                  <p className="text-sm text-gray-500">{selectedChatForInfo.description}</p>
                  <div className="flex items-center gap-2 mt-1">
                    {selectedChatForInfo.isEncrypted && <Lock className="h-3 w-3 text-green-500" />}
                    {selectedChatForInfo.isPinned && <Star className="h-3 w-3 text-yellow-500" />}
                    {selectedChatForInfo.isMuted && <Bell className="h-3 w-3 text-red-500" />}
                  </div>
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="font-medium">Тип чата</p>
                  <p className="text-gray-500">
                    {selectedChatForInfo.type === "private" ? "Приватный" : 
                     selectedChatForInfo.type === "group" ? "Группа" : "Канал"}
                  </p>
                </div>
                <div>
                  <p className="font-medium">Сообщений</p>
                  <p className="text-gray-500">{selectedChatForInfo.messageCount}</p>
                </div>
                <div>
                  <p className="font-medium">Создан</p>
                  <p className="text-gray-500">
                    {new Date(selectedChatForInfo.createdAt).toLocaleDateString()}
                  </p>
                </div>
                <div>
                  <p className="font-medium">Шифрование</p>
                  <p className="text-gray-500">
                    {selectedChatForInfo.isEncrypted ? "Включено" : "Отключено"}
                  </p>
                </div>
              </div>
              
              {selectedChatForInfo.type !== "private" && (
                <div>
                  <p className="font-medium mb-2">Участники</p>
                  <div className="space-y-2 max-h-32 overflow-y-auto">
                    {selectedChatForInfo.participants.map((participant) => (
                      <div key={participant.id} className="flex items-center gap-2">
                        <Avatar className="h-6 w-6">
                          {participant.avatar ? (
                            <AvatarImage src={participant.avatar} />
                          ) : (
                            <AvatarFallback className="text-xs">
                              {participant.username?.charAt(1) || participant.fullName?.charAt(0)}
                            </AvatarFallback>
                          )}
                        </Avatar>
                        <span className="text-sm">{participant.username}</span>
                        {participant.isOnline && (
                          <div className="w-2 h-2 bg-green-500 rounded-full" />
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  )
}
