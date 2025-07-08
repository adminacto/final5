import React from "react"
import { Inter } from "next/font/google"
import "./globals.css"
import { useState } from "react"
import { useRouter } from "next/navigation"

const inter = Inter({ subsets: ["latin"] })

export const metadata = {
  title: "ACTOGRAM - Telegram Clone",
  description: "Real-time chat application built with Next.js",
  icons: {
    icon: "/favicon.ico",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [menuOpen, setMenuOpen] = useState(false)
  const openMenu = () => setMenuOpen(!menuOpen)
  const goToSettings = () => {
    setMenuOpen(false)
    // переход на страницу настроек
    router.push('/settings')
  }

  return (
    <html lang="uz">
      <head>
        <title>ACTOGRAM</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <style>
          {`
            [id^="v0-built-with-button"] {
              display: none !important;
              visibility: hidden !important;
              pointer-events: none !important;
              opacity: 0 !important;
            }
          `}
        </style>
        <link
          rel="icon"
          href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>💬🅰️</text></svg>"
        />
      </head>
      <body className={inter.className}>
        <div className="header">
          <div className="left">
            <span className="logo">ACTOGRAM</span>
            {/* ...другие элементы... */}
          </div>
          <div className="right">
            <button className="menu-btn" onClick={openMenu}>
              ⋮
            </button>
            {/* выпадающее меню */}
            {menuOpen && (
              <div className="dropdown-menu">
                <button onClick={goToSettings}>Настройки</button>
                {/* другие пункты */}
              </div>
            )}
          </div>
        </div>
        {children}
      </body>
    </html>
  )
}

