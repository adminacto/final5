import React from "react"
import { Inter } from "next/font/google"
import "./globals.css"

const inter = Inter({ subsets: ["latin"] })

export const metadata = {
  title: "ACTOGRAM - Telegram Clone",
  description: "Real-time chat application built with Next.js",
  icons: {
    icon: "/favicon.ico",
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
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
      </head>
      <body className={inter.className}>{children}</body>
    </html>
  )
}

