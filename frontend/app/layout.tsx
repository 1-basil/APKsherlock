import './globals.css'
import type { Metadata } from 'next'

export const metadata: Metadata = {
  title: 'SherlockAPK – APK Forensic Analysis Platform',
  description: 'Professional APK forensic analysis with static analysis, IOC extraction, threat scoring, and investigation reporting.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>{children}</body>
    </html>
  )
}
