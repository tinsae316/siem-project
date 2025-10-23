import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SIEM Log Analysis Demo",
  description: "Demo interface for security log analysis",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable}`}
        style={{
          margin: 0,
          fontFamily: "var(--font-geist-sans), sans-serif",
          backgroundColor: "#f5f7fa",
          color: "#111827",
        }}
      >
        <header
          style={{
            backgroundColor: "#1f2937",
            color: "white",
            padding: "1rem 0",
            textAlign: "center",
            boxShadow: "0 2px 4px rgba(0,0,0,0.1)",
          }}
        >
          <nav>
            <a
              href="/login"
              style={{
                marginRight: "2rem",
                color: "white",
                textDecoration: "none",
                fontWeight: 600,
              }}
            >
              Login
            </a>
            <a
              href="/search"
              style={{
                color: "white",
                textDecoration: "none",
                fontWeight: 600,
              }}
            >
              Search/XSS Demo
            </a>
          </nav>
        </header>

        <main
          style={{
            maxWidth: "1200px",
            margin: "2rem auto",
            padding: "0 1rem",
            minHeight: "80vh",
          }}
        >
          {children}
        </main>

        <footer
          style={{
            textAlign: "center",
            padding: "1rem 0",
            borderTop: "1px solid #e5e7eb",
            color: "#6b7280",
          }}
        >
          © 2025 SIEM Log Analysis Demo
        </footer>
      </body>
    </html>
  );
}
