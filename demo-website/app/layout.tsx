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
  title: "Security Demo App",
  description: "Demo website to showcase simple attacks safely",
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
          backgroundColor: "#ffffff",
          color: "#111",
          fontFamily: "var(--font-geist-sans), sans-serif",
          margin: 0,
          padding: 0,
          minHeight: "100vh",
        }}
      >
        <nav
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "16px 32px",
            borderBottom: "1px solid #eaeaea",
            backgroundColor: "#fff",
          }}
        >
          {/* Left side: Landing page */}
          <a
            href="/"
            style={{
              fontWeight: 700,
              fontSize: 20,
              color: "#0070f3",
              textDecoration: "none",
            }}
          >
            SecurityDemo
          </a>

          {/* Right side: Login + Search/XSS */}
          <div style={{ display: "flex", gap: 20 }}>
            <a
              href="/login"
              style={{
                padding: "8px 16px",
                borderRadius: 8,
                backgroundColor: "#0070f3",
                color: "#fff",
                textDecoration: "none",
                fontWeight: 500,
                transition: "background 0.2s",
              }}
            >
              Login
            </a>
            <a
              href="/search"
              style={{
                padding: "8px 16px",
                borderRadius: 8,
                backgroundColor: "#eaeaea",
                color: "#111",
                textDecoration: "none",
                fontWeight: 500,
                transition: "background 0.2s",
              }}
            >
              Search/XSS Demo
            </a>
          </div>
        </nav>

        {children}
      </body>
    </html>
  );
}
