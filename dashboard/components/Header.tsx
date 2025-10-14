"use client";

import Link from "next/link";
import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import { FiBookOpen, FiLogOut, FiLogIn, FiShield, FiHome, FiCpu } from "react-icons/fi";

export default function Header() {
  const router = useRouter();
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    const checkLogin = async () => {
      try {
        const res = await fetch("/api/auth/me");
        const data = await res.json();
        setIsLoggedIn(data.loggedIn);
      } catch {
        setIsLoggedIn(false);
      }
    };
    checkLogin();
  }, []);

  const handleLogout = async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    setIsLoggedIn(false);
    router.push("/landing");
  };

  return (
    <header className="bg-gray-900 text-white shadow-md fixed top-0 left-0 right-0 z-50 h-16">
      <div className="flex items-center justify-between h-full w-full">
        {/* Logo flush left */}
        <Link href="/" className="flex items-center gap-2 text-xl font-semibold pl-5">
          <FiShield className="text-orange-500 h-6 w-6" />
          <span>SIEM</span>
        </Link>

        {/* Navigation flush right */}
        <nav className="flex items-center gap-4 text-sm pr-7">
          {isLoggedIn && (
            <Link
              href="/dashboard"
              className={`flex items-center gap-1 ${
                router.pathname === "/dashboard"
                  ? "border-b-2 border-orange-500 text-orange-500 pb-1"
                  : "hover:text-orange-400 px-2 py-1.5 rounded-md"
              }`}
            >
              <FiHome className="h-4 w-4" />
              <span>Dashboard</span>
            </Link>
          )}

          {/* ✅ Scan button - only if logged in */}
          {isLoggedIn && (
            <Link
              href="/scan"
              className={`flex items-center gap-1 ${
                router.pathname === "/scan"
                  ? "border-b-2 border-orange-500 text-orange-500 pb-1"
                  : "hover:text-orange-400 px-2 py-1.5 rounded-md"
              }`}
            >
              <FiCpu className="h-4 w-4" />
              <span>Scan</span>
            </Link>
          )}

          
          <Link
            href="/about"
            className={`flex items-center gap-1 ${
              router.pathname === "/about"
                ? "border-b-2 border-orange-500 text-orange-500 pb-1"
                : "hover:text-orange-400 px-2 py-1.5 rounded-md"
            }`}
          >
            <FiBookOpen className="h-4 w-4" />
            <span>About</span>
          </Link>

          {isLoggedIn ? (
            <button
              onClick={handleLogout}
              className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium flex items-center gap-1"
            >
              <FiLogOut className="h-4 w-4" /> Logout
            </button>
          ) : (
            <Link
              href="/login"
              className="bg-green-500 hover:bg-green-600 text-white px-4 py-2 rounded-md text-sm font-medium flex items-center gap-1"
            >
              <FiLogIn className="h-4 w-4" /> Login
            </Link>
          )}
        </nav>
      </div>
    </header>
  );
}