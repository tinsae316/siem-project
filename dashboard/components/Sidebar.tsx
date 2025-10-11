"use client";

import { useState } from "react";
import { useRouter } from "next/router";
import {
  FiSettings as SettingsIcon,
  FiHome,
  FiList,
  FiShield,
  FiUser,
} from "react-icons/fi";

export default function Sidebar() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [loading, setLoading] = useState(false); // ✅ loading state
  const router = useRouter();

  const handleNavigation = async (path: string) => {
    setLoading(true); // show spinner
    setTimeout(() => {
      router.push(path); // simulate loading delay
    }, 0); // 0.3s delay for effect
  };

  const handleCreateAdmin = () => router.push("/signup");

  const menuItems = [
    { name: "Overview", path: "/dashboard", icon: <FiHome /> },
    { name: "Security Logs", path: "/logs", icon: <FiList /> },
    { name: "Security Alerts", path: "/alerts", icon: <FiShield /> },
  ];

  return (
    <>
      <aside className="w-60 bg-white border-r border-gray-200 fixed left-0 top-16 bottom-0 flex flex-col justify-between shadow-sm z-40">
        <div className="p-4">
          <nav className="space-y-1">
            {menuItems.map((item) => (
              <button
                key={item.name}
                onClick={() => handleNavigation(item.path)}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  router.pathname === item.path
                    ? "bg-orange-100 text-orange-600 font-semibold"
                    : "text-gray-700 hover:bg-gray-100 hover:text-orange-600"
                }`}
              >
                <span className="text-base">{item.icon}</span>
                <span>{item.name}</span>
              </button>
            ))}

            {/* Settings Dropdown */}
            <div className="mt-2">
              <button
                onClick={() => setSettingsOpen(!settingsOpen)}
                className="w-full flex justify-between items-center px-3 py-2 rounded-md text-sm text-gray-700 hover:bg-gray-100 hover:text-orange-600 transition-all duration-200"
              >
                <div className="flex items-center gap-2">
                  <SettingsIcon className="text-base" />
                  <span>Settings</span>
                </div>
                <span className="text-xs">{settingsOpen ? "▲" : "▼"}</span>
              </button>

              {settingsOpen && (
                <div className="pl-8 mt-1 flex flex-col space-y-1">
                  <button
                    onClick={handleCreateAdmin}
                    className="text-left text-sm text-gray-600 hover:text-orange-600 hover:bg-gray-100 px-3 py-1.5 rounded-md transition-all duration-200 flex items-center gap-2"
                  >
                    <FiUser className="text-base" />
                    Create New Admin
                  </button>
                </div>
              )}
            </div>
          </nav>
        </div>
      </aside>

      {/* Loading overlay */}
      {loading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/20">
          <div className="w-16 h-16 border-4 border-orange-500 border-t-transparent rounded-full animate-spin"></div>
        </div>
      )}
    </>
  );
}
