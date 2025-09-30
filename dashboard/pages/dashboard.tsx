// pages/dashboard.tsx
import { GetServerSideProps } from "next";
import * as cookie from "cookie";
import { verifyToken } from "../lib/auth";
import prisma from "../lib/prisma";
import Link from "next/link";
import { useState } from "react";

interface Log {
  id: number;
  message: string;
  severity: number | null;
  timestamp: string;
  source_ip: string | null;
}

interface Alert {
  id: number;
  rule: string;
  user_name: string;
  source_ip: string | null;
  attempt_count: number | null;
  severity: string | null;
  technique: string | null;
  timestamp: string;
  raw: any | null;
}

interface DashboardProps {
  logs: Log[];
  alerts: Alert[];
}

export const getServerSideProps: GetServerSideProps<DashboardProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);

  if (!token) {
    return { redirect: { destination: "/login", permanent: false } };
  }

  try {
    verifyToken(token);

    const logsRaw = await prisma.logs.findMany({
      orderBy: { timestamp: "desc" },
      take: 10,
      select: {
        id: true,
        message: true,
        severity: true,
        timestamp: true,
        source_ip: true,
      },
    });

    const alertsRaw = await prisma.alerts.findMany({
      orderBy: { timestamp: "desc" },
      take: 10,
    });

    const logs: Log[] = logsRaw.map((log: any) => ({
      ...log,
      message: log.message ?? "No message",
      severity: log.severity ?? null,
      source_ip: log.source_ip ?? null,
      timestamp: log.timestamp instanceof Date ? log.timestamp.toISOString() : String(log.timestamp),
    }));

    const alerts: Alert[] = alertsRaw.map((alert: any) => ({
      id: alert.id,
      rule: alert.rule ?? "No rule",
      user_name: alert.user_name ?? "Unknown user",
      source_ip: alert.source_ip ?? null,
      attempt_count: alert.attempt_count ?? null,
      severity: alert.severity ?? null,
      technique: alert.technique ?? null,
      timestamp: alert.timestamp instanceof Date ? alert.timestamp.toISOString() : String(alert.timestamp),
      raw: alert.raw ?? null,
    }));

    return { props: { logs, alerts } };
  } catch (err) {
    console.error(err);
    return { redirect: { destination: "/login", permanent: false } };
  }
};

export default function Dashboard({ logs, alerts }: DashboardProps) {
  const [isDropdownOpen, setIsDropdownOpen] = useState(false);
  const totalEvents = logs.length;
  const activeAlerts = alerts.filter((a) => a.severity).length;
  const criticalAlerts = alerts.filter((a) => a.severity?.toLowerCase() === "high").length;

  return (
    <div className="container mx-auto p-6 bg-gray-50 min-h-screen">
      {/* Header with Settings Icon */}
      <div className="mb-8 relative">
        <div className="flex justify-between items-start mb-4">
          <div>
            <h1 className="text-3xl font-bold mb-2">SIEM Security Dashboard</h1>
          </div>
          
          {/* Settings Icon Dropdown */}
          <div className="relative">
            <button
              onClick={() => setIsDropdownOpen(!isDropdownOpen)}
              className="p-2 rounded-full hover:bg-gray-200 transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-gray-400"
              aria-label="Settings"
            >
              <svg 
                className="w-6 h-6 text-gray-600" 
                fill="none" 
                stroke="currentColor" 
                viewBox="0 0 24 24" 
                xmlns="http://www.w3.org/2000/svg"
              >
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" 
                />
                <path 
                  strokeLinecap="round" 
                  strokeLinejoin="round" 
                  strokeWidth={2} 
                  d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" 
                />
              </svg>
            </button>
            
            {/* Dropdown Menu */}
            {isDropdownOpen && (
              <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg py-1 z-10 border border-gray-200">
                <Link href="/signup">
                  <div 
                    className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 cursor-pointer"
                    onClick={() => setIsDropdownOpen(false)}
                  >
                    <div className="flex items-center">
                      <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                      </svg>
                      Create New Admin
                    </div>
                  </div>
                </Link>
                <div className="border-t border-gray-100 my-1"></div>
                <Link href="/settings">
                  <div 
                    className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 cursor-pointer"
                    onClick={() => setIsDropdownOpen(false)}
                  >
                    <div className="flex items-center">
                      <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                      </svg>
                      System Settings
                    </div>
                  </div>
                </Link>
                <Link href="/profile">
                  <div 
                    className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 cursor-pointer"
                    onClick={() => setIsDropdownOpen(false)}
                  >
                    <div className="flex items-center">
                      <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                      </svg>
                      User Profile
                    </div>
                  </div>
                </Link>
              </div>
            )}
          </div>
        </div>

        {/* Close dropdown when clicking outside */}
        {isDropdownOpen && (
          <div 
            className="fixed inset-0 z-0" 
            onClick={() => setIsDropdownOpen(false)}
          ></div>
        )}

        {/* Metrics Row */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-gray-400">
            <h2 className="text-gray-600 text-sm font-medium mb-1">Total Events</h2>
            <p className="text-3xl font-bold">{totalEvents}</p>
            <p className="text-xs text-gray-500 mt-1">Last 24 hours</p>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-purple-500">
            <h2 className="text-gray-600 text-sm font-medium mb-1">Active Alerts</h2>
            <p className="text-3xl font-bold text-purple-600">{activeAlerts}</p>
            <p className="text-xs text-gray-500 mt-1">Requires attention</p>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-red-500">
            <h2 className="text-gray-600 text-sm font-medium mb-1">Critical Alerts</h2>
            <p className="text-3xl font-bold text-red-600">{criticalAlerts}</p>
            <p className="text-xs text-gray-500 mt-1">High priority</p>
          </div>
          
          <div className="bg-white p-6 rounded-lg shadow-sm border-l-4 border-green-500">
            <h2 className="text-gray-600 text-sm font-medium mb-1">System Status</h2>
            <p className="text-3xl font-bold text-green-600">Online</p>
            <p className="text-xs text-gray-500 mt-1">All systems operational</p>
          </div>
        </div>

        {/* Navigation Buttons */}
        <div className="flex gap-3 justify-end">
          <Link href="/logs">
            <button className="border border-gray-300 px-4 py-2 rounded text-gray-700 hover:bg-gray-50 transition">
              View Logs
            </button>
          </Link>
          <Link href="/alerts">
            <button className="bg-gray-800 text-white px-4 py-2 rounded hover:bg-gray-700 transition">
              View Alerts
            </button>
          </Link>
        </div>
      </div>

      {/* Content Sections */}
      <div className="space-y-8">
        {/* Recent Security Alerts Section */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">Recent Security Alerts</h2>
          <p className="text-sm text-gray-600 mb-4">Latest security incidents requiring attention</p>
          
          <div className="border-t border-gray-200 pt-4">
            {alerts.length === 0 ? (
              <p className="text-gray-500">No alerts</p>
            ) : (
              <div className="space-y-4">
                {alerts.slice(0, 3).map((alert) => (
                  <div key={alert.id} className="border-l-4 border-red-500 pl-4 py-2">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-1 rounded text-xs font-bold ${
                        alert.severity?.toLowerCase() === "high" 
                          ? "bg-red-100 text-red-800" 
                          : "bg-purple-100 text-purple-800"
                      }`}>
                        {alert.severity ?? "N/A"}
                      </span>
                      <span className="font-medium">{alert.rule}</span>
                    </div>
                    <div className="text-sm text-gray-600 ml-2">
                      <span className="font-medium">{alert.user_name}</span>
                      <span className="mx-2">•</span>
                      <span>{new Date(alert.timestamp).toLocaleDateString()}, {new Date(alert.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* System Activity Logs Section */}
        <div className="bg-white rounded-lg shadow-sm p-6">
          <h2 className="text-xl font-semibold mb-4 text-gray-800">System Activity Logs</h2>
          <p className="text-sm text-gray-600 mb-4">Recent system events and activities</p>
          
          <div className="border-t border-gray-200 pt-4">
            {logs.length === 0 ? (
              <p className="text-gray-500">No logs</p>
            ) : (
              <div className="space-y-4">
                {logs.slice(0, 3).map((log) => (
                  <div key={log.id} className="border-l-4 border-gray-400 pl-4 py-2">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`px-2 py-1 rounded text-xs font-bold ${
                        log.severity === 1 
                          ? "bg-gray-100 text-gray-800"
                          : log.severity === 2 
                          ? "bg-blue-100 text-blue-800"
                          : "bg-purple-100 text-purple-800"
                      }`}>
                        Level {log.severity ?? "N/A"}
                      </span>
                      <span>{log.message}</span>
                    </div>
                    <div className="text-sm text-gray-600 ml-2">
                      <span>{log.source_ip ?? "Unknown IP"}</span>
                      <span className="mx-2">•</span>
                      <span>{new Date(log.timestamp).toLocaleDateString()}, {new Date(log.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}