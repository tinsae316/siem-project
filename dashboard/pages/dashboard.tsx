// pages/dashboard.tsx (replace your broken file with this)
import { GetServerSideProps } from "next";
import * as cookie from "cookie";
import { verifyToken } from "../lib/auth";
import prisma from "../lib/prisma";
import React, { useState } from "react";
import Layout from "../components/Layout";
import { FiSettings as SettingsIcon, FiHome, FiList, FiShield, FiUser, FiLogOut} from "react-icons/fi";
import { useRouter } from "next/router";
import { useMemo } from "react";

interface Log {
  id: number;
  message: string;
  severity: string | null; // normalized to string for charts
  timestamp: string;
  source_ip: string | null;
  outcome?: string | null; // optional outcome field for logs
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

interface User {
  id: number;
  email: string;
  username: string;
}

interface DashboardProps {
  logs: Log[];
  alerts: Alert[];
  users: User[];
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
      select: { id: true, message: true, severity: true, timestamp: true, source_ip: true },
    });

    const alertsRaw = await prisma.alerts.findMany({
      orderBy: { timestamp: "desc" },
      take: 10,
    });

    const users = await prisma.users.findMany({
      select: { id: true, email: true, username: true },
    });

    // Normalize severities to strings (or null)
    const logs: Log[] = logsRaw.map((log: any) => ({
      id: log.id,
      message: log.message ?? "No message",
      // convert undefined/null/number -> string | null
      severity:
        log.severity !== undefined && log.severity !== null ? String(log.severity) : null,
      source_ip: log.source_ip ?? null,
      timestamp:
        log.timestamp instanceof Date ? log.timestamp.toISOString() : String(log.timestamp),
    }));

    const alerts: Alert[] = alertsRaw.map((alert: any) => ({
      id: alert.id,
      rule: alert.rule ?? "No rule",
      user_name: alert.user_name ?? "Unknown user",
      source_ip: alert.source_ip ?? null,
      attempt_count: alert.attempt_count ?? null,
      severity: alert.severity ?? null,
      technique: alert.technique ?? null,
      timestamp:
        alert.timestamp instanceof Date ? alert.timestamp.toISOString() : String(alert.timestamp),
      raw: alert.raw ?? null,
    }));

    return { props: { logs, alerts, users } };
  } catch (err) {
    console.error(err);
    return { redirect: { destination: "/login", permanent: false } };
  }
};

/* ---------------- Sidebar component (Settings dropdown shows Create New Admin) ---------------- */
function Sidebar() {
  const [settingsOpen, setSettingsOpen] = useState(false);
  const router = useRouter();

  const handleCreateAdmin = () => {
    router.push("/signup");
  };

  return (
    <aside className="w-60 bg-gray-900 border-gray-700 shadow-sm fixed top-0 left-0 h-screen flex flex-col justify-between">
      <div>
        <nav className="p-4 space-y-2 text-gray-400 py-14">
          {[
            { name: "Overview", path: "/dashboard", icon: <FiHome /> },
            { name: "Security Logs", path: "/logs", icon: <FiList /> },
            { name: "Security Alerts", path: "/alerts", icon: <FiShield /> },
          ].map((item) => (
            <a
              key={item.name}
              href={item.path}
              className={`w-full  text-left px-3 py-2 rounded hover:bg-gray-100 flex items-center gap-2 ${
                item.name === "Overview" ? "bg-lightblue-500 text-gray-400 hover:bg-lightblue-600" : ""
              }`}
            >
              <span className="text-sm">{item.icon}</span>
              <span>{item.name}</span>
            </a>
          ))}

          {/* Settings Dropdown */}
          <div className="relative">
            <button
              onClick={() => setSettingsOpen(!settingsOpen)}
              className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 flex justify-between items-center"
            >
              <div className="flex items-center gap-2">
                <SettingsIcon />
                <span>Settings</span>
              </div>
              <span className="ml-2 text-xs">{settingsOpen ? "▲" : "▼"}</span>
            </button>

            {settingsOpen && (
              <div className="pl-4 mt-1 flex flex-col space-y-1">
                <button
                  onClick={handleCreateAdmin}
                  className="w-full text-left px-3 py-2 rounded hover:bg-gray-100 text-gray-500"
                > 
                <FiUser className="inline mr-2" />
                  Create New Admin
                </button>
              </div>
            )}
          </div>
        </nav>
      </div>
    </aside>
  );
}

/* ---------------- Dashboard Page ---------------- */
export default function Dashboard({ logs, alerts, users }: DashboardProps) {
  const totalEvents = logs.length;
  const totalAlerts = alerts.length;
  const threatsBlocked = logs.length;
  const activeUsers = users.length;
  const router = useRouter();

  return (
    <Layout>
    <div className="flex min-h-screen bg-gray-50">
      {/* Fixed Sidebar */}
      <Sidebar />

      {/* Scrollable Main Content */}
      <main className="flex-1 ml-60 p-8 overflow-y-auto h-screen">
        {/* Header */}
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold">Security Overview</h1>
            <p className="text-gray-600">Monitor your organization’s security posture and recent activities.</p>
          </div>
        </div>

        {/* Metrics Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <MetricCard title="Total Logs" value={totalEvents} trend="+2.5%" />
          <MetricCard title="Security Alerts" value={totalAlerts} trend="-12%" negative />
          <MetricCard title="Threats Blocked" value={threatsBlocked} trend="+8.2%" />
          <MetricCard title="Active Users" value={activeUsers} trend="+1.8%" />
        </div>
        {/* Two-column content */}
        <div className="grid md:grid-cols-2 gap-8 pb-8">
  {/* Recent Events */}
  <div className="bg-white p-6 rounded-lg shadow-sm border">
    <h2 className="text-lg font-semibold mb-2">Recent Logs</h2>
    <p className="text-sm text-gray-500 mb-4">
      Latest security logs from the past 24 hours
    </p>

    {logs.length === 0 ? (
      <p className="text-gray-400">No events recorded</p>
    ) : (
      <div className="space-y-3">
        {logs.slice(0, 5).map((log) => (
          <div
            key={log.id}
            className="p-3 rounded border-l-4 border-gray-400 bg-gray-50"
          >
            <p className="font-medium">{log.message}</p>
            <p className="text-sm text-gray-500">
              IP: {log.source_ip ?? "Unknown"} •{" "}
              {new Date(log.timestamp).toLocaleString()}
            </p>
          </div>
        ))}
      </div>
    )}
  </div>

  {/* Recent Alerts */}
  <div className="bg-white p-6 rounded-lg shadow-sm border">
    <h2 className="text-lg font-semibold mb-2">Recent Alerts</h2>
    <p className="text-sm text-gray-500 mb-4">
      Latest triggered alerts from the system
    </p>

    {alerts.length === 0 ? (
      <p className="text-gray-400">No alerts triggered</p>
    ) : (
      <div className="space-y-3">
        {alerts.slice(0, 6).map((alert) => (
          <div
            key={alert.id}
            className="p-3 rounded border-l-4 border-red-400 bg-red-50"
          >
            <p className="font-medium text-red-600">{alert.rule}</p>
            <p className="text-sm text-gray-500">
              User: {alert.user_name ?? "Unknown"} •{" "}
              {new Date(alert.timestamp).toLocaleString()}
            </p>
          </div>
        ))}
      </div>
    )}
  </div>
</div>
</main>
</div>
</Layout>
  );
}

/* ---------------- MetricCard component ---------------- */
function MetricCard({
  title,
  value,
  trend,
  negative,
}: {
  title: string;
  value: number;
  trend: string;
  negative?: boolean;
}) {
  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border">
      <h2 className="text-sm text-gray-600 mb-1">{title}</h2>
      <p className="text-3xl font-bold">{value}</p>
      <p className={`text-sm ${negative ? "text-red-500" : "text-green-500"} font-medium mt-1`}>
        {trend} from last month
      </p>
    </div>
  );
}
