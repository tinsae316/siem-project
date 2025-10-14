import { GetServerSideProps } from "next";
import * as cookie from "cookie";
import { verifyToken } from "../lib/auth";
import prisma from "../lib/prisma";
import Layout from "../components/Layout";
import Sidebar from "../components/Sidebar"; // ✅ import Sidebar
import React from "react";

interface Log {
  id: number;
  message: string;
  severity: string | null;
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

interface User {
  id: number;
  email: string;
  username: string;
}

// ✅ Full Dashboard Props with metrics typed correctly
interface DashboardProps {
  logs: Log[];
  alerts: Alert[];
  users: User[];
  totalLogs: number;
  totalAlerts: number;
  threatsBlocked: number;
  activeUsers: number;
}

export const getServerSideProps: GetServerSideProps<DashboardProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);

  if (!token) return { redirect: { destination: "/login", permanent: false } };

  try {
    verifyToken(token);

    const logsRaw = await prisma.logs.findMany({
      orderBy: { timestamp: "desc" },
      take: 10,
    });

    const alertsRaw = await prisma.alerts.findMany({
      orderBy: { timestamp: "desc" },
      take: 10,
    });

    const users = await prisma.users.findMany({
      select: { id: true, email: true, username: true },
    });

    const HIGH = 3;
    const CRITICAL = 4;
    
    // ✅ Count metrics
    const totalLogs = await prisma.logs.count();
    const totalAlerts = await prisma.alerts.count();
    const threatsBlocked = await prisma.logs.count({
      where: {
        severity: { in: [HIGH, CRITICAL] },
      },
    });

    const activeUsers = await prisma.users.count();

    const logs: Log[] = logsRaw.map((log) => ({
      id: log.id,
      message: log.message ?? "No message",
      severity: log.severity ? String(log.severity) : null,
      source_ip: log.source_ip ?? null,
      timestamp: log.timestamp instanceof Date ? log.timestamp.toISOString() : String(log.timestamp),
    }));

    const alerts: Alert[] = alertsRaw.map((alert) => ({
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

    return {
      props: { logs, alerts, users, totalLogs, totalAlerts, threatsBlocked, activeUsers },
    };
  } catch {
    return { redirect: { destination: "/login", permanent: false } };
  }
};

export default function Dashboard({
  logs,
  alerts,
  users,
  totalLogs,
  totalAlerts,
  threatsBlocked,
  activeUsers,
}: DashboardProps) {
  return (
    <Layout>
      <div className="flex min-h-screen bg-gray-50">
        <Sidebar />
        <main className="ml-60 mt-16 p-8 flex-1 bg-gray-50 min-h-screen overflow-y-auto">
          <h1 className="text-3xl font-bold mb-4">Security Overview</h1>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <MetricCard title="Total Logs" value={totalLogs} trend="+2.5%" />
            <MetricCard title="Security Alerts" value={totalAlerts} trend="-12%" negative />
            <MetricCard title="Threats Blocked" value={threatsBlocked} trend="+8.2%" />
            <MetricCard title="Active Users" value={activeUsers} trend="+1.8%" />
          </div>

          <div className="grid md:grid-cols-2 gap-8 pb-8">
            <LogsSection logs={logs} />
            <AlertsSection alerts={alerts} />
          </div>
        </main>
      </div>
    </Layout>
  );
}



function LogsSection({ logs }: { logs: Log[] }) {
  return (
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
  );
}

function AlertsSection({ alerts }: { alerts: Alert[] }) {
  return (
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
  );
}

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
      <p
        className={`text-sm ${
          negative ? "text-red-500" : "text-green-500"
        } font-medium mt-1`}
      >
        {trend} from last month
      </p>
    </div>
  );
}
