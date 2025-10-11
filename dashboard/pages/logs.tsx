"use client";

import { GetServerSideProps } from "next";
import prisma from "../lib/prisma";
import { verifyToken } from "../lib/auth";
import * as cookie from "cookie";
import Layout from "../components/Layout";
import Sidebar from "../components/Sidebar";
import { useState } from "react";

interface Log {
  id: number;
  message: string | null;
  severity: number | null;
  outcome: string;
  timestamp: string;
  source_ip: string | null;
  category?: string;
  type?: string;
}

interface LogsPageProps {
  logs: Log[];
}

export const getServerSideProps: GetServerSideProps<LogsPageProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);
  if (!token) return { redirect: { destination: "/login", permanent: false } };

  try {
    verifyToken(token);

    const { startDate, endDate } = ctx.query;

    const logsRaw = await prisma.logs.findMany({
      where: {
        timestamp: {
          gte: startDate ? new Date(startDate as string) : undefined,
          lte: endDate ? new Date(endDate as string) : undefined,
        },
      },
      orderBy: { timestamp: "desc" },
    });

    const logs: Log[] = logsRaw.map((log: any) => ({
      ...log,
      timestamp: log.timestamp instanceof Date ? log.timestamp.toISOString() : String(log.timestamp),
    }));

    return { props: { logs } };
  } catch {
    return { redirect: { destination: "/login", permanent: false } };
  }
};

// Helper functions
const getOutcomeType = (outcome: string): string => {
  const text = outcome?.toLowerCase() || "";
  if (text.includes("success")) return "Success";
  if (text.includes("failure")) return "Failure";
  if (text.includes("denied")) return "Denied";
  return "Unknown";
};

const getOutcomeIcon = (outcome: string): string => {
  switch (outcome) {
    case "Success":
      return "✓";
    case "Denied":
      return "!";
    case "Failure":
      return "⚠";
    default:
      return "i";
  }
};

const getOutcomeColor = (outcome: string): string => {
  switch (outcome) {
    case "Success":
      return "#10b981";
    case "Denied":
      return "#ef4444";
    case "Failure":
      return "#f59e0b";
    default:
      return "#3b82f6";
  }
};

export default function LogsPage({ logs }: LogsPageProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");

  // Stats
  const totalLogs = logs.length;
  const denied = logs.filter((l) => getOutcomeType(l.outcome) === "Denied").length;
  const failures = logs.filter((l) => getOutcomeType(l.outcome) === "Failure").length;
  const success = logs.filter((l) => getOutcomeType(l.outcome) === "Success").length;
  const unknown = logs.filter((l) => getOutcomeType(l.outcome) === "Unknown").length;

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    const query = new URLSearchParams();
    if (startDate) query.append("startDate", startDate);
    if (endDate) query.append("endDate", endDate);
    window.location.href = `/logs?${query.toString()}`;
  };

  const filteredLogs = logs.filter((log) =>
    !searchTerm
      ? true
      : log.message?.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const formatDate = (d: string) =>
    new Date(d).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });

  return (
    <Layout>
      <div className="flex bg-gray-50 min-h-screen pt-16">
        <Sidebar />

        <main className="flex-1 ml-60 px-8 py-6 overflow-y-auto">
          <h1 className="text-3xl font-bold text-gray-900 mb-6">Security Logs Overview</h1>

          {/* Stat Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-6 mb-8">
            <MetricCard title="Total Logs" value={totalLogs} color="gray" />
            <MetricCard title="Denied" value={denied} color="red" />
            <MetricCard title="Failures" value={failures} color="yellow" />
            <MetricCard title="Success" value={success} color="green" />
            <MetricCard title="Unknown" value={unknown} color="blue" />
          </div>

          {/* Filters */}
          <form
            onSubmit={handleFilter}
            className="flex flex-wrap gap-3 bg-white p-4 rounded-lg shadow-sm mb-8 border"
          >
            <input
              type="text"
              placeholder="Search logs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="px-3 py-2 border rounded-lg border-gray-300 focus:ring-2 focus:ring-orange-400 flex-1 min-w-[180px]"
            />
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              className="px-3 py-2 border rounded-lg border-gray-300 focus:ring-2 focus:ring-orange-400"
            />
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              className="px-3 py-2 border rounded-lg border-gray-300 focus:ring-2 focus:ring-orange-400"
            />
            <button
              type="submit"
              className="bg-orange-600 text-white px-6 py-2 rounded-lg hover:bg-orange-700 transition font-medium"
            >
              Apply
            </button>
          </form>

          {/* Logs Section */}
            <section className="bg-white rounded-2xl shadow-md border flex flex-col h-[calc(100vh-200px)]">
              {/* Sticky Header inside logs section */}
              <div className="p-6 border-b sticky top-0 bg-white z-10 rounded-t-2xl">
                <h2 className="text-xl font-semibold text-gray-900">
                  Log Entries ({filteredLogs.length})
                </h2>
              </div>

              {/* Scrollable log entries */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                {filteredLogs.length === 0 ? (
                  <div className="text-center text-gray-500 py-20">
                    No logs found for the selected filters.
                  </div>
                ) : (
                  filteredLogs.map((log) => {
                    const outcome = getOutcomeType(log.outcome);
                    return (
                      <div
                        key={log.id}
                        className="flex items-start gap-4 border-b border-gray-200 pb-3"
                      >
                        <div
                          className="w-8 h-8 flex items-center justify-center rounded-full text-white font-bold text-sm"
                          style={{ backgroundColor: getOutcomeColor(outcome) }}
                        >
                          {getOutcomeIcon(outcome)}
                        </div>
                        <div className="flex-1">
                          <p className="text-gray-900 font-medium text-base leading-relaxed">
                            {log.message || "No message"}
                          </p>
                          <p className="text-sm text-gray-500 flex gap-2">
                            <span>{formatDate(log.timestamp)}</span>•{" "}
                            <span>{log.source_ip || "System"}</span>
                          </p>
                        </div>
                        <div className="text-xs font-bold text-gray-700 px-3 py-1 bg-gray-100 rounded">
                          {outcome}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </section>
        </main>
      </div>
    </Layout>
  );
}

function MetricCard({
  title,
  value,
  color,
}: {
  title: string;
  value: number;
  color: string;
}) {
  const colorMap: Record<string, string> = {
    gray: "bg-gray-100 text-gray-700",
    red: "bg-red-100 text-red-700",
    yellow: "bg-yellow-100 text-yellow-700",
    green: "bg-green-100 text-green-700",
    blue: "bg-blue-100 text-blue-700",
  };

  return (
    <div className={`rounded-lg p-6 shadow-sm border ${colorMap[color]}`}>
      <h3 className="text-sm font-medium">{title}</h3>
      <p className="text-3xl font-bold mt-1">{value}</p>
    </div>
  );
}
