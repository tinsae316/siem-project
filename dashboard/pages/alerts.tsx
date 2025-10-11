"use client";

import { GetServerSideProps } from "next";
import prisma from "../lib/prisma";
import { verifyToken } from "../lib/auth";
import * as cookie from "cookie";
import Layout from "../components/Layout";
import Sidebar from "../components/Sidebar";
import { useState } from "react";

interface Alert {
  id: number;
  rule: string | null;
  user_name: string | null;
  source_ip: string | null;
  attempt_count: number | null;
  severity: string | null;
  technique: string | null;
  timestamp: string;
  raw: any | null;
}

interface AlertsPageProps {
  alerts: Alert[];
}

export const getServerSideProps: GetServerSideProps<AlertsPageProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);
  if (!token) return { redirect: { destination: "/login", permanent: false } };

  try {
    verifyToken(token);

    const { startDate, endDate } = ctx.query;

    const alertsRaw = await prisma.alerts.findMany({
      where: {
        timestamp: {
          gte: startDate ? new Date(startDate as string) : undefined,
          lte: endDate ? new Date(endDate as string) : undefined,
        },
      },
      orderBy: { timestamp: "desc" },
    });

    const alerts: Alert[] = alertsRaw.map((alert) => ({
      ...alert,
      timestamp:
        alert.timestamp instanceof Date
          ? alert.timestamp.toISOString()
          : String(alert.timestamp),
    }));

    return { props: { alerts } };
  } catch {
    return { redirect: { destination: "/login", permanent: false } };
  }
};

// Severity helpers
const getSeverityColor = (severity: string | null) => {
  if (!severity) return "#6b7280";
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "#ef4444";
    case "HIGH":
      return "#f59e0b";
    case "MEDIUM":
      return "#3b82f6";
    case "LOW":
      return "#10b981";
    default:
      return "#6b7280";
  }
};

const getSeverityIcon = (severity: string | null) => {
  if (!severity) return "i";
  switch (severity.toUpperCase()) {
    case "CRITICAL":
      return "!";
    case "HIGH":
      return "⚠";
    case "MEDIUM":
      return "i";
    case "LOW":
      return "✓";
    default:
      return "i";
  }
};

const getAlertTitle = (alert: Alert) => alert.rule || alert.technique || "Security Alert";

const getAlertDescription = (alert: Alert) => {
  if (alert.technique === "Credential Stuffing")
    return "Large-scale credential stuffing attack detected.";
  if (alert.technique === "XSS")
    return "Cross-site scripting attempt detected in user input.";
  if (alert.technique === "SQLi")
    return "SQL injection pattern detected in request parameters.";
  if (alert.technique === "Brute Force")
    return "Multiple failed login attempts from the same IP.";
  if (alert.rule?.includes("Admin Account Creation"))
    return "Unauthorized admin account creation attempt detected.";
  if (alert.rule?.includes("Admin Role Assignment"))
    return "Admin role assignment without proper authorization.";
  return `Security event detected - ${alert.user_name || alert.source_ip || "Unknown source"}`;
};

export default function AlertsPage({ alerts }: AlertsPageProps) {
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("All Severities");
  const [selectedTechnique, setSelectedTechnique] = useState("All Techniques");

  const totalAlerts = alerts.length;
  const critical = alerts.filter((a) => a.severity === "CRITICAL").length;
  const high = alerts.filter((a) => a.severity === "HIGH").length;
  const medium = alerts.filter((a) => a.severity === "MEDIUM").length;
  const low = alerts.filter((a) => a.severity === "LOW").length;

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    const query = new URLSearchParams();
    if (startDate) query.append("startDate", startDate);
    if (endDate) query.append("endDate", endDate);
    window.location.href = `/alerts?${query.toString()}`;
  };

  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      !searchTerm ||
      alert.rule?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.technique?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.user_name?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      selectedSeverity === "All Severities" ||
      alert.severity === selectedSeverity.toUpperCase();

    const matchesTechnique =
      selectedTechnique === "All Techniques" ||
      alert.technique === selectedTechnique;

    return matchesSearch && matchesSeverity && matchesTechnique;
  });

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
          <h1 className="text-3xl font-bold text-gray-900 mb-6">Security Alerts Overview</h1>

          {/* Stat Cards */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-6 mb-8">
            <MetricCard title="Total Alerts" value={totalAlerts} color="gray" />
            <MetricCard title="Critical" value={critical} color="red" />
            <MetricCard title="High" value={high} color="yellow" />
            <MetricCard title="Medium" value={medium} color="blue" />
            <MetricCard title="Low" value={low} color="green" />
          </div>

          {/* Filters */}
          <form
            onSubmit={handleFilter}
            className="flex flex-wrap gap-3 bg-white p-4 rounded-lg shadow-sm mb-8 border"
          >
            <input
              type="text"
              placeholder="Search alerts..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="px-3 py-2 border rounded-lg border-gray-300 focus:ring-2 focus:ring-orange-400 flex-1 min-w-[180px]"
            />
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="px-3 py-2 border rounded-lg border-gray-300 focus:ring-2 focus:ring-orange-400"
            >
              <option>All Severities</option>
              <option>CRITICAL</option>
              <option>HIGH</option>
              <option>MEDIUM</option>
              <option>LOW</option>
            </select>
            <select
              value={selectedTechnique}
              onChange={(e) => setSelectedTechnique(e.target.value)}
              className="px-3 py-2 border rounded-lg border-gray-300 focus:ring-2 focus:ring-orange-400"
            >
              <option>All Techniques</option>
              <option>Brute Force</option>
              <option>Credential Stuffing</option>
              <option>SQLi</option>
              <option>XSS</option>
            </select>
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

          {/* Alerts List */}
            <section className="bg-white rounded-2xl shadow-md border flex flex-col h-[calc(100vh-200px)]">
              {/* Sticky header for alert section */}
              <div className="p-6 border-b sticky top-0 bg-white z-10 rounded-t-2xl">
                <h2 className="text-xl font-semibold text-gray-900">
                  Alert Entries ({filteredAlerts.length})
                </h2>
              </div>

              {/* Scrollable alert entries */}
              <div className="flex-1 overflow-y-auto p-6 space-y-4">
                {filteredAlerts.length === 0 ? (
                  <div className="text-center text-gray-500 py-20">
                    No alerts found for the selected filters.
                  </div>
                ) : (
                  filteredAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className="flex items-start gap-4 border-b border-gray-200 pb-3"
                    >
                      <div
                        className="w-8 h-8 flex items-center justify-center rounded-full text-white font-bold text-sm"
                        style={{ backgroundColor: getSeverityColor(alert.severity) }}
                      >
                        {getSeverityIcon(alert.severity)}
                      </div>
                      <div className="flex-1">
                        <p className="text-gray-900 font-medium text-base leading-relaxed">
                          {getAlertTitle(alert)}
                        </p>
                        <p className="text-sm text-gray-500">
                          {getAlertDescription(alert)}
                        </p>
                        <p className="text-xs text-gray-400 mt-1 flex flex-wrap gap-2">
                          <span>{formatDate(alert.timestamp)}</span>•{" "}
                          <span>{alert.source_ip || "Unknown IP"}</span>
                          {alert.user_name && <>• <span>{alert.user_name}</span></>}
                          {alert.attempt_count && (
                            <>• <span>{alert.attempt_count} attempts</span></>
                          )}
                        </p>
                      </div>
                      <div
                        className="text-xs font-bold text-gray-700 px-3 py-1 bg-gray-100 rounded"
                        style={{ color: getSeverityColor(alert.severity) }}
                      >
                        {alert.severity || "UNKNOWN"}
                      </div>
                    </div>
                  ))
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
    blue: "bg-blue-100 text-blue-700",
    green: "bg-green-100 text-green-700",
  };

  return (
    <div className={`rounded-lg p-6 shadow-sm border ${colorMap[color]}`}>
      <h3 className="text-sm font-medium">{title}</h3>
      <p className="text-3xl font-bold mt-1">{value}</p>
    </div>
  );
}