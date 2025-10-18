"use client";

import { GetServerSideProps } from "next";
import * as cookie from "cookie";
import { verifyToken } from "../lib/auth";
import { useState, useEffect, useRef } from "react";
import Layout from "../components/Layout";
import Sidebar from "../components/Sidebar";
import {
    FiActivity,
    FiAlertTriangle,
    FiCheckCircle,
    FiClock,
    FiLoader,
    FiPause,
    FiPlay,
    FiRefreshCw,
    FiTerminal,
    FiZap,
} from "react-icons/fi";

// --- SERVER-SIDE AUTH PROTECTION ---
export const getServerSideProps: GetServerSideProps = async (ctx) => {
    const cookies = ctx.req.headers.cookie || "";
    const { token } = cookie.parse(cookies);

    if (!token) {
        return { redirect: { destination: "/login", permanent: false } };
    }

    try {
        verifyToken(token);
    } catch {
        return { redirect: { destination: "/login", permanent: false } };
    }

    return { props: {} };
};

interface DetectorStatus {
    name: string;
    status: "pending" | "starting" | "running" | "stopped" | "error";
    logs: string[];
    lastActivity: Date;
    alertsGenerated: number;
}

interface MonitorStats {
    totalDetectors: number;
    runningDetectors: number;
    totalAlerts: number;
    systemUptime: Date;
}

export default function ScheduledMonitorPage() {
    const [detectors, setDetectors] = useState<DetectorStatus[]>([]);
    const [isMonitoring, setIsMonitoring] = useState(false);
    const [stats, setStats] = useState<MonitorStats | null>(null);
    const [connectionStatus, setConnectionStatus] = useState<"disconnected" | "connecting" | "connected">("disconnected");
    const logContainerRef = useRef<HTMLDivElement>(null);
    const eventSourceRef = useRef<EventSource | null>(null);
    const startTimeRef = useRef<Date>(new Date());

    // 🔹 Update detector state and logs
    const updateDetectorState = (detectorName: string, status: DetectorStatus['status'], logLine: string) => {
        setDetectors((prev) => {
            const existingIndex = prev.findIndex((d) => d.name === detectorName);

            if (existingIndex === -1) {
                const newDetector: DetectorStatus = {
                    name: detectorName,
                    status,
                    logs: [logLine],
                    lastActivity: new Date(),
                    alertsGenerated: 0,
                };
                return [...prev, newDetector];
            }

            const updated = [...prev];
            updated[existingIndex] = {
                ...updated[existingIndex],
                status,
                logs: [...updated[existingIndex].logs, logLine],
                lastActivity: new Date(),
                alertsGenerated: logLine.includes("[ALERT]") || logLine.includes("[*] Alert saved:")
                    ? updated[existingIndex].alertsGenerated + 1
                    : updated[existingIndex].alertsGenerated,
            };
            return updated;
        });
    };

    // 🔹 Start monitoring
    const startMonitoring = () => {
        if (eventSourceRef.current) {
            eventSourceRef.current.close();
        }

        setIsMonitoring(true);
        setConnectionStatus("connecting");
        setDetectors([]);

        const eventSource = new EventSource("/api/scheduled_monitor");
        eventSourceRef.current = eventSource;

        eventSource.onopen = () => {
            setConnectionStatus("connected");
            console.log("Connected to scheduled monitor");
        };

        // 🔸 Handle main SSE messages
        eventSource.onmessage = (event) => {
            const data = event.data;
            try {
                const message = JSON.parse(data);
                if (message.detector && message.status && message.log) {
                    updateDetectorState(message.detector, message.status, message.log);
                    return;
                }
            } catch (e) {
                if (data.startsWith("RAW_LOG:")) {
                    const content = data.substring("RAW_LOG:".length);
                    const parts = content.split(":");
                    const detectorName = parts[0];
                    const logLine = parts.slice(1).join(":");
                    updateDetectorState(detectorName, "running", logLine);
                    return;
                }
            }
        };

        // 🔸 Listen for total alerts updates
        eventSource.addEventListener("total_alerts", (event) => {
            const newCount = parseInt(event.data);
            setStats((prev) =>
                prev
                    ? { ...prev, totalAlerts: newCount }
                    : {
                        totalDetectors: 3,
                        runningDetectors: 0,
                        totalAlerts: newCount,
                        systemUptime: startTimeRef.current,
                    }
            );
        });

        // 🔸 Heartbeat
        eventSource.addEventListener("heartbeat", (event) => {
            setStats((prev) => (prev ? { ...prev } : null));
        });

        // 🔸 Handle errors
        eventSource.onerror = (err) => {
            console.error("EventSource error:", err);
            setConnectionStatus("disconnected");
            setIsMonitoring(false);

            if (eventSource.readyState === EventSource.CLOSED) {
                updateDetectorState("System", "error", "Monitor connection closed. Check your login status.");
            } else {
                updateDetectorState("System", "error", "Connection error with monitor. Check server logs.");
            }
        };
    };

    // 🔹 Stop monitoring
    const stopMonitoring = () => {
        if (eventSourceRef.current) {
            eventSourceRef.current.close();
            eventSourceRef.current = null;
        }
        setIsMonitoring(false);
        setConnectionStatus("disconnected");
    };

    // 🔹 Update stats when detectors change
    useEffect(() => {
        const totalDetectors = detectors.length;
        const runningDetectors = detectors.filter((d) => d.status === "running").length;
        const totalAlerts = stats?.totalAlerts ?? detectors.reduce((sum, d) => sum + d.alertsGenerated, 0);

        setStats({
            totalDetectors,
            runningDetectors,
            totalAlerts,
            systemUptime: startTimeRef.current,
        });
    }, [detectors]);

    // 🔹 Auto-scroll effect
    useEffect(() => {
        logContainerRef.current?.scrollTo({
            top: logContainerRef.current.scrollHeight,
            behavior: "smooth",
        });
    }, [detectors]);

    // 🔹 Cleanup
    useEffect(() => {
        return () => {
            if (eventSourceRef.current) {
                eventSourceRef.current.close();
            }
        };
    }, []);

    // 🔹 Stats display
    const StatsDisplay = ({ stats }: { stats: MonitorStats }) => {
        const uptime = Math.floor((Date.now() - stats.systemUptime.getTime()) / 1000);
        const hours = Math.floor(uptime / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);

        return (
            <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
                    <div className="flex items-center gap-2">
                        <FiActivity className="w-5 h-5 text-blue-600" />
                        <span className="text-sm font-medium text-blue-800">Running Processes</span>
                    </div>
                    <div className="text-2xl font-bold text-blue-900">{stats.runningDetectors}/3</div>
                </div>

                <div className="bg-orange-50 p-4 rounded-lg border border-orange-200">
                    <div className="flex items-center gap-2">
                        <FiAlertTriangle className="w-5 h-5 text-orange-600" />
                        <span className="text-sm font-medium text-orange-800">Total Alerts</span>
                    </div>
                    <div className="text-2xl font-bold text-orange-900">{stats.totalAlerts}</div>
                </div>

                <div className="bg-green-50 p-4 rounded-lg border border-green-200">
                    <div className="flex items-center gap-2">
                        <FiCheckCircle className="w-5 h-5 text-green-600" />
                        <span className="text-sm font-medium text-green-800">System Status</span>
                    </div>
                    <div className="text-lg font-bold text-green-900">
                        {connectionStatus === "connected" ? "MONITORING" : connectionStatus.toUpperCase()}
                    </div>
                </div>

                <div className="bg-purple-50 p-4 rounded-lg border border-purple-200">
                    <div className="flex items-center gap-2">
                        <FiClock className="w-5 h-5 text-purple-600" />
                        <span className="text-sm font-medium text-purple-800">Uptime</span>
                    </div>
                    <div className="text-lg font-bold text-purple-900">
                        {hours}h {minutes}m
                    </div>
                </div>
            </div>
        );
    };

    return (
        <Layout>
            <div className="flex bg-gray-50 min-h-screen pt-16">
                <Sidebar />
                <main className="flex-1 ml-60 px-8 py-6">
                    <div className="flex items-center justify-between mb-8">
                        <div>
                            <h1 className="text-4xl font-extrabold text-gray-900 flex items-center gap-3">
                                <FiActivity className="text-blue-600 w-8 h-8" />
                                Scheduled Detection Monitor
                            </h1>
                            <p className="text-gray-600 mt-2">
                                Monitor running status and live alert count of detection processes.
                            </p>
                        </div>

                        <div className="flex gap-3">
                            {!isMonitoring ? (
                                <button
                                    onClick={startMonitoring}
                                    className="bg-gradient-to-r from-blue-500 to-green-500 hover:from-blue-600 hover:to-green-600 text-white px-6 py-3 rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-xl flex items-center gap-2"
                                >
                                    <FiPlay className="w-5 h-5" />
                                    Start Monitoring
                                </button>
                            ) : (
                                <button
                                    onClick={stopMonitoring}
                                    className="bg-gradient-to-r from-red-500 to-orange-500 hover:from-red-600 hover:to-orange-600 text-white px-6 py-3 rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-xl flex items-center gap-2"
                                >
                                    <FiPause className="w-5 h-5" />
                                    Stop Monitoring
                                </button>
                            )}

                            <button
                                onClick={() => {
                                    stopMonitoring();
                                    setTimeout(startMonitoring, 100);
                                }}
                                className="bg-gray-500 hover:bg-gray-600 text-white px-6 py-3 rounded-xl font-bold transition-all duration-300 shadow-lg hover:shadow-xl flex items-center gap-2"
                            >
                                <FiRefreshCw className="w-5 h-5" />
                                Refresh
                            </button>
                        </div>
                    </div>

                    {stats && <StatsDisplay stats={stats} />}

                    <div
                        className="max-w-6xl mx-auto bg-white p-6 rounded-3xl shadow-2xl border border-gray-100"
                    >
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-xl font-bold text-gray-800 flex items-center gap-2">
                                <FiTerminal className="w-5 h-5 text-gray-600" />
                                Live Detection Logs
                            </h2>
                            <div
                                className={`px-3 py-1 rounded-full text-sm font-medium ${
                                    connectionStatus === "connected"
                                        ? "bg-green-100 text-green-800"
                                        : connectionStatus === "connecting"
                                        ? "bg-yellow-100 text-yellow-800"
                                        : "bg-red-100 text-red-800"
                                }`}
                            >
                                {connectionStatus === "connected" && "🟢 Connected"}
                                {connectionStatus === "connecting" && "🟡 Connecting..."}
                                {connectionStatus === "disconnected" && "🔴 Disconnected"}
                            </div>
                        </div>

                        <div
                            className="flex flex-col gap-0 border rounded-lg bg-gray-100 p-3 shadow-inner"
                            ref={logContainerRef}
                            style={{ maxHeight: 500, overflowY: "auto" }}
                        >
                            {detectors.length === 0 && (
                                <p className="text-gray-500 p-4 font-light italic">
                                    Click "Start Monitoring" to begin tracking the detection processes...
                                </p>
                            )}

                            {detectors.map((det, idx) => {
                                const isRunning = det.status === "running";
                                const isError = det.status === "error";
                                const isStarting = det.status === "starting";
                                const isStopped = det.status === "stopped";

                                const blockClasses = `p-3 rounded-md transition-all duration-300 my-1 ${
                                    isRunning
                                        ? "bg-green-100 border-l-4 border-green-500 shadow-md"
                                        : isError
                                        ? "bg-red-100 border-l-4 border-red-500"
                                        : isStarting
                                        ? "bg-yellow-100 border-l-4 border-yellow-500"
                                        : isStopped
                                        ? "bg-gray-100 border-l-4 border-gray-500"
                                        : "bg-white border border-gray-200"
                                }`;

                                return (
                                    <div key={idx} className={blockClasses}>
                                        <div className="flex items-start gap-3">
                                            <div className="w-5 pt-1 flex-shrink-0">
                                                {isRunning && <FiActivity className="animate-pulse text-green-600 w-5 h-5" />}
                                                {isStarting && <FiLoader className="animate-spin text-yellow-600 w-5 h-5" />}
                                                {isStopped && <FiPause className="text-gray-600 w-5 h-5" />}
                                                {isError && <FiAlertTriangle className="text-red-600 w-5 h-5" />}
                                            </div>

                                            <div className="flex-1 min-w-0">
                                                <div className="flex items-center justify-between">
                                                    <p
                                                        className={`truncate font-bold text-sm ${
                                                            isRunning
                                                                ? "text-green-900"
                                                                : isError
                                                                ? "text-red-900"
                                                                : isStarting
                                                                ? "text-yellow-900"
                                                                : "text-gray-900"
                                                        }`}
                                                    >
                                                        {det.name}
                                                    </p>
                                                    <div className="flex gap-2 text-xs">
                                                        <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded">
                                                            {det.alertsGenerated} alerts
                                                        </span>
                                                        <span className="bg-gray-100 text-gray-600 px-2 py-1 rounded">
                                                            {det.lastActivity.toLocaleTimeString()}
                                                        </span>
                                                    </div>
                                                </div>

                                                {det.logs.length > 0 && (
                                                    <div className="mt-1 space-y-0.5 border-t pt-1 border-dotted border-gray-300">
                                                        {det.logs.slice(-10).map((log, i) => (
                                                            <p
                                                                key={i}
                                                                className={`text-xs pl-2 break-words font-mono ${
                                                                    log.includes("[ERROR]") ||
                                                                    log.includes("❌") ||
                                                                    log.includes("failed")
                                                                        ? "text-red-600 font-semibold"
                                                                        : log.includes("[ALERT]") ||
                                                                          log.includes("[*] Alert saved:")
                                                                        ? "text-orange-600 font-semibold"
                                                                        : log.includes("[WARNING]")
                                                                        ? "text-yellow-600 font-medium"
                                                                        : isRunning
                                                                        ? "text-gray-700"
                                                                        : "text-gray-500"
                                                                }`}
                                                            >
                                                                {log.startsWith("🔹") ||
                                                                log.startsWith("✅") ||
                                                                log.startsWith("🚀") ||
                                                                log.startsWith("⚠️") ||
                                                                log.startsWith("❌")
                                                                    ? log
                                                                    : `> ${log}`}
                                                            </p>
                                                        ))}
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>
                </main>
            </div>
        </Layout>
    );
}
