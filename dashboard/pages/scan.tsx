"use client";

import { GetServerSideProps } from "next"; // Import for server-side protection
import * as cookie from "cookie"; // Import for cookie parsing
import { verifyToken } from "../lib/auth"; // Import your auth verification function
import { useState, useEffect, useRef, useMemo } from "react";
import Layout from "../components/Layout";
import Sidebar from "../components/Sidebar";
import { FiCpu, FiLoader, FiCheckCircle, FiAlertTriangle, FiZap, FiTerminal, FiBarChart2, FiShieldOff, FiSearch, FiCode } from "react-icons/fi"; // Added FiSearch, FiCode

// --- SERVER-SIDE AUTH PROTECTION ---
export const getServerSideProps: GetServerSideProps = async (ctx) => {
    const cookies = ctx.req.headers.cookie || "";
    const { token } = cookie.parse(cookies);

    // If no token, or token is invalid, redirect to login
    if (!token) {
        return { redirect: { destination: "/login", permanent: false } };
    }

    try {
        verifyToken(token); // Validate the token
        // If valid, continue to render the page
    } catch {
        // Invalid token: redirect to login
        return { redirect: { destination: "/login", permanent: false } };
    }

    return { props: {} };
};
// --- END SERVER-SIDE AUTH PROTECTION ---


interface DetectorLog {
    name: string;
    status: "pending" | "running" | "done" | "error";
    logs: string[];
}

interface ScanReport {
    totalDetectors: number;
    completed: number;
    alertsDetected: number;
    errorsEncountered: number;
}

export default function ScanPage() {
    const [detectors, setDetectors] = useState<DetectorLog[]>([]);
    const [isScanning, setIsScanning] = useState(false);
    const [scanComplete, setScanComplete] = useState(false);
    const [report, setReport] = useState<ScanReport | null>(null);
    const logContainerRef = useRef<HTMLDivElement>(null);

    // Helper function to update detector state and logs (Logic remains the same)
    const updateDetectorState = (detectorName: string, status: DetectorLog['status'], logLine: string) => {
        setDetectors((prev) => {
            const isExisting = prev.some((d) => d.name === detectorName);

            if (!isExisting) {
                if (detectorName === "System" && status === "error") {
                    return [...prev, { name: "System Scan", status: "error", logs: [logLine] }];
                }
                return [...prev, { name: detectorName, status: status, logs: [logLine] }];
            }

            return prev.map((d) =>
                d.name === detectorName
                    ? {
                        ...d,
                        status: status === "running" || status === "done" || status === "error" ? status : d.status,
                        logs: [...d.logs, logLine],
                    }
                    : d
            );
        });
    };

    // --- Scan Logic (Unchanged, uses the robust SSE handling) ---
    const startScan = () => {
        // Reset all states
        setDetectors([]);
        setIsScanning(true);
        setScanComplete(false);
        setReport(null); 

        const eventSource = new EventSource("/api/trigger_full_scan");

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
                
                if (data.startsWith("RAW_LOG_ERROR:")) {
                    const content = data.substring("RAW_LOG_ERROR:".length);
                    const parts = content.split(":");
                    const detectorName = parts[0];
                    const logLine = `[ERROR] ${parts.slice(1).join(":")}`;
                    updateDetectorState(detectorName, "running", logLine);
                    return;
                }
            }
        };

        eventSource.addEventListener("done", () => {
            setIsScanning(false);
            setScanComplete(true);
            eventSource.close();
        });

        eventSource.onerror = (err) => {
            // Check for unauthenticated errors
            if (eventSource.readyState === EventSource.CLOSED) {
                // If EventSource closes immediately, the API likely returned an error status (like 401/403)
                // We'll trust the API side handled the 401 response, but we should stop the scan.
                setIsScanning(false);
                updateDetectorState("System", "error", "Scan API connection closed. Check your login status.");
            } else {
                setIsScanning(false);
                updateDetectorState("System", "error", "Connection error with scan API. Check server logs.");
            }
            eventSource.close();
        };
    };

    // --- Report Generation Logic ---
    useEffect(() => {
        if (scanComplete) {
            const totalDetectors = detectors.length;
            const completed = detectors.filter(d => d.status === 'done').length;
            const errorsEncountered = detectors.filter(d => d.status === 'error').length;
            
            let alertsDetected = 0;
            detectors.forEach(d => {
                alertsDetected += d.logs.filter(log => 
                    !log.startsWith('🔹') && !log.startsWith('✅') && !log.includes('[ERROR]')
                ).length;
            });

            setReport({
                totalDetectors,
                completed,
                alertsDetected,
                errorsEncountered,
            });
        }
    }, [scanComplete, detectors]);


    // Auto-scroll effect
    useEffect(() => {
        logContainerRef.current?.scrollTo({
            top: logContainerRef.current.scrollHeight,
            behavior: "smooth",
        });
    }, [detectors]);


    // --- Report Display Component ---
    const ScanReportDisplay = ({ report }: { report: ScanReport }) => {
        const isClean = report.alertsDetected === 0 && report.errorsEncountered === 0;
    
        return (
            <div className="mt-4 p-6 bg-white border border-gray-200 rounded-xl shadow-lg">
                <h3 className="text-xl font-bold mb-4 flex items-center gap-2 text-gray-800 border-b pb-2">
                    <FiBarChart2 className="w-5 h-5 text-orange-500" />
                    Scan Summary Report
                </h3>
    
                <div className="grid grid-cols-2 gap-4 text-center">
                    {/* Total Detectors */}
                    <ReportCard 
                        label="Total Modules Run" 
                        value={report.totalDetectors} 
                        icon={FiCpu} 
                        color="text-indigo-500"
                        bgColor="bg-indigo-50"
                    />
                    
                    {/* Alerts Detected */}
                    <ReportCard 
                        label="Threat Alerts Detected" 
                        value={report.alertsDetected} 
                        icon={report.alertsDetected > 0 ? FiAlertTriangle : FiShieldOff} 
                        color={report.alertsDetected > 0 ? "text-red-600" : "text-green-600"}
                        bgColor={report.alertsDetected > 0 ? "bg-red-50" : "bg-green-50"}
                    />
                    
                    {/* Errors */}
                    <ReportCard 
                        label="Modules with Errors" 
                        value={report.errorsEncountered} 
                        icon={FiAlertTriangle} 
                        color={report.errorsEncountered > 0 ? "text-yellow-600" : "text-gray-500"}
                        bgColor={report.errorsEncountered > 0 ? "bg-yellow-50" : "bg-gray-50"}
                    />
                    
                    {/* Status Message */}
                    <ReportCard 
                        label="Final Status" 
                        value={isClean ? "CLEAN" : "ALERTS FOUND"} 
                        icon={isClean ? FiCheckCircle : FiAlertTriangle} 
                        color={isClean ? "text-green-600" : "text-red-600"}
                        bgColor={isClean ? "bg-green-50" : "bg-red-50"}
                        isTextValue={true}
                    />
                </div>
                
                <p className="mt-6 text-sm text-gray-500 italic">
                    {isClean 
                        ? "The system finished the scan without detecting any immediate threats or errors."
                        : "Review the console output above for details on the detected threats and module errors."
                    }
                </p>
            </div>
        );
    };
    
    // Small reusable component for the report cards
    const ReportCard = ({ label, value, icon: Icon, color, bgColor, isTextValue = false }: any) => (
        <div className={`p-4 rounded-lg flex flex-col items-center justify-center ${bgColor}`}>
            <div className={`p-2 rounded-full ${color} mb-2`}>
                <Icon className="w-5 h-5" />
            </div>
            <p className="text-xs font-medium text-gray-600 uppercase mb-1">{label}</p>
            <p className={`text-2xl font-extrabold ${color}`}>
                {isTextValue ? value : value.toString()}
            </p>
        </div>
    );

    // --- Main Render ---
    return (
        <Layout>
            <div className="flex bg-gray-50 min-h-screen pt-16">
                <Sidebar />
                <main className="flex-1 ml-60 px-8 py-6">
                    <h1 className="text-4xl font-extrabold text-gray-900 mb-8 flex items-center gap-3">
                        <FiCpu className="text-orange-600 w-8 h-8" /> Full System Scan
                    </h1>

                    <div className="max-w-4xl mx-auto bg-white p-10 rounded-3xl shadow-2xl border border-gray-100 flex flex-col gap-8">

                        {/* 2. LOG CONSOLE (Modern Light Theme) */}
                        {/* The Live Log Output Area */}
                        <div 
                            className="flex flex-col gap-0 border rounded-lg bg-gray-100 p-3 shadow-inner" 
                            ref={logContainerRef} 
                            style={{ maxHeight: 400, overflowY: "auto" }}
                        >
                            {detectors.length === 0 && (
                                <p className="text-gray-500 p-4 font-light italic">
                                    Click "Start Scan" to begin the live threat detection process...
                                </p>
                            )}

                            {detectors.map((det, idx) => {
                                const isRunning = det.status === 'running';
                                const isError = det.status === 'error';
                                
                                const blockClasses = `p-3 rounded-md transition-all duration-300 my-1 ${
                                    isRunning 
                                        ? 'bg-orange-100 border-l-4 border-orange-500 shadow-md' 
                                        : isError 
                                        ? 'bg-red-100 border-l-4 border-red-500'
                                        : 'bg-white border border-gray-200'
                                }`;

                                return (
                                    <div 
                                        key={idx} 
                                        className={blockClasses}
                                    >
                                        <div className="flex items-start gap-3">
                                            
                                            {/* Status Icon */}
                                            <div className="w-5 pt-1 flex-shrink-0">
                                                {isRunning && <FiLoader className="animate-spin text-orange-600 w-5 h-5" />}
                                                {det.status === "done" && <FiCheckCircle className="text-green-600 w-5 h-5" />}
                                                {isError && <FiAlertTriangle className="text-red-600 w-5 h-5" />}
                                                {det.status === "pending" && <FiZap className="text-gray-400 w-5 h-5" />}
                                            </div>

                                            <div className="flex-1 min-w-0">
                                                {/* Detector Name */}
                                                <p className={`truncate font-bold text-sm ${isRunning ? 'text-orange-900' : isError ? 'text-red-900' : 'text-gray-900'}`}>
                                                    {det.name}
                                                </p>
                                                
                                                {/* Live Logs - This section now renders the lines */}
                                                {det.logs.length > 0 && (
                                                    <div className="mt-1 space-y-0.5 border-t pt-1 border-dotted border-gray-300">
                                                        {det.logs.map((log, i) => (
                                                            <p 
                                                                key={i} 
                                                                className={`text-xs pl-2 break-words font-mono ${
                                                                    log.includes("[ERROR]") || log.includes("❌") || log.includes("failed")
                                                                        ? 'text-red-600 font-semibold' 
                                                                        : isRunning 
                                                                        ? 'text-gray-700'
                                                                        : 'text-gray-500'
                                                                }`}
                                                            >
                                                                {/* Use '>' prefix for raw logs to look like terminal output */}
                                                                {log.startsWith("🔹") || log.startsWith("✅") ? log : `> ${log}`}
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
                        
                        {/* 3. REPORT SUMMARY (Conditionally shown AFTER scan and log console) */}
                        {scanComplete && report && <ScanReportDisplay report={report} />}
                        {/* 1. START/STOP BUTTON (Prominent & at the Top) */}
                        <button
                            onClick={startScan}
                            disabled={isScanning}
                            className="w-full bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white px-10 py-4 rounded-xl font-bold text-xl transition-all duration-300 disabled:opacity-60 disabled:from-gray-400 disabled:to-gray-500 shadow-lg hover:shadow-xl flex items-center gap-3 justify-center transform hover:-translate-y-0.5"
                        >
                            {isScanning ? (
                                <>
                                    <FiLoader className="animate-spin w-6 h-6" /> Active Threat Detection...
                                </>
                            ) : (
                                "Initiate Full System Scan"
                            )}
                        </button>

                    </div>
                </main>
            </div>
        </Layout>
    );
}