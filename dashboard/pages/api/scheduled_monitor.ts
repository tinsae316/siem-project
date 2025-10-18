import { NextApiRequest, NextApiResponse } from "next";
import { exec } from "child_process";
import fs from "fs";
import path from "path";
import * as cookie from "cookie";
import { verifyToken } from "../../lib/auth";

type SSEApiResponse = NextApiResponse & { flush?: () => void };

// Path to alert log file (adjust if different)
const ALERT_LOG_PATH = path.join(process.cwd(), "collector", "alerts.log");

export default async function handler(req: NextApiRequest, res: SSEApiResponse) {
    if (req.method !== "GET") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    // 🧩 AUTHENTICATION CHECK
    const cookies = req.headers.cookie || "";
    const { token } = cookie.parse(cookies);
    if (!token) return res.status(401).json({ error: "Unauthorized: No token provided." });

    try {
        verifyToken(token);
    } catch (e) {
        console.error("Token verification failed:", e);
        return res.status(401).json({ error: "Unauthorized: Invalid or expired token." });
    }

    // 🔌 SSE headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");

    const writeAndFlush = (data: string) => {
        res.write(data);
        if (typeof res.flush === "function") res.flush();
    };

    const detectors = [
        "Hard_Bruteforce_Detection.py",
        "Hard_SQL_Injection.py",
        "Hard_XSS_Detection.py",
<<<<<<< HEAD
        "Port_Scanning_Detection.py",
        "Suspicious_File_Activity.py",
        "Suspicious_Protocol_Misuse.py",
        "Hard_Suspicious_Admin.py",
        "Firewall_Denied_Access.py",
        "Firewall_Allowed_Suddenly_Blocked.py",
        "DoS_DDoS_Detection.py",
        "Hard_Endpoint_Scan_Detection.py",
=======
>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
    ];

    try {
        // Initial process check
        const runningProcesses = await checkRunningProcesses(detectors);

        for (const detector of detectors) {
            const isRunning = runningProcesses.includes(detector);
            const statusMessage = {
                detector,
                status: isRunning ? "running" : "stopped",
                log: isRunning
                    ? `✅ ${detector} is running (scheduled mode)`
                    : `❌ ${detector} is not running`,
            };
            writeAndFlush(`data: ${JSON.stringify(statusMessage)}\n\n`);
        }

        writeAndFlush(`event: status\ndata: Monitoring ${runningProcesses.length} running detection processes\n\n`);

        // Send initial total alerts count
        const initialCount = await getTotalAlertsCount();
        writeAndFlush(`event: total_alerts\ndata: ${initialCount}\n\n`);

        // 🫀 Heartbeat
        const heartbeat = setInterval(() => {
            writeAndFlush(`event: heartbeat\ndata: ${new Date().toISOString()}\n\n`);
        }, 30000);

        // 🧠 Monitor process status every 10 seconds
        let lastRunning = runningProcesses;
        const statusCheck = setInterval(async () => {
            const current = await checkRunningProcesses(detectors);
            for (const detector of detectors) {
                const wasRunning = lastRunning.includes(detector);
                const isRunning = current.includes(detector);
                if (wasRunning && !isRunning) {
                    writeAndFlush(`data: ${JSON.stringify({
                        detector,
                        status: "stopped",
                        log: `⚠️ ${detector} stopped unexpectedly`,
                    })}\n\n`);
                } else if (!wasRunning && isRunning) {
                    writeAndFlush(`data: ${JSON.stringify({
                        detector,
                        status: "running",
                        log: `✅ ${detector} started`,
                    })}\n\n`);
                }
            }
            lastRunning = current;
        }, 10000);

        // 📊 Send total alerts count every 10s
        let lastAlertCount = initialCount;
        const alertPoll = setInterval(async () => {
            const currentCount = await getTotalAlertsCount();
            if (currentCount !== lastAlertCount) {
                lastAlertCount = currentCount;
                writeAndFlush(`event: total_alerts\ndata: ${currentCount}\n\n`);
            }
        }, 10000);

        // 🔚 Handle client disconnect
        req.on("close", () => {
            clearInterval(heartbeat);
            clearInterval(statusCheck);
            clearInterval(alertPoll);
            console.log("Client disconnected from scheduled monitor");
        });

        await new Promise(() => {}); // keep connection open

    } catch (err: any) {
        writeAndFlush(`data: ${JSON.stringify({
            detector: "System",
            status: "error",
            log: `❌ Monitor failed: ${err.message}`,
        })}\n\n`);
        res.end();
    }
}

// ✅ Check which detection processes are running
async function checkRunningProcesses(detectors: string[]): Promise<string[]> {
    return new Promise((resolve) => {
        const running: string[] = [];
        let done = 0;
        for (const d of detectors) {
            exec(`pgrep -f "${d}"`, (err, stdout) => {
                if (!err && stdout.trim()) running.push(d);
                done++;
                if (done === detectors.length) resolve(running);
            });
        }
    });
}

// ✅ Count total alerts from alert log file
async function getTotalAlertsCount(): Promise<number> {
    try {
        if (!fs.existsSync(ALERT_LOG_PATH)) return 0;
        const data = await fs.promises.readFile(ALERT_LOG_PATH, "utf-8");
        const lines = data.split("\n").filter(l => l.trim());
        return lines.length;
    } catch (e) {
        console.error("Error reading alert log:", e);
        return 0;
    }
}
