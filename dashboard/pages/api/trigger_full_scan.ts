import { NextApiRequest, NextApiResponse } from "next";
import { spawn } from "child_process";
import path from "path";
import * as cookie from "cookie";
import { verifyToken } from "../../lib/auth";

type SSEApiResponse = NextApiResponse & { flush?: () => void };

// Helper: run one detector script
async function runDetector(detector: string, detectionDir: string, env: any, writeAndFlush: (data: string) => void) {
    return new Promise<void>((resolve) => {
        const scriptPath = path.join(detectionDir, detector);

        // Send start message
        const startMessage = {
            detector,
            status: "running",
            log: `🔹 ${detector} started`,
        };
        writeAndFlush(`data: ${JSON.stringify(startMessage)}\n\n`);

        const child = spawn("python3", [scriptPath, "--full-scan"], {
            cwd: detectionDir,
            env,
            stdio: ["pipe", "pipe", "pipe"],
        });

        // Stream stdout
        child.stdout.on("data", (data) => {
            data.toString()
                .split("\n")
                .forEach((line: string) => {
                    if (line.trim()) {
                        writeAndFlush(`data: RAW_LOG:${detector}:${line.trim()}\n\n`);
                    }
                });
        });

        // Stream stderr
        child.stderr.on("data", (data) => {
            data.toString()
                .split("\n")
                .forEach((line: string) => {
                    if (line.trim()) {
                        writeAndFlush(`data: RAW_LOG_WARNING:${detector}:${line.trim()}\n\n`);
                    }
                });
        });

        // On exit
        child.on("close", () => {
            const finishMessage = {
                detector,
                status: "done",
                log: `✅ ${detector} done`,
            };
            writeAndFlush(`data: ${JSON.stringify(finishMessage)}\n\n`);
            resolve();
        });
    });
}

export default async function handler(req: NextApiRequest, res: SSEApiResponse) {
    if (req.method !== "GET") {
        return res.status(405).json({ error: "Method not allowed" });
    }

    // 🧩 AUTH CHECK
    const cookies = req.headers.cookie || "";
    const { token } = cookie.parse(cookies);

    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided." });
    }

    try {
        verifyToken(token);
    } catch (e) {
        console.error("Token verification failed:", e);
        return res.status(401).json({ error: "Unauthorized: Invalid or expired token." });
    }

    // SSE headers
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
        "Firewall_Denied_Access.py",
        "Firewall_Allowed_Suddenly_Blocked.py",
        "Hard_Endpoint_Scan_Detection.py",
        "Hard_Suspicious_Admin.py",
        "Hard_SQL_Injection.py",
        "Hard_XSS_Detection.py",
        "Port_Scanning_Detection.py",
        "Suspicious_File_Activity.py",
        "Suspicious_Protocol_Misuse.py",
        "DoS_DDoS_Detection.py",
    ];

    const projectRoot = path.join(process.cwd(), "..");
    const detectionDir = path.join(projectRoot, "detection");

    const env = {
        ...process.env,
        PYTHONPATH: projectRoot,
        DATABASE_URL: process.env.DATABASE_URL || "",
        GEOIP_DB_PATH: process.env.GEOIP_DB_PATH || "",
    };

    try {
        // ⚡ Run all detectors in parallel
        await Promise.all(detectors.map((detector) => runDetector(detector, detectionDir, env, writeAndFlush)));

        // All finished
        writeAndFlush(`event: done\ndata: scan finished\n\n`);
        res.end();
    } catch (err: any) {
        const errorMessage = {
            detector: "System",
            status: "error",
            log: `❌ Scan failed: ${err.message}`,
        };
        writeAndFlush(`data: ${JSON.stringify(errorMessage)}\n\n`);
        res.end();
    }
}
