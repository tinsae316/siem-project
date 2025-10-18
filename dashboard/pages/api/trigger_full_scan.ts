<<<<<<< HEAD
=======
// pages/api/trigger_full_scan.ts
>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
import { NextApiRequest, NextApiResponse } from "next";
import { spawn } from "child_process";
import path from "path";
import * as cookie from "cookie";
<<<<<<< HEAD
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

=======
import { verifyToken } from "../../lib/auth"; // Import your token verification function

// Define a type for the response with a potential flush method
type SSEApiResponse = NextApiResponse & { flush?: () => void };

>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
export default async function handler(req: NextApiRequest, res: SSEApiResponse) {
    if (req.method !== "GET") {
        return res.status(405).json({ error: "Method not allowed" });
    }

<<<<<<< HEAD
    // 🧩 AUTH CHECK
=======
    // 🛑 AUTHENTICATION CHECK 🛑
>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
    const cookies = req.headers.cookie || "";
    const { token } = cookie.parse(cookies);

    if (!token) {
        return res.status(401).json({ error: "Unauthorized: No token provided." });
    }

    try {
<<<<<<< HEAD
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
=======
        verifyToken(token); // Throws an error if the token is invalid or expired
    } catch (e) {
        // Log error for server-side debugging
        console.error("Token verification failed:", e); 
        // Send a 403 Forbidden or 401 Unauthorized response
        return res.status(401).json({ error: "Unauthorized: Invalid or expired token." });
    }
    // 🛑 END AUTHENTICATION CHECK 🛑

    // Set headers for SSE
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    // NOTE: This line is crucial for preventing proxies/load balancers from buffering.
    res.setHeader("X-Accel-Buffering", "no"); 
    
    // Cast res.write for convenience and implement the flushing logic
    const writeAndFlush = (data: string) => {
        res.write(data);
        // Attempt to force flush the response stream if the method is available (common in Node environments)
        if (typeof res.flush === 'function') {
            res.flush();
        }
    };

    const detectors = [
        // ... (detectors array unchanged)
>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
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
<<<<<<< HEAD
        // ⚡ Run all detectors in parallel
        await Promise.all(detectors.map((detector) => runDetector(detector, detectionDir, env, writeAndFlush)));

        // All finished
        writeAndFlush(`event: done\ndata: scan finished\n\n`);
        res.end();
    } catch (err: any) {
=======
        for (const detector of detectors) {
            const scriptPath = path.join(detectionDir, detector);

            // 1. Send Structured JSON message: START
            const startMessage = {
                detector: detector,
                status: "running",
                log: `🔹 ${detector} started`,
            };
            writeAndFlush(`data: ${JSON.stringify(startMessage)}\n\n`);

            // NOTE: Using 'stdio: [pipe, pipe, pipe]' may also help with buffering.
            const child = spawn("python3", [scriptPath, "--full-scan"], { 
                cwd: detectionDir, 
                env, 
                stdio: ['pipe', 'pipe', 'pipe'] // Explicitly use pipes
            });

            // 2. Stream stdout (Prefixed raw log)
            child.stdout.on("data", (data) => {
                data.toString()
                    .split("\n")
                    .forEach((line: string) => {
                        if (line.trim()) {
                            writeAndFlush(`data: RAW_LOG:${detector}:${line.trim()}\n\n`);
                        }
                    });
            });

            // 3. Stream stderr (Prefixed raw error log) - UPDATED
            child.stderr.on("data", (data) => {
                data.toString()
                    .split("\n")
                    .forEach((line: string) => {
                        if (line.trim()) {
                            // Python often sends logs/warnings to stderr. Changed prefix to WARNING.
                            writeAndFlush(`data: RAW_LOG_WARNING:${detector}:${line.trim()}\n\n`);
                        }
                    });
            });

            // Wait for child process to finish
            await new Promise((resolve) => child.on("close", resolve));

            // 4. Send Structured JSON message: DONE
            const finishMessage = {
                detector: detector,
                status: "done",
                log: `✅ ${detector} done`,
            };
            writeAndFlush(`data: ${JSON.stringify(finishMessage)}\n\n`);
        }

        // Signal frontend that scan is fully done
        writeAndFlush(`event: done\ndata: scan finished\n\n`);
        res.end();
    } catch (err: any) {
        // Send a system error message
>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
        const errorMessage = {
            detector: "System",
            status: "error",
            log: `❌ Scan failed: ${err.message}`,
        };
        writeAndFlush(`data: ${JSON.stringify(errorMessage)}\n\n`);
        res.end();
    }
<<<<<<< HEAD
}
=======
}
>>>>>>> 0f9b2beb050010e2dcaa397886dbb1ae9b40d643
