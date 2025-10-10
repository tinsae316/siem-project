// pages/api/trigger_full_scan.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { spawn } from "child_process";
import path from "path";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    // Define all detectors
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

    // Go one level up to reach project root (since this file is in dashboard/pages/api)
    const projectRoot = path.join(process.cwd(), "..");
    const detectionDir = path.join(projectRoot, "detection");

    // Set environment variables
    const env = {
      ...process.env,
      PYTHONPATH: projectRoot,
      DATABASE_URL: process.env.DATABASE_URL || "",
      GEOIP_DB_PATH: process.env.GEOIP_DB_PATH || "",
    };

    console.log("🚀 Starting FULL SCAN of all detectors...");

    // Run each detector one by one
    for (const detector of detectors) {
      const scriptPath = path.join(detectionDir, detector);

      console.log(`\n🚀 Running detector: ${detector}`);
      console.log(`[${new Date().toISOString()}] Starting FULL scan...`);

      // Spawn the Python process
      const child = spawn("python3", [scriptPath, "--full-scan"], {
        env,
        cwd: detectionDir,
      });

      // Stream output to the terminal (Next.js console)
      child.stdout.on("data", (data) => {
        process.stdout.write(data.toString());
      });

      child.stderr.on("data", (data) => {
        process.stderr.write(data.toString());
      });

      // Wait for process to finish
      await new Promise((resolve) => {
        child.on("close", (code) => {
          console.log(`✅ ${detector} finished with exit code ${code}`);
          resolve(true);
        });
      });
    }

    console.log("\n🎯 All detectors completed successfully.\n");

    // Send short response to frontend
    res.status(200).send("✅ Full scan completed. Check server terminal for logs.");
  } catch (err: any) {
    console.error("❌ Full scan error:", err);
    res.status(500).send(`❌ Internal server error: ${err.message}`);
  }
}
