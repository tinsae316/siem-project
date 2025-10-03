// pages/api/trigger_full_scan.ts
import type { NextApiRequest, NextApiResponse } from "next";
import { exec } from "child_process";
import path from "path";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    const scriptPath = path.join(process.cwd(), "..", "detection", "Hard_Bruteforce_Detection.py");
    const cmd = `python3 ${scriptPath} --full-scan`;

    exec(cmd, { maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) {
        // return stderr when available (more helpful)
        return res.status(500).json({ error: stderr || error.message });
      }
      return res.status(200).json({ message: "Full scan triggered", output: stdout });
    });
  } catch (err) {
    res.status(500).json({ error: String(err) });
  }
}
