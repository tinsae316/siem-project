// pages/api/live_alert.ts
// Next.js API endpoint for streaming and broadcasting security alerts in real time using SSE.

import type { NextApiRequest, NextApiResponse } from "next";

// List of active SSE clients
let clients: NextApiResponse[] = [];

export const config = {
  api: {
    bodyParser: false, // Disable default body parsing for streaming
  },
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === "GET") {
    // --- Client subscribes to live alerts ---
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
    });

    // Register the client connection
    clients.push(res);
    console.log(`[+] Client connected: ${clients.length} total`);

    // Send keep-alive comments every 20 seconds
    const keepAlive = setInterval(() => {
      res.write(`: keep-alive\n\n`);
    }, 20000);

    // Cleanup when client disconnects
    req.on("close", () => {
      clearInterval(keepAlive);
      clients = clients.filter((c) => c !== res);
      console.log(`[-] Client disconnected: ${clients.length} remaining`);
    });

    return;
  }

  if (req.method === "POST") {
    // --- Backend detection sends a new alert ---
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });

    req.on("end", () => {
      try {
        const alert = JSON.parse(body);

        console.log(`[ALERT RECEIVED] ${alert.rule || "Unknown Rule"} from ${alert["source.ip"] || "Unknown IP"}`);

        // Broadcast to all connected clients
        clients.forEach((client) => {
          client.write(`data: ${JSON.stringify(alert)}\n\n`);
        });

        res.status(200).json({ success: true, message: "Alert broadcasted" });
      } catch (err) {
        console.error("Error parsing or broadcasting alert:", err);
        res.status(400).json({ success: false, error: "Invalid JSON format" });
      }
    });

    return;
  }

  // Unsupported methods
  res.setHeader("Allow", ["GET", "POST"]);
  res.status(405).end(`Method ${req.method} Not Allowed`);
}
