import { NextApiRequest, NextApiResponse } from "next";
import { PrismaClient } from "../../lib/generated/prisma";

import OpenAI from "openai"; // or use your own local model API

const prisma = new PrismaClient();
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ message: "Method not allowed" });
  }

  const { message } = req.body;

  // Fetch recent alerts from database
  const alerts = await prisma.alerts.findMany({
    orderBy: { timestamp: "desc" },
    take: 10,
  });

const alertSummary = alerts
  .map(a => 
    `Alert #${a.id}: Rule=${a.rule ?? "N/A"}, User=${a.user_name ?? "N/A"}, Source=${a.source_ip ?? "N/A"}, Technique=${a.technique ?? "N/A"}, Severity=${a.severity ?? "N/A"}`
  )
  .join("\n");


  // Combine user message + alert context
  const prompt = `
You are a cybersecurity assistant for a SIEM dashboard.
You can answer questions about alerts or generate reports.
Here are recent alerts:
${alertSummary}

User: ${message}
Answer clearly and concisely.
`;

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini", // or any available model
      messages: [{ role: "user", content: prompt }],
    });

    const reply = completion.choices[0].message?.content || "I could not generate a response.";
    res.status(200).json({ reply });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error generating response." });
  }
}
