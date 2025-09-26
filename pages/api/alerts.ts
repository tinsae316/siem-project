import type { NextApiRequest, NextApiResponse } from "next";
import prisma from "../../lib/prisma";

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  try {
    const { startDate, endDate } = req.query;

    const alerts = await prisma.alerts.findMany({
      where: {
        timestamp: {
          gte: startDate ? new Date(startDate as string) : undefined,
          lte: endDate ? new Date(endDate as string) : undefined,
        },
      },
      orderBy: { timestamp: "desc" },
    });

    res.status(200).json(alerts);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch alerts" });
  }
}
