// pages/api/auth/logout.ts
import type { NextApiRequest, NextApiResponse } from "next";
import * as cookie from "cookie";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  res.setHeader(
    "Set-Cookie",
    cookie.serialize("token", "", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      expires: new Date(0),
      path: "/",
    })
  );

  return res.status(200).json({ message: "Logged out" });
}
