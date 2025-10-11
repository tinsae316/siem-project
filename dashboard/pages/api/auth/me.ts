// pages/api/auth/me.ts
import type { NextApiRequest, NextApiResponse } from "next";
import * as cookie from "cookie";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const cookies = req.headers.cookie ? cookie.parse(req.headers.cookie) : {};
  const token = cookies.token;

  if (!token) {
    return res.status(401).json({ loggedIn: false });
  }

  // Optionally verify the token here (JWT verification)
  return res.status(200).json({ loggedIn: true });
}
