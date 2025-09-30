import type { NextApiRequest, NextApiResponse } from "next";
import bcrypt from "bcryptjs";
import prisma from "../../../lib/prisma";
import { signToken } from "../../../lib/auth";
import * as cookie from "cookie";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { username, password } = req.body; // must match frontend form

  try {
    // Use the correct Prisma model name
    const user = await prisma.users.findUnique({ where: { username } });
    if (!user) return res.status(401).json({ error: "Invalid username or password" });

    // Compare plain password with hashed password
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: "Invalid username or password" });

    const token = signToken({ id: user.id, username: user.username });

    res.setHeader(
      "Set-Cookie",
      cookie.serialize("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 3600, // 1 hour
        path: "/",
      })
    );

    return res.status(200).json({ message: "Logged in successfully" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
}
