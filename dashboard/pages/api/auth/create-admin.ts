import type { NextApiRequest, NextApiResponse } from "next";
import bcrypt from "bcryptjs";
import prisma from "../../../lib/prisma";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const { username, email, password } = req.body as {
    username: string;
    email: string;
    password: string;
  };

  if (!username || !email || !password) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  try {
    // Check if admin already exists
    const existingAdmin = await prisma.users.findFirst({
      where: { OR: [{ email }, { username }] },
    });

    if (existingAdmin) {
      return res.status(400).json({ error: "Admin already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create admin account
    const admin = await prisma.users.create({
      data: {
        username,
        email,
        password: hashedPassword,
        role: "ADMIN", // assuming you have a 'role' column in users table
        created_at: new Date(),
      },
    });

    return res.status(201).json({
      message: "Admin account created successfully",
      adminId: admin.id,
    });
  } catch (error) {
    console.error("Error creating admin:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}