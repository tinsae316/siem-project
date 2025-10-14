import type { NextApiRequest, NextApiResponse } from 'next';
import prisma from '../../lib/prisma';
import bcrypt from 'bcryptjs';

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  if (req.method !== 'POST') return res.status(405).end();

  const { username, email, password } = req.body as {
    username: string;
    email: string;
    password: string;
  };

  if (!username || !email || !password)
    return res.status(400).json({ error: 'Missing fields' });

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.users.create({
      data: { username, email, password: hashedPassword, created_at: new Date() },
    });
    res.status(201).json({ message: 'User created', userId: user.id });
  } catch (error) {
    res.status(400).json({ error: 'User already exists' });
  }
}
