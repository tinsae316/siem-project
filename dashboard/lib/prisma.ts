// lib/prisma.ts
import { PrismaClient } from "../lib/generated/prisma";
declare global {
  // Extend NodeJS Global type
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

const prisma = global.prisma || new PrismaClient();

if (process.env.NODE_ENV !== "production") {
  global.prisma = prisma;
}

export default prisma;