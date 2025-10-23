"use client";

import { GetServerSideProps } from "next";
import * as cookie from "cookie";
import Layout from "../components/Layout";
import Sidebar from "../components/Sidebar";
import { verifyToken } from "../lib/auth";
import prisma from "../lib/prisma";

interface ProfileProps {
  username: string;
  email: string | null;
}

export const getServerSideProps: GetServerSideProps<ProfileProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);
  if (!token) return { redirect: { destination: "/login", permanent: false } };

  try {
    const payload: any = verifyToken(token);
    if (!payload?.id) throw new Error("Invalid token");

    // Fetch the user from Prisma (assumes users table with id, username, email)
    const user = await prisma.users.findUnique({ where: { id: payload.id } });
    if (!user) return { redirect: { destination: "/login", permanent: false } };

    return { props: { username: user.username, email: user.email ?? null } };
  } catch {
    return { redirect: { destination: "/login", permanent: false } };
  }
};

export default function ProfilePage({ username, email }: ProfileProps) {
  return (
    <Layout>
      <div className="flex bg-gray-50 min-h-screen pt-16">
        <Sidebar />

        <main className="flex-1 ml-60 px-8 py-6 overflow-y-auto">
          <h1 className="text-3xl font-bold text-gray-900 mb-6">Profile</h1>

          <section className="bg-white rounded-2xl shadow-md border p-6 max-w-xl">
            <div className="space-y-4">
              <div>
                <div className="text-sm text-gray-500">Username</div>
                <div className="text-lg font-medium text-gray-900">{username}</div>
              </div>
              <div>
                <div className="text-sm text-gray-500">Email</div>
                <div className="text-lg font-medium text-gray-900">{email || "Not set"}</div>
              </div>
            </div>
          </section>
        </main>
      </div>
    </Layout>
  );
}







