import React, { useEffect, useState } from "react";
import Layout from "../components/Layout";
import { useRouter } from "next/router";

export default function Profile() {
  const [user, setUser] = useState({ username: "", email: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [passwords, setPasswords] = useState({ newPassword: "", confirm: "" });
  const [pwMsg, setPwMsg] = useState("");

  const router = useRouter();

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const res = await fetch("/api/auth/me");
        const data = await res.json();
        if (!data.loggedIn) {
          router.replace("/login");
        } else {
          setUser({ username: data.username, email: data.email });
        }
      } catch {
        setError("Failed to load profile");
      }
      setLoading(false);
    };
    fetchProfile();
  }, [router]);

  const handleReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwMsg("");
    if (passwords.newPassword.length < 6) {
      setPwMsg("Password must be at least 6 characters.");
      return;
    }
    if (passwords.newPassword !== passwords.confirm) {
      setPwMsg("Passwords do not match.");
      return;
    }
    const res = await fetch("/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ newPassword: passwords.newPassword }),
    });
    const data = await res.json();
    if (res.ok) {
      setPwMsg("Password changed successfully!");
      setPasswords({ newPassword: "", confirm: "" });
    } else {
      setPwMsg(data.error || "Password reset failed.");
    }
  };

  if (loading) return <Layout><div className="p-10">Loading...</div></Layout>;

  return (
    <Layout>
      <div className="max-w-xl mx-auto mt-16 bg-white rounded-lg p-8 shadow border">
        <h1 className="text-2xl font-bold mb-4">Profile</h1>
        {error && <div className="text-red-500 mb-4">{error}</div>}
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-semibold">Username:</label>
          <div className="border rounded px-3 py-2 bg-gray-100">{user.username}</div>
        </div>
        <div className="mb-6">
          <label className="block text-gray-700 text-sm font-semibold">Email:</label>
          <div className="border rounded px-3 py-2 bg-gray-100">{user.email}</div>
        </div>
        <hr className="my-8" />
        <h2 className="text-lg font-semibold mb-2">Reset Password</h2>
        <form onSubmit={handleReset} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">New Password</label>
            <input
              type="password"
              value={passwords.newPassword}
              onChange={e => setPasswords(pw => ({ ...pw, newPassword: e.target.value }))}
              className="w-full border rounded px-3 py-2"
              minLength={6}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Confirm Password</label>
            <input
              type="password"
              value={passwords.confirm}
              onChange={e => setPasswords(pw => ({ ...pw, confirm: e.target.value }))}
              className="w-full border rounded px-3 py-2"
              minLength={6}
              required
            />
          </div>
          <button type="submit" className="bg-orange-600 text-white px-6 py-2 rounded hover:bg-orange-700 font-semibold">Reset Password</button>
        </form>
        {pwMsg && <div className="mt-4 text-center text-sm text-orange-600">{pwMsg}</div>}
      </div>
    </Layout>
  );
}
