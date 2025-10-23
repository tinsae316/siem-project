// pages/login.tsx
import { GetServerSideProps } from "next";
import { useState } from "react";
import { useRouter } from "next/router";
import * as cookie from "cookie";
import Layout from "../components/Layout";
import { FiUser, FiLock } from "react-icons/fi";
import { verifyToken } from "../lib/auth"; // your auth verification function

export const getServerSideProps: GetServerSideProps = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);

  // If token exists and is valid, redirect to dashboard
  if (token) {
    try {
      verifyToken(token);
      return { redirect: { destination: "/dashboard", permanent: false } };
    } catch {
      // Invalid token: continue to login page
    }
  }

  return { props: {} };
};

export default function Login() {
  const router = useRouter();
  const [form, setForm] = useState({ username: "", password: "" });
  const [error, setError] = useState("");
  const [isCheckingAuth, setIsCheckingAuth] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCheckingAuth(true);
    setError("");
  
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });
  
      const data = await res.json();
  
      if (res.ok) {
        // Keep the button disabled until redirect finishes
        await router.replace("/dashboard");
        return;
      } else {
        setError(data.error || "Invalid username or password");
      }
    } catch (err) {
      setError("An unexpected error occurred");
    } finally {
      // Only re-enable button if login failed
      setIsCheckingAuth(false);
    }
  };  

  return (
    <Layout>
      <div className="flex items-center justify-center min-h-[calc(100vh-64px)] p-4 mt-16">
        {/* mt-16 pushes content below the fixed header */}
        <div className="w-full max-w-sm">
          <div className="bg-white rounded-lg border border-gray-200 p-8 shadow-sm">
            <div className="text-center mb-8">
              <h1 className="text-2xl font-bold text-gray-800 mb-2">
                Welcome back
              </h1>
              <p className="text-gray-500">Sign in to your account to continue</p>
            </div>

            {error && <p className="text-red-600 mb-4 text-center">{error}</p>}

            <form onSubmit={handleSubmit}>
              <div className="mb-4">
                <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-1">
                  Username or Email
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <FiUser className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="username"
                    type="text"
                    placeholder="Enter your username or email"
                    value={form.username}
                    onChange={(e) => setForm({ ...form, username: e.target.value })}
                    className="w-full pl-10 pr-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
              </div>

              <div className="mb-6">
                <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                  Password
                </label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                    <FiLock className="h-5 w-5 text-gray-400" />
                  </div>
                  <input
                    id="password"
                    type="password"
                    placeholder="Enter your password"
                    value={form.password}
                    onChange={(e) => setForm({ ...form, password: e.target.value })}
                    className="w-full pl-10 pr-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isCheckingAuth}
                className={`w-full py-2 font-semibold rounded-lg transition ${
                  isCheckingAuth
                    ? "bg-orange-300 cursor-not-allowed"
                    : "bg-orange-500 hover:bg-orange-600 text-white"
                }`}
              >
                {isCheckingAuth ? "Signing in..." : "Sign In"}
              </button>
            </form>
          </div>
        </div>
      </div>
    </Layout>
  );
}
