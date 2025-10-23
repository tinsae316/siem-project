"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setMessage(null);
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (res.ok) {
      router.push("/dashboard");
    } else {
      setMessage(data.detail || "Login failed.");
    }
  };

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "80vh",
        padding: 16,
        backgroundColor: "#f9f9f9",
      }}
    >
      <div
        style={{
          maxWidth: 400,
          width: "100%",
          padding: 32,
          background: "#fff",
          borderRadius: 12,
          boxShadow: "0 10px 30px rgba(0,0,0,0.1)",
        }}
      >
        <h2 style={{ textAlign: "center", marginBottom: 24, color: "#111" }}>Login</h2>
        <form
          onSubmit={handleSubmit}
          style={{ display: "flex", flexDirection: "column", gap: 16 }}
        >
          <div style={{ display: "flex", flexDirection: "column" }}>
            <label style={{ marginBottom: 4, color: "#111" }}>Username</label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                padding: 10,
                borderRadius: 8,
                border: "1px solid #ccc",
                outline: "none",
                backgroundColor: "#fefefe", // white input background
                color: "#111", // dark text
              }}
            />
          </div>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <label style={{ marginBottom: 4, color: "#111" }}>Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                padding: 10,
                borderRadius: 8,
                border: "1px solid #ccc",
                outline: "none",
                backgroundColor: "#fefefe",
                color: "#111",
              }}
            />
          </div>
          <button
            type="submit"
            style={{
              padding: 12,
              borderRadius: 8,
              background: "#0070f3",
              color: "#fff",
              fontWeight: 500,
              border: "none",
              cursor: "pointer",
              transition: "background 0.2s",
            }}
          >
            Login
          </button>
        </form>
        {message && (
          <p style={{ color: "red", marginTop: 12, textAlign: "center" }}>{message}</p>
        )}
      </div>
    </div>
  );
}
