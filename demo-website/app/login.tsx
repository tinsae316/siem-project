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
        minHeight: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
         
        padding: "1rem",
      }}
    >
      <div
        style={{
          backgroundColor: "white",
          padding: "2rem",
          borderRadius: "12px",
          boxShadow: "0 10px 25px rgba(0,0,0,0.1)",
          width: "100%",
          maxWidth: "400px",
        }}
      >
        <h2 style={{ textAlign: "center", marginBottom: "1.5rem", color: "#111827" }}>
          SIEM Login
        </h2>

        <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div style={{ display: "flex", flexDirection: "column" }}>
            <label style={{ marginBottom: "0.5rem", fontWeight: 500 }}>Username</label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              style={{
                padding: "0.75rem",
                borderRadius: "8px",
                border: "1px solid #d1d5db",
                outline: "none",
                transition: "border 0.2s",
              }}
            />
          </div>

          <div style={{ display: "flex", flexDirection: "column" }}>
            <label style={{ marginBottom: "0.5rem", fontWeight: 500 }}>Password</label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{
                padding: "0.75rem",
                borderRadius: "8px",
                border: "1px solid #d1d5db",
                outline: "none",
                transition: "border 0.2s",
              }}
            />
          </div>

          <button
            type="submit"
            style={{
              marginTop: "1rem",
              padding: "0.75rem",
              backgroundColor: "#111827",
              color: "white",
              fontWeight: 600,
              borderRadius: "8px",
              border: "none",
              cursor: "pointer",
              transition: "background-color 0.2s",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = "#111827")}
            onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = "#111827")}
          >
            Login
          </button>

          {message && (
            <p
              style={{
                marginTop: "1rem",
                color: "#b91c1c",
                textAlign: "center",
                fontWeight: 500,
              }}
            >
              {message}
            </p>
          )}
        </form>
      </div>
    </div>
  );
}
