"use client";
import { useState } from "react";

export default function SearchPage() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setResult(null);
    const res = await fetch("/api/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query }),
    });
    const data = await res.json();
    setResult(data.result || data.detail || "No result.");
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
          maxWidth: 500,
          width: "100%",
          padding: 32,
          background: "#fff",
          borderRadius: 12,
          boxShadow: "0 10px 30px rgba(0,0,0,0.1)",
        }}
      >
        <h2 style={{ textAlign: "center", marginBottom: 24, color: "#111" }}>Search / XSS Demo</h2>
        <form
          onSubmit={handleSubmit}
          style={{ display: "flex", flexDirection: "column", gap: 16 }}
        >
          <input
            type="text"
            placeholder="Type something..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            required
            style={{
              padding: 12,
              borderRadius: 8,
              border: "1px solid #ccc",
              outline: "none",
              backgroundColor: "#fefefe",
              color: "#111",
              fontSize: 16,
            }}
          />
          <button
            type="submit"
            style={{
              padding: 12,
              borderRadius: 8,
              backgroundColor: "#0070f3",
              color: "#fff",
              fontWeight: 500,
              border: "none",
              cursor: "pointer",
              transition: "background 0.2s",
              fontSize: 16,
            }}
          >
            Search
          </button>
        </form>
        {result && (
          <div
            style={{
              marginTop: 24,
              padding: 16,
              background: "#f4f4f4",
              borderRadius: 8,
              fontFamily: "monospace",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
            }}
          >
            <strong>Server responds:</strong>
            <pre>{result}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
