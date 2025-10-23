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
        minHeight: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
         
        padding: "1rem",
      }}
    >
      <div
        style={{
          backgroundColor: "#ffffffff", // dark card
          padding: "2rem",
          borderRadius: "12px",
          boxShadow: "0 10px 25px rgba(0,0,0,0.5)",
          width: "100%",
          maxWidth: "600px",
        }}
      >
        <h2
          style={{
            textAlign: "center",
            marginBottom: "1.5rem",
            color: "#111827",
            fontSize: "1.75rem",
          }}
        >
          SIEM Log Search
        </h2>

        <style>
          {`
            .siem-input::placeholder {
              color: #d1d5db; /* light gray placeholder */
              opacity: 1;
            }
            .siem-input:focus {
              border-color: #3b82f6;
              box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.4);
            }
          `}
        </style>

        <form
          onSubmit={handleSubmit}
          style={{ display: "flex", flexDirection: "column", gap: "1rem" }}
        >
          <input
            type="text"
            placeholder="Search logs..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            required
            className="siem-input"
            style={{
              width: "100%",
              padding: "0.75rem",
              borderRadius: "8px",
              border: "1px solid #374151",
              outline: "none",
              fontSize: "1rem",
              backgroundColor: "#111827",
              color: "#f9fafb",
              transition: "all 0.2s ease-in-out",
            }}
          />
          <button
            type="submit"
            style={{
              padding: "0.75rem",
              backgroundColor: "#2563eb",
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
            Search
          </button>
        </form>

        {result && (
          <div
            style={{
              marginTop: "1.5rem",
              backgroundColor: "#111827",
              padding: "1rem",
              borderRadius: "8px",
              border: "1px solid #374151",
              maxHeight: "300px",
              overflowY: "auto",
              color: "#f9fafb",
            }}
          >
            <strong>Server responds:</strong>
            <pre
              style={{
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                marginTop: "0.5rem",
              }}
            >
              {result}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
