// components/alert_schedule.tsx
import { useEffect, useState } from "react";

interface AlertData {
  rule?: string;
  description?: string;
  timestamp?: string;
  [key: string]: any;
}

export default function AlertSchedule() {
  const [alerts, setAlerts] = useState<AlertData[]>([]);

  useEffect(() => {
    const es = new EventSource("/api/live_alert");

    es.onmessage = (evt) => {
      try {
        const data = JSON.parse(evt.data);
        setAlerts((prev) => [data, ...prev].slice(0, 200)); // keep newest 200
      } catch (e) {
        console.error("Failed to parse SSE data", e);
      }
    };

    es.onerror = (e) => {
      console.error("SSE error, closing", e);
      es.close();
    };

    return () => es.close();
  }, []);

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <h2 className="text-2xl font-bold mb-4 text-center">⚡ Live Security Alerts</h2>

      <div className="mb-6 flex justify-center">
        <div className="text-sm text-gray-600">Server log (live)</div>
      </div>

      <div className="space-y-3">
        {alerts.length === 0 && (
          <div className="text-center text-gray-500">No alerts yet — waiting for activity...</div>
        )}

        {alerts.map((alert, i) => (
          <div
            key={i}
            className="border rounded-md shadow-sm p-4 flex justify-between items-start bg-white"
            role="article"
            aria-live="polite"
          >
            <div className="flex items-start space-x-3">
              {/* simple inline SVG alert icon */}
              <svg
                className="w-8 h-8 text-red-600"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ color: "#DC2626" }}
              >
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                <line x1="12" y1="9" x2="12" y2="13" />
                <line x1="12" y1="17" x2="12.01" y2="17" />
              </svg>

              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="font-semibold text-lg text-red-700">
                    {alert.rule || "Unknown Rule"}
                  </h3>
                  <span className="text-xs px-2 py-0.5 bg-red-100 text-red-800 rounded">
                    {alert.severity || "INFO"}
                  </span>
                </div>

                <p className="text-sm text-gray-700 mt-1">
                  {alert.description || alert.raw || alert.url || "Potential threat detected."}
                </p>

                <div className="mt-2 text-xs text-gray-500">
                  <span className="mr-3">
                    <strong>IP:</strong> {alert["source.ip"] || "unknown"}
                  </span>
                  <span>
                    <strong>Method:</strong> {alert.http_method || "-"}
                  </span>
                </div>
              </div>
            </div>

            <div className="text-xs text-gray-400 text-right min-w-[110px]">
              <div>
                {alert.timestamp
                  ? new Date(alert.timestamp).toLocaleString()
                  : new Date().toLocaleString()}
              </div>
              <div className="mt-2 text-xs text-gray-500">{alert.count ? `${alert.count} attempts` : ""}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
