import { useState, useCallback, ReactNode, useRef, useEffect } from "react";

// --- TYPE DEFINITIONS ---
interface Alert {
  timestamp: string;
  source: { ip: string | null };
  user: { name: string | null };
  event: { outcome: string | null; category: string | null };
  message: string | null;
  raw: any | null;
}

type Message = {
  role: "user" | "bot";
  text: string;
  reportData?: Alert;
};

// --- HELPER FUNCTIONS ---
const createMessage = (role: Message["role"], text: string, reportData?: Alert): Message => ({
  role,
  text,
  reportData,
});

const Layout = ({ children }: { children: ReactNode }) => (
  <div className="min-h-screen bg-gray-50 font-sans antialiased">{children}</div>
);

const formatLogAlertToReportText = (alert: Alert): string => {
  return (
    `Timestamp: ${alert.timestamp}\n` +
    `Source IP: ${alert.source.ip || "N/A"}\n` +
    `User: ${alert.user.name || "N/A"}\n` +
    `Category/Technique: ${alert.event.category || "Generic Alert"}\n` +
    `Outcome: ${alert.event.outcome || "N/A"}\n` +
    `Message: ${alert.message || "N/A"}\n\n` +
    `Raw Data: ${JSON.stringify(alert.raw, null, 2)}\n\n` +
    `Recommended Actions:\n- Review the raw log data.\n- Investigate the source IP and user.\n- Take corrective security measures.\n`
  );
};

const parseReport = (text: string) => {
  const sections: Record<string, string[]> = {};
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  let currentSection = "General Details";

  const sectionKeywords = [
    { key: "Recommended Actions", regex: /^Recommended Actions/i },
    { key: "Raw Data", regex: /^Raw Data/i },
  ];

  lines.forEach((line) => {
    for (const keyword of sectionKeywords) {
      if (keyword.regex.test(line)) {
        currentSection = keyword.key;
      }
    }
    if (!sections[currentSection]) sections[currentSection] = [];
    sections[currentSection].push(line);
  });

  return sections;
};

// --- API FETCH ---
const searchAlertsFromAPI = async (queryText: string): Promise<Alert | null> => {
  try {
    const response = await fetch(`http://localhost:8000/alerts?limit=50`);
    const data = await response.json();
    if (!data.alerts || data.alerts.length === 0) return null;

    const searchString = queryText.toLowerCase().replace(/report on/i, "").trim();

    const alert = data.alerts.find((a: Alert) =>
      (a.event.category && a.event.category.toLowerCase().includes(searchString)) ||
      (a.user.name && a.user.name.toLowerCase().includes(searchString)) ||
      (a.source.ip && a.source.ip.includes(searchString))
    );

    return alert || null;
  } catch (err) {
    console.error("Error fetching alerts:", err);
    return null;
  }
};

// --- REACT COMPONENT ---
export default function ChatPage() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    if (messagesEndRef.current) messagesEndRef.current.scrollTop = messagesEndRef.current.scrollHeight;
  };
  useEffect(() => scrollToBottom(), [messages]);

  const sendMessage = useCallback(async () => {
    if (!input.trim()) return;

    const userMessage = createMessage("user", input);
    setMessages((prev) => [...prev, userMessage]);
    setInput("");

    const isReportRequest = input.toLowerCase().includes("report");

    if (isReportRequest) {
      const searchingMessage = createMessage("bot", "Searching alert database... Please wait.");
      setMessages((prev) => [...prev, searchingMessage]);

      const alertData = await searchAlertsFromAPI(input);

      setMessages((prev) => prev.filter((m) => m !== searchingMessage));

      if (alertData) {
        const reportText = formatLogAlertToReportText(alertData);
        setMessages((prev) => [...prev, createMessage("bot", reportText, alertData)]);
      } else {
        setMessages((prev) => [
          ...prev,
          createMessage("bot", `No alerts found matching "${input}".`)
        ]);
      }
    } else {
      setMessages((prev) => [
        ...prev,
        createMessage(
          "bot",
          `I received your query: "${input}". To get a report, start your query with 'report on' followed by a category, user, or source IP.`
        )
      ]);
    }
  }, [input]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") sendMessage();
  };

  return (
    <Layout>
      <div className="flex flex-col h-screen p-4 bg-gray-50">
        <div ref={messagesEndRef} className="flex-1 overflow-y-auto mb-4 space-y-4">
          {messages.length === 0 && (
            <div className="w-full flex justify-center text-center py-10">
              <p className="text-gray-500 max-w-md">
                **Database Mode.** Ask for a report based on a category, user, or source IP.<br/>
                Example: <span className="font-mono bg-gray-200 p-1 rounded text-sm">report on Brute Force</span> or <span className="font-mono bg-gray-200 p-1 rounded text-sm">report on 192.168.1.10</span>
              </p>
            </div>
          )}

          {messages.map((m, i) => {
            if (m.reportData) {
              const alert = m.reportData;
              const reportText = formatLogAlertToReportText(alert);
              const sections = parseReport(reportText);

              return (
                <div key={i} className="w-full flex justify-center">
                  <div className="bg-white rounded-xl shadow-2xl max-w-3xl w-full overflow-hidden">
                    <div className="p-5 border-b bg-gray-50 flex justify-between items-center">
                      <h2 className="text-2xl font-extrabold text-gray-800">Security Alert Report</h2>
                    </div>

                    <div className="p-5 space-y-6">
                      {Object.entries(sections).map(([section, lines]) => (
                        <div key={section} className="rounded-xl border border-gray-200 overflow-hidden shadow-sm">
                          <h3 className="font-bold text-sm uppercase p-3 bg-gray-100 text-gray-700">{section}</h3>
                          <div className="p-4 space-y-3 text-sm text-gray-800">
                            {lines.map((line, idx) => <p key={idx} className="leading-relaxed">{line}</p>)}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              );
            }

            return (
              <div key={i} className={`w-full flex ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`p-3 rounded-2xl max-w-xl sm:max-w-md shadow-md ${m.role === "user" ? "bg-blue-600 text-white rounded-br-none" : "bg-gray-200 text-gray-800 rounded-tl-none"}`}>
                  {m.text}
                </div>
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-2 p-3 bg-white border-t rounded-lg shadow-lg">
          <input
            className="flex-1 border border-gray-300 rounded-xl p-3 focus:outline-none focus:ring-2 focus:ring-blue-500 transition duration-150"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={`Ask for a report (e.g., 'report on XSS' or 'report on 192.168.1.10')...`}
          />
          <button
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3 rounded-xl shadow-md transition duration-150 transform hover:scale-[1.02]"
            onClick={sendMessage}
            disabled={!input.trim()}
          >
            Send
          </button>
        </div>
      </div>
    </Layout>
  );
}
