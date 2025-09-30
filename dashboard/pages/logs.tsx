import { GetServerSideProps } from "next";
import prisma from "../lib/prisma";
import { verifyToken } from "../lib/auth";
import * as cookie from "cookie";
import { useState } from "react";

interface Log {
  id: number;
  message: string | null;
  severity: number | null;
  timestamp: string;
  source_ip: string | null;
  category?: string;
  type?: string;
}

interface LogsPageProps {
  logs: Log[];
}

export const getServerSideProps: GetServerSideProps<LogsPageProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);
  if (!token) return { redirect: { destination: "/login", permanent: false } };

  try {
    verifyToken(token);

    const { startDate, endDate } = ctx.query;

    const logsRaw = await prisma.logs.findMany({
      where: {
        timestamp: {
          gte: startDate ? new Date(startDate as string) : undefined,
          lte: endDate ? new Date(endDate as string) : undefined,
        },
      },
      orderBy: { timestamp: "desc" },
    });

    const logs: Log[] = logsRaw.map((log: any) => ({
      ...log,
      timestamp: log.timestamp instanceof Date ? log.timestamp.toISOString() : String(log.timestamp),
    }));

    return { props: { logs } };
  } catch {
    return { redirect: { destination: "/login", permanent: false } };
  }
};

const getSeverityType = (severity: number | null): string => {
  if (severity === null) return "Info";
  switch(severity) {
    case 0: return "Success";
    case 1: return "Info";
    case 2: return "Warning";
    case 3: return "Error";
    default: return "Info";
  }
};

const getSeverityIcon = (severity: string): string => {
  switch(severity) {
    case "Success": return "✓";
    case "Error": return "!";
    case "Warning": return "⚠";
    default: return "i";
  }
};

const getSeverityColor = (severity: string): string => {
  switch(severity) {
    case "Success": return "#10b981";
    case "Error": return "#ef4444";
    case "Warning": return "#f59e0b";
    case "Info": return "#3b82f6";
    default: return "#6b7280";
  }
};

export default function LogsPage({ logs }: LogsPageProps) {
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("All Categories");
  const [selectedType, setSelectedType] = useState("All Types");

  // Calculate counts
  const totalLogs = logs.length;
  const errorCount = logs.filter(log => getSeverityType(log.severity) === "Error").length;
  const warningCount = logs.filter(log => getSeverityType(log.severity) === "Warning").length;
  const successCount = logs.filter(log => getSeverityType(log.severity) === "Success").length;
  const infoCount = logs.filter(log => getSeverityType(log.severity) === "Info").length;

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    const query = new URLSearchParams();
    if (startDate) query.append("startDate", startDate);
    if (endDate) query.append("endDate", endDate);
    window.location.href = `/logs?${query.toString()}`;
  };

  const filteredLogs = logs.filter(log => {
    const matchesSearch = !searchTerm || 
      (log.message && log.message.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesCategory = selectedCategory === "All Categories" || log.category === selectedCategory;
    const matchesType = selectedType === "All Types" || getSeverityType(log.severity) === selectedType;
    
    return matchesSearch && matchesCategory && matchesType;
  });

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      month: 'numeric',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      hour12: true
    });
  };

  return (
    <div style={{ 
      display: 'flex', 
      height: '100vh', 
      backgroundColor: '#f8fafc',
      overflow: 'hidden'
    }}>
      {/* Sidebar */}
      <div style={{ 
        width: '300px', 
        backgroundColor: 'white', 
        padding: '20px',
        borderRight: '1px solid #e2e8f0',
        boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
        overflowY: 'auto'
      }}>
        <h2 style={{ marginBottom: '30px', color: '#1e293b' }}>System Logs</h2>
        <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '30px' }}>
          Monitor and analyze system events and activities
        </p>

        {/* Stats Cards */}
        <div style={{ marginBottom: '30px' }}>
          <div style={{ 
            backgroundColor: '#f8fafc', 
            padding: '15px', 
            borderRadius: '8px',
            marginBottom: '10px'
          }}>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Total Logs</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#1e293b' }}>{totalLogs}</div>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={{ 
              backgroundColor: '#fef2f2', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#ef4444' }}>{errorCount}</div>
              <div style={{ fontSize: '12px', color: '#ef4444' }}>Errors</div>
            </div>
            
            <div style={{ 
              backgroundColor: '#fffbeb', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#f59e0b' }}>{warningCount}</div>
              <div style={{ fontSize: '12px', color: '#f59e0b' }}>Warnings</div>
            </div>
            
            <div style={{ 
              backgroundColor: '#f0fdf4', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#10b981' }}>{successCount}</div>
              <div style={{ fontSize: '12px', color: '#10b981' }}>Success</div>
            </div>
            
            <div style={{ 
              backgroundColor: '#eff6ff', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#3b82f6' }}>{infoCount}</div>
              <div style={{ fontSize: '12px', color: '#3b82f6' }}>Info</div>
            </div>
          </div>
        </div>

        <div style={{ 
          backgroundColor: '#f8fafc', 
          padding: '15px', 
          borderRadius: '8px',
          marginBottom: '20px'
        }}>
          <div style={{ fontSize: '14px', fontWeight: 'bold', color: '#1e293b', marginBottom: '15px' }}>
            Database Logs
          </div>
        </div>

        {/* Filters */}
        <div>
          <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#1e293b', marginBottom: '15px' }}>Filters</h3>
          
          <input
            type="text"
            placeholder="Search logs..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              border: '1px solid #d1d5db',
              borderRadius: '6px',
              marginBottom: '15px',
              fontSize: '14px'
            }}
          />
          
          <select 
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              border: '1px solid #d1d5db',
              borderRadius: '6px',
              marginBottom: '15px',
              fontSize: '14px',
              backgroundColor: 'white'
            }}
          >
            <option>All Categories</option>
            <option>System</option>
            <option>Security</option>
            <option>Auth</option>
            <option>User Management</option>
          </select>
          
          <select 
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              border: '1px solid #d1d5db',
              borderRadius: '6px',
              marginBottom: '15px',
              fontSize: '14px',
              backgroundColor: 'white'
            }}
          >
            <option>All Types</option>
            <option>Error</option>
            <option>Warning</option>
            <option>Success</option>
            <option>Info</option>
          </select>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '15px' }}>
            <input
              type="date"
              value={startDate}
              onChange={(e) => setStartDate(e.target.value)}
              style={{
                padding: '8px',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '12px'
              }}
            />
            <input
              type="date"
              value={endDate}
              onChange={(e) => setEndDate(e.target.value)}
              style={{
                padding: '8px',
                border: '1px solid #d1d5db',
                borderRadius: '6px',
                fontSize: '12px'
              }}
            />
          </div>
          
          <button 
            onClick={handleFilter}
            style={{
              width: '100%',
              padding: '10px',
              backgroundColor: '#3b82f6',
              color: 'white',
              border: 'none',
              borderRadius: '6px',
              fontSize: '14px',
              cursor: 'pointer'
            }}
          >
            Apply Filters
          </button>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ 
        flex: 1, 
        padding: '20px',
        display: 'flex',
        flexDirection: 'column',
        height: '100vh',
        overflow: 'hidden'
      }}>
        <div style={{ 
          backgroundColor: 'white', 
          borderRadius: '8px', 
          padding: '20px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
          flex: 1,
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden'
        }}>
          <div style={{ 
            display: 'flex', 
            justifyContent: 'space-between', 
            alignItems: 'center',
            marginBottom: '20px',
            flexShrink: 0
          }}>
            <h1 style={{ fontSize: '18px', fontWeight: 'bold', color: '#1e293b' }}>
              Log Entries ({filteredLogs.length})
            </h1>
          </div>

          {/* Scrollable Logs Container */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            border: '1px solid #f1f5f9',
            borderRadius: '6px'
          }}>
            {filteredLogs.length === 0 ? (
              <div style={{ 
                color: '#64748b', 
                textAlign: 'center', 
                padding: '40px',
                height: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                No logs found
              </div>
            ) : (
              <div>
                {filteredLogs.map(log => {
                  const severityType = getSeverityType(log.severity);
                  return (
                    <div key={log.id} style={{ 
                      padding: '15px',
                      borderBottom: '1px solid #f1f5f9',
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '15px'
                    }}>
                      <div style={{ 
                        width: '24px',
                        height: '24px',
                        borderRadius: '50%',
                        backgroundColor: getSeverityColor(severityType),
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '12px',
                        fontWeight: 'bold',
                        flexShrink: 0
                      }}>
                        {getSeverityIcon(severityType)}
                      </div>
                      
                      <div style={{ flex: 1 }}>
                        <div style={{ 
                          fontSize: '14px', 
                          color: '#1e293b',
                          marginBottom: '5px',
                          fontWeight: log.message ? 'normal' : '300',
                          fontStyle: log.message ? 'normal' : 'italic'
                        }}>
                          {log.message || "No message"}
                        </div>
                        
                        <div style={{ 
                          fontSize: '12px', 
                          color: '#64748b',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '10px'
                        }}>
                          <span>{formatDate(log.timestamp)}</span>
                          <span style={{ color: '#d1d5db' }}>•</span>
                          <span>{log.source_ip || "A system"}</span>
                        </div>
                      </div>
                      
                      <div style={{ 
                        padding: '4px 8px',
                        backgroundColor: '#f8fafc',
                        borderRadius: '4px',
                        fontSize: '11px',
                        color: '#64748b',
                        fontWeight: 'bold'
                      }}>
                        {severityType}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}