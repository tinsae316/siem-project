import { GetServerSideProps } from "next";
import prisma from "../lib/prisma";
import { verifyToken } from "../lib/auth";
import * as cookie from "cookie";
import { useState } from "react";

interface Alert {
  id: number;
  rule: string | null;
  user_name: string | null;
  source_ip: string | null;
  attempt_count: number | null;
  severity: string | null;
  technique: string | null;
  timestamp: string;
  raw: any | null;
}

interface AlertsPageProps {
  alerts: Alert[];
}

export const getServerSideProps: GetServerSideProps<AlertsPageProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || "";
  const { token } = cookie.parse(cookies);
  if (!token) return { redirect: { destination: "/login", permanent: false } };

  try {
    verifyToken(token);

    const { startDate, endDate } = ctx.query;

    const alertsRaw = await prisma.alerts.findMany({
      where: {
        timestamp: {
          gte: startDate ? new Date(startDate as string) : undefined,
          lte: endDate ? new Date(endDate as string) : undefined,
        },
      },
      orderBy: { timestamp: "desc" },
    });

    const alerts: Alert[] = alertsRaw.map(alert => ({
      ...alert,
      timestamp: alert.timestamp instanceof Date ? alert.timestamp.toISOString() : String(alert.timestamp),
    }));

    return { props: { alerts } };
  } catch {
    return { redirect: { destination: "/login", permanent: false } };
  }
};

const getSeverityColor = (severity: string | null): string => {
  if (!severity) return "#6b7280";
  switch(severity.toUpperCase()) {
    case "CRITICAL": return "#ef4444";
    case "HIGH": return "#f59e0b";
    case "MEDIUM": return "#3b82f6";
    case "LOW": return "#10b981";
    default: return "#6b7280";
  }
};

const getSeverityIcon = (severity: string | null): string => {
  if (!severity) return "i";
  switch(severity.toUpperCase()) {
    case "CRITICAL": return "!";
    case "HIGH": return "⚠";
    case "MEDIUM": return "i";
    case "LOW": return "✓";
    default: return "i";
  }
};

const getAlertTitle = (alert: Alert) => {
  if (alert.rule) return alert.rule;
  if (alert.technique) return alert.technique;
  return "Security Alert";
};

const getAlertDescription = (alert: Alert) => {
  if (alert.technique === "Credential Stuffing") {
    return "Large-scale credential stuffing attack detected";
  } else if (alert.technique === "XSS") {
    return "Cross-site scripting attempt detected in user input";
  } else if (alert.technique === "SQLi") {
    return "SQL injection pattern detected in request parameters";
  } else if (alert.technique === "Brute Force") {
    return "Multiple failed login attempts from same IP";
  } else if (alert.rule?.includes("Admin Account Creation")) {
    return "Unauthorized admin account creation attempt";
  } else if (alert.rule?.includes("Admin Role Assignment")) {
    return "Admin role assignment without proper authorization";
  }
  return `Security event detected - ${alert.user_name || alert.source_ip || "Unknown source"}`;
};

export default function AlertsPage({ alerts }: AlertsPageProps) {
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState("All Severities");
  const [selectedTechnique, setSelectedTechnique] = useState("All Techniques");

  // Calculate counts
  const totalAlerts = alerts.length;
  const criticalCount = alerts.filter(alert => alert.severity === "CRITICAL").length;
  const highCount = alerts.filter(alert => alert.severity === "HIGH").length;
  const mediumCount = alerts.filter(alert => alert.severity === "MEDIUM").length;
  const lowCount = alerts.filter(alert => alert.severity === "LOW").length;

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    const query = new URLSearchParams();
    if (startDate) query.append("startDate", startDate);
    if (endDate) query.append("endDate", endDate);
    window.location.href = `/alerts?${query.toString()}`;
  };

  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = !searchTerm || 
      (alert.rule && alert.rule.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (alert.technique && alert.technique.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (alert.user_name && alert.user_name.toLowerCase().includes(searchTerm.toLowerCase()));
    
    const matchesSeverity = selectedSeverity === "All Severities" || alert.severity === selectedSeverity.toUpperCase();
    const matchesTechnique = selectedTechnique === "All Techniques" || alert.technique === selectedTechnique;
    
    return matchesSearch && matchesSeverity && matchesTechnique;
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
        <h2 style={{ marginBottom: '30px', color: '#1e293b' }}>Security Alerts</h2>
        <p style={{ color: '#64748b', fontSize: '14px', marginBottom: '30px' }}>
          Monitor and analyze security events and threats
        </p>

        {/* Stats Cards */}
        <div style={{ marginBottom: '30px' }}>
          <div style={{ 
            backgroundColor: '#f8fafc', 
            padding: '15px', 
            borderRadius: '8px',
            marginBottom: '10px'
          }}>
            <div style={{ fontSize: '12px', color: '#64748b' }}>Total Alerts</div>
            <div style={{ fontSize: '24px', fontWeight: 'bold', color: '#1e293b' }}>{totalAlerts}</div>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px' }}>
            <div style={{ 
              backgroundColor: '#fef2f2', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#ef4444' }}>{criticalCount}</div>
              <div style={{ fontSize: '12px', color: '#ef4444' }}>Critical</div>
            </div>
            
            <div style={{ 
              backgroundColor: '#fffbeb', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#f59e0b' }}>{highCount}</div>
              <div style={{ fontSize: '12px', color: '#f59e0b' }}>High</div>
            </div>
            
            <div style={{ 
              backgroundColor: '#eff6ff', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#3b82f6' }}>{mediumCount}</div>
              <div style={{ fontSize: '12px', color: '#3b82f6' }}>Medium</div>
            </div>
            
            <div style={{ 
              backgroundColor: '#f0fdf4', 
              padding: '10px', 
              borderRadius: '6px',
              textAlign: 'center'
            }}>
              <div style={{ fontSize: '18px', fontWeight: 'bold', color: '#10b981' }}>{lowCount}</div>
              <div style={{ fontSize: '12px', color: '#10b981' }}>Low</div>
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
            Threat Detection
          </div>
        </div>

        {/* Filters */}
        <div>
          <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#1e293b', marginBottom: '15px' }}>Filters</h3>
          
          <input
            type="text"
            placeholder="Search alerts..."
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
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
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
            <option>All Severities</option>
            <option>CRITICAL</option>
            <option>HIGH</option>
            <option>MEDIUM</option>
            <option>LOW</option>
          </select>
          
          <select 
            value={selectedTechnique}
            onChange={(e) => setSelectedTechnique(e.target.value)}
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
            <option>All Techniques</option>
            <option>Credential Stuffing</option>
            <option>Brute Force</option>
            <option>SQLi</option>
            <option>XSS</option>
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
              Security Alerts ({filteredAlerts.length})
            </h1>
          </div>

          {/* Scrollable Alerts Container */}
          <div style={{
            flex: 1,
            overflowY: 'auto',
            border: '1px solid #f1f5f9',
            borderRadius: '6px'
          }}>
            {filteredAlerts.length === 0 ? (
              <div style={{ 
                color: '#64748b', 
                textAlign: 'center', 
                padding: '40px',
                height: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center'
              }}>
                No alerts found
              </div>
            ) : (
              <div>
                {filteredAlerts.map(alert => {
                  const severity = alert.severity || "UNKNOWN";
                  return (
                    <div key={alert.id} style={{ 
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
                        backgroundColor: getSeverityColor(severity),
                        color: 'white',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: '12px',
                        fontWeight: 'bold',
                        flexShrink: 0
                      }}>
                        {getSeverityIcon(severity)}
                      </div>
                      
                      <div style={{ flex: 1 }}>
                        <div style={{ 
                          fontSize: '14px', 
                          color: '#1e293b',
                          marginBottom: '5px',
                          fontWeight: 'bold'
                        }}>
                          {getAlertTitle(alert)}
                        </div>
                        
                        <div style={{ 
                          fontSize: '13px', 
                          color: '#64748b',
                          marginBottom: '5px'
                        }}>
                          {getAlertDescription(alert)}
                        </div>
                        
                        <div style={{ 
                          fontSize: '12px', 
                          color: '#64748b',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '10px'
                        }}>
                          <span>{formatDate(alert.timestamp)}</span>
                          <span style={{ color: '#d1d5db' }}>•</span>
                          <span>{alert.source_ip || "Unknown IP"}</span>
                          {alert.user_name && (
                            <>
                              <span style={{ color: '#d1d5db' }}>•</span>
                              <span>{alert.user_name}</span>
                            </>
                          )}
                          {alert.attempt_count && (
                            <>
                              <span style={{ color: '#d1d5db' }}>•</span>
                              <span>{alert.attempt_count} attempts</span>
                            </>
                          )}
                        </div>
                      </div>
                      
                      <div style={{ 
                        padding: '4px 8px',
                        backgroundColor: '#f8fafc',
                        borderRadius: '4px',
                        fontSize: '11px',
                        color: getSeverityColor(severity),
                        fontWeight: 'bold',
                        border: `1px solid ${getSeverityColor(severity)}20`
                      }}>
                        {severity}
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