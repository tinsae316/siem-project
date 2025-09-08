"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { Shield, LogOut, Calendar, Clock, Filter, RefreshCw, AlertTriangle } from "lucide-react"
import { AuthGuard } from "@/components/auth-guard"
import { apiService, type LogEntry } from "@/lib/api"
import Link from "next/link"

export default function DashboardPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  // Filter states
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [timeframe, setTimeframe] = useState("")
  const [limit, setLimit] = useState(20)
  const [autoRefresh, setAutoRefresh] = useState(false)

  const handleLogout = () => {
    apiService.logout()
    window.location.href = "/login"
  }

  const fetchLogs = async () => {
    setIsLoading(true)
    setError("")

    try {
      const params: any = { limit }

      if (timeframe) {
        params.timeframe = timeframe
      } else if (startDate && endDate) {
        params.start = startDate
        params.end = endDate
      }

      const fetchedLogs = await apiService.getLogs(params)
      setLogs(fetchedLogs)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch logs")
      // rely on backend only
      setLogs([])
    }

    setIsLoading(false)
  }

  const handleTimeframeSelect = (value: string) => {
    setTimeframe(value)
    setStartDate("")
    setEndDate("")
  }

  const handleDateRangeChange = () => {
    setTimeframe("")
  }

  const applyFilters = () => {
    fetchLogs()
  }

  const clearFilters = () => {
    setStartDate("")
    setEndDate("")
    setTimeframe("")
    setLimit(20)
  }

  // Auto-refresh functionality
  useEffect(() => {
    let interval: NodeJS.Timeout | undefined

    if (autoRefresh) {
      interval = setInterval(() => {
        fetchLogs()
      }, 10000) // 10 seconds
    }

    return () => {
      if (interval) clearInterval(interval)
    }
  }, [autoRefresh, startDate, endDate, timeframe, limit])

  // Initial load
  useEffect(() => {
    fetchLogs()
  }, [])

  const formatTimestamp = (timestamp: string | null) => {
    if (!timestamp) return ""
    try {
      return new Date(timestamp).toLocaleString()
    } catch {
      return String(timestamp)
    }
  }

  const isAlertLog = (message: string) => {
    return message?.includes("ALERT")
  }

  return (
    <AuthGuard>
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900">
        {/* Header */}
        <header className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center space-x-3">
                <div className="p-2 bg-blue-100 dark:bg-blue-900 rounded-lg">
                  <Shield className="h-6 w-6 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">SIEM Dashboard</h1>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Web Logs Viewer</p>
                </div>
              </div>

              <div className="flex items-center space-x-4">
                <Button
                  variant={autoRefresh ? "default" : "outline"}
                  size="sm"
                  onClick={() => setAutoRefresh(!autoRefresh)}
                >
                  <RefreshCw className={`h-4 w-4 mr-2 ${autoRefresh ? "animate-spin" : ""}`} />
                  Auto-Refresh
                </Button>
                <Button variant="outline" size="sm" onClick={handleLogout}>
                  <LogOut className="h-4 w-4 mr-2" />
                  Logout
                </Button>
              </div>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="mb-6">
            <Link href="/alerts">
              <Button variant="outline" className="mb-4 bg-transparent">
                <AlertTriangle className="h-4 w-4 mr-2" />
                View Security Alerts ({logs.filter((log) => log.message.includes("ALERT")).length})
              </Button>
            </Link>
          </div>

          {/* Filtering Controls */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Filter className="h-5 w-5" />
                <span>Filter Controls</span>
              </CardTitle>
              <CardDescription>Filter logs by date range, timeframe, or limit results</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                {/* Date Range */}
                <div className="space-y-2">
                  <Label htmlFor="startDate" className="flex items-center space-x-1">
                    <Calendar className="h-4 w-4" />
                    <span>Start Date</span>
                  </Label>
                  <Input
                    id="startDate"
                    type="date"
                    value={startDate}
                    onChange={(e) => {
                      setStartDate(e.target.value)
                      handleDateRangeChange()
                    }}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="endDate" className="flex items-center space-x-1">
                    <Calendar className="h-4 w-4" />
                    <span>End Date</span>
                  </Label>
                  <Input
                    id="endDate"
                    type="date"
                    value={endDate}
                    onChange={(e) => {
                      setEndDate(e.target.value)
                      handleDateRangeChange()
                    }}
                  />
                </div>

                {/* Timeframe Presets */}
                <div className="space-y-2">
                  <Label className="flex items-center space-x-1">
                    <Clock className="h-4 w-4" />
                    <span>Timeframe</span>
                  </Label>
                  <Select value={timeframe} onValueChange={handleTimeframeSelect}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select timeframe" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="10m">Last 10 minutes</SelectItem>
                      <SelectItem value="30m">Last 30 minutes</SelectItem>
                      <SelectItem value="1h">Last 1 hour</SelectItem>
                      <SelectItem value="24h">Last 24 hours</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Log Limit */}
                <div className="space-y-2">
                  <Label>Log Limit</Label>
                  <Select value={limit.toString()} onValueChange={(value) => setLimit(Number.parseInt(value))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="10">10 logs</SelectItem>
                      <SelectItem value="20">20 logs</SelectItem>
                      <SelectItem value="50">50 logs</SelectItem>
                      <SelectItem value="100">100 logs</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="flex space-x-2">
                <Button onClick={applyFilters} disabled={isLoading}>
                  {isLoading ? "Loading..." : "Apply Filters"}
                </Button>
                <Button variant="outline" onClick={clearFilters}>
                  Clear Filters
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Logs Display */}
          <Card>
            <CardHeader>
              <CardTitle>Web Logs</CardTitle>
              <CardDescription>
                Displaying {logs.length} logs {autoRefresh && "(Auto-refreshing every 10 seconds)"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {error && (
                <div className="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
                  <p className="text-sm text-yellow-800 dark:text-yellow-200">{error}</p>
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-700">
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">ID</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Timestamp</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Source</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log) => (
                      <tr
                        key={log.id}
                        className={`border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 ${
                          isAlertLog(log.message) ? "bg-red-50 dark:bg-red-900/20" : ""
                        }`}
                      >
                        <td className="p-3 text-sm font-mono">{log.id}</td>
                        <td className="p-3 text-sm">{formatTimestamp(log.timestamp)}</td>
                        <td className="p-3 text-sm font-mono">{log.source}</td>
                        <td className="p-3 text-sm">
                          <div className="flex items-center space-x-2">
                            {isAlertLog(log.message) && (
                              <Badge variant="destructive" className="text-xs">
                                ALERT
                              </Badge>
                            )}
                            <span className={isAlertLog(log.message) ? "font-medium text-red-700 dark:text-red-300" : ""}>
                              {log.message}
                            </span>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {logs.length === 0 && !isLoading && (
                  <div className="text-center py-8 text-slate-500 dark:text-slate-400">No logs found for the selected criteria.</div>
                )}
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    </AuthGuard>
  )
}
