"use client"

import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Badge } from "@/components/ui/badge"
import { AlertTriangle, LogOut, Calendar, Clock, Filter, RefreshCw, ArrowLeft } from "lucide-react"
import { AuthGuard } from "@/components/auth-guard"
import { apiService, type LogEntry } from "@/lib/api"
import Link from "next/link"

export default function AlertsPage() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  // Filter states
  const [startDate, setStartDate] = useState("")
  const [endDate, setEndDate] = useState("")
  const [timeframe, setTimeframe] = useState("")
  const [limit, setLimit] = useState(50)
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
      const alertLogs = fetchedLogs.filter((log) => log.message.includes("ALERT"))
      setLogs(alertLogs)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch logs")
      // Do not use mock data — clear logs so UI reflects real backend state
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
    setLimit(50)
  }

  // Auto-refresh functionality
  useEffect(() => {
    let interval: NodeJS.Timeout

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

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString()
  }

  const getSeverityLevel = (message: string) => {
    if (message.includes("SQL Injection") || message.includes("malware")) return "critical"
    if (message.includes("failed login") || message.includes("Unauthorized")) return "high"
    return "medium"
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-600 text-white"
      case "high":
        return "bg-orange-500 text-white"
      case "medium":
        return "bg-yellow-500 text-white"
      default:
        return "bg-gray-500 text-white"
    }
  }

  return (
    <AuthGuard>
      <div className="min-h-screen bg-slate-50 dark:bg-slate-900">
        {/* Header */}
        <header className="bg-white dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between items-center h-16">
              <div className="flex items-center space-x-3">
                <Link href="/dashboard">
                  <Button variant="ghost" size="sm">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Back to Dashboard
                  </Button>
                </Link>
                <div className="p-2 bg-red-100 dark:bg-red-900 rounded-lg">
                  <AlertTriangle className="h-6 w-6 text-red-600 dark:text-red-400" />
                </div>
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Security Alerts</h1>
                  <p className="text-sm text-slate-600 dark:text-slate-400">Critical Security Events</p>
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
          {/* Alert Summary */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <Card className="border-red-200 dark:border-red-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-red-600 dark:text-red-400">Critical Alerts</p>
                    <p className="text-2xl font-bold text-red-700 dark:text-red-300">
                      {logs.filter((log) => getSeverityLevel(log.message) === "critical").length}
                    </p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-500" />
                </div>
              </CardContent>
            </Card>

            <Card className="border-orange-200 dark:border-orange-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-orange-600 dark:text-orange-400">High Priority</p>
                    <p className="text-2xl font-bold text-orange-700 dark:text-orange-300">
                      {logs.filter((log) => getSeverityLevel(log.message) === "high").length}
                    </p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-orange-500" />
                </div>
              </CardContent>
            </Card>

            <Card className="border-yellow-200 dark:border-yellow-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-yellow-600 dark:text-yellow-400">Medium Priority</p>
                    <p className="text-2xl font-bold text-yellow-700 dark:text-yellow-300">
                      {logs.filter((log) => getSeverityLevel(log.message) === "medium").length}
                    </p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-yellow-500" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Filtering Controls */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <Filter className="h-5 w-5" />
                <span>Alert Filters</span>
              </CardTitle>
              <CardDescription>Filter security alerts by date range, timeframe, or limit results</CardDescription>
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

                {/* Alert Limit */}
                <div className="space-y-2">
                  <Label>Alert Limit</Label>
                  <Select value={limit.toString()} onValueChange={(value) => setLimit(Number.parseInt(value))}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="25">25 alerts</SelectItem>
                      <SelectItem value="50">50 alerts</SelectItem>
                      <SelectItem value="100">100 alerts</SelectItem>
                      <SelectItem value="200">200 alerts</SelectItem>
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

          {/* Alerts Display */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center space-x-2">
                <AlertTriangle className="h-5 w-5 text-red-500" />
                <span>Security Alerts</span>
              </CardTitle>
              <CardDescription>
                Displaying {logs.length} security alerts {autoRefresh && "(Auto-refreshing every 10 seconds)"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {error && (
                <div className="mb-4 p-3 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
                  <p className="text-sm text-yellow-800 dark:text-yellow-200">
                    API connection failed.
                  </p>
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-slate-200 dark:border-slate-700">
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Severity</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">ID</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Timestamp</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Source</th>
                      <th className="text-left p-3 font-medium text-slate-600 dark:text-slate-400">Alert Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logs.map((log) => {
                      const severity = getSeverityLevel(log.message)
                      return (
                        <tr
                          key={log.id}
                          className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 bg-red-50 dark:bg-red-900/20"
                        >
                          <td className="p-3">
                            <Badge className={`text-xs ${getSeverityColor(severity)}`}>{severity.toUpperCase()}</Badge>
                          </td>
                          <td className="p-3 text-sm font-mono">{log.id}</td>
                          <td className="p-3 text-sm">{formatTimestamp(log.timestamp)}</td>
                          <td className="p-3 text-sm font-mono">{log.source}</td>
                          <td className="p-3 text-sm">
                            <div className="flex items-center space-x-2">
                              <Badge variant="destructive" className="text-xs">
                                ALERT
                              </Badge>
                              <span className="font-medium text-red-700 dark:text-red-300">{log.message}</span>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>

                {logs.length === 0 && !isLoading && (
                  <div className="text-center py-8 text-slate-500 dark:text-slate-400">
                    <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-slate-300 dark:text-slate-600" />
                    <p className="text-lg font-medium mb-2">No security alerts found</p>
                    <p>No alerts match the selected criteria.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
    </AuthGuard>
  )
}
