import { type NextRequest, NextResponse } from "next/server"
import { Pool } from "pg"

// Use globalThis to avoid TypeScript errors about `global`/`process` during linting
const connectionString = (globalThis as any).process?.env?.DATABASE_URL as string | undefined

// Warn early if not configured
if (!connectionString) {
  console.error("DATABASE_URL is not set. /api/logs requires a configured database.")
}

// Reuse a global pool to avoid creating many connections during hot reloads
if ((globalThis as any).__pgPool === undefined) {
  ;(globalThis as any).__pgPool = connectionString ? new Pool({ connectionString }) : undefined
}
const pool: Pool | undefined = (globalThis as any).__pgPool

export async function GET(request: NextRequest) {
  try {
    if (!pool) {
      return NextResponse.json({ message: "DATABASE_URL not configured on server" }, { status: 500 })
    }

    const { searchParams } = new URL(request.url)
    let limit = Number.parseInt(searchParams.get("limit") || "50")
    const startParam = searchParams.get("start")
    const endParam = searchParams.get("end")
    const timeframe = searchParams.get("timeframe")

    // sanitize & cap limit
    if (!Number.isFinite(limit) || limit <= 0) limit = 50
    const MAX_LIMIT = 1000
    limit = Math.min(limit, MAX_LIMIT)

    // Build SQL with optional date range
    // Select all columns to support multiple table shapes (source/message columns OR a JSONB `log` column)
    let query = `SELECT * FROM logs`
    const values: any[] = []
    const where: string[] = []

    // Helper to push a timestamp range
    const pushRange = (startIso: string, endIso: string) => {
      const posStart = values.length + 1
      const posEnd = values.length + 2
      values.push(startIso, endIso)
      // cast to timestamptz for safety if your column is timestamptz
      where.push(`timestamp BETWEEN $${posStart}::timestamptz AND $${posEnd}::timestamptz`)
    }

    // If a timeframe like '10m', '1h', or '24h' is provided, compute start/end
    if (timeframe && !startParam && !endParam) {
      const m = timeframe.match(/^(\d+)(m|h|d)$/)
      if (!m) {
        return NextResponse.json({ message: "Invalid timeframe format. Examples: 10m, 1h, 2d" }, { status: 400 })
      }

      const val = Number(m[1])
      const unit = m[2]
      let ms = 0
      if (unit === "m") ms = val * 60 * 1000
      if (unit === "h") ms = val * 60 * 60 * 1000
      if (unit === "d") ms = val * 24 * 60 * 60 * 1000

      if (ms <= 0) {
        return NextResponse.json({ message: "Invalid timeframe value" }, { status: 400 })
      }

      const now = new Date()
      const computedStart = new Date(now.getTime() - ms).toISOString()
      const computedEnd = now.toISOString()
      pushRange(computedStart, computedEnd)
    } else if (startParam && endParam) {
      // validate ISO date strings
      const startDate = new Date(startParam)
      const endDate = new Date(endParam)
      if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
        return NextResponse.json({ message: "Invalid start or end date" }, { status: 400 })
      }
      pushRange(startDate.toISOString(), endDate.toISOString())
    }

    if (where.length) query += ` WHERE ${where.join(" AND ")}`

    const limitPos = values.length + 1
    query += ` ORDER BY timestamp DESC LIMIT $${limitPos}`
    values.push(limit)

    const result = await pool.query(query, values)

    // Map rows to a uniform shape. Support rows that store the event in a JSONB `log` column
    const logs = result.rows.map((r: any) => {
      const id = r.id != null ? Number(r.id) : null
      const timestamp = r.timestamp ? new Date(r.timestamp).toISOString() : null

      // Prefer dedicated columns, fall back to JSONB `log` payload when present
      let source: string | null = null
      let message: string = ""

      if (r.source !== undefined || r.message !== undefined) {
        source = r.source ?? null
        message = r.message ?? ""
      } else if (r.log) {
        // r.log is expected to be an object (JSONB)
        try {
          source = r.log.source ?? r.log.host ?? null
          if (typeof r.log.message === "string") message = r.log.message
          else message = JSON.stringify(r.log)
        } catch (e) {
          message = String(r.log)
        }
      } else {
        // generic fallback: stringify entire row
        message = JSON.stringify(r)
      }

      return { id, timestamp, source, message }
    })

    return NextResponse.json(logs)
  } catch (error) {
    console.error("[logs] error:", error)
    return NextResponse.json({ message: "Failed to fetch logs" }, { status: 500 })
  }
}
