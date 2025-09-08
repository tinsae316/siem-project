const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "/api"

export interface SignupRequest {
  username: string
  email: string
  password: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  token: string
}

export interface LogEntry {
  id: number
  timestamp: string
  source: string
  message: string
}

class ApiService {
  private getAuthHeaders(): HeadersInit {
    const token = localStorage.getItem("siem_jwt_token")
    return {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
    }
  }

  async signup(data: SignupRequest): Promise<{ message: string }> {
    const response = await fetch(`${API_BASE_URL}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: "Signup failed" }))
      throw new Error(error.message || "Signup failed")
    }

    return response.json()
  }

  async login(data: LoginRequest): Promise<LoginResponse> {
    const response = await fetch(`${API_BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ message: "Login failed" }))
      throw new Error(error.message || "Invalid credentials")
    }

    return response.json()
  }

  async getLogs(params?: {
    start?: string
    end?: string
    timeframe?: string
    limit?: number
  }): Promise<LogEntry[]> {
    const searchParams = new URLSearchParams()
    if (params?.start) searchParams.append("start", params.start)
    if (params?.end) searchParams.append("end", params.end)
    if (params?.timeframe) searchParams.append("timeframe", params.timeframe)
    if (params?.limit) searchParams.append("limit", params.limit.toString())

    const response = await fetch(`${API_BASE_URL}/logs?${searchParams}`, {
      headers: this.getAuthHeaders(),
    })

    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem("siem_jwt_token")
        window.location.href = "/login"
        return []
      }
      throw new Error("Failed to fetch logs")
    }

    return response.json()
  }

  isAuthenticated(): boolean {
    return !!localStorage.getItem("siem_jwt_token")
  }

  logout(): void {
    localStorage.removeItem("siem_jwt_token")
  }
}

export const apiService = new ApiService()
