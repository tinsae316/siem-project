import { type NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  try {
    const { username, email, password } = await request.json()

    // Basic validation
    if (!username || !email || !password) {
      return NextResponse.json({ message: "All fields are required" }, { status: 400 })
    }

    if (password.length < 6) {
      return NextResponse.json({ message: "Password must be at least 6 characters" }, { status: 400 })
    }

    // For MVP, we'll just simulate successful signup
    // In production, you'd save to database and hash password
    console.log("[v0] User signup attempt:", { username, email })

    return NextResponse.json({ message: "Account created successfully" })
  } catch (error) {
    console.error("[v0] Signup error:", error)
    return NextResponse.json({ message: "Internal server error" }, { status: 500 })
  }
}
