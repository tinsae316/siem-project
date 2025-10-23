import { NextRequest, NextResponse } from 'next/server';
import Database from 'better-sqlite3';

const DB_PATH = process.env.DB_PATH || 'db/demo-users.db';
const COLLECTOR_URL = process.env.COLLECTOR_URL || 'http://localhost:8000/collect';

// Ensure users table and demo user exists
declare global { var __demo_db_init: boolean | undefined; }
function dbInit() {
  if (global.__demo_db_init) return;
  const db = new Database(DB_PATH);
  db.exec(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT);
    INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'password123'), ('test', 'test123');
  `);
  db.close();
  global.__demo_db_init = true;
}
dbInit();

async function sendLogToCollector(payload: any) {
  try {
    await fetch(COLLECTOR_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
  } catch (e) {}
}

export async function POST(req: NextRequest) {
  const body: any = await req.json();
  const invalidInput = !body || typeof body.username !== 'string' || typeof body.password !== 'string';
  if (invalidInput) {
    return NextResponse.json({ detail: 'Missing username or password.' }, { status: 400 });
  }
  // @ts-expect-error checked above
  const { username, password } = body;
  const db = new Database(DB_PATH);
  let result, outcome = 'failure', labels = ['auth'];
  try {
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (user && user.password === password) {
      outcome = 'success';
      result = { detail: 'Login successful.' };
    } else {
      result = { detail: 'Invalid username or password.' };
    }
  } finally {
    db.close();
  }
  // SIEM log
  const log = {
    timestamp: new Date().toISOString(),
    event: {
      action: 'user_login',
      outcome,
      category: 'authentication',
      severity: outcome === 'success' ? 2 : 5
    },
    host: { hostname: req.headers.get('host') || 'demo-website' },
    source: { ip: req.headers.get('x-forwarded-for') || 'unknown' },
    user: { name: username },
    http: { request: { method: 'POST' } },
    url: { path: '/login' },
    message: `User ${username} attempted to log in: ${outcome}`,
    labels,
  };
  sendLogToCollector(log);
  if (outcome === 'success') {
    return NextResponse.json(result);
  } else {
    return NextResponse.json(result, { status: 401 });
  }
}
