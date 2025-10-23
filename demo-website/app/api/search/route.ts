import { NextRequest, NextResponse } from 'next/server';

const COLLECTOR_URL = process.env.COLLECTOR_URL || 'http://localhost:8000/collect';
function isLikelyXSS(raw: string): boolean {
  return /<script.*?>.*?<\/script>/i.test(raw) || /onerror=|onload=|alert\(/i.test(raw);
}
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
  const { query } = await req.json();
  const isAttack = isLikelyXSS(query);
  const outcome = 'success';
  const labels = isAttack ? ['search', 'attack', 'xss'] : ['search'];
  const category = ['web'];
  // Fix: Only send allowed values for severity (2 = ok, 5 = alert/attack)
  const severity = isAttack ? 5 : 2;
  const log = {
    timestamp: new Date().toISOString(),
    event: {
      action: 'user_search',
      outcome,
      category,
      severity,
      reason: isAttack ? 'XSS suspected in query' : undefined,
    },
    host: { hostname: req.headers.get('host') || 'demo-website' },
    source: { ip: req.headers.get('x-forwarded-for') || 'unknown' },
    http: { request: { method: 'POST' } },
    url: { path: '/search' },
    message: isAttack
      ? `Possible XSS payload detected in search: ${query}`
      : `User search: ${query}`,
    attack: isAttack
      ? { technique: 'xss', confidence: 'medium', input: query }
      : undefined,
    labels,
  };
  await sendLogToCollector(log);
  return NextResponse.json({ result: query });
}
