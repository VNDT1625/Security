import { NextRequest, NextResponse } from 'next/server';
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export const dynamic = 'force-dynamic';
export async function GET(request: NextRequest) {
  const response = await fetch(`${BACKEND_URL}/v1/waitlist/admin/releases`, { cache: 'no-store', headers: { Authorization: request.headers.get('authorization') || '' } });
  return NextResponse.json(await response.json(), { status: response.status });
}
export async function POST(request: NextRequest) {
  const response = await fetch(`${BACKEND_URL}/v1/waitlist/admin/releases`, { method: 'POST', headers: { Authorization: request.headers.get('authorization') || '', 'Content-Type': 'application/json' }, body: await request.text() });
  return NextResponse.json(await response.json(), { status: response.status });
}
