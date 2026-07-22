import { NextRequest, NextResponse } from 'next/server';
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export async function PATCH(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const response = await fetch(`${BACKEND_URL}/v1/feedback/admin/${encodeURIComponent(id)}`, { method: 'PATCH', headers: { Authorization: request.headers.get('authorization') || '', 'Content-Type': 'application/json' }, body: await request.text() });
  return NextResponse.json(await response.json(), { status: response.status });
}
