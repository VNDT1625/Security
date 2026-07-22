import { NextRequest, NextResponse } from 'next/server';
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export async function DELETE(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const response = await fetch(`${BACKEND_URL}/v1/waitlist/admin/${encodeURIComponent(id)}`, { method: 'DELETE', headers: { Authorization: request.headers.get('authorization') || '' } });
  return new NextResponse(null, { status: response.status });
}
