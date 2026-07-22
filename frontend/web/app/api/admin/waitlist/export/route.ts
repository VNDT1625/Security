import { NextRequest, NextResponse } from 'next/server';
const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export async function GET(request: NextRequest) {
  const response = await fetch(`${BACKEND_URL}/v1/waitlist/admin/export.csv${request.nextUrl.search}`, { cache: 'no-store', headers: { Authorization: request.headers.get('authorization') || '' } });
  return new NextResponse(await response.arrayBuffer(), { status: response.status, headers: { 'Content-Type': response.headers.get('content-type') || 'text/csv', 'Content-Disposition': 'attachment; filename=prewise-waitlist.csv' } });
}
