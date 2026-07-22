import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
export const dynamic = "force-dynamic";

export async function GET(request: NextRequest) {
  const response = await fetch(`${BACKEND_URL}/admin/finance`, {
    cache: "no-store",
    headers: { Authorization: request.headers.get("authorization") || "" },
  });
  return NextResponse.json(await response.json(), { status: response.status });
}
