import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL = process.env.BACKEND_INTERNAL_URL || process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
export const dynamic = "force-dynamic";

function headers(request: NextRequest): HeadersInit {
  return {
    "Content-Type": "application/json",
    Authorization: request.headers.get("authorization") || "",
  };
}

export async function GET(request: NextRequest) {
  const response = await fetch(`${BACKEND_URL}/admin/settings/ai-context-weight`, {
    headers: headers(request),
  });
  const data = await response.json();
  return NextResponse.json(data, { status: response.status });
}

export async function PUT(request: NextRequest) {
  const response = await fetch(`${BACKEND_URL}/admin/settings/ai-context-weight`, {
    method: "PUT",
    headers: headers(request),
    body: JSON.stringify(await request.json()),
  });
  const data = await response.json();
  return NextResponse.json(data, { status: response.status });
}
