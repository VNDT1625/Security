import { NextResponse } from "next/server";
import { readFile } from "node:fs/promises";
import path from "node:path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const candidates = [
    path.resolve(process.cwd(), "logo-removebg.png"),
    path.resolve(process.cwd(), "..", "..", "logo-removebg.png"),
  ];

  for (const filePath of candidates) {
    try {
      const file = await readFile(filePath);
      return new NextResponse(file, {
        status: 200,
        headers: {
          "Content-Type": "image/png",
          "Content-Length": String(file.byteLength),
          "Cache-Control": "public, max-age=3600",
        },
      });
    } catch {
      // Try the next supported runtime location.
    }
  }

  return new NextResponse(null, { status: 404 });
}
