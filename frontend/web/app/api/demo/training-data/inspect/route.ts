import { NextRequest, NextResponse } from "next/server";

const BACKEND_URL =
    process.env.BACKEND_INTERNAL_URL ||
    process.env.NEXT_PUBLIC_BACKEND_URL ||
    "http://localhost:8000";

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const response = await fetch(`${BACKEND_URL}/v1/demo/training-data/inspect`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });

        const data = await response.json();
        return NextResponse.json(data, { status: response.status });
    } catch (error) {
        console.error("Error inspecting training data:", error);
        return NextResponse.json(
            { detail: "Không thể kiểm tra dữ liệu huấn luyện" },
            { status: 500 },
        );
    }
}
