import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';
export const dynamic = 'force-dynamic';

export async function GET(request: NextRequest) {
    try {
        const response = await fetch(`${BACKEND_URL}/admin/models/train/status`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': request.headers.get('authorization') || '',
            },
        });

        const data = await response.json();
        return NextResponse.json(data, { status: response.status });
    } catch (error) {
        console.error('Error fetching training status:', error);
        return NextResponse.json(
            { error: 'Failed to fetch training status' },
            { status: 500 }
        );
    }
}
