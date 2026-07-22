import { NextRequest } from 'next/server';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GET as getSpecs } from './specs/route';
import { POST as executeSpec } from './specs/execute/route';
import { GET as getSpecStatus } from './specs/[specId]/status/route';
import { POST as trainModel } from './models/train/route';
import { GET as getTrainingStatus } from './models/train/status/route';

function rejectFromBackend(status: number) {
    return new Response(JSON.stringify({ detail: 'backend rejected request' }), {
        status,
        headers: { 'Content-Type': 'application/json' },
    });
}

function request(path: string, init?: { method?: string; body?: string }) {
    return new NextRequest(`http://localhost${path}`, {
        method: init?.method,
        body: init?.body,
        headers: {
            Authorization: 'Bearer test-token',
            ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        },
    });
}

async function expectBackendStatus(response: Response, status: number) {
    expect(response.status).toBe(status);
    await expect(response.json()).resolves.toEqual({ detail: 'backend rejected request' });
}

describe('admin specs/models proxies', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('preserves backend status for spec list, execution, and job status', async () => {
        vi.stubGlobal('fetch', vi.fn()
            .mockResolvedValueOnce(rejectFromBackend(401))
            .mockResolvedValueOnce(rejectFromBackend(422))
            .mockResolvedValueOnce(rejectFromBackend(403)));

        await expectBackendStatus(await getSpecs(request('/api/admin/specs')), 401);
        await expectBackendStatus(await executeSpec(request('/api/admin/specs/execute', {
            method: 'POST',
            body: JSON.stringify({ specId: 'demo', mode: 'remaining' }),
        })), 422);
        await expectBackendStatus(await getSpecStatus(
            request('/api/admin/specs/demo/status'),
            { params: Promise.resolve({ specId: 'demo' }) },
        ), 403);
    });

    it('preserves backend status for model training and training status', async () => {
        vi.stubGlobal('fetch', vi.fn()
            .mockResolvedValueOnce(rejectFromBackend(409))
            .mockResolvedValueOnce(rejectFromBackend(503)));

        await expectBackendStatus(await trainModel(request('/api/admin/models/train', {
            method: 'POST',
            body: JSON.stringify({ dataPath: 'data/demo.csv', models: ['text'] }),
        })), 409);
        await expectBackendStatus(await getTrainingStatus(request('/api/admin/models/train/status')), 503);
    });
});
