import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import AdminPage, { adminRiskTone } from './page';

const mocks = vi.hoisted(() => ({
    replace: vi.fn(),
    useAuth: vi.fn(),
}));

vi.mock('next/navigation', () => ({ useRouter: () => ({ replace: mocks.replace }) }));
vi.mock('@/context/AuthContext', () => ({ useAuth: mocks.useAuth }));
vi.mock('@/components/PrewiseUI', () => ({
    PrewiseShell: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe('AdminPage access and risk presentation', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        vi.stubGlobal('fetch', vi.fn());
    });

    it('maps persisted risk levels to the intended admin color tone', () => {
        expect(adminRiskTone('critical')).toBe('danger');
        expect(adminRiskTone('high')).toBe('danger');
        expect(adminRiskTone('medium')).toBe('warn');
        expect(adminRiskTone('low')).toBe('safe');
        expect(adminRiskTone('safe')).toBe('safe');
    });

    it('redirects a hydrated non-admin without calling admin APIs', async () => {
        mocks.useAuth.mockReturnValue({
            isHydrated: true,
            session: { token: 'user-token', user: { id: 'user-1', role: 'user' } },
        });

        render(<AdminPage />);

        expect(screen.getByText('Đang chuyển hướng…')).toBeInTheDocument();
        await waitFor(() => expect(mocks.replace).toHaveBeenCalledWith('/analyze'));
        expect(fetch).not.toHaveBeenCalled();
    });
});
