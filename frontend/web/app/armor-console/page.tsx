'use client';

import { useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from 'react';
import { useRouter } from 'next/navigation';
import {
    Activity,
    AlertCircle,
    CheckCircle2,
    Clock3,
    Database,
    KeyRound,
    Play,
    RefreshCw,
    Search,
    SlidersHorizontal,
    UserRound,
    WalletCards,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { PrewiseShell } from '@/components/PrewiseUI';
import styles from './page.module.css';
import { AdminFeedbackReleases } from './AdminFeedbackReleases';
import { shouldPollTraining, type TrainingLifecycleStatus } from './training-status';

interface Spec {
    id: string;
    name: string;
    path: string;
    tasksTotal: number;
    tasksCompleted: number;
    tasksRemaining: number;
}

interface TaskExecutionStatus {
    specId: string;
    status: 'idle' | 'running' | 'completed' | 'failed' | 'error';
    currentTask?: string;
    progress: number;
    message?: string;
}

interface ModelTrainingStatus {
    status: TrainingLifecycleStatus;
    currentModel?: string;
    progress: number;
    message?: string;
    enabled?: boolean;
    unavailableReason?: string | null;
    results?: {
        model: string;
        status: 'completed' | 'failed';
        f1_score?: number;
        f1?: number;
        accuracy?: number;
        error?: string;
    }[];
}

interface SpecExecutionCapability {
    enabled: boolean;
    reason?: string | null;
}

interface AIContextWeightSettings {
    percent: number;
    minPercent: number;
    maxPercent: number;
    absoluteMaxPercent: number;
    mode: 'shadow' | 'weighted';
}

interface LLMProviderSettings {
    provider: 'auto' | 'adapter' | 'local' | 'endpoint';
    baseUrl: string;
    model: string;
    apiKeyConfigured: boolean;
    configured: boolean;
    source: 'environment' | 'database';
    allowedProviders: Array<'adapter' | 'local' | 'endpoint'>;
    allowedModels: string[];
}

interface URLAssessmentCacheSettings {
    enabled: boolean;
    ttlSeconds: number;
}

interface OperationalSwitchesSettings {
    threatFeedSchedulerEnabled: boolean;
    openphishEnabled: boolean;
    operationalMaintenanceSchedulerEnabled: boolean;
}

type AdminView = 'overview' | 'users' | 'finance' | 'feedback' | 'operations';

interface AdminOverview {
    metrics: {
        usersTotal: number;
        activeUsers: number;
        scansTotal: number;
        dangerousScans: number;
        averageLatencyMs: number;
    };
    recentScans: Array<{ id: string; createdAt: string; modality: string; riskLevel: string; score: number; target: string }>;
    recentJobs: Array<{ id: string; type: string; status: string; progress: number; message?: string; createdAt: string }>;
    models: Array<{ id: string; name: string; modality: string; status: string; f1?: number; accuracy?: number; createdAt: string }>;
}

interface AdminUser {
    id: string;
    displayName: string;
    email: string;
    role: string;
    status: 'active' | 'suspended';
    currentPlan: string;
    subscriptionStatus?: string | null;
    scansTotal: number;
    createdAt: string;
    lastLoginAt?: string | null;
}

interface FinanceOverview {
    summary: {
        totalRevenueVnd: number;
        revenueLast30DaysVnd: number;
        pendingAmountVnd: number;
        paidOrders: number;
        pendingOrders: number;
        activeSubscriptions: number;
    };
    planDistribution: Record<string, number>;
    monthlyRevenue: Array<{ month: string; amountVnd: number }>;
    plans: Array<{ tier: string; label: string; monthlyPriceVnd?: number | null; yearlyPriceVnd?: number | null }>;
    recentOrders: Array<{
        id: string;
        reference: string;
        email: string;
        amountVnd: number;
        planTier?: string | null;
        billingPeriod?: string | null;
        status: string;
        provider: string;
        paidAt?: string | null;
        createdAt: string;
    }>;
}

const formatCurrency = (value: number) => `${new Intl.NumberFormat('vi-VN').format(value)} ₫`;
const formatDate = (value?: string | null) => value ? new Intl.DateTimeFormat('vi-VN', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value)) : 'Chưa có';

export function adminRiskTone(riskLevel: string): 'danger' | 'warn' | 'safe' {
    const normalized = riskLevel.toLowerCase();
    if (normalized === 'critical' || normalized === 'high') return 'danger';
    if (normalized === 'medium') return 'warn';
    return 'safe';
}

export default function AdminPage() {
    const router = useRouter();
    const { session, isHydrated } = useAuth();
    const isAdmin = session?.user.role === 'admin';
    const authHeaders = useMemo<Record<string, string>>(
        (): Record<string, string> => {
            if (!session) return {};
            return { Authorization: `Bearer ${session.token}` };
        },
        [session]
    );
    const [specs, setSpecs] = useState<Spec[]>([]);
    const [specExecution, setSpecExecution] = useState<SpecExecutionCapability>({ enabled: false });
    const [taskStatus, setTaskStatus] = useState<Record<string, TaskExecutionStatus>>({});
    const [trainingStatus, setTrainingStatus] = useState<ModelTrainingStatus>({
        status: 'idle',
        progress: 0
    });
    const [loading, setLoading] = useState(true);
    const [aiWeight, setAiWeight] = useState<AIContextWeightSettings>({ percent: 0, minPercent: 0, maxPercent: 40, absoluteMaxPercent: 100, mode: 'shadow' });
    const [aiWeightDraft, setAiWeightDraft] = useState(0);
    const [aiWeightMinDraft, setAiWeightMinDraft] = useState(0);
    const [aiWeightMaxDraft, setAiWeightMaxDraft] = useState(40);
    const [savingAIWeight, setSavingAIWeight] = useState(false);
    const [aiWeightNotice, setAiWeightNotice] = useState('');
    const [llmProvider, setLLMProvider] = useState<LLMProviderSettings>({
        provider: 'endpoint', baseUrl: '', model: '', apiKeyConfigured: false,
        configured: false, source: 'environment', allowedProviders: ['adapter', 'local', 'endpoint'], allowedModels: [],
    });
    const [llmDraft, setLLMDraft] = useState({ provider: 'endpoint' as LLMProviderSettings['provider'], baseUrl: '', model: '', apiKey: '', allowedProviders: ['adapter', 'local', 'endpoint'] as LLMProviderSettings['allowedProviders'], allowedModelsText: '' });
    const [savingLLM, setSavingLLM] = useState(false);
    const [testingLLM, setTestingLLM] = useState(false);
    const [llmNotice, setLLMNotice] = useState('');
    const [urlCache, setUrlCache] = useState<URLAssessmentCacheSettings>({ enabled: true, ttlSeconds: 900 });
    const [savingUrlCache, setSavingUrlCache] = useState(false);
    const [purgingUrlCache, setPurgingUrlCache] = useState(false);
    const [urlCacheNotice, setUrlCacheNotice] = useState('');
    const [operations, setOperations] = useState<OperationalSwitchesSettings>({
        threatFeedSchedulerEnabled: false,
        openphishEnabled: false,
        operationalMaintenanceSchedulerEnabled: false,
    });
    const [savingOperations, setSavingOperations] = useState(false);
    const [operationsNotice, setOperationsNotice] = useState('');
    const [activeView, setActiveView] = useState<AdminView>('overview');
    const [overview, setOverview] = useState<AdminOverview | null>(null);
    const [users, setUsers] = useState<AdminUser[]>([]);
    const [finance, setFinance] = useState<FinanceOverview | null>(null);
    const [centerLoading, setCenterLoading] = useState(true);
    const [centerNotice, setCenterNotice] = useState('');
    const [userQuery, setUserQuery] = useState('');
    const [updatingUserId, setUpdatingUserId] = useState('');
    const trainingPollRef = useRef(0);

    const loadSpecs = useCallback(async () => {
        if (!isAdmin) return;
        try {
            setLoading(true);
            const response = await fetch('/api/admin/specs', { headers: authHeaders });
            const data = await response.json() as { specs?: Spec[]; execution?: SpecExecutionCapability; detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể tải registry đặc tả');
            setSpecs(data.specs || []);
            setSpecExecution(data.execution || { enabled: false, reason: 'Không có executor đặc tả.' });
        } catch (error) {
            console.error('Failed to load specs:', error);
        } finally {
            setLoading(false);
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        loadSpecs();
    }, [loadSpecs]);

    const loadAdminCenter = useCallback(async () => {
        if (!isAdmin) return;
        setCenterLoading(true);
        setCenterNotice('');
        try {
            const [overviewResponse, usersResponse, financeResponse] = await Promise.all([
                fetch('/api/admin/overview', { headers: authHeaders, cache: 'no-store' }),
                fetch('/api/admin/users', { headers: authHeaders, cache: 'no-store' }),
                fetch('/api/admin/finance', { headers: authHeaders, cache: 'no-store' }),
            ]);
            if (!overviewResponse.ok || !usersResponse.ok || !financeResponse.ok) {
                const failed = [overviewResponse, usersResponse, financeResponse].find((response) => !response.ok);
                const detail = failed ? await failed.json().catch(() => ({})) as { detail?: string } : {};
                throw new Error(detail.detail || 'Không thể tải dữ liệu quản trị');
            }
            const [overviewData, usersData, financeData] = await Promise.all([
                overviewResponse.json() as Promise<AdminOverview>,
                usersResponse.json() as Promise<{ users: AdminUser[] }>,
                financeResponse.json() as Promise<FinanceOverview>,
            ]);
            setOverview(overviewData);
            setUsers(usersData.users || []);
            setFinance(financeData);
        } catch (error) {
            setCenterNotice(error instanceof Error ? error.message : 'Không thể tải dữ liệu quản trị');
        } finally {
            setCenterLoading(false);
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        void loadAdminCenter();
    }, [loadAdminCenter]);

    const loadAIWeight = useCallback(async () => {
        if (!isAdmin) return;
        try {
            const response = await fetch('/api/admin/settings/ai-context-weight', { headers: authHeaders });
            if (!response.ok) throw new Error('Không thể tải cấu hình AI');
            const data = await response.json() as AIContextWeightSettings;
            setAiWeight(data);
            setAiWeightDraft(data.percent);
            setAiWeightMinDraft(data.minPercent);
            setAiWeightMaxDraft(data.maxPercent);
        } catch (error) {
            setAiWeightNotice(error instanceof Error ? error.message : 'Không thể tải cấu hình AI');
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        loadAIWeight();
    }, [loadAIWeight]);

    const loadLLMProvider = useCallback(async () => {
        if (!isAdmin) return;
        try {
            const response = await fetch('/api/admin/settings/llm-provider', { headers: authHeaders, cache: 'no-store' });
            const data = await response.json() as LLMProviderSettings & { detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể tải cấu hình endpoint AI');
            setLLMProvider(data);
            setLLMDraft({ provider: data.provider, baseUrl: data.baseUrl, model: data.model, apiKey: '', allowedProviders: data.allowedProviders, allowedModelsText: data.allowedModels.join(', ') });
        } catch (error) {
            setLLMNotice(error instanceof Error ? error.message : 'Không thể tải cấu hình endpoint AI');
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        loadLLMProvider();
    }, [loadLLMProvider]);

    const loadURLCache = useCallback(async () => {
        if (!isAdmin) return;
        try {
            const response = await fetch('/api/admin/settings/url-assessment-cache', { headers: authHeaders });
            if (!response.ok) throw new Error('Không thể tải cấu hình cache');
            setUrlCache(await response.json() as URLAssessmentCacheSettings);
        } catch (error) {
            setUrlCacheNotice(error instanceof Error ? error.message : 'Không thể tải cấu hình cache');
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        loadURLCache();
    }, [loadURLCache]);

    const loadOperations = useCallback(async () => {
        if (!isAdmin) return;
        try {
            const response = await fetch('/api/admin/settings/operations', { headers: authHeaders });
            if (!response.ok) throw new Error('Không thể tải cấu hình vận hành');
            setOperations(await response.json() as OperationalSwitchesSettings);
        } catch (error) {
            setOperationsNotice(error instanceof Error ? error.message : 'Không thể tải cấu hình vận hành');
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        loadOperations();
    }, [loadOperations]);

    useEffect(() => {
        if (!isHydrated || isAdmin) return;
        router.replace(session ? '/analyze' : '/auth?next=/admin');
    }, [isAdmin, isHydrated, router, session]);

    // Web and desktop share the same admin settings in the Core database.
    // Re-read that source of truth when this admin surface becomes active again,
    // so a change made in either client is reflected in the other one.
    useEffect(() => {
        const syncAdminState = () => {
            if (!isAdmin) return;
            if (document.visibilityState !== 'visible') return;
            void loadAdminCenter();
            void loadAIWeight();
            void loadLLMProvider();
            void loadURLCache();
            void loadOperations();
            void loadSpecs();
        };
        window.addEventListener('focus', syncAdminState);
        document.addEventListener('visibilitychange', syncAdminState);
        return () => {
            window.removeEventListener('focus', syncAdminState);
            document.removeEventListener('visibilitychange', syncAdminState);
        };
    }, [isAdmin, loadAdminCenter, loadAIWeight, loadLLMProvider, loadURLCache, loadOperations, loadSpecs]);

    const saveAIWeight = async () => {
        setSavingAIWeight(true);
        setAiWeightNotice('');
        try {
            const response = await fetch('/api/admin/settings/ai-context-weight', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ...authHeaders },
                body: JSON.stringify({ percent: aiWeightDraft, minPercent: aiWeightMinDraft, maxPercent: aiWeightMaxDraft }),
            });
            const data = await response.json() as AIContextWeightSettings & { detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể lưu cấu hình AI');
            setAiWeight(data);
            setAiWeightDraft(data.percent);
            setAiWeightMinDraft(data.minPercent);
            setAiWeightMaxDraft(data.maxPercent);
            setAiWeightNotice(data.percent === 0 ? 'AI đang ở chế độ shadow.' : `Đã áp dụng AI Context tối đa ${data.percent}% cho các lần quét mới.`);
        } catch (error) {
            setAiWeightNotice(error instanceof Error ? error.message : 'Không thể lưu cấu hình AI');
        } finally {
            setSavingAIWeight(false);
        }
    };

    const saveLLMProvider = async () => {
        setSavingLLM(true);
        setLLMNotice('');
        try {
            const response = await fetch('/api/admin/settings/llm-provider', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ...authHeaders },
                body: JSON.stringify({
                    provider: llmDraft.provider,
                    baseUrl: llmDraft.baseUrl,
                    model: llmDraft.model,
                    allowedProviders: llmDraft.allowedProviders,
                    allowedModels: llmDraft.allowedModelsText.split(',').map(item => item.trim()).filter(Boolean),
                    ...(llmDraft.apiKey ? { apiKey: llmDraft.apiKey } : {}),
                }),
            });
            const data = await response.json() as LLMProviderSettings & { detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể lưu endpoint AI');
            setLLMProvider(data);
            setLLMDraft((current) => ({ ...current, apiKey: '' }));
            setLLMNotice('Đã lưu mã hóa và áp dụng ngay cho các lần quét mới; không cần restart backend.');
        } catch (error) {
            setLLMNotice(error instanceof Error ? error.message : 'Không thể lưu endpoint AI');
        } finally {
            setSavingLLM(false);
        }
    };

    const testLLMProvider = async () => {
        setTestingLLM(true);
        setLLMNotice('');
        try {
            const response = await fetch('/api/admin/settings/llm-provider', {
                method: 'POST', headers: authHeaders,
            });
            const data = await response.json() as { ok?: boolean; modelAvailable?: boolean; modelsCount?: number; completionOk?: boolean; detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể kiểm tra endpoint AI');
            setLLMNotice(data.modelAvailable
                ? `Kết nối và gọi model thành công · endpoint trả về ${data.modelsCount ?? 0} model.`
                : `Kết nối thành công nhưng không thấy model “${llmProvider.model}” trong danh sách endpoint.`);
        } catch (error) {
            setLLMNotice(error instanceof Error ? error.message : 'Không thể kiểm tra endpoint AI');
        } finally {
            setTestingLLM(false);
        }
    };

    const saveURLCache = async (enabled: boolean) => {
        setSavingUrlCache(true);
        setUrlCacheNotice('');
        try {
            const response = await fetch('/api/admin/settings/url-assessment-cache', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ...authHeaders },
                body: JSON.stringify({ enabled }),
            });
            const data = await response.json() as URLAssessmentCacheSettings & { detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể lưu cấu hình cache');
            setUrlCache(data);
            setUrlCacheNotice(data.enabled ? `Đã bật cache URL trong ${data.ttlSeconds / 60} phút.` : 'Đã tắt cache URL; mọi lần quét mới sẽ chạy lại.');
        } catch (error) {
            setUrlCacheNotice(error instanceof Error ? error.message : 'Không thể lưu cấu hình cache');
        } finally {
            setSavingUrlCache(false);
        }
    };

    const purgeURLCache = async () => {
        if (!window.confirm('Xóa toàn bộ kết quả URL đang lưu trong cache? Hành động này không xóa lịch sử quét.')) return;
        setPurgingUrlCache(true);
        setUrlCacheNotice('');
        try {
            const response = await fetch('/api/admin/settings/url-assessment-cache', {
                method: 'DELETE',
                headers: authHeaders,
            });
            const data = await response.json() as { purged?: number; detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể xóa cache URL');
            setUrlCacheNotice(`Đã xóa ${data.purged ?? 0} kết quả URL khỏi cache.`);
        } catch (error) {
            setUrlCacheNotice(error instanceof Error ? error.message : 'Không thể xóa cache URL');
        } finally {
            setPurgingUrlCache(false);
        }
    };

    const saveOperations = async (next: OperationalSwitchesSettings) => {
        setSavingOperations(true);
        setOperationsNotice('');
        try {
            const response = await fetch('/api/admin/settings/operations', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json', ...authHeaders },
                body: JSON.stringify(next),
            });
            const data = await response.json() as OperationalSwitchesSettings & { detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể lưu cấu hình vận hành');
            setOperations(data);
            setOperationsNotice('Đã lưu. Scheduler nhận thay đổi trong tối đa 60 giây, không cần restart server.');
        } catch (error) {
            setOperationsNotice(error instanceof Error ? error.message : 'Không thể lưu cấu hình vận hành');
        } finally {
            setSavingOperations(false);
        }
    };

    const updateUserStatus = async (user: AdminUser) => {
        const nextStatus: AdminUser['status'] = user.status === 'active' ? 'suspended' : 'active';
        const action = nextStatus === 'suspended' ? 'khóa' : 'kích hoạt lại';
        if (!window.confirm(`Xác nhận ${action} tài khoản ${user.email}?`)) return;
        setUpdatingUserId(user.id);
        setCenterNotice('');
        try {
            const response = await fetch(`/api/admin/users/${encodeURIComponent(user.id)}/status`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', ...authHeaders },
                body: JSON.stringify({ status: nextStatus }),
            });
            const data = await response.json() as { id?: string; status?: AdminUser['status']; detail?: string };
            if (!response.ok) throw new Error(data.detail || 'Không thể cập nhật tài khoản');
            setUsers((current) => current.map((item) => item.id === user.id ? { ...item, status: nextStatus } : item));
            setCenterNotice(`Đã ${action} tài khoản ${user.email}.`);
        } catch (error) {
            setCenterNotice(error instanceof Error ? error.message : 'Không thể cập nhật tài khoản');
        } finally {
            setUpdatingUserId('');
        }
    };

    const pollTrainingStatus = useCallback(async (pollId: number) => {
        if (!isAdmin) return;
        while (trainingPollRef.current === pollId) {
            await new Promise((resolve) => window.setTimeout(resolve, 3000));
            if (trainingPollRef.current !== pollId) return;

            try {
                const response = await fetch('/api/admin/models/train/status', {
                    headers: authHeaders,
                    cache: 'no-store',
                });
                const data = await response.json() as ModelTrainingStatus & { detail?: string; error?: string };
                if (!response.ok) {
                    throw new Error(data.detail || data.error || 'Không thể đọc trạng thái huấn luyện');
                }
                setTrainingStatus(data);
                if (!shouldPollTraining(data.status)) return;
            } catch (error) {
                setTrainingStatus((current) => ({
                    ...current,
                    status: 'error',
                    message: error instanceof Error ? error.message : 'Không thể đọc trạng thái huấn luyện',
                }));
                return;
            }
        }
    }, [authHeaders, isAdmin]);

    useEffect(() => {
        if (!isAdmin) return;
        const pollId = ++trainingPollRef.current;
        const loadTrainingStatus = async () => {
            try {
                const response = await fetch('/api/admin/models/train/status', {
                    headers: authHeaders,
                    cache: 'no-store',
                });
                const data = await response.json() as ModelTrainingStatus & { detail?: string; error?: string };
                if (!response.ok) {
                    throw new Error(data.detail || data.error || 'Không thể đọc trạng thái huấn luyện');
                }
                if (trainingPollRef.current !== pollId) return;
                setTrainingStatus(data);
                if (shouldPollTraining(data.status)) void pollTrainingStatus(pollId);
            } catch (error) {
                if (trainingPollRef.current !== pollId) return;
                setTrainingStatus({
                    status: 'error',
                    progress: 0,
                    message: error instanceof Error ? error.message : 'Không thể đọc trạng thái huấn luyện',
                });
            }
        };
        void loadTrainingStatus();
        return () => {
            if (trainingPollRef.current === pollId) trainingPollRef.current += 1;
        };
    }, [authHeaders, isAdmin, pollTrainingStatus]);

    const trainModels = async () => {
        const pollId = ++trainingPollRef.current;
        setTrainingStatus({
            status: 'training',
            progress: 0,
            message: 'Đang khởi tạo huấn luyện…'
        });

        try {
            const response = await fetch('/api/admin/models/train', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...authHeaders },
                body: JSON.stringify({
                    dataPath: 'data/demo_text_training.csv',
                    models: ['text']
                })
            });

            const data = await response.json() as { detail?: string; error?: string };
            if (!response.ok) throw new Error(data.detail || data.error || 'Không thể bắt đầu huấn luyện');
            void pollTrainingStatus(pollId);
        } catch (error) {
            setTrainingStatus({
                status: 'error',
                progress: 0,
                message: error instanceof Error ? error.message : 'Không thể bắt đầu huấn luyện'
            });
        }
    };

    const getStatusIcon = (status: string) => {
        switch (status) {
            case 'running':
            case 'training':
                return <RefreshCw className={styles.spin} aria-hidden />;
            case 'completed':
                return <CheckCircle2 className={styles.successIcon} aria-hidden />;
            case 'error':
            case 'failed':
                return <AlertCircle className={styles.errorIcon} aria-hidden />;
            default:
                return <Clock3 className={styles.mutedIcon} aria-hidden />;
        }
    };

    const totalTasks = specs.reduce((sum, spec) => sum + spec.tasksTotal, 0);
    const completedTasks = specs.reduce((sum, spec) => sum + spec.tasksCompleted, 0);
    const overallProgress = totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0;
    const activeAutomations = Object.values(operations).filter(Boolean).length;
    const rangeSpan = aiWeightMaxDraft - aiWeightMinDraft;
    const rangeProgress = rangeSpan > 0 ? ((aiWeightDraft - aiWeightMinDraft) / rangeSpan) * 100 : 100;
    const visibleUsers = users.filter((user) => `${user.displayName} ${user.email} ${user.currentPlan}`.toLowerCase().includes(userQuery.trim().toLowerCase()));
    const maxMonthlyRevenue = Math.max(1, ...(finance?.monthlyRevenue.map((item) => item.amountVnd) ?? []));

    if (!isHydrated || !isAdmin || loading) {
        return (
            <PrewiseShell>
                <main id="main-content" className={styles.loading} aria-busy="true">
                    <span><RefreshCw aria-hidden /></span>
                    <p>{!isHydrated ? 'Đang kiểm tra phiên…' : !isAdmin ? 'Đang chuyển hướng…' : 'Đang đồng bộ trung tâm vận hành…'}</p>
                </main>
            </PrewiseShell>
        );
    }

    return (
        <PrewiseShell>
        <div className={styles.console}>
            {/* Header */}
            <header className={styles.hero}>
                <div className={styles.heroTop}>
                    <div>
                        <p className={styles.eyebrow}><i /> PREWISE / ADMIN CENTER</p>
                        <h1>Trung tâm<br />quản trị<span>.</span></h1>
                        <p className={styles.lede}>Một không gian thống nhất để theo dõi hệ thống, quản lý người dùng, tài chính và lớp vận hành kỹ thuật.</p>
                    </div>
                    <div className={styles.liveBadge}>
                        <span><i /> HỆ THỐNG SẴN SÀNG</span>
                        <small>ADMIN CONTROL PLANE</small>
                    </div>
                </div>
                <div className={styles.overview} aria-label="Tổng quan vận hành">
                    <div><span>AI CONTEXT</span><strong>{aiWeightDraft}<small>%</small></strong><p>{aiWeight.mode === 'weighted' ? 'Weighted active' : 'Shadow mode'}</p></div>
                    <div><span>AI ENDPOINT</span><strong>{llmProvider.configured ? 'ON' : 'OFF'}</strong><p>{llmProvider.model || 'Chưa chọn model'}</p></div>
                    <div><span>URL CACHE</span><strong>{urlCache.enabled ? 'ON' : 'OFF'}</strong><p>TTL {urlCache.ttlSeconds / 60} phút</p></div>
                    <div><span>AUTOMATION</span><strong>{activeAutomations}<small>/3</small></strong><p>Tác vụ đang bật</p></div>
                    <div><span>SPEC PROGRESS</span><strong>{overallProgress}<small>%</small></strong><p>{completedTasks}/{totalTasks} tác vụ hoàn tất</p></div>
                </div>
            </header>

            <nav className={styles.adminTabs} aria-label="Khu vực quản trị">
                {[
                    ['overview', 'Tổng quan', Activity],
                    ['users', 'Người dùng', UserRound],
                    ['finance', 'Tài chính', WalletCards],
                    ['feedback', 'Phản hồi & phát hành', AlertCircle],
                    ['operations', 'Vận hành', SlidersHorizontal],
                ].map(([view, label, Icon]) => {
                    const target = view as AdminView;
                    const TabIcon = Icon as typeof Activity;
                    return <button key={target} type="button" className={activeView === target ? styles.activeTab : ''} aria-current={activeView === target ? 'page' : undefined} onClick={() => setActiveView(target)}><TabIcon aria-hidden /><span>{label as string}</span></button>;
                })}
            </nav>

            <main id="main-content" className={styles.viewArea}>
                {centerNotice && <div className={styles.centerNotice} role="status">{centerNotice}</div>}

                {activeView === 'overview' && <section className={styles.managementView} aria-labelledby="overview-title">
                    <div className={styles.managementHeading}>
                        <div><span>01 / EXECUTIVE OVERVIEW</span><h2 id="overview-title">Tổng quan quản trị</h2><p>Tình hình người dùng, lưu lượng phân tích và hoạt động hệ thống gần nhất.</p></div>
                        <button type="button" onClick={() => void loadAdminCenter()} disabled={centerLoading}><RefreshCw className={centerLoading ? styles.spin : ''} aria-hidden />Làm mới</button>
                    </div>
                    <div className={styles.metricGrid}>
                        <article><span>NGƯỜI DÙNG</span><strong>{overview?.metrics.usersTotal ?? 0}</strong><p>{overview?.metrics.activeUsers ?? 0} đang hoạt động</p></article>
                        <article><span>LƯỢT PHÂN TÍCH</span><strong>{overview?.metrics.scansTotal ?? 0}</strong><p>Tổng lượt đã ghi nhận</p></article>
                        <article><span>RỦI RO CAO</span><strong>{overview?.metrics.dangerousScans ?? 0}</strong><p>Tín hiệu cần chú ý</p></article>
                        <article><span>ĐỘ TRỄ TRUNG BÌNH</span><strong>{overview?.metrics.averageLatencyMs ?? 0}<small> ms</small></strong><p>Thời gian phản hồi</p></article>
                    </div>
                    <div className={styles.managementGrid}>
                        <article className={`${styles.dataPanel} ${styles.wideDataPanel}`}>
                            <header><div><span>LIVE ACTIVITY</span><h3>Phân tích gần đây</h3></div><b>{overview?.recentScans.length ?? 0} bản ghi</b></header>
                            <div className={styles.dataRows}>
                                {overview?.recentScans.length ? overview.recentScans.map((scan) => <div key={scan.id} className={styles.scanRow}>
                                    <span className={`${styles.riskMark} ${adminRiskTone(scan.riskLevel) === 'danger' ? styles.riskDanger : adminRiskTone(scan.riskLevel) === 'warn' ? styles.riskWarn : styles.riskSafe}`}>{Math.round(scan.score)}</span>
                                    <div><b>{scan.target}</b><small>{scan.modality.toUpperCase()} · {formatDate(scan.createdAt)}</small></div>
                                    <em>{scan.riskLevel}</em>
                                </div>) : <p className={styles.compactEmpty}>Chưa có lượt phân tích nào.</p>}
                            </div>
                        </article>
                        <article className={styles.dataPanel}>
                            <header><div><span>BACKGROUND</span><h3>Tác vụ gần đây</h3></div></header>
                            <div className={styles.dataRows}>
                                {overview?.recentJobs.length ? overview.recentJobs.map((job) => <div key={job.id} className={styles.jobRow}><i className={job.status === 'completed' ? styles.onlineDot : job.status === 'error' ? styles.errorDot : styles.pendingDot} /><div><b>{job.type}</b><small>{job.message || `${job.progress}%`} · {formatDate(job.createdAt)}</small></div></div>) : <p className={styles.compactEmpty}>Chưa có tác vụ nền.</p>}
                            </div>
                        </article>
                        <article className={styles.dataPanel}>
                            <header><div><span>MODEL REGISTRY</span><h3>Phiên bản mô hình</h3></div></header>
                            <div className={styles.dataRows}>
                                {overview?.models.length ? overview.models.map((model) => <div key={model.id} className={styles.modelRow}><div><b>{model.name}</b><small>{model.modality} · {model.status}</small></div><span>{model.f1 !== undefined && model.f1 !== null ? `F1 ${(model.f1 * 100).toFixed(1)}%` : '—'}</span></div>) : <p className={styles.compactEmpty}>Chưa có phiên bản mô hình.</p>}
                            </div>
                        </article>
                    </div>
                </section>}

                {activeView === 'users' && <section className={styles.managementView} aria-labelledby="users-title">
                    <div className={styles.managementHeading}>
                        <div><span>02 / IDENTITY MANAGEMENT</span><h2 id="users-title">Quản lý người dùng</h2><p>Tra cứu tài khoản, gói hiện tại, mức sử dụng và trạng thái truy cập.</p></div>
                        <label className={styles.userSearch}><Search aria-hidden /><span className="sr-only">Tìm người dùng</span><input value={userQuery} onChange={(event) => setUserQuery(event.target.value)} placeholder="Tên, email hoặc gói…" /></label>
                    </div>
                    <div className={styles.metricGrid}>
                        <article><span>TỔNG TÀI KHOẢN</span><strong>{users.length}</strong><p>Trong 100 tài khoản mới nhất</p></article>
                        <article><span>ĐANG HOẠT ĐỘNG</span><strong>{users.filter((user) => user.status === 'active').length}</strong><p>Có quyền truy cập</p></article>
                        <article><span>TÀI KHOẢN PRO+</span><strong>{users.filter((user) => user.currentPlan !== 'free').length}</strong><p>Đang có gói trả phí</p></article>
                        <article><span>ĐÃ TẠM KHÓA</span><strong>{users.filter((user) => user.status === 'suspended').length}</strong><p>Không thể đăng nhập</p></article>
                    </div>
                    <div className={`${styles.dataPanel} ${styles.userTable}`}>
                        <header><div><span>ACCOUNT DIRECTORY</span><h3>Danh sách tài khoản</h3></div><b>{visibleUsers.length} kết quả</b></header>
                        <div className={styles.tableHeader}><span>Người dùng</span><span>Vai trò</span><span>Gói</span><span>Lượt quét</span><span>Đăng nhập gần nhất</span><span>Trạng thái</span></div>
                        <div className={styles.userRows}>
                            {visibleUsers.map((user) => <div key={user.id} className={styles.userRow}>
                                <div className={styles.userIdentity}><i>{(user.displayName || user.email).slice(0, 2).toUpperCase()}</i><span><b>{user.displayName}</b><small>{user.email}</small></span></div>
                                <span className={styles.roleBadge}>{user.role}</span>
                                <span className={styles.planBadge}>{user.currentPlan.toUpperCase()}</span>
                                <span>{user.scansTotal}</span>
                                <span>{formatDate(user.lastLoginAt)}</span>
                                <div className={styles.userAction}><em className={user.status === 'active' ? styles.statusActive : styles.statusSuspended}>{user.status === 'active' ? 'Hoạt động' : 'Tạm khóa'}</em><button type="button" onClick={() => void updateUserStatus(user)} disabled={updatingUserId === user.id || user.id === session?.user.id}>{updatingUserId === user.id ? 'Đang lưu…' : user.status === 'active' ? 'Khóa' : 'Kích hoạt'}</button></div>
                            </div>)}
                            {!visibleUsers.length && <p className={styles.compactEmpty}>Không tìm thấy tài khoản phù hợp.</p>}
                        </div>
                    </div>
                </section>}

                {activeView === 'finance' && <section className={styles.managementView} aria-labelledby="finance-title">
                    <div className={styles.managementHeading}>
                        <div><span>03 / FINANCE &amp; BILLING</span><h2 id="finance-title">Tài chính &amp; gói dịch vụ</h2><p>Doanh thu đã xác nhận, đơn chờ thanh toán và phân bổ thuê bao theo gói.</p></div>
                        <small>Dữ liệu trực tiếp từ payment orders và subscriptions</small>
                    </div>
                    <div className={styles.metricGrid}>
                        <article><span>TỔNG DOANH THU</span><strong className={styles.currencyMetric}>{formatCurrency(finance?.summary.totalRevenueVnd ?? 0)}</strong><p>Đơn đã thanh toán</p></article>
                        <article><span>30 NGÀY GẦN NHẤT</span><strong className={styles.currencyMetric}>{formatCurrency(finance?.summary.revenueLast30DaysVnd ?? 0)}</strong><p>Doanh thu theo paid_at</p></article>
                        <article><span>ĐANG CHỜ</span><strong className={styles.currencyMetric}>{formatCurrency(finance?.summary.pendingAmountVnd ?? 0)}</strong><p>{finance?.summary.pendingOrders ?? 0} đơn chưa hoàn tất</p></article>
                        <article><span>THUÊ BAO ACTIVE</span><strong>{finance?.summary.activeSubscriptions ?? 0}</strong><p>{finance?.summary.paidOrders ?? 0} đơn đã thanh toán</p></article>
                    </div>
                    <div className={styles.financeGrid}>
                        <article className={styles.dataPanel}>
                            <header><div><span>REVENUE TREND</span><h3>Doanh thu 6 tháng</h3></div></header>
                            <div className={styles.revenueChart}>
                                {finance?.monthlyRevenue.length ? finance.monthlyRevenue.map((item) => <div key={item.month}><b>{formatCurrency(item.amountVnd)}</b><i style={{ height: `${Math.max(8, (item.amountVnd / maxMonthlyRevenue) * 100)}%` }} /><span>{item.month}</span></div>) : <p className={styles.compactEmpty}>Chưa có doanh thu được xác nhận.</p>}
                            </div>
                        </article>
                        <article className={styles.dataPanel}>
                            <header><div><span>PLAN MIX</span><h3>Phân bổ gói</h3></div></header>
                            <div className={styles.planList}>
                                {finance?.plans.map((plan) => <div key={plan.tier}><span><b>{plan.label}</b><small>{plan.monthlyPriceVnd ? `${formatCurrency(plan.monthlyPriceVnd)}/tháng` : 'Miễn phí / liên hệ'}</small></span><strong>{finance.planDistribution[plan.tier] ?? 0}</strong></div>)}
                                {!finance?.plans.length && <p className={styles.compactEmpty}>Chưa cấu hình bảng giá.</p>}
                            </div>
                        </article>
                    </div>
                    <div className={`${styles.dataPanel} ${styles.orderTable}`}>
                        <header><div><span>PAYMENT LEDGER</span><h3>Giao dịch gần đây</h3></div><b>{finance?.recentOrders.length ?? 0} giao dịch</b></header>
                        <div className={styles.orderHeader}><span>Mã tham chiếu</span><span>Khách hàng</span><span>Gói</span><span>Số tiền</span><span>Thời gian</span><span>Trạng thái</span></div>
                        <div className={styles.orderRows}>
                            {finance?.recentOrders.map((order) => <div key={order.id} className={styles.orderRow}><code>{order.reference}</code><span>{order.email}</span><span>{order.planTier?.toUpperCase() || 'CREDIT'}</span><b>{formatCurrency(order.amountVnd)}</b><span>{formatDate(order.paidAt || order.createdAt)}</span><em className={order.status === 'paid' ? styles.statusActive : order.status === 'pending' ? styles.statusPending : styles.statusSuspended}>{order.status}</em></div>)}
                            {!finance?.recentOrders.length && <p className={styles.compactEmpty}>Chưa có giao dịch nào.</p>}
                        </div>
                    </div>
                </section>}

                {activeView === 'feedback' && <div className={styles.managementView}><AdminFeedbackReleases authHeaders={authHeaders} /></div>}

                {activeView === 'operations' && <div className={styles.dashboard}>
                <div className={styles.sectionIntro}>
                    <div><span>01 / CONTROL PLANE</span><h2>Điều khiển hệ thống</h2></div>
                    <p>Cấu hình được lưu trực tiếp và áp dụng cho các lần xử lý tiếp theo.</p>
                </div>
                <section className={`${styles.panel} ${styles.llmPanel}`}>
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                        <div className="flex items-start gap-3">
                            <KeyRound className="w-8 h-8 text-cyan-400" />
                            <div>
                                <h2 className="text-2xl font-bold">Endpoint AI OpenAI-compatible</h2>
                                <p className="text-sm text-slate-400 mt-1">Khóa chỉ đi vào backend, được mã hóa trong database và không bao giờ được trả lại trình duyệt.</p>
                            </div>
                        </div>
                        <div className={`rounded-lg border px-4 py-3 ${llmProvider.configured ? 'border-emerald-700 bg-emerald-950/30' : 'border-amber-700 bg-amber-950/30'}`}>
                            <b className={llmProvider.configured ? 'text-emerald-300' : 'text-amber-300'}>{llmProvider.configured ? 'ĐÃ CẤU HÌNH' : 'CHƯA SẴN SÀNG'}</b>
                            <p className="mt-1 text-xs text-slate-400">Nguồn: {llmProvider.source === 'database' ? 'Admin database' : 'Biến môi trường'}</p>
                        </div>
                    </div>
                    <div className="mt-6 grid gap-4 md:grid-cols-2">
                        <label className="block">
                            <span className="mb-2 block text-sm font-medium text-slate-200">Chế độ provider</span>
                            <select className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-3 text-sm" value={llmDraft.provider} onChange={(event) => setLLMDraft({ ...llmDraft, provider: event.target.value as LLMProviderSettings['provider'] })}>
                                <option value="endpoint">API endpoint · dùng API key</option>
                                <option value="local">Local model · không gửi API key</option>
                                <option value="adapter">Adapter model của Prewise</option>
                                <option value="auto">Auto / tương thích cấu hình cũ</option>
                            </select>
                        </label>
                        <label className="block">
                            <span className="mb-2 block text-sm font-medium text-slate-200">Model ID</span>
                            <input className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-3 text-sm" value={llmDraft.model} onChange={(event) => setLLMDraft({ ...llmDraft, model: event.target.value })} placeholder="Ví dụ: model-id-from-/v1/models" autoComplete="off" />
                        </label>
                        <label className="block md:col-span-2">
                            <span className="mb-2 block text-sm font-medium text-slate-200">Base URL</span>
                            <input className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-3 font-mono text-sm" value={llmDraft.baseUrl} onChange={(event) => setLLMDraft({ ...llmDraft, baseUrl: event.target.value })} placeholder="http://127.0.0.1:20128/v1" inputMode="url" autoComplete="off" spellCheck={false} />
                            <small className="mt-2 block text-slate-500">HTTP chỉ được chấp nhận cho localhost/127.0.0.1; endpoint từ xa bắt buộc HTTPS.</small>
                        </label>
                        {llmDraft.provider === 'endpoint' && <label className="block md:col-span-2">
                            <span className="mb-2 block text-sm font-medium text-slate-200">API key {llmProvider.apiKeyConfigured && <em className="ml-2 not-italic text-emerald-300">● Đã lưu</em>}</span>
                            <input className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-3 font-mono text-sm" type="password" value={llmDraft.apiKey} onChange={(event) => setLLMDraft({ ...llmDraft, apiKey: event.target.value })} placeholder={llmProvider.apiKeyConfigured ? 'Để trống để giữ nguyên khóa đang lưu' : 'Nhập API key'} autoComplete="new-password" spellCheck={false} />
                        </label>}
                        <div className="md:col-span-2 rounded-lg border border-slate-700 bg-slate-950/50 p-4">
                            <span className="mb-1 block text-sm font-medium text-slate-200">Provider user được phép chọn</span>
                            <p className="mb-3 text-xs text-slate-500">Web chỉ hiển thị adapter/endpoint. Local chỉ dành cho Desktop khi Core API và LLM cùng chạy trên máy người dùng.</p>
                            <div className="flex flex-wrap gap-4">{(['adapter', 'local', 'endpoint'] as const).map(provider => <label key={provider} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={llmDraft.allowedProviders.includes(provider)} onChange={event => setLLMDraft(current => ({ ...current, allowedProviders: event.target.checked ? [...current.allowedProviders, provider] : current.allowedProviders.filter(item => item !== provider) }))} />{provider === 'local' ? 'local · Desktop/Core local' : provider}</label>)}</div>
                        </div>
                        <label className="block md:col-span-2">
                            <span className="mb-2 block text-sm font-medium text-slate-200">Model user được phép chọn</span>
                            <input className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-3 text-sm" value={llmDraft.allowedModelsText} onChange={event => setLLMDraft({ ...llmDraft, allowedModelsText: event.target.value })} placeholder="Để trống = mọi model; hoặc model-a, model-b" />
                            <small className="mt-2 block text-slate-500">Backend kiểm tra allowlist này; sửa HTML phía client không thể vượt qua.</small>
                        </label>
                    </div>
                    <div className="mt-5 flex flex-wrap items-center gap-3">
                        <button onClick={saveLLMProvider} disabled={savingLLM} className="rounded-lg bg-cyan-600 px-5 py-3 font-semibold hover:bg-cyan-700 disabled:bg-slate-700">{savingLLM ? 'Đang lưu...' : 'Lưu và áp dụng'}</button>
                        <button onClick={testLLMProvider} disabled={testingLLM || !llmProvider.configured} className="rounded-lg border border-slate-600 px-5 py-3 font-semibold text-slate-200 hover:border-cyan-500 disabled:opacity-40">{testingLLM ? 'Đang kiểm tra...' : 'Kiểm tra endpoint + model'}</button>
                        <span className="text-xs text-slate-500">Pro AI gửi nội dung/ngữ cảnh đã chọn tới endpoint này; Risk Core vẫn là lớp quyết định cuối.</span>
                    </div>
                    {llmNotice && <p className="mt-4 rounded-lg border border-cyan-900 bg-cyan-950/30 px-4 py-3 text-sm text-cyan-200" role="status">{llmNotice}</p>}
                </section>

                <section className={`${styles.panel} ${styles.aiPanel}`}>
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                        <div className="flex items-start gap-3">
                            <SlidersHorizontal className="w-8 h-8 text-cyan-400" />
                            <div>
                                <h2 className="text-2xl font-bold">AI Context Weight</h2>
                                <p className="text-sm text-slate-400 mt-1">Admin đặt sàn, trần và mặc định toàn cục. User Pro chỉ được chọn bên trong biên này.</p>
                            </div>
                        </div>
                        <div className="rounded-lg bg-slate-900 px-4 py-3 text-right">
                            <b className="text-3xl text-cyan-300">{aiWeightDraft}%</b>
                            <p className="text-xs text-slate-400">AI · Risk Core {100 - aiWeightDraft}%</p>
                        </div>
                    </div>
                    <div className="mt-6 grid gap-4 md:grid-cols-[1fr_auto] md:items-end">
                        <div className="grid grid-cols-2 gap-3 md:col-span-2">
                            <label><span className="mb-2 block text-sm text-slate-300">Sàn user (%)</span><input className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2" type="number" min="0" max={aiWeightMaxDraft} value={aiWeightMinDraft} onChange={event => { const value = Number(event.target.value); setAiWeightMinDraft(value); setAiWeightDraft(current => Math.max(value, current)); }} /></label>
                            <label><span className="mb-2 block text-sm text-slate-300">Trần user (%)</span><input className="w-full rounded-lg border border-slate-600 bg-slate-900 px-3 py-2" type="number" min={aiWeightMinDraft} max={aiWeight.absoluteMaxPercent} value={aiWeightMaxDraft} onChange={event => { const value = Number(event.target.value); setAiWeightMaxDraft(value); setAiWeightDraft(current => Math.min(value, current)); }} /></label>
                        </div>
                        <label className="block">
                            <span className="mb-2 block text-sm font-medium text-slate-200">Trọng số mặc định toàn cục</span>
                            <input
                                className="w-full accent-cyan-400"
                                type="range"
                                min={aiWeightMinDraft}
                                max={aiWeightMaxDraft}
                                step="1"
                                value={aiWeightDraft}
                                style={{ '--value': `${rangeProgress}%` } as CSSProperties}
                                onChange={(event) => setAiWeightDraft(Number(event.target.value))}
                                aria-label="Tỷ trọng AI Context"
                            />
                            <div className="mt-1 flex justify-between text-xs text-slate-500"><span>{aiWeightMinDraft}% · Sàn</span><span>{aiWeightMaxDraft}% · Trần</span></div>
                        </label>
                        <button
                            onClick={saveAIWeight}
                            disabled={savingAIWeight || (aiWeightDraft === aiWeight.percent && aiWeightMinDraft === aiWeight.minPercent && aiWeightMaxDraft === aiWeight.maxPercent)}
                            className="px-5 py-3 bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-700 disabled:cursor-not-allowed rounded-lg font-semibold transition-colors"
                        >
                            {savingAIWeight ? 'Đang lưu...' : 'Lưu tỷ trọng'}
                        </button>
                    </div>
                    <p className="mt-4 text-sm text-slate-400">Trạng thái mặc định: <b className={aiWeight.mode === 'weighted' ? 'text-cyan-300' : 'text-yellow-300'}>{aiWeight.mode === 'weighted' ? 'Weighted active' : 'Shadow'}</b>. Điểm kỹ thuật từ Risk Core ≥60 vẫn không bị AI làm giảm xuống dưới ngưỡng chặn.</p>
                    {aiWeightNotice && <p className="mt-3 text-sm text-slate-300" role="status">{aiWeightNotice}</p>}
                </section>

                <section className={`${styles.panel} ${styles.cachePanel}`}>
                    <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                        <div className="flex items-start gap-3">
                            <Database className="w-8 h-8 text-emerald-400" />
                            <div>
                                <h2 className="text-2xl font-bold">URL Result Cache</h2>
                                <p className="text-sm text-slate-400 mt-1">Trả kết quả đã lưu cho cùng URL và cùng cấu hình quét trong tối đa {urlCache.ttlSeconds / 60} phút.</p>
                            </div>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            aria-checked={urlCache.enabled}
                            onClick={() => saveURLCache(!urlCache.enabled)}
                            disabled={savingUrlCache}
                            className={`relative h-10 w-20 rounded-full transition-colors disabled:cursor-not-allowed ${urlCache.enabled ? 'bg-emerald-600' : 'bg-slate-700'}`}
                        >
                            <span className={`absolute top-1 h-8 w-8 rounded-full bg-white transition-transform ${urlCache.enabled ? 'translate-x-10' : 'translate-x-1'}`} />
                            <span className="sr-only">Bật hoặc tắt cache URL</span>
                        </button>
                    </div>
                    <div className="mt-4 flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-slate-400">{urlCache.enabled ? 'Đang bật: URL quick scan trùng khớp trả ngay từ database và không trừ lượt quét.' : 'Đang tắt: không đọc hoặc ghi cache; các bản ghi cũ vẫn được giữ tới khi hết hạn.'}</p><button type="button" onClick={() => void purgeURLCache()} disabled={purgingUrlCache} className="rounded-lg border border-rose-500/60 px-4 py-2 text-sm font-semibold text-rose-200 transition-colors hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-60">{purgingUrlCache ? 'Đang xóa...' : 'Xóa cache URL'}</button></div>
                    {urlCacheNotice && <p className="mt-3 text-sm text-slate-300" role="status">{urlCacheNotice}</p>}
                </section>

                <section className={`${styles.panel} ${styles.operationsPanel}`}>
                    <div className="flex items-start gap-3">
                        <RefreshCw className="w-8 h-8 text-amber-300" />
                        <div>
                            <h2 className="text-2xl font-bold">Threat Feed &amp; Maintenance</h2>
                            <p className="text-sm text-slate-400 mt-1">Bật/tắt tác vụ nền trực tiếp từ Admin. Các thay đổi được lưu trong database.</p>
                        </div>
                    </div>
                    <div className="mt-5 grid gap-3 md:grid-cols-3">
                        {[
                            ['threatFeedSchedulerEnabled', 'Tự cập nhật threat-feed', 'Chạy lịch đồng bộ nguồn URL độc hại.'],
                            ['openphishEnabled', 'Dùng OpenPhish', 'Cho phép nguồn OpenPhish tham gia lần đồng bộ tiếp theo.'],
                            ['operationalMaintenanceSchedulerEnabled', 'Tự dọn dữ liệu hết hạn', 'Dọn cache và lịch sử quét theo retention policy.'],
                        ].map(([key, title, description]) => {
                            const settingKey = key as keyof OperationalSwitchesSettings;
                            const enabled = operations[settingKey];
                            return <button
                                key={settingKey}
                                type="button"
                                role="switch"
                                aria-checked={enabled}
                                disabled={savingOperations}
                                onClick={() => void saveOperations({ ...operations, [settingKey]: !enabled })}
                                className={`rounded-xl border p-4 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${enabled ? 'border-emerald-500/60 bg-emerald-500/10' : 'border-slate-700 bg-slate-900/50 hover:border-slate-500'}`}
                            >
                                <span className={`mb-3 inline-block rounded-full px-2 py-1 text-xs font-semibold ${enabled ? 'bg-emerald-500/20 text-emerald-200' : 'bg-slate-700 text-slate-300'}`}>{enabled ? 'Đang bật' : 'Đang tắt'}</span>
                                <b className="block text-sm">{title}</b>
                                <span className="mt-1 block text-xs text-slate-400">{description}</span>
                            </button>;
                        })}
                    </div>
                    {operationsNotice && <p className="mt-4 text-sm text-slate-300" role="status">{operationsNotice}</p>}
                </section>

                {/* Model Training Section */}
                <section className={`${styles.panel} ${styles.trainingPanel}`}>
                    <div className="flex flex-col gap-4 mb-6 sm:flex-row sm:items-center sm:justify-between">
                        <div className="flex items-center gap-3">
                            <Database className="w-8 h-8 text-purple-400" />
                            <div>
                                <h2 className="text-2xl font-bold">Huấn luyện mô hình</h2>
                                <p className="text-sm text-slate-400">
                                    Huấn luyện lại text model với data/demo_text_training.csv
                                </p>
                                {trainingStatus.enabled === false && trainingStatus.unavailableReason && (
                                    <p className="mt-2 text-sm text-amber-300" role="status">
                                        Không khả dụng: {trainingStatus.unavailableReason}
                                    </p>
                                )}
                            </div>
                        </div>
                        <button
                            onClick={trainModels}
                            disabled={trainingStatus.status === 'training' || trainingStatus.enabled === false}
                            className="px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-slate-700 disabled:cursor-not-allowed rounded-lg flex items-center gap-2 transition-colors font-semibold"
                        >
                            {trainingStatus.status === 'training' ? (
                                <>
                                    <RefreshCw className="w-5 h-5 animate-spin" />
                                    Đang chạy…
                                </>
                            ) : (
                                <>
                                    <Play className="w-5 h-5" />
                                    Huấn luyện
                                </>
                            )}
                        </button>
                    </div>

                    {trainingStatus.status !== 'idle' && (
                        <div className="space-y-4">
                            <div className="flex items-center gap-3">
                                {getStatusIcon(trainingStatus.status)}
                                <div className="flex-1">
                                    <div className="flex justify-between mb-1">
                                        <span className="text-sm font-medium">
                                            {trainingStatus.currentModel || 'Đang chuẩn bị…'}
                                        </span>
                                        <span className="text-sm text-slate-400">
                                            {trainingStatus.progress}%
                                        </span>
                                    </div>
                                    <div className="w-full bg-slate-700 rounded-full h-2">
                                        <div
                                            className="bg-purple-500 h-2 rounded-full transition-all duration-300"
                                            style={{ width: `${trainingStatus.progress}%` }}
                                        />
                                    </div>
                                    {trainingStatus.message && (
                                        <p className="text-xs text-slate-400 mt-2">
                                            {trainingStatus.message}
                                        </p>
                                    )}
                                </div>
                            </div>

                            {trainingStatus.results && trainingStatus.results.length > 0 && (
                                <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
                                    {trainingStatus.results.map((result) => (
                                        <div
                                            key={result.model}
                                            className="bg-slate-700/50 rounded-lg p-4"
                                        >
                                            <h3 className="font-semibold mb-2">{result.model}</h3>
                                            <p className={result.status === 'completed' ? 'text-sm text-green-300' : 'text-sm text-red-300'}>
                                                {result.status === 'completed' ? 'Hoàn tất' : 'Thất bại'}
                                            </p>
                                            {result.error && <p className="mt-2 text-xs text-red-300">{result.error}</p>}
                                            {(result.f1_score !== undefined || result.f1 !== undefined) && (
                                                <p className="text-sm text-slate-300">
                                                    F1 Score: <span className="text-green-400 font-bold">
                                                        {((result.f1_score ?? result.f1 ?? 0) * 100).toFixed(2)}%
                                                    </span>
                                                </p>
                                            )}
                                            {result.accuracy !== undefined && (
                                                <p className="text-sm text-slate-300">
                                                    Accuracy: <span className="text-blue-400 font-bold">
                                                        {(result.accuracy * 100).toFixed(2)}%
                                                    </span>
                                                </p>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    )}
                </section>

                {/* Spec Execution Section */}
                <section className={styles.specSection}>
                    <div className={styles.specHeading}>
                        <div><span>02 / EXECUTION REGISTRY</span><h2>Tiến độ đặc tả</h2></div>
                        <p>{specs.length} đặc tả · {totalTasks} tác vụ được theo dõi</p>
                    </div>
                    {!specExecution.enabled && specExecution.reason && (
                        <p className="mb-4 rounded-lg border border-amber-800 bg-amber-950/30 px-4 py-3 text-sm text-amber-200" role="status">
                            Chỉ theo dõi: {specExecution.reason}
                        </p>
                    )}
                    {specs.length === 0 ? (
                        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-8 text-center">
                            <Clock3 aria-hidden />
                            <p className="text-slate-400">Chưa có đặc tả nào để theo dõi.</p>
                        </div>
                    ) : (
                        <div className="grid grid-cols-1 gap-6">
                            {specs.map((spec) => {
                                const status = taskStatus[spec.id];
                                const progressPercent = spec.tasksTotal > 0
                                    ? (spec.tasksCompleted / spec.tasksTotal) * 100
                                    : 0;

                                return (
                                    <div
                                        key={spec.id}
                                        className="bg-slate-800/50 border border-slate-700 rounded-xl p-6"
                                    >
                                        <div className="flex items-start justify-between mb-4">
                                            <div className="flex-1">
                                                <h3 className="text-xl font-bold mb-2">{spec.name}</h3>
                                                <p className="text-sm text-slate-400 mb-3">{spec.path}</p>
                                                <div className="flex gap-6 text-sm">
                                                    <span className="text-slate-300">
                                                        Tổng: <span className="font-semibold">{spec.tasksTotal}</span>
                                                    </span>
                                                    <span className="text-green-400">
                                                        Hoàn tất: <span className="font-semibold">{spec.tasksCompleted}</span>
                                                    </span>
                                                    <span className="text-yellow-400">
                                                        Còn lại: <span className="font-semibold">{spec.tasksRemaining}</span>
                                                    </span>
                                                </div>
                                            </div>
                                        </div>

                                        {/* Progress Bar */}
                                        <div className="mb-4">
                                            <div className="flex justify-between mb-1">
                                                <span className="text-sm font-medium">Tiến độ tổng</span>
                                                <span className="text-sm text-slate-400">
                                                    {progressPercent.toFixed(0)}%
                                                </span>
                                            </div>
                                            <div className="w-full bg-slate-700 rounded-full h-2">
                                                <div
                                                    className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                                                    style={{ width: `${progressPercent}%` }}
                                                />
                                            </div>
                                        </div>

                                        {/* Execution Status */}
                                        {status && status.status !== 'idle' && (
                                            <div className="flex items-center gap-3 p-4 bg-slate-700/50 rounded-lg">
                                                {getStatusIcon(status.status)}
                                                <div className="flex-1">
                                                    <p className="text-sm font-medium">
                                                        {status.currentTask || 'Đang xử lý…'}
                                                    </p>
                                                    {status.message && (
                                                        <p className="text-xs text-slate-400 mt-1">
                                                            {status.message}
                                                        </p>
                                                    )}
                                                </div>
                                                {status.status === 'running' && (
                                                    <div className="text-right">
                                                        <p className="text-sm text-slate-400">
                                                            {status.progress}%
                                                        </p>
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </section>
                </div>}
            </main>
        </div>
        </PrewiseShell>
    );
}
