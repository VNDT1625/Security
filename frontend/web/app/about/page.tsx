import type { Metadata } from "next";

/**
 * Trang About — Server Component tĩnh (không "use client", không hook).
 *
 * Render tĩnh để tối ưu tải và SEO (Requirements 10.1, 10.2). Toàn bộ nội dung
 * bằng tiếng Việt, khớp wireframe §1.4:
 *   - Hero/intro "Vì sao chúng tôi xây sản phẩm này"
 *   - Threat model (Attacker → Email/URL → Người & AI Agent) minh họa bằng JSX/CSS
 *   - Đội ngũ (thẻ thành viên placeholder)
 *   - Công nghệ (chips) + nút "Đọc tài liệu kỹ thuật"
 */

export const metadata: Metadata = {
    title: "Về chúng tôi — Prewise",
    description:
        "Vì sao chúng tôi xây Prewise: khi phishing không chỉ nhắm vào con người mà còn nhắm vào AI agent. Prompt injection chính là phishing dành cho AI.",
};

interface TeamMember {
    name: string;
    role: string;
    initials: string;
}

const TEAM: TeamMember[] = [
    { name: "Nguyễn Minh An", role: "Trưởng nhóm & Kiến trúc ML", initials: "MA" },
    { name: "Trần Thu Hà", role: "Kỹ sư Bảo mật AI", initials: "TH" },
    { name: "Lê Quốc Bảo", role: "Kỹ sư Frontend", initials: "QB" },
    { name: "Phạm Gia Linh", role: "Nghiên cứu NLP tiếng Việt", initials: "GL" },
];

const TECH_STACK: string[] = [
    "LightGBM",
    "PhoBERT",
    "ONNX",
    "FastAPI",
    "MCP Protocol",
];

export default function AboutPage() {
    return (
        <main className="mx-auto w-full max-w-5xl overflow-hidden px-4 py-10 sm:px-6 sm:py-16">
            {/* Hero / Intro — "Vì sao chúng tôi xây sản phẩm này" */}
            <section className="text-center">
                <p className="text-sm font-semibold uppercase tracking-widest text-neutral-500">
                    Về chúng tôi
                </p>
                <h1 className="mt-3 text-3xl font-bold leading-tight tracking-tight text-neutral-900 sm:text-4xl">
                    Vì sao chúng tôi xây sản phẩm này
                </h1>
                <div className="mx-auto mt-5 max-w-2xl space-y-4 text-base leading-7 text-neutral-600 sm:mt-6 sm:text-lg">
                    <p>
                        Trong nhiều năm, phishing nhắm vào con người: những email giả mạo,
                        đường link đánh cắp thông tin đăng nhập. Giờ đây, khi các AI agent
                        thay chúng ta đọc email, truy cập URL và tự động hành động, kẻ tấn
                        công chuyển hướng nhắm thẳng vào chính những AI agent đó.
                    </p>
                    <p className="text-lg font-semibold text-neutral-900 sm:text-xl">
                        “Prompt injection = phishing dành cho AI.”
                    </p>
                    <p>
                        Chúng tôi xây Prewise để trở thành lớp kiểm soát giữa nội dung
                        độc hại và các quy trình AI — đánh giá rủi ro tức thì, luôn kèm bằng
                        chứng minh bạch, để cả con người lẫn AI agent đều ra quyết định an
                        toàn hơn.
                    </p>
                </div>
            </section>

            {/* Threat model — sơ đồ minh họa bằng JSX/CSS */}
            <section className="mt-14 sm:mt-20">
                <h2 className="text-center text-2xl font-bold tracking-tight text-neutral-900">
                    Mô hình mối đe dọa
                </h2>
                <p className="mt-2 text-center text-neutral-600">
                    Attacker phát tán nội dung độc hại qua Email/URL, nhắm đồng thời vào
                    con người và AI agent.
                </p>

                <div className="mt-8 flex flex-col items-center gap-4 sm:mt-10 sm:gap-6 md:flex-row md:justify-center">
                    {/* Attacker */}
                    <div className="flex w-full max-w-xs flex-col items-center rounded-xl border border-risk-danger-border bg-risk-danger-bg px-6 py-5 text-center">
                        <span className="text-3xl" aria-hidden="true">
                            🕵️
                        </span>
                        <span className="mt-2 font-semibold text-risk-danger-fg">
                            Attacker
                        </span>
                        <span className="text-sm text-risk-danger-fg/80">
                            Kẻ tấn công
                        </span>
                    </div>

                    {/* Mũi tên */}
                    <span
                        className="rotate-90 text-2xl text-neutral-400 md:rotate-0"
                        aria-hidden="true"
                    >
                        →
                    </span>

                    {/* Email / URL */}
                    <div className="flex w-full max-w-xs flex-col items-center rounded-xl border border-risk-warn-border bg-risk-warn-bg px-6 py-5 text-center">
                        <span className="text-3xl" aria-hidden="true">
                            ✉️
                        </span>
                        <span className="mt-2 font-semibold text-risk-warn-fg">
                            Email / URL
                        </span>
                        <span className="text-sm text-risk-warn-fg/80">
                            Nội dung độc hại
                        </span>
                    </div>

                    {/* Mũi tên tách nhánh */}
                    <span
                        className="rotate-90 text-2xl text-neutral-400 md:rotate-0"
                        aria-hidden="true"
                    >
                        →
                    </span>

                    {/* Mục tiêu: Người và AI Agent */}
                    <div className="flex w-full max-w-xs flex-col gap-4">
                        <div className="flex flex-col items-center rounded-xl border border-neutral-300 bg-neutral-50 px-6 py-4 text-center">
                            <span className="text-2xl" aria-hidden="true">
                                🧑
                            </span>
                            <span className="mt-1 font-semibold text-neutral-800">
                                Người
                            </span>
                        </div>
                        <div className="flex flex-col items-center rounded-xl border border-neutral-300 bg-neutral-50 px-6 py-4 text-center">
                            <span className="text-2xl" aria-hidden="true">
                                🤖
                            </span>
                            <span className="mt-1 font-semibold text-neutral-800">
                                AI Agent
                            </span>
                        </div>
                    </div>
                </div>
            </section>

            {/* Đội ngũ */}
            <section className="mt-14 sm:mt-20">
                <h2 className="text-center text-2xl font-bold tracking-tight text-neutral-900">
                    Đội ngũ
                </h2>
                <div className="mt-8 grid grid-cols-1 gap-4 sm:mt-10 sm:grid-cols-2 sm:gap-6 lg:grid-cols-4">
                    {TEAM.map((member) => (
                        <div
                            key={member.name}
                            className="flex flex-col items-center rounded-xl border border-neutral-200 bg-white p-5 text-center shadow-sm sm:p-6"
                        >
                            <div
                                className="flex h-16 w-16 items-center justify-center rounded-full bg-neutral-100 text-xl font-semibold text-neutral-600"
                                aria-hidden="true"
                            >
                                {member.initials}
                            </div>
                            <p className="mt-4 font-semibold text-neutral-900">
                                {member.name}
                            </p>
                            <p className="mt-1 text-sm text-neutral-500">
                                {member.role}
                            </p>
                        </div>
                    ))}
                </div>
            </section>

            {/* Công nghệ */}
            <section className="mt-14 sm:mt-20">
                <h2 className="text-center text-2xl font-bold tracking-tight text-neutral-900">
                    Công nghệ
                </h2>
                <p className="mt-2 text-center text-neutral-600">
                    Nền tảng được xây trên các công nghệ ML và hạ tầng hiện đại.
                </p>
                <ul className="mt-8 flex flex-wrap justify-center gap-3">
                    {TECH_STACK.map((tech) => (
                        <li
                            key={tech}
                            className="rounded-full border border-neutral-300 bg-neutral-50 px-4 py-2 text-sm font-medium text-neutral-700"
                        >
                            {tech}
                        </li>
                    ))}
                </ul>
                <div className="mt-10 text-center">
                    <a
                        href="/analyze"
                        className="inline-flex min-h-11 w-full items-center justify-center rounded-lg bg-neutral-900 px-6 py-3 text-sm font-semibold text-white transition-colors hover:bg-neutral-700 sm:w-auto"
                    >
                        Mở demo kỹ thuật
                    </a>
                </div>
            </section>
        </main>
    );
}
