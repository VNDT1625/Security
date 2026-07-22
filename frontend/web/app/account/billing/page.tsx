import PricingPlans from "@/components/PricingPlans";
import type { PricingTier } from "@/lib/types";

const tiers: PricingTier[] = [
    {
        id: "free",
        name: "FREE",
        priceMonthly: 0,
        priceYearly: 0,
        highlighted: false,
        ctaLabel: "Bắt đầu miễn phí",
        features: [
            { label: "1000 lượt Risk Core/ngày", included: true },
            { label: "5 AI credit/ngày", included: true },
            { label: "100 lượt chuyên sâu/ngày", included: true },
            { label: "10 phiên Web Sandbox/ngày", included: true },
            { label: "Không có Windows EXE Sandbox", included: false },
        ],
    },
    {
        id: "pro",
        name: "PRO",
        priceMonthly: 5_000,
        priceYearly: 4_167,
        highlighted: true,
        ctaLabel: "Nâng cấp PRO",
        features: [
            { label: "Risk Core không giới hạn", included: true },
            { label: "50 AI credit + 100 lượt chuyên sâu/ngày", included: true },
            { label: "Tặng 2 Sandbox credit khi kích hoạt", included: true },
            { label: "PRO 15 phút = 1 credit", included: true },
            { label: "Mua thêm 1 credit = 5.000đ qua SePay", included: true },
        ],
    },
    {
        id: "team",
        name: "TEAM / MAX",
        priceMonthly: 29_000,
        priceYearly: 24_167,
        highlighted: false,
        ctaLabel: "Nâng cấp MAX",
        features: [
            { label: "100 AI credit + 100 lượt chuyên sâu/ngày", included: true },
            { label: "Tặng 6 Sandbox credit khi kích hoạt", included: true },
            { label: "MAX GPU 30 phút = 3 credit", included: true },
            { label: "API key và MCP endpoint", included: true },
            { label: "Dashboard và hỗ trợ kỹ thuật", included: true },
        ],
    },
];

const faq = [
    [
        "Sandbox PRO và MAX tính phí thế nào?",
        "PRO dùng 1 credit/phiên 15 phút; MAX dùng 3 credit/phiên 30 phút. Mỗi credit mua thêm có giá demo 5.000đ qua SePay.",
    ],
    [
        "MAX khác PRO ở đâu?",
        "PRO dành cho EXE thông thường. MAX dùng máy Windows có GPU, thời lượng dài hơn và phù hợp ứng dụng nặng.",
    ],
    [
        "Dữ liệu có được dùng để huấn luyện không?",
        "Không mặc định. Mẫu chỉ được giữ tạm để chạy trong phiên sandbox và được xóa khi phiên kết thúc hoặc hết thời hạn lưu giữ.",
    ],
];

export default function AccountBillingPage() {
    return (
        <div className="pricing-page pricing-page-compact account-pricing">
            <PricingPlans tiers={tiers} />
            <section className="pricing-faq">
                <span>FAQ / CLARITY</span>
                <h2>Điều cần biết trước khi chọn.</h2>
                {faq.map((item) => (
                    <details key={item[0]}>
                        <summary>
                            {item[0]}
                            <i>＋</i>
                        </summary>
                        <p>{item[1]}</p>
                    </details>
                ))}
            </section>
        </div>
    );
}
