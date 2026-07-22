"use client";

import Link from "next/link";
import { useState } from "react";

import type { PricingTier } from "../lib/types";
import styles from "./PricingPlans.module.css";

type Period = "monthly" | "yearly";

const money = (amount: number) => `${new Intl.NumberFormat("vi-VN").format(amount)}đ`;

export default function PricingPlans({ tiers }: { tiers: PricingTier[] }) {
    const [period, setPeriod] = useState<Period>("monthly");

    return (
        <section className={`pricing-plans ${styles.plans}`}>
            <div className="billing-toggle">
                <button
                    className={period === "monthly" ? "active" : ""}
                    onClick={() => setPeriod("monthly")}
                >
                    Theo tháng
                </button>
                <button
                    className={period === "yearly" ? "active" : ""}
                    onClick={() => setPeriod("yearly")}
                >
                    Theo năm <small>Tiết kiệm</small>
                </button>
            </div>
            <div className="pricing-grid">
                {tiers.map((tier, index) => {
                    const raw = period === "yearly" ? tier.priceYearly : tier.priceMonthly;
                    const amount = raw === null ? "Liên hệ" : raw === 0 ? "0đ" : money(raw);
                    const href =
                        tier.id === "free"
                            ? "/analyze"
                            : tier.id === "pro" || tier.id === "team"
                              ? `/account/checkout?plan=${tier.id}&period=${period}`
                              : "mailto:hello@prewise.site";
                    return (
                        <article className={tier.highlighted ? "featured" : ""} key={tier.id}>
                            {tier.highlighted && <em>RECOMMENDED</em>}
                            <span>
                                0{index + 1} / {tier.name}
                            </span>
                            <div className="plan-price">
                                <strong>{amount}</strong>
                                {raw !== null && raw > 0 && <small>/ tháng</small>}
                            </div>
                            {period === "yearly" && raw !== null && raw > 0 && (
                                <p className="saving">Thanh toán một lần theo năm</p>
                            )}
                            <ul>
                                {tier.features.map((feature) => (
                                    <li className={feature.included ? "" : "off"} key={feature.label}>
                                        <i>{feature.included ? "✓" : "—"}</i>
                                        {feature.label}
                                    </li>
                                ))}
                            </ul>
                            <Link href={href}>
                                {tier.ctaLabel}
                                <b>→</b>
                            </Link>
                        </article>
                    );
                })}
            </div>
        </section>
    );
}
