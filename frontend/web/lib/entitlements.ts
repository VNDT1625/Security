import type { PlanTier } from "@/lib/types";

export function canUseProAI(tier: PlanTier | null | undefined): boolean {
    return tier != null && tier !== "free";
}
