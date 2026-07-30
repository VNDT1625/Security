/**
 * Factory chọn hiện thực ApiClient theo môi trường.
 *
 * `getApiClient()` đọc biến môi trường `NEXT_PUBLIC_API_MODE`:
 *   - "real" (mặc định) => RealApiClient (gọi REST `/v1/assess/*` + WS `/v1/chat`)
 *   - "mock" => MockApiClient (demo standalone, in-memory) — phải bật tường minh
 *
 * Trả về một singleton (cache instance) để toàn ứng dụng dùng chung một
 * client và một trạng thái. Nhờ interface chung, đổi `NEXT_PUBLIC_API_MODE`
 * giữa "mock"/"real" không cần sửa mã UI.
 *
 * _Requirements: 16.1, 16.2, 16.3, 16.5_
 */

import type { ApiClient, ApiMode } from "@/lib/api/client";
import { MockApiClient } from "@/lib/api/mock";
import { RealApiClient } from "@/lib/api/real";

export type { ApiClient, ApiMode } from "@/lib/api/client";

/** Singleton cache — đảm bảo dùng chung một instance trên toàn ứng dụng. */
let cachedClient: ApiClient | null = null;

/** Chuẩn hóa giá trị env thành ApiMode; mặc định "real". */
function resolveApiMode(): ApiMode {
    return process.env.NEXT_PUBLIC_API_MODE === "mock" ? "mock" : "real";
}

/**
 * Lấy ApiClient phù hợp với môi trường hiện tại (singleton).
 *
 * @returns instance ApiClient dùng chung.
 */
export function getApiClient(): ApiClient {
    if (cachedClient === null) {
        cachedClient =
            resolveApiMode() === "real"
                ? new RealApiClient()
                : new MockApiClient();
    }
    return cachedClient;
}

/**
 * Reset singleton đã cache. Hữu ích cho kiểm thử để buộc khởi tạo lại
 * client theo giá trị `NEXT_PUBLIC_API_MODE` mới.
 */
export function resetApiClient(): void {
    cachedClient = null;
}
