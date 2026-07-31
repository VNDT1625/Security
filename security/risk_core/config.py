"""Immutable configuration for URL evidence collection and confidence."""

from __future__ import annotations

from dataclasses import dataclass

_NAMES = (
    "Tuổi tên miền",
    "Thời hạn tên miền",
    "Thông tin chủ sở hữu",
    "Nhà đăng ký tên miền",
    "Tên miền giả mạo",
    "Ký tự bất thường",
    "Subdomain đáng ngờ",
    "Không sử dụng HTTPS",
    "Chứng chỉ SSL/TLS bất thường",
    "Lỗi chứng chỉ",
    "Có trong blacklist",
    "Uy tín tên miền thấp",
    "Uy tín IP thấp",
    "Vị trí hạ tầng (tham khảo)",
    "Hosting chung với website xấu",
    "Chuyển hướng bất thường",
    "URL rút gọn",
    "Tham số URL bất thường",
    "Giả mạo nội dung thương hiệu",
    "Thông tin liên hệ",
    "Email khớp tên miền doanh nghiệp",
    "Địa chỉ doanh nghiệp công bố",
    "Danh tính pháp lý công bố",
    "Chính sách bảo mật",
    "Điều khoản và hoàn tiền",
    "Chất lượng nội dung đo được",
    "Tuyên bố giảm giá cực đoan",
    "Nội dung gây áp lực",
    "Yêu cầu dữ liệu nhạy cảm",
    "Biểu mẫu nhạy cảm không tin cậy",
    "Phương thức thanh toán",
    "Tài khoản nhận tiền",
    "Quyền trình duyệt",
    "Tệp tải xuống",
    "JavaScript độc hại",
    "Script bên thứ ba",
    "Popup lừa đảo",
    "Quảng cáo độc hại",
    "Sao chép nội dung",
    "Hình ảnh giả",
    "Mạng xã hội",
    "Lịch sử website",
    "Thay đổi nội dung bất thường",
    "DNS bất thường",
    "MX, SPF, DKIM, DMARC",
    "Title, favicon, metadata",
    "Kênh hỗ trợ",
    "Khiếu nại người dùng",
    "Đánh giá giả",
    "Điểm tổng hợp",
)
_COVERAGE_CLASSES = {
    "direct_behavior": 3.0,
    "strong_identity": 2.0,
    "reputation_infrastructure": 1.5,
    "business_context": 1.0,
    "weak_context": 0.75,
}
_DIRECT = {29, 30, 34, 35}
_STRONG = {5, 6, 7, 16, 18, 19, 28, 32, 46}
_REPUTATION = {1, 2, 4, 8, 9, 10, 11, 12, 13, 15, 17, 36, 42, 43, 44, 45, 48, 49}
_BUSINESS = {3, 20, 21, 22, 23, 24, 25, 27, 31, 33, 41, 47}

# Criteria that may contain an immediate access hazard. Membership alone never
# creates a floor: the engine also requires an allow-listed direct finding type,
# malicious status, strong evidence quality, and an independently actionable fact.
DANGEROUS_CRITERION_IDS = frozenset(
    {5, 6, 7, 10, 11, 13, 16, 19, 29, 30, 31, 32, 34, 35, 36, 37, 38, 40, 48}
)


@dataclass(frozen=True)
class CriterionConfig:
    criterion_id: int
    name: str
    coverage_weight: float


@dataclass(frozen=True)
class SourceConfig:
    source_id: str
    name: str
    family: str
    coverage_weight: float


@dataclass(frozen=True)
class RiskConfig:
    criteria: tuple[CriterionConfig, ...]
    sources: tuple[SourceConfig, ...]
    rules_version: str = "risk-rules-v3.0"
    normalization_version: str = "url-normalization-v2"

    def validate(self) -> None:
        ids = [c.criterion_id for c in self.criteria]
        if ids != list(range(1, 51)) or len(set(ids)) != 50:
            raise ValueError("criteria must contain unique ordered ids 1..50")
        if any(c.coverage_weight <= 0 for c in self.criteria[:49]):
            raise ValueError("applicable criteria require positive coverage_weight")
        if len(self.sources) != 14 or len({s.source_id for s in self.sources}) != 14:
            raise ValueError("exactly 14 unique external sources required")
        if any(not s.family or s.coverage_weight <= 0 for s in self.sources):
            raise ValueError("invalid source config")


def _coverage(i: int) -> float:
    if i in _DIRECT:
        key = "direct_behavior"
    elif i in _STRONG:
        key = "strong_identity"
    elif i in _REPUTATION:
        key = "reputation_infrastructure"
    elif i in _BUSINESS:
        key = "business_context"
    else:
        key = "weak_context"
    return _COVERAGE_CLASSES[key]


_SOURCE_ROWS = (
    (51, "ScamAdviser", "commercial_reputation"),
    (52, "Criminal IP", "infrastructure_ip"),
    (53, "Hudson Rock", "breach_infostealer"),
    (54, "Have I Been Pwned", "breach_infostealer"),
    (55, "PhishTank", "phishing_malware"),
    (56, "CyRadar", "phishing_malware"),
    (57, "National Cybersecurity Association", "phishing_malware"),
    (58, "NCSC", "phishing_malware"),
    (59, "ScamVN", "phishing_malware"),
    (60, "IP Quality Score", "infrastructure_ip"),
    (61, "Google Safe Browsing", "phishing_malware"),
    (62, "Bfore", "infrastructure_ip"),
    (63, "APIVoid", "infrastructure_ip"),
    (64, "PhishDestroy", "phishing_malware"),
)


def default_config() -> RiskConfig:
    criteria = tuple(
        CriterionConfig(
            i,
            _NAMES[i - 1],
            _coverage(i) if i < 50 else 0.75,
        )
        for i in range(1, 51)
    )
    sources = tuple(
        SourceConfig(str(i), name, family, 1.5)
        for i, name, family in _SOURCE_ROWS
    )
    cfg = RiskConfig(criteria, sources)
    cfg.validate()
    return cfg
