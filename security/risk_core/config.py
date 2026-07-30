"""Immutable, fail-fast CoreGuide v2 scoring configuration."""

from __future__ import annotations

from dataclasses import dataclass
from math import isclose

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
    "Email doanh nghiệp",
    "Địa chỉ doanh nghiệp",
    "Thông tin pháp lý",
    "Chính sách bảo mật",
    "Điều khoản và hoàn tiền",
    "Chất lượng nội dung",
    "Giá bán bất thường",
    "Nội dung gây áp lực",
    "Yêu cầu dữ liệu nhạy cảm",
    "Biểu mẫu đăng nhập",
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
_WEIGHTS = (
    1.5,
    1,
    1,
    1,
    3,
    2,
    3,
    1,
    1,
    2,
    4,
    2,
    2,
    0,
    1,
    3,
    1.5,
    2.5,
    3,
    1,
    1,
    1.5,
    1.5,
    0.5,
    0.5,
    1,
    2,
    3,
    3,
    3,
    2.5,
    3,
    1,
    2,
    2.5,
    1,
    1,
    1,
    1,
    1.5,
    1,
    1,
    1.5,
    1.5,
    0.5,
    1.5,
    0.5,
    1.5,
    1,
    0,
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
    max_weight: float
    coverage_weight: float


@dataclass(frozen=True)
class SourceConfig:
    source_id: str
    name: str
    family: str
    raw_weight: float
    coverage_weight: float


@dataclass(frozen=True)
class RiskConfig:
    criteria: tuple[CriterionConfig, ...]
    sources: tuple[SourceConfig, ...]
    family_caps: dict[str, float]
    internal_cap: float = 80.0
    external_cap: float = 20.0
    rules_version: str = "risk-rules-v2.2"
    weights_version: str = "risk-weights-v2"
    normalization_version: str = "url-normalization-v2"

    def validate(self) -> None:
        ids = [c.criterion_id for c in self.criteria]
        if ids != list(range(1, 51)) or len(set(ids)) != 50:
            raise ValueError("criteria must contain unique ordered ids 1..50")
        if any(c.coverage_weight <= 0 for c in self.criteria[:49]):
            raise ValueError("applicable criteria require positive coverage_weight")
        if self.criteria[49].max_weight != 0:
            raise ValueError("criterion 50 must have zero risk weight")
        if not isclose(sum(c.max_weight for c in self.criteria[:49]), 80.0, abs_tol=1e-9):
            raise ValueError("criteria 1..49 must total exactly 80")
        if len(self.sources) != 14 or len({s.source_id for s in self.sources}) != 14:
            raise ValueError("exactly 14 unique external sources required")
        if not isclose(sum(s.raw_weight for s in self.sources), 25.0, abs_tol=1e-9):
            raise ValueError("external raw weights must total exactly 25")
        if any(
            s.family not in self.family_caps or s.raw_weight < 0 or s.coverage_weight <= 0
            for s in self.sources
        ):
            raise ValueError("invalid source config")
        if not isclose(sum(self.family_caps.values()), 20.0, abs_tol=1e-9):
            raise ValueError("family caps must total exactly 20")


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
    (51, "ScamAdviser", 1.5, "commercial_reputation"),
    (52, "Criminal IP", 2.5, "infrastructure_ip"),
    (53, "Hudson Rock", 1, "breach_infostealer"),
    (54, "Have I Been Pwned", 0.5, "breach_infostealer"),
    (55, "PhishTank", 2.5, "phishing_malware"),
    (56, "CyRadar", 1.5, "phishing_malware"),
    (57, "National Cybersecurity Association", 1.5, "phishing_malware"),
    (58, "NCSC", 2.5, "phishing_malware"),
    (59, "ScamVN", 1.5, "phishing_malware"),
    (60, "IP Quality Score", 2, "infrastructure_ip"),
    (61, "Google Safe Browsing", 4, "phishing_malware"),
    (62, "Bfore", 1, "infrastructure_ip"),
    (63, "APIVoid", 2, "infrastructure_ip"),
    (64, "PhishDestroy", 1, "phishing_malware"),
)


def default_config() -> RiskConfig:
    criteria = tuple(
        CriterionConfig(i, _NAMES[i - 1], float(_WEIGHTS[i - 1]), _coverage(i) if i < 50 else 0.75)
        for i in range(1, 51)
    )
    sources = tuple(
        SourceConfig(str(i), name, family, float(weight), 1.5)
        for i, name, weight, family in _SOURCE_ROWS
    )
    cfg = RiskConfig(
        criteria,
        sources,
        {
            "phishing_malware": 11.0,
            "infrastructure_ip": 6.0,
            "commercial_reputation": 1.5,
            "breach_infostealer": 1.5,
        },
    )
    cfg.validate()
    return cfg
