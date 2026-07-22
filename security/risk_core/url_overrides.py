"""High-confidence URL risk floors shared by API and regression tests."""

from __future__ import annotations

from .overrides import OverrideRule

URL_OVERRIDE_RULES = (
    OverrideRule(
        "url-local-active-threat-feed-v1",
        frozenset({"local_feed_exact_url"}),
        90.0,
        "hard_block",
        "The exact URL matched an active, locally stored public threat-feed IOC.",
    ),
    OverrideRule(
        "distributed-exact-malicious-consensus-v1",
        frozenset({"distributed_exact_malicious_consensus"}),
        90.0,
        "hard_block",
        "Multiple independent endpoint sensors observed the exact URL as malicious.",
    ),
    OverrideRule(
        "urlvet-phishtank-confirmed-v1",
        frozenset({"urlvet_phishtank_confirmed"}),
        90.0,
        "hard_block",
        "The separate url.vet analyzer relayed an exact verified PhishTank match.",
    ),
    OverrideRule(
        "url-brand-credential-lure-v1",
        frozenset({"brand_domain_mismatch", "brand_credential_lure_combination"}),
        85.0,
        "hard_block",
        "A non-official brand domain combines impersonation with a credential lure.",
    ),
    OverrideRule(
        "url-brand-typo-credential-lure-v1",
        frozenset({"brand_typosquatting", "brand_credential_lure_combination"}),
        85.0,
        "hard_block",
        "A brand typo-squat combines impersonation with a credential lure.",
    ),
    OverrideRule(
        "url-disguised-executable-v1",
        frozenset({"disguised_executable_download"}),
        85.0,
        "hard_block",
        "A document-looking filename resolves to an executable payload.",
    ),
    OverrideRule(
        "url-unverified-payee-without-business-identity-v1",
        frozenset(
            {
                "unverified_payment_recipient",
                "missing_legal_identity",
                "metadata_identity_mismatch",
            }
        ),
        60.0,
        "soft_block",
        "The page requests payment to an unverified recipient, publishes no legal business identity, and presents inconsistent identity metadata.",
    ),
    OverrideRule(
        "url-brand-shared-hosting-lure-v1",
        frozenset(
            {
                "brand_domain_mismatch",
                "credential_lure_cluster",
                "shared_hosting_abuse_context",
            }
        ),
        85.0,
        "hard_block",
        "Brand impersonation and credential lures are combined on shared hosting.",
    ),
    OverrideRule(
        "url-deceptive-brand-credential-v1",
        frozenset(
            {"brand_domain_mismatch", "deceptive_subdomain", "credential_theft_intent"}
        ),
        85.0,
        "hard_block",
        "A deceptive brand subdomain requests sensitive credentials.",
    ),
    OverrideRule(
        "url-deceptive-brand-lure-v1",
        frozenset(
            {"brand_domain_mismatch", "deceptive_subdomain", "credential_lure_cluster"}
        ),
        85.0,
        "hard_block",
        "A deceptive brand subdomain contains a coordinated credential lure.",
    ),
    OverrideRule(
        "url-homoglyph-risky-tld-lure-v1",
        frozenset({"homoglyph", "risky_tld", "suspicious_keywords"}),
        85.0,
        "hard_block",
        "A brand look-alike combines an abused TLD with an authentication lure.",
    ),
    OverrideRule(
        "url-google-known-malicious-v1",
        frozenset({"external_google_web_risk_known_malicious"}),
        90.0,
        "hard_block",
        "Google Safe Browsing returned an exact known-threat match.",
    ),
    OverrideRule(
        "url-phishtank-verified-v1",
        frozenset({"external_phishtank_known_malicious"}),
        90.0,
        "hard_block",
        "PhishTank returned a verified and currently valid phishing match.",
    ),
)
