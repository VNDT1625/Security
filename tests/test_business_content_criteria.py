from security.risk_core.business_content import (
    assess_business_address,
    assess_business_email,
    assess_coercive_content,
    assess_content_quality,
    assess_legal_identity,
    assess_privacy_policy,
    assess_promotion_claim,
    assess_terms_refund,
)


def test_business_email_compares_registrable_domains_but_does_not_judge_gmail() -> None:
    aligned = assess_business_email(
        "https://shop.example.co.uk",
        commercial=True,
        emails=["support@mail.example.co.uk"],
    )
    public_mailbox = assess_business_email(
        "https://shop.example.co.uk",
        commercial=True,
        emails=["example.shop@gmail.com"],
    )
    mismatched = assess_business_email(
        "https://shop.example.co.uk",
        commercial=True,
        emails=["billing@unrelated.test"],
    )

    assert aligned.status == "clean"
    assert public_mailbox.status == "not_applicable"
    assert mismatched.status == "suspicious"


def test_address_and_legal_identity_only_claim_publication_not_real_world_verification() -> None:
    address = assess_business_address(
        commercial=True,
        addresses=["12 Nguyen Hue Street, District 1, Ho Chi Minh City"],
    )
    legal = assess_legal_identity(
        commercial=True,
        legal_names=["Example Trading Company Ltd."],
    )

    assert address.status == "clean"
    assert "not verified" in address.summary
    assert legal.status == "clean"
    assert "not verified" in legal.summary
    assert assess_business_address(commercial=True, addresses=["Address"]).status == "suspicious"


def test_policy_checks_require_links_and_context() -> None:
    assert assess_privacy_policy(
        collects_sensitive_data=True,
        privacy_links=[],
    ).status == "suspicious"
    assert assess_privacy_policy(
        collects_sensitive_data=True,
        privacy_links=["https://example.test/privacy"],
    ).status == "clean"
    assert assess_terms_refund(commercial=False).status == "not_applicable"
    assert assess_terms_refund(commercial=True).status == "suspicious"


def test_content_quality_requires_measurable_strong_pattern() -> None:
    assert assess_content_quality(
        word_count=10,
        unique_word_ratio=0.1,
    ).status == "not_applicable"
    assert assess_content_quality(
        word_count=100,
        unique_word_ratio=0.1,
    ).status == "suspicious"
    assert assess_content_quality(
        word_count=100,
        unique_word_ratio=0.6,
        placeholder_hits=["lorem ipsum", "insert text here"],
    ).status == "suspicious"


def test_extreme_discount_is_only_a_claim_signal_and_urgency_needs_action_context() -> None:
    no_baseline = assess_promotion_claim(None)
    extreme = assess_promotion_claim(95)
    harmless_urgency = assess_coercive_content(
        urgency_hits=["act now"],
        sensitive_context=False,
        transaction_context=False,
        external_form=False,
    )
    coupled_urgency = assess_coercive_content(
        urgency_hits=["act now"],
        sensitive_context=True,
        transaction_context=False,
        external_form=False,
    )

    assert no_baseline.status == "not_applicable"
    assert extreme.status == "suspicious"
    assert extreme.severity <= 0.4
    assert harmless_urgency.status == "clean"
    assert coupled_urgency.status == "suspicious"
