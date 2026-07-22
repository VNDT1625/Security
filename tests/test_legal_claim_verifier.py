from dataclasses import dataclass, replace

from security.legal.verifier import ClaimVerifier, verify_legal_claims


@dataclass
class Evidence:
    chunk_id: str = "law::c00001"
    section: str = "law::article-1"
    text: str = (
        "Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu cá nhân trong thời hạn 72 giờ. "
        "Mức phạt tiền là 20 triệu đồng."
    )
    legal_weight: str = "binding"
    status: str = "current"
    effective_date: str = "2026-01-01"
    status_checked_at: str = "2026-07-22"
    extraction_method: str = "native_pdf_text"
    text_verification_status: str = ""


def payload(*, claim_type="obligation", text=None, quote=None, **extra):
    result = {
        "status": "answered",
        "claims": [
            {
                "claim_id": "claim-1",
                "claim_type": claim_type,
                "text": text or "Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu trong 72 giờ.",
                "evidence": [
                    {
                        "provision_id": "law::article-1",
                        "chunk_id": "law::c00001",
                        "quote": quote
                        or (
                            "Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu cá nhân "
                            "trong thời hạn 72 giờ."
                        ),
                    }
                ],
            }
        ],
        "missing_facts": [],
        "uncertainties": [],
        "requires_human_review": False,
    }
    result.update(extra)
    return result


def codes(result):
    return {issue.code for issue in result.issues}


def test_accepts_grounded_binding_claim_and_duck_typed_mapping():
    result = verify_legal_claims(payload(), [Evidence().__dict__], as_of_date="2026-07-22")

    assert result.accepted is True
    assert result.status == "answered"
    assert result.used_chunk_ids == ("law::c00001",)
    assert result.verified_claims[0].claim_id == "claim-1"


def test_strict_schema_forbids_model_generated_metadata():
    generated = payload()
    generated["claims"][0]["evidence"][0]["document_number"] = "91/2025/QH15"

    result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")

    assert result.status == "insufficient_legal_basis"
    assert "schema_invalid" in codes(result)


def test_unknown_chunk_and_non_exact_quote_fail_closed():
    unknown = payload()
    unknown["claims"][0]["evidence"][0]["chunk_id"] = "invented"
    result = ClaimVerifier().verify(unknown, [Evidence()], as_of_date="2026-07-22")
    assert "unknown_chunk_id" in codes(result)

    invented_quote = payload(quote="Bên kiểm soát luôn luôn phải xóa ngay dữ liệu.")
    result = ClaimVerifier().verify(invented_quote, [Evidence()], as_of_date="2026-07-22")
    assert "quote_not_found" in codes(result)


def test_model_controlled_provision_id_must_match_cited_db_record():
    generated = payload()
    generated["claims"][0]["evidence"][0]["provision_id"] = "Điều 999 bịa đặt"

    result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")

    assert result.status == "insufficient_legal_basis"
    assert "unknown_provision_id" in codes(result)

    generated["claims"][0]["evidence"][0]["provision_id"] = "law::c00001"
    accepted = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")
    assert accepted.accepted
    assert accepted.verified_claims[0].evidence[0].provision_id == "law::article-1"


def test_policy_strategy_cannot_support_normative_claim():
    source = Evidence(legal_weight="policy_strategy")

    result = ClaimVerifier().verify(payload(), [source], as_of_date="2026-07-22")

    assert result.status == "insufficient_legal_basis"
    assert "binding_basis_required" in codes(result)


def test_temporal_checks_require_real_fresh_metadata():
    missing = Evidence(status_checked_at="")
    result = ClaimVerifier().verify(payload(), [missing], as_of_date="2026-07-22")
    assert "status_check_missing" in codes(result)

    stale = Evidence(status_checked_at="2026-07-21")
    result = ClaimVerifier().verify(payload(), [stale], as_of_date="2026-07-22")
    assert "status_check_stale" in codes(result)

    future = Evidence(effective_date="2026-07-23")
    result = ClaimVerifier().verify(payload(), [future], as_of_date="2026-07-22")
    assert "source_not_yet_effective" in codes(result)


def test_material_number_must_appear_in_claim_evidence():
    generated = payload(
        text="Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu trong 48 giờ.",
    )

    result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")

    assert "material_value_not_in_evidence" in codes(result)


def test_material_value_comparison_does_not_accept_numeric_substrings():
    source = Evidence(text="Theo Điều 20, bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu cá nhân.")
    generated = payload(
        text="Theo Điều 2, bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu.",
        quote="Theo Điều 20, bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu cá nhân.",
    )

    result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")

    assert "material_value_not_in_evidence" in codes(result)


def test_every_plain_digit_token_must_appear_in_exact_quote():
    for suffix in (" vào năm 2099", " với thời hạn 9999", " phiên bản 8888"):
        generated = payload(
            text=("Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu trong 72 giờ" + suffix + ".")
        )
        result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")
        assert result.accepted is False, suffix
        assert "digit_not_in_evidence" in codes(result), suffix


def test_rejects_citation_laundering_and_wrong_normative_polarity():
    source = Evidence(text="Dữ liệu cá nhân bao gồm thông tin gắn với một cá nhân cụ thể.")
    generated = payload(
        text="Doanh nghiệp được phép bán dữ liệu cá nhân.",
        claim_type="permission",
        quote="Dữ liệu cá nhân bao gồm thông tin gắn với một cá nhân cụ thể.",
    )

    result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")

    assert "citation_not_relevant" in codes(result)


def test_model_cannot_label_normative_text_as_fact_to_bypass_binding_gate():
    generated = payload(claim_type="fact")

    result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")

    assert result.status == "insufficient_legal_basis"
    assert "claim_type_mismatch" in codes(result)


def test_rejects_supported_prefix_with_unsupported_normative_suffix():
    generated = payload(
        text=(
            "Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu trong 72 giờ "
            "và phải công khai sự việc trên báo chí."
        ),
    )

    result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")

    assert "citation_not_relevant" in codes(result)


def test_unverified_ocr_as_sole_basis_requires_human_review():
    source = Evidence(extraction_method="tesseract_ocr", text_verification_status="pending")

    result = ClaimVerifier().verify(payload(), [source], as_of_date="2026-07-22")

    assert result.status == "human_legal_review"
    assert result.requires_human_review is True
    assert "unverified_ocr_sole_basis" in codes(result)


def test_human_verified_ocr_can_support_answer():
    source = Evidence(
        extraction_method="tesseract_ocr",
        text_verification_status="human_verified",
    )

    result = ClaimVerifier().verify(payload(), [source], as_of_date="2026-07-22")

    assert result.status == "answered"
    assert result.accepted is True


def test_safe_upstream_status_is_never_upgraded_to_answered():
    generated = {
        "status": "conflicting_sources",
        "claims": [],
        "missing_facts": [],
        "uncertainties": ["sources conflict"],
        "requires_human_review": True,
    }

    result = ClaimVerifier().verify(generated, [], as_of_date="2026-07-22")

    assert result.status == "conflicting_sources"
    assert result.accepted is False
    assert result.requires_human_review is True


def test_unicode_whitespace_normalizes_but_zero_width_cannot_hide_obligation():
    grounded = payload(
        text="BÊN KIỂM SOÁT DỮ LIỆU CÁ NHÂN PHẢI XÓA DỮ LIỆU TRONG 72 GIỜ.",
        quote=(
            "Bên kiểm soát dữ liệu cá nhân phải\u00a0xóa dữ liệu cá nhân trong thời hạn 72 giờ."
        ),
    )
    assert ClaimVerifier().verify(grounded, [Evidence()], as_of_date="2026-07-22").accepted

    concealed = payload(claim_type="fact")
    concealed["claims"][0]["text"] = concealed["claims"][0]["text"].replace("phải", "ph\u200bải")
    concealed["claims"][0]["evidence"][0]["quote"] = concealed["claims"][0]["evidence"][0][
        "quote"
    ].replace("phải", "ph\u200bải")
    source = replace(
        Evidence(),
        text=Evidence().text.replace("phải", "ph\u200bải"),
        legal_weight="policy_strategy",
    )
    result = ClaimVerifier().verify(concealed, [source], as_of_date="2026-07-22")
    assert result.status == "insufficient_legal_basis"
    assert "unsafe_unicode" in codes(result)
    assert "claim_type_mismatch" in codes(result)


def test_cross_script_homoglyph_cannot_downgrade_claim_type():
    # First letter is Cyrillic er, visually similar to Latin p.
    disguised_word = "\u0440hải"
    generated = payload(claim_type="fact")
    generated["claims"][0]["text"] = generated["claims"][0]["text"].replace("phải", disguised_word)
    generated["claims"][0]["evidence"][0]["quote"] = generated["claims"][0]["evidence"][0][
        "quote"
    ].replace("phải", disguised_word)
    source = replace(
        Evidence(),
        text=Evidence().text.replace("phải", disguised_word),
        legal_weight="policy_strategy",
    )

    result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")

    assert "unsafe_unicode" in codes(result)
    assert result.accepted is False


def test_quote_cannot_crop_condition_or_exception_from_same_sentence():
    source = Evidence(
        text=(
            "Trong trường hợp có yêu cầu, Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu "
            "cá nhân trong thời hạn 72 giờ, trừ khi pháp luật quy định khác."
        )
    )
    generated = payload(
        quote=("Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu cá nhân trong thời hạn 72 giờ")
    )

    result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")

    assert "citation_omits_qualifier" in codes(result)


def test_quote_cannot_keep_condition_but_crop_a_second_exception():
    source = Evidence(
        text=(
            "Trong trường hợp có yêu cầu, Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu "
            "cá nhân trong thời hạn 72 giờ, trừ khi pháp luật quy định khác."
        )
    )
    generated = payload(
        quote=(
            "Trong trường hợp có yêu cầu, Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu "
            "cá nhân trong thời hạn 72 giờ"
        )
    )

    result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")

    assert "citation_omits_qualifier" in codes(result)


def test_duration_written_in_words_must_be_in_evidence():
    generated = payload(
        text="Bên kiểm soát dữ liệu cá nhân phải xóa dữ liệu trong bốn giờ.",
    )

    result = ClaimVerifier().verify(generated, [Evidence()], as_of_date="2026-07-22")

    assert "material_value_not_in_evidence" in codes(result)


def test_unknown_extraction_method_and_homoglyph_ocr_require_review():
    for method in ("", "tesseract_scan", "\u043ecr_tesseract"):
        result = ClaimVerifier().verify(
            payload(),
            [Evidence(extraction_method=method)],
            as_of_date="2026-07-22",
        )
        assert result.status == "human_legal_review"
        assert "unverified_ocr_sole_basis" in codes(result)


def test_native_policy_source_cannot_launder_unverified_binding_ocr():
    ocr = Evidence(chunk_id="ocr", extraction_method="ocr_tesseract")
    policy = Evidence(
        chunk_id="policy",
        section="policy::section-1",
        legal_weight="policy_strategy",
    )
    generated = payload()
    generated["claims"][0]["evidence"][0]["chunk_id"] = "ocr"
    generated["claims"][0]["evidence"].append(
        {
            "provision_id": "policy::section-1",
            "chunk_id": "policy",
            "quote": generated["claims"][0]["evidence"][0]["quote"],
        }
    )

    result = ClaimVerifier().verify(generated, [ocr, policy], as_of_date="2026-07-22")

    assert result.status == "human_legal_review"
    assert "unverified_ocr_sole_basis" in codes(result)


def test_duplicate_context_ids_fail_closed_even_when_records_match():
    result = ClaimVerifier().verify(payload(), [Evidence(), Evidence()], as_of_date="2026-07-22")
    assert result.status == "insufficient_legal_basis"
    assert "context_duplicate_id" in codes(result)


def test_permission_prohibition_polarity_survives_unicode_whitespace():
    source = Evidence(text="Doanh nghiệp không\u00a0được phép bán dữ liệu cá nhân.")
    generated = payload(
        claim_type="permission",
        text="Doanh nghiệp được phép bán dữ liệu cá nhân.",
        quote="Doanh nghiệp không\u00a0được phép bán dữ liệu cá nhân.",
    )

    result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")

    assert "citation_not_relevant" in codes(result)


def test_legality_synonyms_cannot_be_labelled_as_non_normative_fact():
    for phrase in ("hợp pháp", "không hợp pháp", "trái pháp luật", "cần xóa"):
        text = f"Việc doanh nghiệp bán dữ liệu cá nhân là {phrase}."
        source = Evidence(text=text, legal_weight="policy_strategy")
        generated = payload(claim_type="fact", text=text, quote=text)
        result = ClaimVerifier().verify(generated, [source], as_of_date="2026-07-22")
        assert result.accepted is False, phrase
        assert "claim_type_mismatch" in codes(result), phrase
