from security.risk_core.registrar_identity import assess_registrar_identity


def test_missing_registrar_is_unavailable_not_risky() -> None:
    result = assess_registrar_identity([None, "", None])
    assert result.status == "unavailable"


def test_single_public_registrar_completes_check() -> None:
    result = assess_registrar_identity(["NameCheap, Inc.", None])
    assert result.status == "clean"
    assert result.names == ("NameCheap, Inc.",)


def test_format_variants_are_same_registrar() -> None:
    result = assess_registrar_identity(["NameCheap, Inc.", "NAMECHEAP INC"])
    assert result.status == "clean"


def test_independent_registrar_conflict_is_detected() -> None:
    result = assess_registrar_identity(["NameCheap, Inc.", "Cloudflare Registrar, LLC"])
    assert result.status == "conflict"
    assert len(result.names) == 2
