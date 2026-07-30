from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_desktop_production_bundle_has_https_api_fallback_and_build_gate() -> None:
    api_source = (ROOT / "frontend/desktop/src/api.ts").read_text(encoding="utf-8")
    package = (ROOT / "frontend/desktop/package.json").read_text(encoding="utf-8")
    validator = (
        ROOT / "frontend/desktop/scripts/validate-built-api.mjs"
    ).read_text(encoding="utf-8")

    assert 'const PRODUCTION_API_BASE = "https://api.prewise.site"' in api_source
    assert "import.meta.env.DEV ? DEVELOPMENT_API_BASE : PRODUCTION_API_BASE" in api_source
    assert "scripts/validate-built-api.mjs" in package
    assert "http://localhost:8000" in validator
    assert "still contains a localhost Core API fallback" in validator


def test_codespaces_cors_keeps_packaged_electron_origin() -> None:
    prepare = (ROOT / "scripts/codespaces-demo-prepare.sh").read_text(encoding="utf-8")

    assert (
        'CORS_ALLOW_ORIGINS=["https://prewise.site","https://www.prewise.site","null"]'
        in prepare
    )
    assert 'ensure_json_array_value CORS_ALLOW_ORIGINS "null"' in prepare
