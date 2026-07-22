"""Re-encrypt stored LLM provider credentials after rotating API_KEY_PEPPER.

The previous pepper is read from OLD_API_KEY_PEPPER so neither pepper appears
in the command line. The update is atomic and safe to rerun.
"""

from __future__ import annotations

import base64
import hmac
import os
from hashlib import sha256

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select

from backend.db import SessionLocal
from backend.models import LLMProviderSetting, UserLLMProviderSetting
from backend.services.llm_provider_config_service import _decrypt, _encrypt

_CONTEXT = b"prewise:llm-provider-credential:v1"


def _cipher(pepper: str) -> Fernet:
    derived = hmac.new(pepper.encode("utf-8"), _CONTEXT, sha256).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def main() -> int:
    old_pepper = os.environ.get("OLD_API_KEY_PEPPER", "")
    if not old_pepper:
        raise RuntimeError("Set OLD_API_KEY_PEPPER before rotating credentials")

    old_cipher = _cipher(old_pepper)
    rotated = 0
    already_current = 0
    with SessionLocal() as session:
        for model in (LLMProviderSetting, UserLLMProviderSetting):
            records = session.execute(
                select(model).where(model.api_key_ciphertext != "")
            ).scalars()
            for record in records:
                try:
                    _decrypt(record.api_key_ciphertext)
                except ValueError:
                    try:
                        plaintext = old_cipher.decrypt(
                            record.api_key_ciphertext.encode("ascii")
                        ).decode("utf-8")
                    except (InvalidToken, UnicodeError, ValueError) as exc:
                        raise RuntimeError(
                            "A stored LLM credential matches neither the current nor old pepper"
                        ) from exc
                    record.api_key_ciphertext = _encrypt(plaintext)
                    rotated += 1
                else:
                    already_current += 1
        session.commit()

    print(f"LLM credentials rotated={rotated}, already_current={already_current}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
