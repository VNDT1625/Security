"""Patch build-time public-origin sentinels in the generated Next.js bundle."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    build_dir = Path(sys.argv[1])
    replacements = {
        b"https://__PREWISE_SPACE_HOST__": os.environ["PREWISE_PUBLIC_BASE_URL"].encode(),
        b"wss://__PREWISE_SPACE_HOST__": os.environ["PREWISE_PUBLIC_WS_BASE_URL"].encode(),
    }
    for path in build_dir.rglob("*"):
        if not path.is_file():
            continue
        content = path.read_bytes()
        updated = content
        for marker, value in replacements.items():
            updated = updated.replace(marker, value)
        if updated != content:
            path.write_bytes(updated)


if __name__ == "__main__":
    main()
