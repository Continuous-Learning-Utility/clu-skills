#!/usr/bin/env python3
"""Compute SHA-256 hashes for a skill's files.

Run this before submitting a PR to get the hash snippet to paste into registry.json.

Usage:
    python scripts/compute_hashes.py skills/my-skill/
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

_SKILL_FILES = ("skill.yaml", "prompt.md")


def compute(skill_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for fname in _SKILL_FILES:
        fpath = skill_dir / fname
        if fpath.is_file():
            hashes[fname] = hashlib.sha256(fpath.read_bytes()).hexdigest()
        else:
            print(f"Warning: {fname} not found in {skill_dir}", file=sys.stderr)
    return hashes


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"Usage: python {argv[0]} <skill-dir>", file=sys.stderr)
        return 1

    skill_dir = Path(argv[1]).resolve()
    if not skill_dir.is_dir():
        print(f"Error: {skill_dir} is not a directory", file=sys.stderr)
        return 1

    hashes = compute(skill_dir)
    if not hashes:
        return 1

    snippet = json.dumps({"sha256": hashes}, indent=2)
    print(f"\nSHA-256 hashes for {skill_dir.name}:")
    print(snippet)
    print("\nPaste the 'sha256' block into the matching entry in registry.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
