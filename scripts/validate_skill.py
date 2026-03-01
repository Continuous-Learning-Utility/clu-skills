#!/usr/bin/env python3
"""CLU Community Skills Registry — CI Validator.

Replicates the same security checks as CLU's SkillLoader._load_one() and
skills/registry.py._download_and_install_skill(), so PRs are blocked before
reaching any human reviewer.

Patterns are kept in sync with:
  - skills/loader.py  (_SECRET_PATTERNS, _INJECTION_PATTERNS, _SCANNABLE_EXTENSIONS)
  - skills/registry.py (_SKILL_FILES)

Usage:
    python scripts/validate_skill.py          # validates everything
    python scripts/validate_skill.py skills/my-skill/  # single skill
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

import yaml

# ---------------------------------------------------------------------------
# Patterns (verbatim copy from skills/loader.py)
# ---------------------------------------------------------------------------

_SCANNABLE_EXTENSIONS = {".py", ".yaml", ".yml", ".md", ".txt", ".toml", ".json", ".sh"}

_SECRET_PATTERNS: list[re.Pattern] = [
    # Generic key=value secrets
    re.compile(
        r"""(?ix)
        (api[_-]?key | secret[_-]?key | access[_-]?token | auth[_-]?token
         | password | passwd | credential | private[_-]?key)
        ['"]?\s*[:=]\s*['"]?[A-Za-z0-9+/._\-]{20,}
        """
    ),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),             # OpenAI key
    re.compile(r"ghp_[A-Za-z0-9]{36}"),              # GitHub personal token
    re.compile(r"ghs_[A-Za-z0-9]{36}"),              # GitHub server token
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),           # Google API key
    re.compile(r"AKIA[0-9A-Z]{16}"),                 # AWS access key
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9\-._~+/]{40,}"),  # Bearer token
]

_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)ignore\s+(previous|all|above)\s+instructions?"),
    re.compile(r"(?i)forget\s+(everything|all|your\s+instructions?)"),
    re.compile(r"(?i)\byou\s+are\s+now\b"),
    re.compile(r"(?i)\bact\s+as\b"),
    re.compile(r"(?i)\bpretend\s+(to\s+be|you\s+are)\b"),
    re.compile(r"(?i)\byour\s+(new\s+)?role\s+is\b"),
    re.compile(r"(?i)\boverride\s+(system|instructions?|prompt)\b"),
    re.compile(r"(?i)\b(system\s+prompt|system\s+message)\s*[:=]"),
    re.compile(r"(?i)\bDAN\b"),                      # "Do Anything Now" jailbreak keyword
]

# Files that constitute a complete community skill (mirrors registry.py _SKILL_FILES)
_SKILL_FILES = ("skill.yaml", "prompt.md")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scan_secrets(skill_dir: Path) -> list[str]:
    """Return list of '<file>: <snippet>' for each secret hit found."""
    hits: list[str] = []
    for root, _dirs, files in os.walk(skill_dir):
        for fname in files:
            fpath = Path(root) / fname
            if fpath.suffix.lower() not in _SCANNABLE_EXTENSIONS:
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = fpath.relative_to(skill_dir)
            for pat in _SECRET_PATTERNS:
                m = pat.search(content)
                if m:
                    snippet = m.group(0)[:40].replace("\n", " ")
                    hits.append(f"{rel}: '{snippet}…'")
                    break  # one hit per file
    return hits


def _scan_injection(prompt_path: Path) -> list[str]:
    """Return list of pattern descriptions for each injection hit in prompt.md."""
    hits: list[str] = []
    try:
        content = prompt_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    for pat in _INJECTION_PATTERNS:
        m = pat.search(content)
        if m:
            hits.append(f"pattern '{pat.pattern[:50]}' matched: '{m.group(0)}'")
    return hits


# ---------------------------------------------------------------------------
# Per-skill validation
# ---------------------------------------------------------------------------

def validate_skill(skill_dir: Path, registry_index: dict) -> list[str]:
    """Validate one skill directory. Returns list of error strings (empty = OK)."""
    errors: list[str] = []
    name = skill_dir.name

    # 1. skill.yaml: exists + valid YAML + mapping
    yaml_path = skill_dir / "skill.yaml"
    if not yaml_path.is_file():
        errors.append("skill.yaml is missing")
        return errors  # can't continue

    try:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        errors.append(f"skill.yaml is not valid YAML: {e}")
        return errors

    if not isinstance(data, dict):
        errors.append("skill.yaml must be a YAML mapping (dict)")
        return errors

    # 2. Required fields: name + version
    skill_name = data.get("name", "")
    skill_version = data.get("version", "")
    if not skill_name:
        errors.append("skill.yaml: missing required field 'name'")
    if not skill_version:
        errors.append("skill.yaml: missing required field 'version'")
    if errors:
        return errors

    # 3. Name must match directory name
    if str(skill_name) != name:
        errors.append(
            f"skill.yaml 'name' ({skill_name!r}) does not match directory name ({name!r})"
        )

    # 4. prompt.md must exist
    prompt_path = skill_dir / "prompt.md"
    if not prompt_path.is_file():
        errors.append("prompt.md is missing (required for community skills)")

    # 5. Secret scanning (all scannable files in skill dir)
    secret_hits = _scan_secrets(skill_dir)
    for hit in secret_hits:
        errors.append(f"secret detected: {hit}")

    # 6. Prompt injection check (prompt.md only)
    if prompt_path.is_file():
        injection_hits = _scan_injection(prompt_path)
        for hit in injection_hits:
            errors.append(f"prompt injection detected: {hit}")

    # 7. registry.json consistency + SHA-256
    registry_skills: dict[str, dict] = {
        s["name"]: s for s in registry_index.get("skills", []) if isinstance(s, dict)
    }
    if name not in registry_skills:
        errors.append(
            f"no entry found in registry.json for skill '{name}' — "
            f"run: python scripts/compute_hashes.py {skill_dir} and add the entry"
        )
        return errors

    entry = registry_skills[name]
    sha256s: dict = entry.get("sha256", {})

    for fname in _SKILL_FILES:
        fpath = skill_dir / fname
        if not fpath.is_file():
            continue  # already reported above
        expected = sha256s.get(fname, "")
        if not expected:
            errors.append(
                f"registry.json entry for '{name}' is missing sha256.{fname}"
            )
            continue
        actual = _sha256(fpath)
        if actual != expected:
            errors.append(
                f"registry.json SHA-256 mismatch for {name}/{fname}:\n"
                f"    expected: {expected}\n"
                f"    actual:   {actual}\n"
                f"    (re-run: python scripts/compute_hashes.py {skill_dir})"
            )

    return errors


# ---------------------------------------------------------------------------
# Registry-level validation
# ---------------------------------------------------------------------------

def validate_registry(repo_root: Path, registry_index: dict) -> list[str]:
    """Validate registry.json structure and consistency with skills/ directory."""
    errors: list[str] = []

    # Structure
    if not isinstance(registry_index.get("version"), int):
        errors.append("registry.json: 'version' must be an integer")
    if not isinstance(registry_index.get("skills"), list):
        errors.append("registry.json: 'skills' must be a list")
        return errors

    entries = registry_index["skills"]

    # No duplicate names
    seen: set[str] = set()
    for entry in entries:
        n = entry.get("name", "")
        if n in seen:
            errors.append(f"registry.json: duplicate skill name '{n}'")
        seen.add(n)

    # Every registry entry must have a corresponding skills/ directory
    for entry in entries:
        n = entry.get("name", "")
        if not n:
            errors.append("registry.json: skill entry is missing 'name'")
            continue
        if not (repo_root / "skills" / n).is_dir():
            errors.append(
                f"registry.json: entry '{n}' has no matching skills/{n}/ directory"
            )
        # sha256 sub-keys required
        sha256s = entry.get("sha256", {})
        for fname in _SKILL_FILES:
            if fname not in sha256s:
                errors.append(
                    f"registry.json: entry '{n}' is missing sha256.{fname}"
                )

    # Every skills/ directory must have a registry entry
    skills_dir = repo_root / "skills"
    if skills_dir.is_dir():
        registered_names = {e.get("name") for e in entries}
        for item in sorted(skills_dir.iterdir()):
            if not item.is_dir() or item.name.startswith("."):
                continue
            if (item / "skill.yaml").is_file() and item.name not in registered_names:
                errors.append(
                    f"skills/{item.name}/ exists but has no entry in registry.json"
                )

    return errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    repo_root = Path(__file__).parent.parent.resolve()

    # Load registry.json
    registry_path = repo_root / "registry.json"
    registry_index: dict = {}
    registry_errors: list[str] = []

    if not registry_path.is_file():
        registry_errors.append("registry.json not found at repo root")
    else:
        try:
            registry_index = json.loads(registry_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            registry_errors.append(f"registry.json is not valid JSON: {e}")

    # Determine which skills to validate
    if len(argv) > 1:
        skill_dirs = [Path(a).resolve() for a in argv[1:] if Path(a).is_dir()]
    else:
        skills_root = repo_root / "skills"
        skill_dirs = sorted(
            d for d in skills_root.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ) if skills_root.is_dir() else []

    total_errors = 0
    skill_results: list[tuple[str, list[str]]] = []

    # Validate each skill
    for skill_dir in skill_dirs:
        errs = validate_skill(skill_dir, registry_index)
        skill_results.append((skill_dir.name, errs))
        total_errors += len(errs)

    # Validate registry structure (only when validating everything)
    registry_level_errors: list[str] = []
    if len(argv) <= 1:
        if registry_errors:
            registry_level_errors = registry_errors
        elif registry_index:
            registry_level_errors = validate_registry(repo_root, registry_index)
        total_errors += len(registry_level_errors)

    # Output
    print()
    for name, errs in skill_results:
        if errs:
            print(f"  \u2717 {name}")
            for e in errs:
                for line in e.splitlines():
                    print(f"      {line}")
        else:
            print(f"  \u2713 {name} \u2014 all checks passed")

    if registry_level_errors:
        print(f"  \u2717 registry.json")
        for e in registry_level_errors:
            for line in e.splitlines():
                print(f"      {line}")
    elif len(argv) <= 1 and registry_index:
        skill_count = len(registry_index.get("skills", []))
        print(f"  \u2713 registry.json \u2014 consistent ({skill_count} skill(s))")

    print()
    if total_errors:
        print(f"{total_errors} error(s) found \u2014 validation failed.")
        return 1
    else:
        validated = len(skill_dirs)
        print(f"All {validated} skill(s) valid.")
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
