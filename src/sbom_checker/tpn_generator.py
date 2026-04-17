"""
tpn_generator.py — Generate TPN draft from FOSSA JSON + OneCLI TPN + package-lock.json

Approach B: FULL entries for known packages, stubs for transitive npm unknowns.

Sources (priority order per entry type):
  1. FOSSA JSON  source=npm/electron  → 11 npm direct + Electron (full attribution)
  2. OneCLI TPN FINAL                 → 17 C/C++ libs (copy-forward, stripped of internal notes)
  3. package-lock.json                → transitive npm not in FOSSA (stub, MANUAL TODO)

Usage (CLI):
  sbom-checker gen-tpn --platform win --fossa-json ux_win_fossa.json \\
      --onecli-tpn "...OneCLI-FINAL.txt" --pkg-lock package-lock.json \\
      --output ux_win_tpn_draft.txt

Usage (module):
  from sbom_checker.tpn_generator import generate_tpn
  generate_tpn(platform="win", fossa_json=..., onecli_tpn=..., pkg_lock=..., output=...)
"""
from __future__ import annotations

import json
import re
import warnings
from dataclasses import dataclass
from pathlib import Path

SEP = "-" * 80
STUB_MARKER = "[MANUAL TODO]"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class TpnEntry:
    name: str
    version: str
    license_name: str      # SPDX or descriptive name; empty for onecli_tpn (embedded)
    attribution: str       # full license+copyright text, or MANUAL TODO stub
    authors: str
    project_url: str
    source: str            # "fossa_npm" | "fossa_electron" | "onecli_tpn" | "pkg_lock"
    is_stub: bool = False


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_fossa_npm(fossa_json_path: Path) -> dict[str, dict]:
    """
    Extract npm + electron entries with full attribution from FOSSA JSON.

    Returns: {package_name: {license_name, attribution, authors, project_url}}
    Only includes source="npm" and the single source="archive" entry titled "electron".
    """
    data = json.loads(fossa_json_path.read_text(encoding="utf-8"))
    result: dict[str, dict] = {}

    for dep in data.get("directDependencies", []):
        src = dep.get("source", "")
        title = dep.get("title", "")

        if src == "npm":
            pass  # always include
        elif src == "archive" and title == "electron":
            pass  # include electron only
        else:
            continue  # skip UX source dirs and output binaries

        licenses = dep.get("licenses") or []
        if not licenses:
            continue  # no license info — skip (user/archive without license)

        if len(licenses) > 1:
            names = [lic.get("name", "") for lic in licenses]
            warnings.warn(
                f"[gen-tpn] {title}: multiple licenses {names} — using first only. "
                "Verify manually.",
                stacklevel=2,
            )

        lic = licenses[0]
        attribution = lic.get("attribution", "").strip()
        if not attribution:
            continue  # no attribution text — will fall through to stub

        result[title] = {
            "license_name": lic.get("name", ""),
            "attribution": attribution,
            "authors": ", ".join(dep.get("authors") or []),
            "project_url": dep.get("projectUrl", ""),
        }

    return result


def parse_onecli_tpn(tpn_path: Path) -> list[dict]:
    """
    Parse TPN blocks from OneCLI TPN FINAL .txt file.

    Strips "Source & ..." annotation lines (internal audit evidence — not for external TPN).
    Returns list of {name, version, block_text}.
    """
    raw = tpn_path.read_bytes().decode("utf-8", errors="replace")
    if "\ufffd" in raw:
        warnings.warn(
            f"[gen-tpn] {tpn_path.name}: replacement characters found — "
            "encoding issue in source file. Review output for \ufffd markers.",
            stacklevel=2,
        )
    # Tolerate separators of 60–90 dashes (handles CRLF and minor width variations)
    parts = re.split(r"-{60,}", raw)
    blocks: list[dict] = []

    for part in parts:
        if "Package Title:" not in part:
            continue

        # Strip internal "Source & ..." lines
        lines = part.split("\n")
        cleaned = [ln for ln in lines if not re.match(r"\s*Source\s*&", ln)]
        block_text = "\n".join(cleaned).strip()

        # Extract name + version from "Package Title: Name (version)"
        m = re.search(r"Package Title:\s*(.+?)\s*\(([^)]+)\)", block_text)
        if m:
            name = m.group(1).strip()
            version = m.group(2).strip()
        else:
            m2 = re.search(r"Package Title:\s*(.+)", block_text)
            name = m2.group(1).strip() if m2 else "Unknown"
            version = ""

        blocks.append({"name": name, "version": version, "block_text": block_text})

    return blocks


def parse_package_lock(lock_path: Path, prod_only: bool = True) -> dict[str, dict]:
    """
    Extract npm packages with version + SPDX license from package-lock.json (v3).

    Args:
        prod_only: If True (default), skip packages with "dev": true.
                   Dev-only packages (eslint, vite, babel build tools) are not
                   distributed in the product and should not appear in TPN.

    Returns: {package_name: {version, license}}
    Skips: root entry (empty key), dev-only packages, and nested hoisted packages
           (e.g. node_modules/@babel/core/node_modules/semver) which are internal
           deduplication artifacts and not independent distributed components.
    """
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    result: dict[str, dict] = {}

    for key, pkg in data.get("packages", {}).items():
        if not key.startswith("node_modules/"):
            continue
        name = key[len("node_modules/"):]
        if not name:
            continue
        # Skip nested hoisted packages (e.g. "@babel/core/node_modules/semver")
        # These are internal deduplication artifacts — the canonical entry is the
        # top-level node_modules/<pkg> entry.
        bare = name.lstrip("@")
        if "/" in bare and "node_modules/" in bare:
            continue
        if prod_only and pkg.get("dev") is True:
            continue  # skip dev-only dependencies
        result[name] = {
            "version": pkg.get("version") or "",
            "license": pkg.get("license") or "",
        }

    return result


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _stub_attribution(name: str, license_name: str) -> str:
    pkg_url = f"https://www.npmjs.com/package/{name}"
    hint = ""
    if license_name in ("MIT",):
        hint = f"\n  2. Standard {license_name} text: search \"{name} license\" on GitHub."
    return (
        f"{STUB_MARKER} Attribution text not available in FOSSA scan.\n"
        f"Resolution options:\n"
        f"  1. Check: {pkg_url}{hint}"
    )


def merge(
    fossa: dict[str, dict],
    onecli_blocks: list[dict],
    pkg_lock: dict[str, dict],
) -> tuple[list[TpnEntry], list[TpnEntry]]:
    """
    Merge all sources into a sorted list of TpnEntry objects.

    Returns: (all_entries, stubs_only)
    """
    entries: list[TpnEntry] = []
    seen: set[str] = set()

    # --- Source 1: FOSSA npm + electron (FULL entries) ---
    for name, info in fossa.items():
        version = pkg_lock.get(name, {}).get("version", "")
        entries.append(TpnEntry(
            name=name,
            version=version,
            license_name=info["license_name"],
            attribution=info["attribution"],
            authors=info["authors"],
            project_url=info["project_url"],
            source="fossa_npm",
            is_stub=False,
        ))
        seen.add(name)

    # --- Source 2: OneCLI TPN copy-forward (FULL entries) ---
    for block in onecli_blocks:
        entries.append(TpnEntry(
            name=block["name"],
            version=block["version"],
            license_name="",          # embedded in block_text
            attribution=block["block_text"],
            authors="",
            project_url="",
            source="onecli_tpn",
            is_stub=False,
        ))
        # Use name+version key: OneCLI TPN legitimately has two entries for the
        # same package at different versions (e.g. openssl 3.4.0 and openssl 3.1.5).
        # Bare name dedup would silently drop the second entry.
        seen_key = f"{block['name']} ({block['version']})" if block["version"] else block["name"]
        seen.add(seen_key)
        seen.add(block["name"])  # also mark bare name to avoid pkg_lock stubs for C/C++ libs

    # --- Source 3: package-lock transitive (STUB entries) ---
    for name, info in pkg_lock.items():
        if name in seen:
            continue
        entries.append(TpnEntry(
            name=name,
            version=info["version"],
            license_name=info["license"],
            attribution=_stub_attribution(name, info["license"]),
            authors=STUB_MARKER,
            project_url=f"https://www.npmjs.com/package/{name}",
            source="pkg_lock",
            is_stub=True,
        ))
        seen.add(name)

    # Sort alphabetically (strip leading @ for sort key)
    entries.sort(key=lambda e: e.name.lstrip("@").lower())
    stubs = [e for e in entries if e.is_stub]
    return entries, stubs


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

_PLATFORM_HEADERS = {
    "win": ("Lenovo XClarity Essentials UpdateXpress Windows", "windows zip package"),
    "linux": ("Lenovo XClarity Essentials UpdateXpress Linux", "linux tgz package"),
}


def _format_entry(entry: TpnEntry) -> str:
    """
    Render a single TPN block.

    Each entry emits an opening SEP + content (NO trailing SEP).
    write_tpn() appends the final SEP so consecutive entries produce exactly
    one separator between them.
    """
    if entry.source == "onecli_tpn":
        # block_text is already the inner content (no surrounding separators)
        return f"{SEP}\n\n{entry.attribution}\n"

    ver_str = f" ({entry.version})" if entry.version else ""
    lines = [
        SEP,
        "",
        f"Package Title: {entry.name}{ver_str}",
        "",
        "",
        "* Declared Licenses *",
        entry.license_name or STUB_MARKER,
        "",
        entry.attribution,
        "",
        "* Package Info *",
        "",
        f"Authors: {entry.authors}",
        "",
        f"Project URL: {entry.project_url}",
        "",
    ]
    return "\n".join(lines)


def _tpn_header(platform: str, product_version: str = "") -> str:
    prod_name, pkg_type = _PLATFORM_HEADERS.get(platform, ("Lenovo XClarity Essentials UpdateXpress", "package"))
    ver_line = f"\nVersion: {product_version}" if product_version else ""
    return f"""{prod_name}{ver_line}

This Lenovo Product may include software licensed under the General Public \
License and/or the Lesser General Public License (the "open source software"). \
Use and distribution of such open source software is subject to the terms of \
the applicable open source license(s).

You may obtain a copy of the corresponding source code for any such open source \
software licensed under the General Public License and/or the Lesser General \
Public License (or any other license requiring us to make a written offer to \
provide corresponding source code to you) from Lenovo for a period of three \
years without charge except for the cost of media, shipping, and handling, \
upon written request to Lenovo or at \
https://support.lenovo.com/us/en/solutions/ht116433-lenovo-xclarity-essentials-onecli-onecli.

The following 3rd-party software packages may be used by or distributed with \
the UpdateXpress {pkg_type}. Any information relevant to third-party vendors \
listed below are collected using common, reasonable means.
"""


def write_tpn(
    entries: list[TpnEntry],
    output_path: Path,
    platform: str,
    product_version: str = "",
) -> None:
    parts = [_tpn_header(platform, product_version)]
    for entry in entries:
        parts.append(_format_entry(entry))
    # Append the final closing separator (each entry emits opening SEP only)
    parts.append(SEP + "\n")
    output_path.write_text("\n".join(parts), encoding="utf-8")


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(entries: list[TpnEntry], stubs: list[TpnEntry], output_path: Path) -> None:
    full = [e for e in entries if not e.is_stub]
    by_source: dict[str, int] = {}
    for e in full:
        by_source[e.source] = by_source.get(e.source, 0) + 1

    print(f"\nTPN Draft Generated: {output_path}")
    print(f"{'='*60}")
    print(f"  FULL entries:    {len(full):3d}")
    print(f"    fossa_npm:     {by_source.get('fossa_npm', 0):3d}  (npm direct + Electron)")
    print(f"    onecli_tpn:    {by_source.get('onecli_tpn', 0):3d}  (C/C++ copy-forward)")
    print(f"  STUB entries:    {len(stubs):3d}  ← [MANUAL TODO] attribution needed")
    print(f"  TOTAL:           {len(entries):3d}")
    print(f"{'='*60}")

    if stubs:
        print(f"\nStub entries requiring manual attribution ({len(stubs)}):")
        for s in stubs:
            print(f"  [{s.license_name or '?':12s}]  {s.name} ({s.version})")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_tpn(
    platform: str,
    fossa_json_path: Path,
    onecli_tpn_path: Path,
    pkg_lock_path: Path,
    output_path: Path,
    product_version: str = "",
    verbose: bool = True,
) -> None:
    """
    Full pipeline: parse all sources → merge → write TPN draft.

    Args:
        platform:          "win" or "linux"
        fossa_json_path:   Path to ux_win_fossa.json or ux_linux_fossa_json.json
        onecli_tpn_path:   Path to OneCLI TPN FINAL .txt
        pkg_lock_path:     Path to package-lock.json
        output_path:       Output .txt path (never overwrites original)
        product_version:   e.g. "5.4.0" for TPN header
        verbose:           Print summary to stdout
    """
    fossa = parse_fossa_npm(fossa_json_path)
    onecli = parse_onecli_tpn(onecli_tpn_path)
    pkg_lock = parse_package_lock(pkg_lock_path)

    entries, stubs = merge(fossa, onecli, pkg_lock)
    write_tpn(entries, output_path, platform, product_version)

    if verbose:
        print_summary(entries, stubs, output_path)
