"""
tpn_delta.py — Version delta comparison for UX TPN/SBOM between releases.

Compares:
  - Old TPN FINAL (v5.3.x) vs New TPN/DRAFT (v5.4.x): package add/remove/version/license changes
  - Old SBOM xlsx vs New SBOM xlsx: component-level delta (Col A name, Col B version, Col C license)

Output: Markdown delta report with [ACTION] items for TPN authors.

Usage (CLI):
  sbom-checker tpn-delta --platform win \\
      --old-tpn  "UX-v5.3.0-Win-TPN-FINAL.txt" \\
      --new-tpn  "UX-v5.4.0-Win-TPN-DRAFT.txt" \\
      --old-sbom "UX-v5.3.0-Win-SBOM-FINAL.xlsx" \\
      --new-sbom "UX-v5.4.0-Win-SBOM-current.xlsx" \\
      --output   delta_report_win.md

Usage (module):
  from sbom_checker.tpn_delta import compute_delta, write_delta_report
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PackageRecord:
    name: str
    version: str
    license: str = ""     # from TPN or SBOM Col C

    @property
    def name_key(self) -> str:
        """Normalised name-only key (used for version-change detection)."""
        return self.name.lower().strip()

    @property
    def key(self) -> str:
        """
        Normalised name+version key.
        Allows multiple entries for the same package name at different versions
        (e.g. openssl 3.4.0 and openssl 1.1.1a) to coexist independently.
        """
        v = self.version.strip()
        return f"{self.name.lower().strip()} ({v})" if v else self.name.lower().strip()


@dataclass
class DeltaReport:
    platform: str
    added: list[PackageRecord] = field(default_factory=list)
    removed: list[PackageRecord] = field(default_factory=list)
    version_changed: list[tuple[PackageRecord, PackageRecord]] = field(default_factory=list)  # (old, new)
    license_changed: list[tuple[PackageRecord, PackageRecord]] = field(default_factory=list)  # (old, new)
    unchanged: list[PackageRecord] = field(default_factory=list)


# ---------------------------------------------------------------------------
# TPN parser
# ---------------------------------------------------------------------------

def parse_tpn_packages(tpn_path: Path) -> dict[str, PackageRecord]:
    """
    Parse Package Title blocks from a TPN .txt file.

    Returns: {normalised_name → PackageRecord(name, version, license)}
    """
    txt = tpn_path.read_text(encoding="utf-8", errors="replace")
    sep = "-" * 80
    parts = txt.split(sep)
    result: dict[str, PackageRecord] = {}

    for part in parts:
        if "Package Title:" not in part:
            continue

        # Extract name + version
        m = re.search(r"Package Title:\s*(.+?)\s*\(([^)]+)\)", part)
        if m:
            name = m.group(1).strip()
            version = m.group(2).strip()
        else:
            m2 = re.search(r"Package Title:\s*(.+)", part)
            if not m2:
                continue
            name = m2.group(1).strip()
            version = ""

        # Extract declared license (first non-empty line after "* Declared Licenses *")
        lic = ""
        in_lic = False
        for line in part.split("\n"):
            if "* Declared Licenses *" in line:
                in_lic = True
                continue
            if in_lic:
                stripped = line.strip()
                if stripped and not stripped.startswith("*"):
                    lic = stripped
                    break

        rec = PackageRecord(name=name, version=version, license=lic)
        result[rec.key] = rec

    return result


# ---------------------------------------------------------------------------
# SBOM xlsx parser
# ---------------------------------------------------------------------------

def parse_sbom_xlsx(xlsx_path: Path) -> dict[str, PackageRecord]:
    """
    Extract component rows from a UX SBOM xlsx file.

    Reads Col A (name), Col B (version), Col C (license).
    Skips header rows, BUILD OUTPUT rows, empty Col A rows.
    Returns: {normalised_name → PackageRecord}
    """
    try:
        import openpyxl
    except ImportError as e:
        raise ImportError("openpyxl required: pip install openpyxl") from e

    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    result: dict[str, PackageRecord] = {}
    try:
        ws = wb.active
        header_found = False
        for row in ws.iter_rows(values_only=True):
            col_a = str(row[0]).strip() if row[0] else ""
            col_b = str(row[1]).strip() if len(row) > 1 and row[1] else ""
            col_c = str(row[2]).strip() if len(row) > 2 and row[2] else ""

            # Detect header row
            if "OSS Component Name" in col_a or "Component Name" in col_a:
                header_found = True
                continue
            if not header_found:
                continue

            # Skip empty, BUILD OUTPUT, metadata rows
            if not col_a:
                continue
            if col_a.startswith("*BUILD OUTPUT") or col_a in (
                "Direct dependencies", "Deep dependencies", "None"
            ):
                continue
            if col_c in ("PROPRIETARY", "IGNORE"):
                continue

            rec = PackageRecord(name=col_a, version=col_b, license=col_c)
            result[rec.key] = rec
    finally:
        wb.close()
    return result


# ---------------------------------------------------------------------------
# Delta computation
# ---------------------------------------------------------------------------

def compute_delta(
    old: dict[str, PackageRecord],
    new: dict[str, PackageRecord],
) -> tuple[list[PackageRecord], list[PackageRecord],
           list[tuple[PackageRecord, PackageRecord]],
           list[tuple[PackageRecord, PackageRecord]],
           list[PackageRecord]]:
    """
    Compare old and new package sets using a two-pass approach.

    Pass 1 — name-level: for packages whose name exists in both old and new
             with exactly ONE entry each side, classify as version_changed /
             license_changed / unchanged.

    Pass 2 — key-level (name+version): entries not resolved in Pass 1 are
             classified as added or removed. This correctly handles multi-version
             packages (e.g. openssl 3.4.0 and openssl 1.1.1a) where the same
             name appears at two different versions on either side.

    Returns: (added, removed, version_changed, license_changed, unchanged)
    """
    added: list[PackageRecord] = []
    removed: list[PackageRecord] = []
    version_changed: list[tuple[PackageRecord, PackageRecord]] = []
    license_changed: list[tuple[PackageRecord, PackageRecord]] = []
    unchanged: list[PackageRecord] = []

    # Group entries by name_key to detect single-name vs multi-name packages
    from collections import defaultdict
    old_by_name: dict[str, list[PackageRecord]] = defaultdict(list)
    new_by_name: dict[str, list[PackageRecord]] = defaultdict(list)
    for r in old.values():
        old_by_name[r.name_key].append(r)
    for r in new.values():
        new_by_name[r.name_key].append(r)

    resolved_old_keys: set[str] = set()
    resolved_new_keys: set[str] = set()

    all_name_keys = set(old_by_name) | set(new_by_name)
    for name_key in sorted(all_name_keys):
        old_recs = old_by_name.get(name_key, [])
        new_recs = new_by_name.get(name_key, [])

        # Single entry on each side → version/license change detection
        if len(old_recs) == 1 and len(new_recs) == 1:
            old_r, new_r = old_recs[0], new_recs[0]
            ver_diff = old_r.version != new_r.version
            lic_diff = bool(old_r.license and new_r.license and old_r.license != new_r.license)
            if ver_diff:
                version_changed.append((old_r, new_r))
            if lic_diff:
                license_changed.append((old_r, new_r))
            if not ver_diff and not lic_diff:
                unchanged.append(new_r)
            resolved_old_keys.add(old_r.key)
            resolved_new_keys.add(new_r.key)

        # Multi-version package: fall through to key-level comparison below

    # Pass 2 — key-level for unresolved entries (multi-version packages)
    all_keys = set(old) | set(new)
    for key in sorted(all_keys):
        if key in resolved_old_keys or key in resolved_new_keys:
            continue
        if key in new and key not in old:
            added.append(new[key])
        elif key in old and key not in new:
            removed.append(old[key])
        # same key in both: already unchanged (single-entry case handled above)

    return added, removed, version_changed, license_changed, unchanged


# ---------------------------------------------------------------------------
# Report writer
# ---------------------------------------------------------------------------

def _md_table(rows: list[list[str]], headers: list[str]) -> str:
    col_w = [max(len(h), max((len(r[i]) for r in rows), default=0)) for i, h in enumerate(headers)]
    def row_fmt(cells: list[str]) -> str:
        return "| " + " | ".join(c.ljust(col_w[i]) for i, c in enumerate(cells)) + " |"
    sep_row = "| " + " | ".join("-" * w for w in col_w) + " |"
    lines = [row_fmt(headers), sep_row] + [row_fmt(r) for r in rows]
    return "\n".join(lines)


def write_delta_report(
    report: DeltaReport,
    output_path: Path,
    old_label: str = "old",
    new_label: str = "new",
) -> None:
    lines: list[str] = [
        f"# TPN Delta Report — {report.platform.upper()} ({old_label} → {new_label})",
        "",
        "## Summary",
        "",
        f"| Category | Count |",
        f"|---|---|",
        f"| Added | {len(report.added)} |",
        f"| Removed | {len(report.removed)} |",
        f"| Version changed | {len(report.version_changed)} |",
        f"| License changed | {len(report.license_changed)} |",
        f"| Unchanged | {len(report.unchanged)} |",
        "",
    ]

    # --- Added ---
    if report.added:
        lines += ["## [ACTION] Add to TPN", ""]
        rows = [[r.name, r.version, r.license] for r in report.added]
        lines.append(_md_table(rows, ["Package", "Version", "License"]))
        lines.append("")

    # --- Removed ---
    if report.removed:
        lines += ["## [ACTION] Remove from TPN", ""]
        rows = [[r.name, r.version, r.license] for r in report.removed]
        lines.append(_md_table(rows, ["Package", "Version", "License"]))
        lines.append("")

    # --- Version changed ---
    if report.version_changed:
        lines += ["## [ACTION] Update version in TPN", ""]
        rows = [[o.name, o.version, n.version] for o, n in report.version_changed]
        lines.append(_md_table(rows, ["Package", f"Version ({old_label})", f"Version ({new_label})"]))
        lines.append("")

    # --- License changed ---
    if report.license_changed:
        lines += ["## [ACTION] Review license change", ""]
        rows = [[o.name, o.version, o.license, n.license] for o, n in report.license_changed]
        lines.append(_md_table(rows, ["Package", "Version", f"License ({old_label})", f"License ({new_label})"]))
        lines.append("")

    # --- Unchanged (collapsed) ---
    if report.unchanged:
        lines += [
            "## Unchanged (no action needed)",
            "",
            "<details><summary>Click to expand</summary>",
            "",
        ]
        rows = [[r.name, r.version, r.license] for r in report.unchanged]
        lines.append(_md_table(rows, ["Package", "Version", "License"]))
        lines += ["", "</details>", ""]

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nDelta report: {output_path}")
    print(f"  Added:           {len(report.added)}")
    print(f"  Removed:         {len(report.removed)}")
    print(f"  Version changed: {len(report.version_changed)}")
    print(f"  License changed: {len(report.license_changed)}")
    print(f"  Unchanged:       {len(report.unchanged)}")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_delta(
    platform: str,
    old_tpn_path: Optional[Path],
    new_tpn_path: Optional[Path],
    old_sbom_path: Optional[Path],
    new_sbom_path: Optional[Path],
    output_path: Path,
    old_label: str = "v5.3.x",
    new_label: str = "v5.4.x",
) -> None:
    """
    Full delta pipeline.

    TPN delta (if both paths provided) compares Package Title blocks.
    SBOM delta (if both paths provided) compares Col A component rows.
    Both comparisons are written to the same report.
    """
    if not (old_tpn_path and new_tpn_path) and not (old_sbom_path and new_sbom_path):
        raise ValueError(
            "Provide either --old-tpn + --new-tpn or --old-sbom + --new-sbom."
        )

    report = DeltaReport(platform=platform)

    # --- TPN delta ---
    if old_tpn_path and new_tpn_path:
        print(f"Parsing TPN: {old_tpn_path.name}")
        old_pkgs = parse_tpn_packages(old_tpn_path)
        print(f"Parsing TPN: {new_tpn_path.name}")
        new_pkgs = parse_tpn_packages(new_tpn_path)

        added, removed, ver_chg, lic_chg, unchanged = compute_delta(old_pkgs, new_pkgs)
        report.added = added
        report.removed = removed
        report.version_changed = ver_chg
        report.license_changed = lic_chg
        report.unchanged = unchanged

    elif old_sbom_path and new_sbom_path:
        # --- SBOM delta (fallback if TPN not provided) ---
        print(f"Parsing SBOM: {old_sbom_path.name}")
        old_pkgs = parse_sbom_xlsx(old_sbom_path)
        print(f"Parsing SBOM: {new_sbom_path.name}")
        new_pkgs = parse_sbom_xlsx(new_sbom_path)

        added, removed, ver_chg, lic_chg, unchanged = compute_delta(old_pkgs, new_pkgs)
        report.added = added
        report.removed = removed
        report.version_changed = ver_chg
        report.license_changed = lic_chg
        report.unchanged = unchanged

    write_delta_report(report, output_path, old_label=old_label, new_label=new_label)
