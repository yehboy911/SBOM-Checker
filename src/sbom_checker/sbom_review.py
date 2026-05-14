"""
sbom_review.py — OneCLI SBOM review (Linux + Windows, dual-platform).

Checks: format, versions, duplicates, Col D/E/F annotations, boost linkage,
I/O tool versions, source archive coverage, CP-12 boost sub-libraries.

Usage:
    cd /path/to/OneCLI && python3 sbom_review.py           # zero-config
    python3 sbom_review.py --base /path/to/OneCLI          # explicit base
    python3 sbom_review.py --help                          # all options

Output: console summary + sbom_review_<version>.md in <base>.
"""
import argparse
import re
import sys
from datetime import date
from pathlib import Path

import openpyxl

# ---------------------------------------------------------------------------
# Paths — module-level stubs; main() overwrites them from CLI args / glob.
# ---------------------------------------------------------------------------
BASE: Path       = Path.cwd()
SBOM_LINUX: Path = Path()
SBOM_WIN: Path   = Path()
REPORT_OUT: Path = Path()

HEADER_ROW = 20   # 1-based row index of the column header row in the SBOM

# ---------------------------------------------------------------------------
# Audit baseline — from version_audit_5.6.0.log
# Keys are lowercase library names as they appear in col A of the SBOM.
# ---------------------------------------------------------------------------
AUDIT_BASELINE = {
    "boost":        {"expected": "1.86.0",    "audit_status": "OK"},
    "curl":         {"expected": "8.17.0",    "audit_status": "FAIL",  "actual_extlibs": "8.19.0"},
    # electron belongs to BoMC / UpdateXpress, not OneCLI — excluded from this scope
    "libssh2":      {"expected": "1.11.1",    "audit_status": "OK"},
    "openssl":      {"expected": "3.6.0",     "audit_status": "WARN",  "actual_extlibs": "3.6.2"},
    "pegasus":      {"expected": "2.14.1",    "audit_status": "OK"},
    "pthreads-w32": {"expected": "2.9.1",     "audit_status": "FAIL",  "actual_extlibs": "2.8.0"},
    "snmp++":       {"expected": "3.3.10",    "audit_status": "OK"},
    "websocket++":  {"expected": "0.8.3-dev", "audit_status": "OK"},
    "zlib":         {"expected": "1.3.1",     "audit_status": "FAIL",  "actual_extlibs": "1.3.2"},
}

# Matches Col A values that are I/O tool package names (lnvgy_* / intc-*)
_IO_TOOL_NAME_RE = re.compile(r'^(?:lnvgy_|intc[-_])', re.IGNORECASE)
# Matches Col B pure-hex checksums (MD5/SHA) — not version strings
_CHECKSUM_RE = re.compile(r'^[0-9a-fA-F]{16,}$')

# Regex: a value that looks like a semantic version (not a hex hash)
_SEM_VER = re.compile(r'^\d+\.\d+[\.\d\w\-]*$')
_BOOST_CMAKE_RE = re.compile(r"target_link_libraries\s*\(\s*(\S+)")
_COL_D_SEE_RE   = re.compile(r'^see\s+"([^"]+)"')
_CMAKE_TARGET_RE   = re.compile(r'(?:add_library|add_executable)\s*\(\s*(\w+)', re.IGNORECASE)
_CMAKE_OUTNAME_RE  = re.compile(r'set_target_properties\s*\(.+?OUTPUT_NAME\s+"([^"]+)"', re.IGNORECASE | re.DOTALL)
_CMAKE_INSTALL_RE  = re.compile(r'install\s*\(FILES[^)]+?(\w[\w.\-]+\.(?:dll|so))', re.IGNORECASE)
_SOURCE_PREFIXES = ("modularization/", "onecli/", "rdcli_red/")

# ---------------------------------------------------------------------------
# I/O package version baseline (Check 1g)
# Canonical full package names per platform, from LXC I/O version reference.
# ---------------------------------------------------------------------------
_IO_VERSION_START_RE = re.compile(r'-(\d|j9|ja|pm\d|tsv\d)')
_IO_PKG_REF_RE = re.compile(r'^see\s+"((?:lnvgy|intc)[^"]+)"', re.IGNORECASE)

_IO_CANONICAL: dict = {
    "linux": [
        "lnvgy_utl_bootstor_sata.mvcli-2.3.10.1095-0_linux_x86-64",
        "lnvgy_utl_bootstor_nvme.mnvcli-j9lng-00c1_linux_indiv",
        "lnvgy_utl_raid_mr3.storcli-007.3205.0000.0000-1-j9vjc-0191_linux_indiv",
        "lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-j9abc-0062_windows_indiv",
        "lnvgy_utl_storage-adapter_smartpqi.arcconf-27449-j9vpb-0311_linux_indiv",
        "lnvgy_utl_drives_all.ss.wg-250912-ja090-0222_linux_indiv",
        "lnvgy_fw_drives_all-1.55.08-0_linux_x86-64",
        "intc-lnvgy_fw_pmem_pm200-02.02.00.1553-8_linux_x86-64",
    ],
    "windows": [
        "lnvgy_utl_bootstor_sata.mvcli-2.3.10.1095-0_windows_x86-64",
        "lnvgy_utl_bootstor_nvme.mnvcli-j9lne-0061_windows_indiv",
        "lnvgy_utl_raid_mr3.storcli-007.3205.0000.0000-j9vjd-0171_windows_indiv",
        "lnvgy_utl_storehba_sas4.storcli2-008.0016.0000.0011-ja9bc-0062_windows_indiv",
        "intc-lnvgy_utl_swraid_vroc.cli.tsv4-9.1.0.1449-j9vgc-0091_windows_indiv",
        "lnvgy_utl_storage-adapter_smartpqi.arcconf-27449-j9vpb-02f1_windows_indiv",
        "lnvgy_utl_drives_all.ss.wg-250912-ja090-01e2_windows_indiv",
        "lnvgy_fw_drives_all-1.55.08-0-a_windows_x86-64",
        "intc-lnvgy_fw_pmem_pm200-02.02.00.1553-8-a_windows_x86-64",
    ],
}

# ---------------------------------------------------------------------------
# Source archive baseline (Check 1h)
# ---------------------------------------------------------------------------
_SRC_ARCHIVE_EXT_RE  = re.compile(r'\.(tar\.gz|tar\.bz2|tar\.xz|tgz|zip|tar\.Z)$', re.IGNORECASE)
_SRC_ARCHIVE_NAME_RE = re.compile(r'^(.+?)[-_]\d')  # extract libname prefix from archive filename


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def _cell(row, idx):
    """Return stripped string for row[idx], or '' if None."""
    v = row[idx] if idx < len(row) else None
    return str(v).strip().replace('\n', ' ') if v is not None else ''


def parse_sbom(path: Path) -> dict:
    """
    Load the SBOM xlsx and return a dict with:
      metadata  — dict of header key/value pairs (rows 4-18)
      rows      — list of dicts for every data row (row 21+)
                  keys: name, version, license, link, path, use, modified,
                        project, src_redist, written_offer, notice, src_pub
                  plus: row_num (1-based), is_section_header (bool)
    """
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active

    metadata = {}
    data_rows = []
    current_section = ""

    for i, raw in enumerate(ws.iter_rows(values_only=True), 1):
        if i < 4:
            continue
        if 4 <= i <= 18:
            # metadata key/value pairs in col A / col B
            key = _cell(raw, 0)
            val = _cell(raw, 1)
            if key:
                metadata[key.rstrip(':')] = val
            continue
        if i < HEADER_ROW + 1:
            continue  # skip header row itself and preamble

        name    = _cell(raw, 0)
        version = _cell(raw, 1)
        lic     = _cell(raw, 2)
        link    = _cell(raw, 3)
        path_   = _cell(raw, 4)
        use     = _cell(raw, 5)
        modified = _cell(raw, 6)

        # Skip fully empty rows
        if not any([name, version, lic, path_]):
            continue

        is_header = name.startswith('*BUILD OUTPUT for')
        is_divider = name.lower() in ('direct dependencies', 'indirect dependencies',
                                      'transitive dependencies')

        if is_header:
            current_section = name

        data_rows.append({
            "row_num":          i,
            "name":             name,
            "version":          version,
            "license":          lic,
            "link":             link,
            "path":             path_,
            "use":              use,
            "modified":         modified,
            "is_section_header": is_header,
            "is_divider":       is_divider,
            "section":          current_section,
        })

    wb.close()
    return {"metadata": metadata, "rows": data_rows}


# ---------------------------------------------------------------------------
# Check 1 — Format validation
# ---------------------------------------------------------------------------
def check_format(rows: list) -> dict:
    """
    Returns dict with:
      target_sections  — list of section header names
      total_data_rows  — count of non-header, non-divider rows
      orphans          — rows with non-empty name but empty path (excluding headers)
      no_name_rows     — rows with empty name and non-empty path (reversed orphan)
      see_below_count  — rows where license == 'see below' (unresolved license ref)
      issues           — list of human-readable issue strings
    """
    target_sections = []
    orphans = []
    no_name_rows = []
    see_below_count = 0
    total_data = 0

    for r in rows:
        if r["is_section_header"]:
            target_sections.append(r["name"])
            continue
        if r["is_divider"]:
            continue

        total_data += 1

        name = r["name"]
        path = r["path"]
        lic  = r["license"]

        if name and not path:
            orphans.append(r)
        if not name and path:
            no_name_rows.append(r)
        if lic.lower() == "see below":
            see_below_count += 1

    issues = []
    if not target_sections:
        issues.append("No Target section headers found — SBOM may be malformed.")
    if orphans:
        issues.append(f"{len(orphans)} row(s) have a component name but empty path field.")
    if no_name_rows:
        issues.append(f"{len(no_name_rows)} row(s) have a path but no component name.")

    return {
        "target_sections":  target_sections,
        "total_data_rows":  total_data,
        "orphans":          orphans,
        "no_name_rows":     no_name_rows,
        "see_below_count":  see_below_count,
        "issues":           issues,
    }


# ---------------------------------------------------------------------------
# Check 4 — Col F (USE) must not be empty; value must match Col A file type
# ---------------------------------------------------------------------------
# Exact Col F values observed in reference SBOM screenshots, keyed by extension.
# Order matters: check longer suffixes first (.tar.gz before .gz).
_EXT_USE_MAP = [
    # Source archives — must come before shorter suffix matches
    (".tar.gz",     "GZ"),
    (".tar.bz2",    "BZ2"),
    # Dynamic libraries (.so also catches versioned symlinks via substring check below)
    (".dll",        "Dynamic Library"),
    # Executables / binaries
    (".exe",        "Binary"),
    (".bin",        "Binary"),
    # Distribution packages
    (".tgz",        "TGZ"),
    (".zip",        "ZIP"),
    (".rpm",        "RPM"),
    (".bz2",        "BZ2"),
    # Image / media assets
    (".png",        "PNG"),
    (".gif",        "GIF"),
    (".jpg",        "PNG"),
    # Documents / misc files
    (".pdf",        "PDF"),
    (".cat",        "File"),
    (".sys",        "File"),
    (".properties", "File"),
    (".vsix",       "File"),
]

# Lenovo package name prefixes that map to "Binary Package"
_LENOVO_PKG_PREFIXES = ("lnvgy_", "intc-lnvgy_")


def _infer_use(name: str) -> str:
    """
    Return the expected Col F value for a given Col A entry, based on the
    file-type rules observed in reference SBOM screenshots.
    Returns '' when inference is not possible (human review required).
    """
    low = name.lower()

    # Dynamic library — .so anywhere in name covers libfoo.so, libfoo.so.1, libfoo.so.1.2.3
    if ".so" in low:
        return "Dynamic Library"

    # Extension-based lookup (ordered: longest suffix first)
    for ext, use in _EXT_USE_MAP:
        if low.endswith(ext):
            return use

    # Lenovo binary packages (no extension, long Lenovo naming convention)
    if any(low.startswith(p) for p in _LENOVO_PKG_PREFIXES):
        return "Binary Package"

    # Path-like entries (source code paths inside the repo)
    if "/" in name or "\\" in name:
        return "Source Code"

    # No pattern matched — human must decide
    return ""


def check_col_f(rows: list) -> dict:
    """
    Flag every non-header data row where Col F (USE) is empty.
    No license-based exemptions: per SBOM spec every row must have USE filled
    based on the file type shown in Col A.

    Returns dict with:
      violations    — row dicts augmented with 'suggested' key
      total_checked — rows inspected (excludes section headers and dividers)
    """
    violations = []
    total_checked = 0

    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        if not r["name"]:
            continue

        total_checked += 1

        if not r["use"]:
            violations.append({**r, "suggested": _infer_use(r["name"])})

    return {"violations": violations, "total_checked": total_checked}


# ---------------------------------------------------------------------------
# Check 6 — Col E path must use constant folder name (no version), excluding
#            OneCLI distribution packages in Col A
# ---------------------------------------------------------------------------
_VER_FOLDER_RE = re.compile(
    r'(lnvgy_utl_lxce[br]?_onecli[^/\\]*\d+\.\d+[^/\\"]*)',
    re.IGNORECASE,
)


def check_col_e_path(rows: list, platform: str) -> dict:
    """
    For every row whose Col E starts with Target/ (or Target\\),
    check that the path does NOT contain a version-specific folder component.

    Excluded from check: rows where Col A is an OneCLI distribution package
    (.tgz / .zip / .exe / .bin / .rpm).

    Returns dict with:
      violations      — list of row dicts with 'current_path' and 'corrected_path'
      total_checked   — rows inspected
      version_folder  — the version-specific folder name detected (e.g.
                        'lnvgy_utl_lxce_onecli01d-5.6.0_linux_indiv')
      constant_folder — the replacement constant folder name
    """
    constant = _CONSTANT_FOLDER.get(platform, "")
    violations = []
    total_checked = 0
    version_folder_seen: set = set()

    for r in rows:
        name = r["name"]
        path = r["path"]

        if not name or not path:
            continue
        # Exclude OneCLI package files
        low = name.lower()
        if any(low.endswith(ext) for ext in _TOP_PKG_EXTS):
            continue
        # Only check paths in the Target section
        if not path.lower().startswith("target"):
            continue

        total_checked += 1
        m = _VER_FOLDER_RE.search(path)
        if m:
            version_folder_seen.add(m.group(1))
            corrected = _VER_FOLDER_RE.sub(constant, path, count=1)
            violations.append({**r, "current_path": path, "corrected_path": corrected})

    return {
        "violations":      violations,
        "total_checked":   total_checked,
        "version_folders": sorted(version_folder_seen),
        "constant_folder": constant,
    }


# ---------------------------------------------------------------------------
# Check 5 — Col D folder name must use constant platform name (no version)
# ---------------------------------------------------------------------------
# The top-level OneCLI package files (.tgz/.zip/.exe/.bin/.rpm) directly
# under *BUILD OUTPUT for "Target" must reference the constant platform
# sub-folder in Col D, not the version-specific filename stem.
_CONSTANT_FOLDER = {
    "linux":   "lnvgy_utl_lxce_onecli_linux_x86-64",
    "windows": "lnvgy_utl_lxce_onecli_winsrv_x86-64",
}
_TOP_PKG_EXTS = (".tgz", ".zip", ".exe", ".bin", ".rpm")


def check_col_d_folder(rows: list, platform: str) -> dict:
    """
    Inspect only rows that sit directly under *BUILD OUTPUT for "Target"
    (the outermost Target section, before any sub-section header).

    For each OneCLI distribution package entry there, verify Col D
    references the constant platform folder name, not a version-specific path.

    Expected values:
      Linux  : see "Target/lnvgy_utl_lxce_onecli_linux_x86-64"
      Windows: see "Target/lnvgy_utl_lxce_onecli_winsrv_x86-64"

    Returns dict with:
      violations      — list of row dicts with 'current_link' and 'expected_link'
      expected_folder — the constant folder name for this platform
      checked_rows    — rows inspected in the top Target section
    """
    expected_folder = _CONSTANT_FOLDER.get(platform, "")
    expected_link   = f'see "Target/{expected_folder}"'
    violations = []
    checked_rows = []
    in_top_target = False

    for r in rows:
        if r["is_section_header"]:
            if r["name"] == '*BUILD OUTPUT for "Target"':
                in_top_target = True
            else:
                in_top_target = False   # entered sub-section — stop
            continue
        if r["is_divider"] or not r["name"]:
            continue
        if not in_top_target:
            continue

        # Only package distribution files
        low = r["name"].lower()
        if not any(low.endswith(ext) for ext in _TOP_PKG_EXTS):
            continue

        checked_rows.append(r)
        link = r["link"]

        if not link:
            violations.append({**r, "current_link": "(empty)", "expected_link": expected_link})
        elif expected_folder and expected_folder not in link:
            violations.append({**r, "current_link": link, "expected_link": expected_link})

    return {
        "violations":      violations,
        "expected_folder": expected_folder,
        "expected_link":   expected_link,
        "checked_rows":    checked_rows,
    }


# ---------------------------------------------------------------------------
# Check 1d — Col A section headers must use constant folder name (no version)
# ---------------------------------------------------------------------------
def check_col_a_sections(rows: list, platform: str) -> dict:
    """
    Inspect every *BUILD OUTPUT for "Target/..." section header row.
    Flag any that contain a version-specific folder component in the path.

    The bare '*BUILD OUTPUT for "Target"' row (no sub-path) is always OK.

    Returns dict with:
      violations      — list of row dicts with 'current_header' and 'corrected_header'
      total_checked   — section header rows inspected (excludes bare "Target" row)
      version_folders — set of version-specific folder names found
      constant_folder — the required constant folder name
    """
    constant = _CONSTANT_FOLDER.get(platform, "")
    violations = []
    total_checked = 0
    version_folder_seen: set = set()

    for r in rows:
        if not r["is_section_header"]:
            continue
        header = r["name"]
        # Skip the bare *BUILD OUTPUT for "Target" — it has no sub-path to check
        if header == '*BUILD OUTPUT for "Target"':
            continue

        total_checked += 1
        m = _VER_FOLDER_RE.search(header)
        if m:
            version_folder_seen.add(m.group(1))
            corrected = _VER_FOLDER_RE.sub(constant, header, count=1)
            violations.append({**r, "current_header": header, "corrected_header": corrected})

    return {
        "violations":      violations,
        "total_checked":   total_checked,
        "version_folders": sorted(version_folder_seen),
        "constant_folder": constant,
    }


# ---------------------------------------------------------------------------
# Check 1e — Col D must include "boost" for components linking against boost
# ---------------------------------------------------------------------------
def _build_boost_target_map(src_root: Path) -> dict:
    """
    Scan all CMakeLists.txt under src_root for boost_ dependencies.
    Returns {target_name_lower: set_of_platforms}.
    Platform ∈ {"linux", "windows", "common"}.
    Logic mirrors boost_filter/scan_boost_v2.py (stdlib only).
    """
    result: dict = {}
    for cmake_path in src_root.rglob("CMakeLists.txt"):
        current_platform = "common"
        current_target = None
        try:
            for line in cmake_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if "if(WIN32)" in line or "if (WIN32)" in line:
                    current_platform = "windows"
                elif "elseif(UNIX)" in line or "elseif (UNIX)" in line:
                    current_platform = "linux"
                elif "endif()" in line:
                    current_platform = "common"
                m = _BOOST_CMAKE_RE.search(line)
                if m:
                    current_target = m.group(1)
                if current_target and "boost_" in line:
                    result.setdefault(current_target.lower(), set()).add(current_platform)
        except Exception:
            pass
    return result


def _col_a_to_cmake_target(name: str) -> str:
    """
    libacquire.so.5.4      → "acquire"
    libBMCRedfishConfig.so → "bmcredfishconfig"
    curlcpp.dll            → "curlcpp"
    Returns '' for non-.so/.dll entries.
    """
    low = name.lower()
    so_idx = low.find(".so")
    if so_idx != -1:
        stem = name[:so_idx]
        if stem.lower().startswith("lib"):
            stem = stem[3:]
        return stem.lower()
    if low.endswith(".dll"):
        return name[:-4].lower()
    return ""


def check_col_d_boost(rows: list, boost_map: dict, platform: str) -> dict:
    """
    Flag .so/.dll rows where the CMake target uses boost but Col D lacks '"boost"'.

    Returns dict with:
      violations    — row dicts augmented with 'cmake_target'
      total_checked — .so/.dll rows inspected
    """
    violations = []
    total_checked = 0

    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        name = r["name"]
        if not name:
            continue
        target = _col_a_to_cmake_target(name)
        if not target:
            continue

        total_checked += 1
        platforms = boost_map.get(target, set())
        if not platforms:
            continue
        if not ("common" in platforms or platform in platforms):
            continue

        if not re.search(r'"boost"', r["link"]):
            violations.append({**r, "cmake_target": target})

    return {"violations": violations, "total_checked": total_checked}


# ---------------------------------------------------------------------------
# Check 1f — Col A component name vs Col D source path (CMakeLists.txt target)
# ---------------------------------------------------------------------------
def _find_source_dir(base: Path, rel_path: str) -> Path:
    """Resolve rel_path under base; fall back to first @hash variant (git submodules)."""
    direct = base / rel_path
    if direct.is_dir():
        return direct
    parent = direct.parent
    stem = direct.name
    if parent.is_dir():
        candidates = sorted(parent.glob(f"{stem}@*"))
        if candidates:
            return candidates[0]
    return None


def _cmake_targets_in_dir(src_dir: Path) -> set:
    """
    Return lowercase set of effective output names from src_dir/CMakeLists.txt.
    Includes add_library/add_executable target names AND any OUTPUT_NAME overrides
    from set_target_properties(... OUTPUT_NAME "...").
    """
    cmake = src_dir / "CMakeLists.txt"
    if not cmake.is_file():
        return set()
    targets = set()
    try:
        text = cmake.read_text(encoding="utf-8", errors="ignore")
        for m in _CMAKE_TARGET_RE.finditer(text):
            targets.add(m.group(1).lower())
        for m in _CMAKE_OUTNAME_RE.finditer(text):
            targets.add(m.group(1).lower())
        # Pre-built binaries bundled via install(FILES ...)
        for m in _CMAKE_INSTALL_RE.finditer(text):
            fname = m.group(1)
            stem = fname.lower()
            if stem.endswith(".dll"):
                stem = stem[:-4]
            elif ".so" in stem:
                stem = stem[:stem.index(".so")]
            targets.add(stem)
    except Exception:
        pass
    return targets


def check_col_a_col_d_source(rows: list, base: Path) -> dict:
    """
    For each .so/.dll row where Col D = see "source/path/...", verify:
      - the path (or its @hash variant) exists under base
      - CMakeLists.txt at that path declares a target matching Col A's stem

    Skips: Target/ output paths, rows with no see "..." in Col D.

    Returns:
      matches       — correctly verified rows
      path_missing  — Col D path not found on disk
      mismatches    — path found but CMake target name doesn't match Col A
      no_cmake      — path found but CMakeLists.txt absent
      total_checked — .so/.dll rows with a source see "..." Col D
    """
    matches = []
    path_missing = []
    mismatches = []
    no_cmake = []
    total_checked = 0

    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        name = r["name"]
        if not name:
            continue
        target = _col_a_to_cmake_target(name)
        if not target:
            continue
        link = r["link"] or ""
        m = _COL_D_SEE_RE.match(link.strip())
        if not m:
            continue
        rel_path = m.group(1)
        # Only check source tree paths; skip output (Target/) paths
        if not any(rel_path.startswith(p) for p in _SOURCE_PREFIXES):
            continue

        total_checked += 1
        src_dir = _find_source_dir(base, rel_path)
        if src_dir is None:
            path_missing.append({**r, "cmake_target": target, "src_path": rel_path})
            continue

        cmake_targets = _cmake_targets_in_dir(src_dir)
        if not cmake_targets:
            no_cmake.append({**r, "cmake_target": target, "src_path": rel_path,
                             "resolved_dir": str(src_dir.relative_to(base))})
            continue

        if target in cmake_targets:
            matches.append({**r, "cmake_target": target, "src_path": rel_path})
        else:
            mismatches.append({**r, "cmake_target": target, "src_path": rel_path,
                               "found_targets": sorted(cmake_targets)})

    return {
        "matches":       matches,
        "path_missing":  path_missing,
        "mismatches":    mismatches,
        "no_cmake":      no_cmake,
        "total_checked": total_checked,
    }


# ---------------------------------------------------------------------------
# Check 1g — I/O package version consistency
# ---------------------------------------------------------------------------
def _io_package_family(pkg_name: str) -> str:
    """Strip version and platform suffix to get the I/O package family key.

    e.g. 'lnvgy_utl_storage-adapter_smartpqi.arcconf-27449-j9vpb-0311_linux_indiv'
         → 'lnvgy_utl_storage-adapter_smartpqi.arcconf'
    """
    base = re.sub(r'_(linux|windows).*$', '', pkg_name)
    m = _IO_VERSION_START_RE.search(base)
    return base[:m.start()] if m else base


def check_io_version(rows: list, platform: str) -> dict:
    """
    For rows where Col D references an I/O bundle (lnvgy_* / intc-*), verify
    the full package name matches the canonical baseline for this platform.

    Also detects internal inconsistency: same Col A binary referenced with
    more than one distinct package (constant condition violated).

    Returns:
      ok           — rows matching canonical exactly
      wrong        — rows whose package family is known but version differs
      unknown      — rows whose package family is not in the baseline
      inconsistent — list of {col_a, refs} where same binary has >1 distinct pkg
      total_checked
    """
    canonical = {_io_package_family(pkg): pkg for pkg in _IO_CANONICAL.get(platform, [])}
    binary_refs: dict = {}
    ok: list = []
    wrong: list = []
    unknown: list = []

    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        link = (r["link"] or "").strip()
        m = _IO_PKG_REF_RE.match(link)
        if not m:
            continue

        pkg = m.group(1)
        col_a = r["name"].strip()
        family = _io_package_family(pkg)
        binary_refs.setdefault(col_a, set()).add(pkg)

        if family in canonical:
            if pkg == canonical[family]:
                ok.append({**r, "pkg": pkg, "family": family})
            else:
                wrong.append({**r, "pkg": pkg, "family": family,
                              "expected": canonical[family]})
        else:
            unknown.append({**r, "pkg": pkg, "family": family})

    inconsistent = [
        {"col_a": col_a, "refs": sorted(refs)}
        for col_a, refs in sorted(binary_refs.items())
        if len(refs) > 1
    ]

    return {
        "ok":            ok,
        "wrong":         wrong,
        "unknown":       unknown,
        "inconsistent":  inconsistent,
        "total_checked": len(ok) + len(wrong) + len(unknown),
    }


# ---------------------------------------------------------------------------
# Check 1h — OSS source archive presence
# ---------------------------------------------------------------------------
def check_source_archives(rows: list) -> dict:
    """
    For every row where Col E starts with '1/', verify there is a corresponding
    compressed source archive in Col A (e.g. openssl-3.6.0.tar.gz).

    Returns:
      paired        — {lib_name, archive_name, row} for matched entries
      missing       — {lib_name, row} for 1/ entries with no archive found
      archive_rows  — all source archive rows found in Col A
      total_checked — distinct libnames in 1/ section
    """
    # Build archive map: libname_lower → first archive row found
    archive_map: dict = {}
    archive_rows: list = []
    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        name = r["name"].strip()
        if not _SRC_ARCHIVE_EXT_RE.search(name):
            continue
        archive_rows.append(r)
        m = _SRC_ARCHIVE_NAME_RE.match(name.lower())
        lib = m.group(1) if m else name.lower()
        if lib not in archive_map:
            archive_map[lib] = r

    # Walk 1/ section entries, one entry per distinct libname
    seen: set = set()
    paired: list = []
    missing: list = []

    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        path = (r["path"] or "").strip()
        if not path.startswith("1/"):
            continue
        tail = path[2:]
        # Skip source tree sub-paths (1/modularization/...) and URL entries (1/https://...)
        if "/" in tail or tail.startswith("http"):
            continue
        lib_name = tail.lower()
        if lib_name in seen:
            continue
        seen.add(lib_name)

        if lib_name in archive_map:
            paired.append({**r, "lib_name": lib_name,
                           "archive_name": archive_map[lib_name]["name"]})
        else:
            missing.append({**r, "lib_name": lib_name})

    return {
        "paired":        paired,
        "missing":       missing,
        "archive_rows":  archive_rows,
        "total_checked": len(paired) + len(missing),
    }


# ---------------------------------------------------------------------------
# Check 2 — Version correctness
# ---------------------------------------------------------------------------
def check_versions(rows: list, platform: str) -> dict:
    """
    Extract rows that carry a semantic version in col B.
    Compare against AUDIT_BASELINE; return findings per library.
    """
    # Collect all semantic-version entries: {lib_name_lower: [version, ...]}
    sbom_versions: dict[str, list[str]] = {}
    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        ver = r["version"]
        name = r["name"].lower().strip()
        if not _SEM_VER.match(ver):
            continue
        # Normalise common name variants
        name = name.replace("lib", "", 1) if name.startswith("lib") and name != "libssh2" else name
        sbom_versions.setdefault(name, [])
        if ver not in sbom_versions[name]:
            sbom_versions[name].append(ver)

    findings = []
    for lib, baseline in AUDIT_BASELINE.items():
        # pthreads-w32 is Windows-only
        if lib == "pthreads-w32" and platform == "linux":
            continue
        # snmp++ is Linux-only
        if lib == "snmp++" and platform == "windows":
            continue

        sbom_vers = sbom_versions.get(lib, [])
        expected  = baseline["expected"]
        audit_st  = baseline["audit_status"]
        actual_ex = baseline.get("actual_extlibs", expected)

        if not sbom_vers:
            if audit_st == "FAIL":
                status = "MISSING"
                note   = f"Library absent from SBOM; expected {expected}"
            else:
                status = "OK"
                note   = "Not applicable / not present (expected)"
        elif expected in sbom_vers:
            if audit_st == "FAIL":
                # SBOM still declares the old expected version; extlibs has moved on
                status = "UNRESOLVED"
                note   = (f"SBOM still declares {expected}; "
                          f"extlibs header is {actual_ex} — version drift not updated in SBOM")
            elif audit_st == "WARN":
                status = "WARN"
                note   = (f"SBOM declares {expected}; actual extlibs is {actual_ex} "
                          f"(patch drift within same minor)")
            else:
                status = "OK"
                note   = f"SBOM declares {expected} — matches audit baseline"
        else:
            # SBOM has a different version from expected
            status = "MISMATCH"
            note   = f"SBOM has {sbom_vers}; expected {expected} (extlibs: {actual_ex})"

        findings.append({
            "library":    lib,
            "expected":   expected,
            "sbom_vers":  sbom_vers,
            "audit_st":   audit_st,
            "status":     status,
            "note":       note,
        })

    return {"findings": findings, "all_sbom_versions": sbom_versions}


# ---------------------------------------------------------------------------
# Check 3 — Duplicate / multi-version detection
# ---------------------------------------------------------------------------
def _is_io_sourced_row(row: dict) -> bool:
    """True if this row's component is sourced from an I/O package (not OneCLI extlibs).

    Rows in the '1/' source section are canonical extlibs declarations — they inherit
    the section of the last *BUILD OUTPUT header (often a utilities/ header) but are
    never I/O-sourced regardless.
    """
    if row.get("path", "").startswith("1/"):
        return False
    return (
        bool(_IO_PKG_REF_RE.match(row.get("link", "")))
        or "utilities/" in row.get("section", "")
    )


def check_duplicates(rows: list, platform: str = "linux") -> dict:
    """
    Return {"stale": [...], "approved": [...]} for libraries with >1 semantic version.

    Auto-detects I/O-sourced versions: a version is I/O-sourced when ALL its rows
    either (a) have Col D referencing an lnvgy_*/intc-* package, or (b) belong to
    a 'utilities/' section.  I/O-sourced versions surface as 'approved' (need
    per-release confirmation, not deletion); the rest go to 'stale'.
    """
    # Build: library (lower) → version → [rows]
    ver_map: dict = {}
    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        ver = r["version"]
        name = r["name"].lower().strip()
        if not _SEM_VER.match(ver):
            continue
        ver_map.setdefault(name, {}).setdefault(ver, []).append(r)

    stale = []
    approved = []
    for lib, by_ver in ver_map.items():
        if len(by_ver) <= 1:
            continue
        all_row_nums = [r["row_num"] for vers in by_ver.values() for r in vers]
        stale_vers = []
        io_vers = []
        for ver, ver_rows in by_ver.items():
            if all(_is_io_sourced_row(r) for r in ver_rows):
                m = _IO_PKG_REF_RE.match(ver_rows[0].get("link", ""))
                io_ref = _io_package_family(m.group(1)) if m else "utilities section"
                io_vers.append((ver, f"I/O-sourced: {io_ref}; re-confirm each release"))
            else:
                stale_vers.append(ver)
        if len(stale_vers) > 1:
            stale.append({"library": lib, "versions": stale_vers, "row_nums": all_row_nums})
        if io_vers:
            approved.append({
                "library": lib,
                "approved_versions": io_vers,
                "all_versions": list(by_ver.keys()),
                "row_nums": all_row_nums,
            })
    return {"stale": stale, "approved": approved}


# ---------------------------------------------------------------------------
# Check 1i — I/O tool license map
# ---------------------------------------------------------------------------
def check_io_tool_licenses(rows: list) -> list:
    """
    Find I/O tool entries (Col A matches lnvgy_*/intc-*, Col B is a version not a
    checksum) and map each tool to the OSS components it bundles (rows whose Col D
    references that tool).

    Returns list of:
      {io_tool, version, license, section,
       oss_deps: [{name, version, license, row_num}]}
    """
    io_tools: dict = {}  # full package name → entry dict

    # Pass 1 — collect I/O tool rows
    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        name = r["name"].strip()
        ver  = r["version"].strip()
        if not _IO_TOOL_NAME_RE.match(name):
            continue
        if not ver or _CHECKSUM_RE.match(ver) or not _SEM_VER.match(ver):
            continue
        if name not in io_tools:
            io_tools[name] = {
                "io_tool":  name,
                "version":  ver,
                "license":  r["license"],
                "section":  r.get("section", ""),
                "oss_deps": [],
            }

    # Build section → [io_tool entries] mapping for section-based attribution
    section_tools: dict = {}
    for tool_name, entry in io_tools.items():
        sec = entry["section"]
        if sec:
            section_tools.setdefault(sec, []).append(tool_name)

    def _add_dep(entry: dict, r: dict) -> None:
        dep = {"name": r["name"], "version": r["version"],
               "license": r["license"], "row_num": r["row_num"]}
        key = (dep["name"].lower(), dep["version"])
        if not any((d["name"].lower(), d["version"]) == key for d in entry["oss_deps"]):
            entry["oss_deps"].append(dep)

    # Pass 2 — find OSS rows by two signals:
    #   (a) Col D explicitly references the I/O tool (see "lnvgy_...")
    #   (b) row is in the same utilities section as the I/O tool, and is NOT an
    #       I/O tool row itself, and has a real version (not checksum)
    for r in rows:
        if r["is_section_header"] or r["is_divider"]:
            continue
        if _IO_TOOL_NAME_RE.match(r["name"]):
            continue  # skip I/O tool rows themselves
        if r.get("path", "").startswith("1/"):
            continue  # skip canonical source declarations

        link = r.get("link", "").strip()
        m = _IO_PKG_REF_RE.match(link)
        if m:
            # Signal (a): explicit lnvgy Col D reference
            io_ref_family = _io_package_family(m.group(1))
            for tool_name, entry in io_tools.items():
                if _io_package_family(tool_name) == io_ref_family:
                    _add_dep(entry, r)
                    break
        else:
            # Signal (b): same utilities section, real semver in Col B
            sec = r.get("section", "")
            if "utilities/" not in sec:
                continue
            ver = r["version"].strip()
            if not ver or _CHECKSUM_RE.match(ver):
                continue
            for tool_name in section_tools.get(sec, []):
                _add_dep(io_tools[tool_name], r)

    return sorted(io_tools.values(), key=lambda e: e["io_tool"])


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
_STATUS_ICON = {
    "OK":         "✅",
    "WARN":       "⚠️",
    "UNRESOLVED": "❌",
    "MISSING":    "❌",
    "MISMATCH":   "❌",
}


def _fmt_versions(vers: list) -> str:
    return ", ".join(vers) if vers else "—"


def generate_report(linux: dict, windows: dict, out_path: Path) -> None:
    lines = []
    a = lines.append

    a(f"# SBOM Review Report — OneCLI v5.6.0")
    a(f"**Generated:** {date.today().isoformat()}  ")
    a(f"**Scope:** Linux SBOM + Windows SBOM  ")
    a(f"**Reference:** version_audit_5.6.0.log  ")
    a("")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        meta = res["parse"]["metadata"]
        fmt  = res["format"]
        ver  = res["versions"]
        dup  = res["duplicates"]
        colf = res["col_f"]
        cold = res["col_d"]
        cole = res["col_e"]
        cola = res["col_a"]

        a(f"---")
        a(f"")
        a(f"## {label} SBOM")
        a(f"")

        # Metadata
        prod_name = meta.get("Product Name", "—")
        prod_ver  = meta.get("Product Version", "—")
        scan_date = meta.get("Date Scan completed", "—")
        total_scanned = meta.get("Total number of components scanned", "—")
        total_oss     = meta.get("Total number of Open Source packages", "—")
        a(f"**Product:** {prod_name} {prod_ver}  ")
        a(f"**Scan date:** {scan_date}  ")
        a(f"**Components scanned:** {total_scanned} total / {total_oss} OSS  ")
        a(f"")

        # Check 1
        a(f"### Check 1 — Format Validation")
        a(f"")
        target_count = len(fmt["target_sections"])
        a(f"| Item | Value |")
        a(f"|---|---|")
        a(f"| Target sections found | {target_count} |")
        a(f"| Total data rows | {fmt['total_data_rows']} |")
        a(f"| Orphan rows (name, no path) | {len(fmt['orphans'])} |")
        a(f"| Reversed orphan rows (path, no name) | {len(fmt['no_name_rows'])} |")
        a(f"| `see below` license refs | {fmt['see_below_count']} |")
        a(f"")
        if fmt["issues"]:
            a(f"**Issues:**")
            for iss in fmt["issues"]:
                a(f"- ⚠️ {iss}")
        else:
            a(f"✅ No format issues detected.")
        if fmt["orphans"]:
            a(f"")
            a(f"<details><summary>Orphan rows (first 10)</summary>")
            a(f"")
            a(f"| Row | Name | Path |")
            a(f"|---|---|---|")
            for r in fmt["orphans"][:10]:
                a(f"| {r['row_num']} | `{r['name'][:50]}` | _(empty)_ |")
            a(f"")
            a(f"</details>")
        a(f"")

        # Check 1c — Col E version-specific path (systematic)
        a(f"### Check 1c — Col E (Path) Version-Specific Folder")
        a(f"")
        a(f"Col E must use the **constant platform folder name** for re-use across releases.  ")
        a(f"OneCLI distribution packages (`.tgz` / `.zip` / `.exe` / `.bin` / `.rpm`) are excluded — "
          f"they keep their exact filename in Col E.")
        a(f"")
        n_viol = len(cole["violations"])
        n_total = cole["total_checked"]
        vf_list = cole["version_folders"]
        if n_viol:
            a(f"❌ **Systematic issue — {n_viol} / {n_total} Target rows use a version-specific folder in Col E.**")
            a(f"")
            a(f"| Item | Value |")
            a(f"|---|---|")
            for vf in vf_list:
                a(f"| Version-specific folder (current) | `{vf}` |")
            a(f"| Constant folder (required) | `{cole['constant_folder']}` |")
            a(f"")
            a(f"**Substitution rule:** replace every occurrence of `{vf_list[0] if vf_list else '?'}` "
              f"in Col E with `{cole['constant_folder']}`.")
            a(f"")
            # Show first 5 sample rows
            a(f"**Sample rows (first 5 of {n_viol}):**")
            a(f"")
            a(f"| Row | Col A | Col E (current) | Col E (required) |")
            a(f"|---|---|---|---|")
            for v in cole["violations"][:5]:
                a(f"| {v['row_num']} | `{v['name'][:40]}` "
                  f"| `{v['current_path'][:55]}` | `{v['corrected_path'][:55]}` |")
            if n_viol > 5:
                a(f"| … | _(+{n_viol - 5} more rows)_ | | |")
        else:
            a(f"✅ All Col E paths use the constant folder name.")
        a(f"")

        # Check 1d — Col A section header folder name
        a(f"### Check 1d — Col A (Section Headers) Version-Specific Folder")
        a(f"")
        a(f"`*BUILD OUTPUT for \"Target/...\"` section headers must use the **constant platform folder name** — "
          f"not a version-specific folder — so they remain stable across releases.")
        a(f"")
        n_av = len(cola["violations"])
        n_at = cola["total_checked"]
        vfa_list = cola["version_folders"]
        if n_av:
            a(f"❌ **Systematic issue — {n_av} / {n_at} section headers use a version-specific folder in Col A.**")
            a(f"")
            a(f"| Item | Value |")
            a(f"|---|---|")
            for vf in vfa_list:
                a(f"| Version-specific folder (current) | `{vf}` |")
            a(f"| Constant folder (required) | `{cola['constant_folder']}` |")
            a(f"")
            a(f"**Substitution rule:** replace `{vfa_list[0] if vfa_list else '?'}` "
              f"with `{cola['constant_folder']}` in every `*BUILD OUTPUT` header.")
            a(f"")
            a(f"**All affected headers:**")
            a(f"")
            a(f"| Row | Current Header | Required Header |")
            a(f"|---|---|---|")
            for v in cola["violations"]:
                a(f"| {v['row_num']} | `{v['current_header']}` | `{v['corrected_header']}` |")
        else:
            a(f"✅ All section headers use the constant folder name.")
        a(f"")

        # Check 1a — Col D folder name consistency
        a(f"### Check 1a — Col D (Link) Folder Name Consistency")
        a(f"")
        a(f"Top-level OneCLI package entries directly under `*BUILD OUTPUT for \"Target\"` must have")
        a(f"Col D referencing the **constant platform folder name** — not a version-specific path.")
        a(f"")
        a(f"Expected Col D: `{cold['expected_link']}`")
        a(f"")
        if cold["violations"]:
            a(f"❌ **{len(cold['violations'])} package(s) use a non-constant (version-specific) Col D:**")
            a(f"")
            a(f"| Row | Col A (Package) | Col D (current) | Col D (required) |")
            a(f"|---|---|---|---|")
            for v in cold["violations"]:
                a(f"| {v['row_num']} | `{v['name']}` | `{v['current_link']}` | `{v['expected_link']}` |")
        else:
            a(f"✅ All top-level package entries use the correct constant folder name in Col D.")
        a(f"")

        # Check 1e — Col D boost annotation
        a(f"### Check 1e — Col D Boost Annotation")
        a(f"")
        a(f"For each `.so`/`.dll` row whose CMake target links against boost "
          f"(per `CMakeLists.txt` `target_link_libraries`), "
          f"Col D must include `; \"boost\"` — e.g. `see \"modularization/src/module/acquire\"; \"boost\"`.")
        a(f"")
        coldb = res["col_d_boost"]
        n_bv = len(coldb["violations"])
        n_bt = coldb["total_checked"]
        if n_bv:
            a(f"❌ **{n_bv} row(s) missing boost annotation in Col D** "
              f"(out of {n_bt} `.so`/`.dll` rows checked):")
            a(f"")
            a(f"| Row | Col A | CMake Target | Col D (current) |")
            a(f"|---|---|---|---|")
            for v in coldb["violations"][:25]:
                link_display = v["link"][:60] if v["link"] else "_(empty)_"
                a(f"| {v['row_num']} | `{v['name'][:45]}` | `{v['cmake_target']}` "
                  f"| `{link_display}` |")
            if n_bv > 25:
                a(f"| … | _(+{n_bv - 25} more rows)_ | | |")
        else:
            a(f"✅ All `.so`/`.dll` rows with boost dependencies have the boost annotation in Col D.")
        a(f"")

        # Check 1f — Col A vs Col D source path
        a(f"### Check 1f — Col A ↔ Col D Source Path Verification")
        a(f"")
        a(f"For each `.so`/`.dll` row where Col D is `see \"source/path\"`, verify the source "
          f"path exists and its `CMakeLists.txt` declares a target matching Col A's component name.")
        a(f"")
        cds = res["col_d_src"]
        n_ok   = len(cds["matches"])
        n_miss = len(cds["path_missing"])
        n_mm   = len(cds["mismatches"])
        n_nc   = len(cds["no_cmake"])
        n_tot  = cds["total_checked"]
        a(f"| Result | Count |")
        a(f"|---|---|")
        a(f"| ✅ Verified (target matches) | {n_ok} |")
        a(f"| ❌ Mismatch (dir exists, wrong target) | {n_mm} |")
        a(f"| ⚠️ Path missing (dir not found) | {n_miss} |")
        a(f"| ⚠️ No CMakeLists.txt | {n_nc} |")
        a(f"| Total checked | {n_tot} |")
        a(f"")
        if cds["mismatches"]:
            a(f"**❌ Mismatches — Col D path exists but CMake target does not match Col A:**")
            a(f"")
            a(f"| Row | Col A | Expected target | Col D path | Targets found |")
            a(f"|---|---|---|---|---|")
            for v in cds["mismatches"]:
                found = ", ".join(v["found_targets"][:5]) or "_(none)_"
                a(f"| {v['row_num']} | `{v['name'][:45]}` | `{v['cmake_target']}` "
                  f"| `{v['src_path']}` | `{found}` |")
            a(f"")
        if cds["path_missing"]:
            a(f"<details><summary>⚠️ {n_miss} path(s) not found on disk</summary>")
            a(f"")
            a(f"| Row | Col A | Expected target | Col D path |")
            a(f"|---|---|---|---|")
            for v in cds["path_missing"]:
                a(f"| {v['row_num']} | `{v['name'][:45]}` | `{v['cmake_target']}` "
                  f"| `{v['src_path']}` |")
            a(f"")
            a(f"</details>")
            a(f"")
        if cds["no_cmake"]:
            a(f"<details><summary>⚠️ {n_nc} path(s) found but no CMakeLists.txt</summary>")
            a(f"")
            a(f"| Row | Col A | Expected target | Resolved dir |")
            a(f"|---|---|---|---|")
            for v in cds["no_cmake"]:
                a(f"| {v['row_num']} | `{v['name'][:45]}` | `{v['cmake_target']}` "
                  f"| `{v['resolved_dir']}` |")
            a(f"")
            a(f"</details>")
            a(f"")
        if n_mm == 0 and n_miss == 0 and n_nc == 0:
            a(f"✅ All {n_ok} checked components verified — Col A names match CMakeLists.txt targets.")
        a(f"")

        # Check 1g — I/O package version consistency
        a(f"### Check 1g — I/O Package Version Consistency")
        a(f"")
        a(f"For rows where Col D references an I/O bundle (`lnvgy_*` / `intc-*`), verify the "
          f"full package name matches the canonical baseline (constant condition) and is "
          f"consistent across all Target sections.")
        a(f"")
        iov = res["io_ver"]
        n_iok  = len(iov["ok"])
        n_iwr  = len(iov["wrong"])
        n_iunk = len(iov["unknown"])
        n_iinc = len(iov["inconsistent"])
        n_itot = iov["total_checked"]
        a(f"| Result | Count |")
        a(f"|---|---|")
        a(f"| ✅ Matches canonical | {n_iok} |")
        a(f"| ❌ Wrong version (family known) | {n_iwr} |")
        a(f"| ⚠️ Unknown package family | {n_iunk} |")
        a(f"| ⚠️ Internally inconsistent (multiple versions) | {n_iinc} |")
        a(f"| Total checked | {n_itot} |")
        a(f"")
        if iov["wrong"]:
            a(f"**❌ Wrong package versions:**")
            a(f"")
            a(f"| Row | Col A | Actual package | Expected package |")
            a(f"|---|---|---|---|")
            for v in iov["wrong"]:
                a(f"| {v['row_num']} | `{v['name'][:45]}` | `{v['pkg']}` | `{v['expected']}` |")
            a(f"")
        if iov["inconsistent"]:
            a(f"**⚠️ Internally inconsistent binaries (same binary, multiple package versions):**")
            a(f"")
            a(f"| Col A binary | Package refs found |")
            a(f"|---|---|")
            for inc in iov["inconsistent"]:
                refs_str = "<br>".join(f"`{r}`" for r in inc["refs"])
                a(f"| `{inc['col_a']}` | {refs_str} |")
            a(f"")
        if iov["unknown"]:
            a(f"<details><summary>⚠️ {n_iunk} reference(s) with unknown package family "
              f"(not in canonical baseline)</summary>")
            a(f"")
            a(f"| Row | Col A | Package referenced |")
            a(f"|---|---|---|")
            for v in iov["unknown"][:30]:
                a(f"| {v['row_num']} | `{v['name'][:45]}` | `{v['pkg']}` |")
            if n_iunk > 30:
                a(f"| … | _(+{n_iunk - 30} more)_ | |")
            a(f"")
            a(f"</details>")
            a(f"")
        if n_iwr == 0 and n_iinc == 0 and n_iunk == 0:
            a(f"✅ All {n_iok} I/O package references match the canonical baseline.")
        a(f"")

        # Check 1h — OSS source archive presence
        a(f"### Check 1h — OSS Source Archive Presence")
        a(f"")
        a(f"For every row where Col E starts with `1/` (source distribution section), "
          f"verify a corresponding compressed source archive exists in Col A "
          f"(e.g. `openssl-3.6.0.tar.gz`, `pegasus-2.14.1.zip`).")
        a(f"")
        sa = res["src_arch"]
        n_spaired = len(sa["paired"])
        n_smiss   = len(sa["missing"])
        n_stot    = sa["total_checked"]
        a(f"| Result | Count |")
        a(f"|---|---|")
        a(f"| ✅ Source archive present | {n_spaired} |")
        a(f"| ❌ Source archive missing | {n_smiss} |")
        a(f"| Total `1/` libs checked | {n_stot} |")
        a(f"")
        if sa["missing"]:
            a(f"**❌ OSS components in `1/` section with no source archive:**")
            a(f"")
            a(f"| Row | Col A (component) | Col E path |")
            a(f"|---|---|---|")
            for v in sa["missing"]:
                a(f"| {v['row_num']} | `{v['name'][:50]}` | `{v['path']}` |")
            a(f"")
        else:
            a(f"✅ All {n_spaired} OSS components in the `1/` section have a source archive.")
        a(f"")

        # Check 1i — I/O tool license map
        a(f"### Check 1i — I/O Tool License Map")
        a(f"")
        a(f"I/O tools identified by Col A matching `lnvgy_*`/`intc-*` with a version in Col B.  ")
        a(f"OSS dependencies are rows whose Col D references the same I/O tool package.")
        a(f"")
        io_lic = res["io_lic"]
        if io_lic:
            for entry in io_lic:
                a(f"#### `{entry['io_tool']}`")
                a(f"")
                a(f"| Field | Value |")
                a(f"|---|---|")
                a(f"| Version | `{entry['version']}` |")
                a(f"| License | {entry['license'] or '_(not filled)_'} |")
                a(f"| Section | `{entry['section']}` |")
                a(f"")
                if entry["oss_deps"]:
                    a(f"**Bundled OSS dependencies:**")
                    a(f"")
                    a(f"| Component | Version | License |")
                    a(f"|---|---|---|")
                    for dep in sorted(entry["oss_deps"], key=lambda d: d["name"].lower()):
                        a(f"| `{dep['name']}` | `{dep['version']}` | {dep['license'] or '_(blank)_'} |")
                    a(f"")
                else:
                    a(f"_No OSS dependencies found via Col D reference._")
                    a(f"")
        else:
            a(f"✅ No I/O tool entries found (Col A `lnvgy_*`/`intc-*` with version in Col B).")
        a(f"")

        # Check 1b — Col F empty
        a(f"### Check 1b — Col F (USE) Completeness")
        a(f"")
        a(f"Col F must be filled for **every** component row; value must reflect the file type in Col A.  ")
        a(f"Only `*BUILD OUTPUT` section headers (which carry `DIR`) are excluded from this check.")
        a(f"")
        if colf["violations"]:
            a(f"⚠️ **{len(colf['violations'])} row(s) have an empty Col F** (out of {colf['total_checked']} checked):")
            a(f"")
            a(f"| Row | Col A (Component Name) | Col A Extension | Suggested Col F |")
            a(f"|---|---|---|---|")
            for v in colf["violations"]:
                name = v["name"]
                low  = name.lower()
                # Determine display extension
                if ".so" in low:
                    ext = ".so[.N]"
                elif "." in name.rsplit("/", 1)[-1]:
                    ext = "." + name.rsplit(".", 1)[-1]
                else:
                    ext = "(no ext)"
                suggested = v["suggested"] if v["suggested"] else "_(unknown — fill manually)_"
                a(f"| {v['row_num']} | `{name[:55]}` | `{ext}` | **{suggested}** |")
        else:
            a(f"✅ All component rows have Col F filled.")
        a(f"")

        # Check 2
        a(f"### Check 2 — Version Correctness")
        a(f"")
        a(f"Comparing SBOM-declared versions against `version_audit_5.6.0.log` baseline.")
        a(f"")
        a(f"| Library | Expected | SBOM Declares | Audit Baseline | Status | Note |")
        a(f"|---|---|---|---|---|---|")
        for f in ver["findings"]:
            icon = _STATUS_ICON.get(f["status"], "?")
            a(f"| {f['library']} | {f['expected']} | {_fmt_versions(f['sbom_vers'])} "
              f"| {f['audit_st']} | {icon} {f['status']} | {f['note']} |")
        a(f"")

        # Check 3
        a(f"### Check 3 — Duplicate / Multi-Version Detection")
        a(f"")
        if dup["stale"]:
            a(f"**❌ Stale duplicate versions (remove excess entries):**")
            a(f"")
            a(f"| Library | Versions Found | Row Numbers |")
            a(f"|---|---|---|")
            for d in dup["stale"]:
                rows_str = ", ".join(str(r) for r in d["row_nums"][:6])
                if len(d["row_nums"]) > 6:
                    rows_str += f" … (+{len(d['row_nums'])-6})"
                a(f"| {d['library']} | {', '.join(d['versions'])} | {rows_str} |")
            a(f"")
        if dup["approved"]:
            a(f"**⚠️ I/O-sourced versions — not stale, but confirm each release:**")
            a(f"")
            a(f"| Library | I/O-Sourced Version | All Versions Present | Note |")
            a(f"|---|---|---|---|")
            for d in dup["approved"]:
                all_vers = ", ".join(d["all_versions"])
                for ver, reason in d["approved_versions"]:
                    a(f"| {d['library']} | `{ver}` | {all_vers} | {reason} |")
            a(f"")
        if not dup["stale"] and not dup["approved"]:
            a(f"✅ No duplicate versions detected.")
        a(f"")

    # Summary
    a(f"---")
    a(f"")
    a(f"## Summary — Action Items")
    a(f"")
    a(f"| Priority | Library | Platform | Finding | Action |")
    a(f"|---|---|---|---|---|")

    # Collect UNRESOLVED / MISSING / MISMATCH across both platforms
    seen = set()
    for label, res in [("Linux", linux), ("Windows", windows)]:
        cola = res["col_a"]
        if cola["violations"]:
            vf = cola["version_folders"][0] if cola["version_folders"] else "?"
            a(f"| HIGH | Col A headers | {label} | {len(cola['violations'])}/{cola['total_checked']} "
              f"section headers: `{vf}` → `{cola['constant_folder']}` | "
              f"Global find-and-replace in Col A section headers |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        cole = res["col_e"]
        if cole["violations"]:
            vf = cole["version_folders"][0] if cole["version_folders"] else "?"
            a(f"| HIGH | Col E path | {label} | {len(cole['violations'])}/{cole['total_checked']} "
              f"Target rows: `{vf}` → `{cole['constant_folder']}` | "
              f"Global find-and-replace in Col E |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        for v in res["col_d"]["violations"]:
            a(f"| HIGH | Col D folder | {label} | Row {v['row_num']}: `{v['name'][:40]}` — "
              f"uses `{v['current_link'][:50]}` | Change to `{v['expected_link']}` |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        coldb = res["col_d_boost"]
        if coldb["violations"]:
            a(f"| HIGH | Col D boost | {label} | "
              f"{len(coldb['violations'])} row(s) missing `; \"boost\"` annotation in Col D | "
              f"Append `; \"boost\"` to Col D for each flagged row |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        cds = res["col_d_src"]
        for v in cds["mismatches"]:
            found = ", ".join(v["found_targets"][:3]) or "none"
            a(f"| HIGH | Col A/D mismatch | {label} | Row {v['row_num']}: `{v['name'][:40]}` — "
              f"expected target `{v['cmake_target']}`, found `{found}` | "
              f"Correct Col A name or Col D path |")
        if cds["path_missing"]:
            a(f"| MEDIUM | Col D path missing | {label} | "
              f"{len(cds['path_missing'])} row(s) — source dir not found on disk | "
              f"Verify source tree is fully checked out |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        sa = res["src_arch"]
        for v in sa["missing"]:
            a(f"| HIGH | Src archive missing | {label} | Row {v['row_num']}: "
              f"`{v['name'][:45]}` (`{v['path']}`) — no source archive in Col A | "
              f"Add `{v['lib_name']}-{{version}}.tar.gz` (or `.zip`) to Col A |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        iov = res["io_ver"]
        for v in iov["wrong"]:
            a(f"| HIGH | I/O pkg version | {label} | Row {v['row_num']}: `{v['name'][:35]}` — "
              f"`{v['pkg'][:60]}` | "
              f"Change Col D to `{v['expected']}` |")
        for inc in iov["inconsistent"]:
            refs_str = " vs ".join(f"`{r}`" for r in inc["refs"])
            a(f"| HIGH | I/O pkg inconsistency | {label} | "
              f"`{inc['col_a']}` has {len(inc['refs'])} distinct pkg refs: "
              f"{refs_str[:80]} | "
              f"Standardize all Col D refs to canonical package |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        for v in res["col_f"]["violations"]:
            suggested = v["suggested"] if v["suggested"] else "fill manually"
            a(f"| HIGH | Col F empty | {label} | Row {v['row_num']}: `{v['name'][:45]}` — "
              f"Col F is blank | Set to **{suggested}** |")

    for label, res in [("Linux + Windows", linux), ("Windows", windows)]:
        for f in res["versions"]["findings"]:
            key = (f["library"], f["status"])
            if key in seen:
                continue
            seen.add(key)
            if f["status"] in ("UNRESOLVED", "MISSING", "MISMATCH"):
                plat = "Linux + Windows" if f["library"] not in ("pthreads-w32",) else "Windows"
                if f["library"] == "electron":
                    plat = "Linux + Windows"
                a(f"| HIGH | {f['library']} | {plat} | {f['status']}: {f['note'][:80]} | "
                  f"Update SBOM version or confirm with dev team |")
            elif f["status"] == "WARN":
                a(f"| MEDIUM | {f['library']} | Linux + Windows | {f['status']}: {f['note'][:80]} | "
                  f"Confirm patch-level drift is accepted |")

    for label, res in [("Linux", linux), ("Windows", windows)]:
        for d in res["duplicates"]["stale"]:
            a(f"| MEDIUM | {d['library']} | {label} | Stale duplicate versions: {', '.join(d['versions'])} | "
              f"Remove stale version entry from SBOM |")
        for d in res["duplicates"]["approved"]:
            for ver, reason in d["approved_versions"]:
                a(f"| MEDIUM | {d['library']} | {label} | I/O-sourced `{ver}` present — {reason} | "
                  f"Confirm version is still current for this release |")

    a(f"")
    a(f"*Report generated by `sbom_review.py`*")

    out_path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def _run_checks(sbom_path: Path, platform: str, boost_map: dict) -> dict:
    print(f"  Parsing {sbom_path.name} …", end=" ", flush=True)
    parsed = parse_sbom(sbom_path)
    print(f"{len(parsed['rows'])} rows")

    fmt   = check_format(parsed["rows"])
    ver   = check_versions(parsed["rows"], platform)
    dup   = check_duplicates(parsed["rows"], platform)
    colf  = check_col_f(parsed["rows"])
    cold  = check_col_d_folder(parsed["rows"], platform)
    cole  = check_col_e_path(parsed["rows"], platform)
    cola  = check_col_a_sections(parsed["rows"], platform)
    coldb = check_col_d_boost(parsed["rows"], boost_map, platform)
    col_d_src = check_col_a_col_d_source(parsed["rows"], BASE)
    io_ver    = check_io_version(parsed["rows"], platform)
    src_arch  = check_source_archives(parsed["rows"])
    io_lic    = check_io_tool_licenses(parsed["rows"])
    return {"parse": parsed, "format": fmt, "versions": ver, "duplicates": dup,
            "col_f": colf, "col_d": cold, "col_e": cole, "col_a": cola,
            "col_d_boost": coldb, "col_d_src": col_d_src,
            "io_ver": io_ver, "src_arch": src_arch, "io_lic": io_lic}


def _print_summary(label: str, res: dict) -> None:
    fmt  = res["format"]
    ver  = res["versions"]
    dup  = res["duplicates"]
    colf = res["col_f"]
    cold = res["col_d"]
    cole = res["col_e"]
    cola = res["col_a"]

    fails = sum(1 for f in ver["findings"] if f["status"] in ("UNRESOLVED", "MISSING", "MISMATCH"))
    warns = sum(1 for f in ver["findings"] if f["status"] == "WARN")
    coldb = res["col_d_boost"]

    print(f"\n  [{label}]")
    print(f"    Format : {len(fmt['target_sections'])} targets, "
          f"{len(fmt['orphans'])} orphans, "
          f"{len(fmt['issues'])} issue(s)")
    vfa = cola['version_folders']
    print(f"    Col A  : {len(cola['violations'])}/{cola['total_checked']} section headers use "
          f"version-specific folder ({', '.join(vfa) if vfa else 'none'} → {cola['constant_folder']})")
    print(f"    Col D  : {len(cold['violations'])} package(s) with non-constant folder in Col D "
          f"(expected: {cold['expected_folder']})")
    print(f"    Col D+ : {len(coldb['violations'])} .so/.dll row(s) missing boost annotation "
          f"(out of {coldb['total_checked']} checked)")
    col_d_src = res["col_d_src"]
    n_miss = len(col_d_src["path_missing"])
    n_mm   = len(col_d_src["mismatches"])
    n_nc   = len(col_d_src["no_cmake"])
    n_ok   = len(col_d_src["matches"])
    print(f"    Col D~ : {n_ok} verified / {n_mm} mismatch / {n_miss} path-missing / "
          f"{n_nc} no-cmake  (of {col_d_src['total_checked']} checked)")
    iov = res["io_ver"]
    print(f"    I/O Ver: {len(iov['ok'])} ok / {len(iov['wrong'])} wrong / "
          f"{len(iov['unknown'])} unknown / {len(iov['inconsistent'])} inconsistent "
          f"(of {iov['total_checked']} checked)")
    sa = res["src_arch"]
    print(f"    Src Arch: {len(sa['paired'])} ok / {len(sa['missing'])} missing "
          f"(of {sa['total_checked']} 1/ libs checked)")
    vf = cole['version_folders']
    print(f"    Col E  : {len(cole['violations'])}/{cole['total_checked']} Target rows use "
          f"version-specific path ({', '.join(vf) if vf else 'none'} → {cole['constant_folder']})")
    print(f"    Col F  : {len(colf['violations'])} empty USE field(s) out of {colf['total_checked']} rows checked")
    print(f"    Versions: {fails} FAIL/MISSING, {warns} WARN, "
          f"{sum(1 for f in ver['findings'] if f['status']=='OK')} OK")
    print(f"    Dupes  : {len(dup['stale'])} stale / {len(dup['approved'])} approved multi-version entries")

    if fails or warns:
        for f in ver["findings"]:
            if f["status"] not in ("OK",):
                icon = {"UNRESOLVED": "✗", "MISSING": "✗", "MISMATCH": "✗", "WARN": "~"}.get(f["status"], "?")
                print(f"      {icon} {f['library']:<15} [{f['status']}] {f['note'][:70]}")


_SBOM_GLOB = "lnvgy_utl_lxce_onecli_{platform}_indiv*-SBOM-*.xlsx"
# Matches both Linux (`-5.6.x-(Tasmania)`) and Windows (`-v5.6.x (Tasmania)`) forms.
_VERSION_RE   = re.compile(r"-v?(\d+\.\d+)\.x[-_( ]")
_VERSION_SAFE = re.compile(r"^[\d.]+$")


def _find_sbom(base: Path, platform: str) -> Path:
    """Glob for the SBOM .xlsx of `platform` ('linux'/'windows') in `base`.

    Raises SystemExit with an actionable message when 0 or >1 files match.
    """
    matches = sorted(base.glob(_SBOM_GLOB.format(platform=platform)))
    if not matches:
        raise SystemExit(
            f"ERROR: no {platform} SBOM found in {base}\n"
            f"  expected pattern: {_SBOM_GLOB.format(platform=platform)}\n"
            f"  use --{platform}-sbom PATH to specify explicitly"
        )
    if len(matches) > 1:
        names = "\n    ".join(p.name for p in matches)
        raise SystemExit(
            f"ERROR: multiple {platform} SBOM files found in {base}:\n    {names}\n"
            f"  use --{platform}-sbom PATH to specify which one"
        )
    return matches[0]


def _extract_version(sbom: Path) -> str:
    """Pull '5.6.0' style version from an SBOM filename. Fallback: 'unknown'."""
    m = _VERSION_RE.search(sbom.name)
    return f"{m.group(1)}.0" if m else "unknown"


def _parse_args() -> argparse.Namespace:
    """Define and parse command-line arguments for the SBOM review CLI."""
    p = argparse.ArgumentParser(
        prog="sbom_review.py",
        description="OneCLI SBOM review — dual-platform (Linux + Windows) "
                    "compliance checks against extlibs and CMake targets.",
    )
    p.add_argument("--base", type=Path, default=Path.cwd(),
                   help="OneCLI workspace root (default: CWD)")
    p.add_argument("--linux-sbom", type=Path,
                   help="Linux SBOM .xlsx path (default: glob in --base)")
    p.add_argument("--windows-sbom", type=Path,
                   help="Windows SBOM .xlsx path (default: glob in --base)")
    p.add_argument("--output", type=Path,
                   help="Report output path (default: <base>/sbom_review_<version>.md)")
    p.add_argument("--version", dest="version",
                   help="Product version for report header "
                        "(default: extracted from Linux SBOM filename)")
    return p.parse_args()


def main() -> int:
    args = _parse_args()

    global BASE, SBOM_LINUX, SBOM_WIN, REPORT_OUT
    BASE = args.base.resolve()
    if not BASE.is_dir():
        print(f"ERROR: --base is not a directory: {BASE}")
        return 1

    SBOM_LINUX = args.linux_sbom.resolve() if args.linux_sbom else _find_sbom(BASE, "linux")
    SBOM_WIN   = args.windows_sbom.resolve() if args.windows_sbom else _find_sbom(BASE, "windows")
    version    = args.version or _extract_version(SBOM_LINUX)
    if not _VERSION_SAFE.fullmatch(version) and version != "unknown":
        print(f"ERROR: --version must be numeric (got: {version!r})")
        return 1
    REPORT_OUT = args.output.resolve() if args.output else BASE / f"sbom_review_{version}.md"

    print(f"=== OneCLI v{version} SBOM Review ===")
    print(f"  Base    : {BASE}")
    print(f"  Linux   : {SBOM_LINUX.name}")
    print(f"  Windows : {SBOM_WIN.name}")
    print(f"  Output  : {REPORT_OUT}\n")

    missing = [p for p in (SBOM_LINUX, SBOM_WIN) if not p.exists()]
    if missing:
        for p in missing:
            print(f"  ERROR: SBOM not found: {p}")
        return 1

    print("Building boost target map from CMakeLists.txt …", end=" ", flush=True)
    boost_map = _build_boost_target_map(BASE)
    print(f"{len(boost_map)} boost targets found")

    print("Running checks …")
    linux_res   = _run_checks(SBOM_LINUX, "linux",   boost_map)
    windows_res = _run_checks(SBOM_WIN,   "windows", boost_map)

    _print_summary("Linux",   linux_res)
    _print_summary("Windows", windows_res)

    print(f"\nWriting report → {REPORT_OUT}")
    generate_report(linux_res, windows_res, REPORT_OUT)
    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
