# Plan: SBOM Review Script — OneCLI v5.6.0

## Request
Implement the OSC review checklist defined in
`~/Downloads/OSC Review - OneCLI v5.6.0 SBOM.txt`:
1. Format validation — Target/Source structure, orphan records
2. Version correctness — compare SBOM-declared versions against version_audit_5.6.0.log defects

## Input Files
| File | Role |
|---|---|
| `lnvgy_utl_lxce_onecli_linux_indiv (tgz)-5.6.x-(Tasmania)-SBOM-13May2026.xlsx` | Linux SBOM |
| `lnvgy_utl_lxce_onecli_windows_indiv (zip)-v5.6.x (Tasmania)-SBOM-12May2026.xlsx` | Windows SBOM |
| `version_audit_5.6.0.log` | Known defects baseline |

## SBOM Structure (observed)
- Row 20: column headers
- Section markers: rows starting with `*BUILD OUTPUT for "Target..."` in col A
- Data rows: component name (A), version/hash (B), license (C), link (D), path (E), use (F), …
- "Source" section starts around row 610+ where path col E shifts from `Target/...` to `1/libname`

## What the Script Does

### Check 1 — Format Validation
- Count Target section headers (`*BUILD OUTPUT for "Target..."`)
- Count entries inside each Target section (rows between consecutive section headers)
- For each data row: verify col A (name) and col E (path) are not both empty → flag orphans
- Verify all `see below` license entries have a resolved license entry later in the sheet
- Report: targets found, total entries, orphan count, format issues

### Check 2 — Version Correctness
Compare SBOM-declared versions for key libraries against the audit log baseline:

| Library | Audit baseline (expected) | Audit result | Check |
|---|---|---|---|
| curl | 8.17.0 | FAIL (actual 8.19.0) | SBOM says 8.17.0 → unresolved |
| zlib | 1.3.1 | FAIL (actual 1.3.2) | SBOM says 1.3.1 → unresolved |
| openssl | 3.6.0 | WARN (actual 3.6.2) | SBOM says 3.6.0 → unresolved |
| pthreads-w32 | 2.9.1 | FAIL (actual 2.8.0) | Windows SBOM only |
| electron | 39.2.6 | FAIL (NOT FOUND) | Missing from SBOM |
| boost | 1.86.0 | OK | — |
| libssh2 | 1.11.1 | OK | — |
| pegasus | 2.14.1 | OK | — |
| snmp++ | 3.3.10 | OK | — |
| websocket++ | 0.8.3-dev | OK | — |

### Check 3 — Duplicate/Multiple-Version Detection
Flag libraries with >1 distinct version in the same SBOM (e.g., openssl 3.6.0 + 3.4.0).

### Check 1e — Col D Boost Annotation (NEW)
Authority source: `boost_filter/scan_boost_v2.py` (CMakeLists.txt scanning).

Steps:
1. **Scan CMakeLists.txt** recursively under `BASE/` using the same `target_link_libraries + boost_` keyword logic as `scan_boost_v2.py` (pure stdlib os + re, inlined — no import).
2. Build `boost_map`: `{cmake_target_name_lower: set(platforms)}` where platforms ∈ `{"linux","windows","common"}`.
3. For each SBOM Col A `.so` / `.dll` row: normalize name → cmake target (strip `lib` prefix + `.so[.ver]` or `.dll` suffix).
4. Look up target in `boost_map`; skip if not found or platform doesn't match.
5. If boost is used **AND** `"boost"` is NOT already quoted in Col D → flag as **MISSING_BOOST**.
6. Compute `boost_map` once in `main()`, pass to both `_run_checks` calls.

**Col A normalization:**
- `libacquire.so.5.4` → `acquire`
- `libBMCRedfishConfig.so` → `bmcredfishconfig`
- `curlcpp.dll` → `curlcpp`

**Col D format examples:**
- `see "modularization/src/module/acquire"; "boost"` → already annotated ✅
- `see "modularization/src/module/acquire"` → uses boost but missing annotation ❌

**5.6.0 boost targets confirmed by scan_boost_v2.py run:**
- Windows: RemoteController, bmu_env, cmm, cmmffdc, curlcpp, discovery, file_client, file_transfer, iolog, pcidevice, xmunzip, xmzip
- Linux: BMCRedfishConfig, CFCBMCRedfishConfig, ConfigCompatibleModule, EnclosureConfigProc, PowerManagement, RedfishConfig, RedfishConfigAction, RedfishConfigAssistant, RedfishConfigCommon, Rest, acquire, arcconfopt, chassisEventLog, cimom, comparepackage, credential, dcpmem, diagnosticdata, driverinfo, emulex, environment, ffdc, fod, fpusb_config, globalconfig, ibdisksw, iflashBroker, immapp, installedappsandupdates, ipmanip, ipmi_client, ipmi_kcs_eable, lsiopt, modmanager, network, onecli_serase, operatingsystem, optionupdate, osinfo, pci, port_forwarding_config, portcontrol, qlogic, raidconfig, raidlink, repository, rest_broadcom_switch, rest_sftp_enable, restore_customer_env, smminventory, softwareidentity, ssd, storcli_cmd, system_query, systemhealth, systeminfo, time_estimation, usblancfg, usblancfgipv6, vmesxiupdate, xFirmwareConfig, xfirmwareinventory
- Common: eventloglinux, onecli_update_rollback, osspecific_static, secure_erase

### Output
- Console summary (pass/fail per check)
- Markdown report written to `./sbom_review_5.6.0.md`

## Script Location
`~/.claude/skills/OSC-compliance-sbom-review/scripts/sbom_review.py`

## Assumptions
- openpyxl is available (confirmed)
- Hardcode SBOM paths and audit baselines in script constants (no argparse needed)
- stdlib + openpyxl only
