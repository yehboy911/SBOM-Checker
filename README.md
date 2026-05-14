# SBOM Checker v2.0.0

OSC (Open Source Compliance) 流程中，驗證 SBOM CSV 正確性的自動化工具。
透過解析 Source Code 的 CMakeLists.txt 與 SBOM CSV 進行交叉比對，自動找出不一致的項目，並將差異自動分類為可供法務審核的格式。

**狀態:** ✅ 生產級發佈 (v2.0.0)
**GitHub:** https://github.com/yehboy911/SBOM-Checker/releases/tag/v1.0.0-sbom-validation-complete

---

## 🎯 核心功能

### 1. **來源參照驗證**
檢查每個 Target 輸出項目的 `see "xxx"` 參照是否指向已知的 Source 來源。快速識別遺漏的參照。

### 2. **CMake 交叉比對**
比對 CMakeLists.txt 定義的輸出檔案與 SBOM 中列出的 Target，找出遺漏或多餘項目。

### 3. **自動分類** ⭐ (v1.0.0 新功能)
將 CMake 差異自動分類為 6 層優先級：
- `cmake_internal` — CMake 內部工具 (FortranLib, cmake_*)
- `test_sample` — 測試/範例程式 (test*, sample*, *test*)
- `static_lib` — 靜態庫 (.a, .lib) — 通常不在產品發佈
- `third_party` — 第三方套件 (boost, curl, zlib, ...)
- `platform_specific` — 平台特定檔案 (.exe, .dll, .so, .dylib)
- `unknown` — 需人工審查的項目

**分類準確率:** 92.3% (224/297 項已自動分類)

### 4. **CMake 掃描**
獨立掃描 CMakeLists.txt，列出所有 build target 及推算的輸出檔名。

---

## 📊 驗證結果示例

對 LXCE OneCLI v5.5.0 的雙平台驗證結果：

| 平台 | 目標數 | 來源數 | 來源驗證 | CMake 差異 | 分類準確率 |
|------|--------|---------|---------|----------|----------|
| **Linux** | 573 | 4,284 | ✅ PASS (0) | 297 | 92.3% |
| **Windows** | 399 | 642 | ❌ FAIL (4) | 297 | 92.3% |

**Windows 4 個問題：** VC++ Runtime 參照遺漏 (msvcp140.dll, vcruntime140.dll × 2, vcruntime140_1.dll)

---

## 🚀 安裝

```bash
pipx install -e "/path/to/sbom_checker"
```

## 📖 使用方式

### 子指令總覽

| 子指令 | 用途 |
|--------|------|
| `check` | 驗證 SBOM CSV（來源參照 + CMake 交叉比對） |
| `scan` | 掃描 CMakeLists.txt，列出所有 build target |
| `review-ux` | 審查 UpdateXpress Excel SBOM（支援多重 npm 參照來源） |
| `review-bomc` | 審查 BoMC Excel SBOM |
| `review-notice` | 比對 Notice TXT 與 SBOM Excel，找出 GAP 與 ORPHAN |
| `gen-tpn` | 從 FOSSA JSON + OneCLI TPN + package-lock.json 生成 TPN draft |
| `tpn-delta` | 比對兩版本 TPN/SBOM，輸出 delta 報告 |

---

### `check` — 驗證 SBOM CSV

```bash
sbom-checker check <csv_path> [OPTIONS]
```

| 參數 | 說明 |
|------|------|
| `csv_path` | SBOM CSV 檔案路徑 |
| `--check-refs-only` | 僅驗證來源參照（不需 source code） |
| `--source-dir DIR` | Source code 根目錄（CMake 交叉比對） |
| `--platform {linux,windows}` | 指定平台（預設自動偵測） |

```bash
# 僅驗證 SBOM 內部參照 (不需 source code)
sbom-checker check /path/to/sbom.csv --check-refs-only

# 完整驗證: 參照 + CMake 交叉比對 + 自動分類
sbom-checker check /path/to/sbom.csv --source-dir /path/to/source --platform linux
```

---

### `scan` — 掃描 CMakeLists.txt

```bash
sbom-checker scan <source_dir> [OPTIONS]
```

| 參數 | 說明 |
|------|------|
| `source_dir` | Source code 根目錄 |
| `--platform {linux,windows}` | 輸出平台（預設 linux） |

```bash
sbom-checker scan /path/to/source --platform linux
```

---

### `review-ux` — 審查 UpdateXpress Excel SBOM

> `review-xlsx` 為 legacy alias，行為相同。

```bash
sbom-checker review-ux <xlsx_path> [OPTIONS]
```

| 參數 | 說明 |
|------|------|
| `xlsx_path` | SBOM .xlsx 檔案路徑 |
| `--platform {linux,windows}` | 平台（預設從檔名自動偵測） |
| `--deps-info PATH` | `dependencies_info.json` 路徑（主要 npm 參照） |
| `--lock PATH` | `package-lock.json` 路徑（次要 npm 參照） |
| `--fossa-json PATH` | FOSSA 匯出 JSON 路徑（第三優先 npm 參照） |
| `--onecli-json PATH` | OneCLI SBOM JSON 路徑（覆蓋預設） |
| `--output PATH` | 輸出路徑（預設：`<原檔名>_reviewed.xlsx`） |

```bash
# Linux，提供 package-lock.json 為 npm 參照
sbom-checker review-ux "ux_linux_sbom.xlsx" \
  --platform linux \
  --lock /path/to/package-lock.json

# Windows，完整參照鏈
sbom-checker review-ux "ux_windows_sbom.xlsx" \
  --platform windows \
  --deps-info ux/gui/dependencies_info.json \
  --lock ux/gui/app/package-lock.json \
  --fossa-json ux_win_fossa.json \
  --output reviewed/ux_windows_reviewed.xlsx
```

---

### `review-bomc` — 審查 BoMC Excel SBOM

```bash
sbom-checker review-bomc <xlsx_path> [OPTIONS]
```

| 參數 | 說明 |
|------|------|
| `xlsx_path` | SBOM .xlsx 檔案路徑 |
| `--platform {linux,windows}` | 平台（預設從檔名自動偵測） |
| `--lock PATH` | `package-lock.json` 路徑（npm 參照） |
| `--output PATH` | 輸出路徑（預設：`<原檔名>_reviewed.xlsx`） |

```bash
# Linux（從檔名自動偵測平台）
sbom-checker review-bomc "lnvgy_utl_lxce_bomc_linux_v14.4.0.xlsx"

# Windows，指定 package-lock.json
sbom-checker review-bomc "bomc_windows_sbom.xlsx" \
  --platform windows \
  --lock bomc/gui/app/package-lock.json

# 自訂輸出路徑
sbom-checker review-bomc "bomc_sbom.xlsx" \
  --platform linux \
  --lock bomc/package-lock.json \
  --output reviewed/bomc_reviewed.xlsx
```

---

### `review-notice` — 比對 Notice TXT 與 SBOM

```bash
sbom-checker review-notice <notice.txt> --sbom <sbom.xlsx> [--product {ux,bomc}]
```

| 參數 | 說明 |
|------|------|
| `notice_path` | Third Party Notice .txt 檔案路徑 |
| `--sbom PATH` | SBOM .xlsx 檔案路徑（必填） |
| `--product {ux,bomc}` | 產品類型（預設從 SBOM 檔名自動偵測：含 `bomc` → bomc，否則 → ux） |

**輸出：**

| 報告項目 | 說明 |
|---|---|
| `Matched` | SBOM 中找到對應 Notice entry 的元件數 |
| `[GAP]` | 在 SBOM 中但未出現在 Notice 的元件（需確認是否應補入 Notice） |
| `[ORPHAN]` | 在 Notice 中但未出現在 SBOM 的 entry（可能為過期或 package-level 差異） |

**SBOM 排除規則：**
- 第 1–20 列（Header/Metadata）
- Col C = `see below` / `IGNORE` / `NOT DISTRIBUTED` / `PROPRIETARY`（sub-entry 或非第三方）
- UX only: OUTPUT group（`Col E` 以 `Target/` 開頭）、INPUT_ONECLI group

```bash
# BoMC Windows
sbom-checker review-notice "bomc_windows_notice.txt" \
  --sbom "bomc_windows_sbom.xlsx"

# BoMC Linux（明確指定 product）
sbom-checker review-notice "bomc_linux_notice.txt" \
  --sbom "bomc_linux_sbom.xlsx" \
  --product bomc

# UX Windows
sbom-checker review-notice "ux_windows_notice.txt" \
  --sbom "ux_windows_sbom.xlsx" \
  --product ux
```

> **UX 注意：** C/C++ 套件（boost, curl, openssl 等）在 UX SBOM 中只以 OUTPUT 已編譯 DLL 形式存在，  
> Notice 以 package 層級記錄，因此這些 entry 會出現在 `[ORPHAN]` 清單中，屬已知結構差異。

---

### `gen-tpn` — 生成 TPN Draft

從 FOSSA JSON + OneCLI TPN + package-lock.json 生成 TPN draft（Approach B: FULL + STUB）。

```bash
sbom-checker gen-tpn --platform {win|linux} --fossa-json PATH \
  --onecli-tpn PATH --pkg-lock PATH --output PATH [--version VER]
```

| 參數 | 必填 | 說明 |
|------|------|------|
| `--platform {win,linux}` | ✅ | 平台 |
| `--fossa-json PATH` | ✅ | FOSSA 匯出 JSON |
| `--onecli-tpn PATH` | ✅ | OneCLI TPN FINAL .txt（C/C++ copy-forward 來源） |
| `--pkg-lock PATH` | ✅ | `package-lock.json`（npm 版本 + transitive stubs） |
| `--output PATH` | ✅ | 輸出 TPN draft .txt 路徑 |
| `--version VER` | | 產品版本號（用於 TPN header，例如 `5.4.0`） |

```bash
sbom-checker gen-tpn \
  --platform win \
  --fossa-json ux_win_fossa.json \
  --onecli-tpn onecli_tpn_final.txt \
  --pkg-lock ux/gui/app/package-lock.json \
  --output tpn_draft_win.txt \
  --version 5.4.0
```

---

### `tpn-delta` — 比對兩版本 TPN/SBOM

```bash
sbom-checker tpn-delta --platform {win|linux} --output PATH [OPTIONS]
```

| 參數 | 必填 | 說明 |
|------|------|------|
| `--platform {win,linux}` | ✅ | 平台 |
| `--output PATH` | ✅ | 輸出 delta 報告 .md 路徑 |
| `--old-tpn PATH` | | 舊版 TPN FINAL .txt |
| `--new-tpn PATH` | | 新版 TPN FINAL/DRAFT .txt |
| `--old-sbom PATH` | | 舊版 SBOM .xlsx（TPN 不存在時使用） |
| `--new-sbom PATH` | | 新版 SBOM .xlsx（TPN 不存在時使用） |
| `--old-label TEXT` | | 舊版標籤（預設：`v5.3.x`） |
| `--new-label TEXT` | | 新版標籤（預設：`v5.4.x`） |

```bash
sbom-checker tpn-delta \
  --platform win \
  --old-tpn tpn_v533_final.txt \
  --new-tpn tpn_v540_draft.txt \
  --old-label v5.3.3 \
  --new-label v5.4.0 \
  --output delta_win_v533_v540.md
```

---

---

## 🔄 OneCLI SBOM 審查工作流程

### 快速全流程 (5 步驟)

```
Step 1: 準備 SBOM Excel + source tree
Step 2: 執行 sbom_review.py → 自動跑 10 項 Check
Step 3: 查閱 sbom_review_<ver>.md → 分類 FAIL / WARN
Step 4: 修正 SBOM → 重新執行確認
Step 5: 搭配其他子指令做完整審查
```

---

### Step 1 — 準備檔案

| 所需項目 | 說明 |
|---|---|
| Linux SBOM `.xlsx` | `lnvgy_utl_lxce_onecli_linux_indiv (tgz)-<ver>-SBOM-<date>.xlsx` |
| Windows SBOM `.xlsx` | `lnvgy_utl_lxce_onecli_windows_indiv (zip)-<ver>-SBOM-<date>.xlsx` |
| OneCLI source tree | `modularization/` + `onecli/` （Boost target map 需要） |

更新 `src/sbom_checker/sbom_review.py` 頂部路徑設定：

```python
BASE       = Path("/your/path/to/OneCLI")
SBOM_LINUX = BASE / "<linux_sbom_filename>.xlsx"
SBOM_WIN   = BASE / "<windows_sbom_filename>.xlsx"
REPORT_OUT = BASE / "sbom_review_<version>.md"
```

---

### Step 2 — 執行審查

```bash
python3 src/sbom_checker/sbom_review.py
```

輸出範例：

```
=== OneCLI v5.6.0 SBOM Review ===
Building boost target map from CMakeLists.txt … 61 boost targets found
Running checks …
  Parsing lnvgy_utl_lxce_onecli_linux_indiv…xlsx … 560 rows
  Parsing lnvgy_utl_lxce_onecli_windows_indiv…xlsx … 420 rows

  [Linux]
    Format  : 12 targets,  0 orphans,  0 issue(s)
    Col A   : 0/560 section headers use version-specific folder
    Col D   : 0 package(s) with non-constant folder
    Col D+  : 0 .so rows missing boost annotation (of 150 checked)
    Col D~  : 148 verified / 0 mismatch / 0 path-missing / 2 no-cmake
    I/O Ver : 3 ok / 1 wrong / 0 unknown / 0 inconsistent
    Src Arch: 45 ok / 0 missing
    Col E   : 0/560 Target rows use version-specific path
    Col F   : 0 empty USE field(s)
    Versions: 2 FAIL/MISSING, 1 WARN, 5 OK

Writing report → sbom_review_5.6.0.md
Done.
```

---

### Step 3 — 解讀報告

每項 Check 對應的修正方向：

| Check | FAIL / WARN 代表 | 修正方向 |
|---|---|---|
| `Format` orphans | 無對應 Header 的孤立行 | 確認應屬哪個 section 或刪除 |
| `Col A` version folder | Section Header 路徑含版本號 | 統一為固定路徑（不含版本） |
| `Col D` folder | `see "..."` 前綴路徑不一致 | 對齊至 `Target/<product>/libs/` |
| `Col D+` boost | `.so`/`.dll` 行缺 boost 標注 | 補上 `; "boost"` + 粉紅填色 |
| `Col D~` source | Col D 路徑指向不存在的目錄 | 修正至正確 CMakeLists.txt 位置 |
| `Col E` Target path | Target 路徑含版本號 | 改為不含版本的固定路徑 |
| `Col F` USE empty | USE 欄位空白 | 填入 `STATIC` / `DYNAMIC` / `TOOL` |
| `Versions` FAIL | SBOM 版本 ≠ extlibs 實際版本 | 修正 SBOM 版本號，或與開發確認 |
| `I/O Ver` wrong | I/O 工具版本標記錯誤 | 聯絡 I/O vendor 確認版本後修正 |
| `Src Arch` missing | `1/` 標記行無對應 source archive | 補上 source tarball |
| `Dupes` stale | 重複版本且非 I/O-sourced | 移除舊版本行 |

---

### Step 4 — 修正 SBOM 後重新執行

```bash
python3 src/sbom_checker/sbom_review.py
# 確認所有 FAIL → 0，WARN 均有文件說明
```

---

### Step 5 — 搭配其他工具做完整審查

| 工具 | 用途 |
|---|---|
| `sbom_review.py` | 自動檢查 10 項，雙平台同時執行，輸出 Markdown 報告 |
| `sbom-checker check` | CSV 格式驗證 + CMake target 交叉比對 |
| `sbom-checker review-ux` | UpdateXpress Excel SBOM 審查 |
| `sbom-checker review-bomc` | BoMC Excel SBOM 審查 |
| `sbom-checker gen-tpn` | 從 FOSSA JSON + OneCLI TPN 生成 TPN draft |
| `sbom-checker tpn-delta` | 比對前後版本 TPN/SBOM delta |

---

### 常見修正情境

**情境 A — Boost 標注缺失 (`Col D+`)**

```
症狀: 30 .so rows missing boost annotation
原因: Col D 欄位缺少 "; "boost"" 標注
修正: 使用 openpyxl 腳本批次補上 "; "boost"" + 粉紅填色
      (參見 reports/plan_v5.6.0.md 的 Issue 3 說明)
```

**情境 B — 版本漂移 (`Versions FAIL`)**

```
症狀: curl [FAIL] SBOM declares 8.17.0 but extlibs header shows 8.19.0
原因: Extlibs 升了 patch version，SBOM 未同步更新
修正: 向開發確認實際發佈版本，更新 SBOM 對應版本欄位
```

**情境 C — I/O 工具版本不明 (`I/O Ver unknown`)**

```
症狀: storcli2 version unknown (0 matched)
原因: I/O tool 版本未向 vendor 確認，SBOM 僅含 checksum
修正: 聯絡 vendor 取得版本號 → 填入 Col B → 更新審查基線
```

---

## 📦 交付報表

驗證完成後會產生可供法務審核的報表包（tar.gz + zip）：

| 報表 | 用途 | 讀者 |
|------|------|------|
| `DELIVERY_MANIFEST.md` | 法務審核指南 + 關鍵問題總結 | 法務、管理層 |
| `SBOM_Validation_Summary_v5.5.0.md` | 執行摘要與建議 | 領導層、產品經理 |
| `linux_final_report_v5.5.0.txt` | Linux 完整驗證報表 | 開發、QA |
| `windows_final_report_v5.5.0.txt` | Windows 完整驗證報表 | 開發、QA |
| `METRICS_SUMMARY.txt` | 快速參考統計表 | 所有人 |
| `IMPLEMENTATION_LOG.md` | 技術實作詳情與分類規則 | 架構、開發 |

---

## ✨ 快速開始

### 法務人員 (30 分鐘)
1. 閱讀 `DELIVERY_MANIFEST.md`
2. 查看「關鍵問題總結」及優先級清單
3. 確認後續修正時間表 (P1: 1-2 天, P2: 3-5 天, P3-P4: 1-2 週)

### 開發人員 (1-2 小時)
1. 參考 `IMPLEMENTATION_LOG.md` 了解分類邏輯
2. 查看各報表的 unknown 分類項目
3. 確認平台特定檔案是否應納入 SBOM

### QA 人員 (30 分鐘)
1. 參考驗證命令重新執行驗證
2. 驗證修正後的 SBOM 對齊性
3. 確認所有 unknown 項目已分類

---

## 📋 系統需求

- Python >= 3.8
- 支援: Linux, macOS, Windows
- `check` / `scan` / `tpn-delta`: 純 Python stdlib，無外部依賴
- `review-ux` / `review-bomc` / `gen-tpn`: 需要 `openpyxl`

```bash
pip install openpyxl
```

---

## 🔍 技術特性

- **動態 CSV 解析** — 不硬編 header 行號，自動偵測
- **平台感知 CMake 掃描** — 支援 Linux/Windows 雙平台偵測
- **狀態機解析** — 精確處理複雜 CMakeLists.txt 語法
- **標準化比對** — 正規化檔名後進行交叉比對 (如 .so → lib*.so)
- **分類優先級** — 6 層規則、優先級遞減，確保準確分類

---

## 📈 驗證覆蓋率

**CMake 掃描覆蓋 (LXCE OneCLI v5.5.0):**
- 掃描 CMakeLists.txt: 499 個
- 偵測 CMake Targets: 539 個
- CMake 警告: 17 個 (全為良性，如 `${VAR}` 變數)

---

## 🔗 相關資源

- **GitHub Release:** https://github.com/yehboy911/SBOM-Checker/releases/tag/v1.0.0-sbom-validation-complete
- **完整驗證報表:** 見發佈包中的 tar.gz/zip 檔案
- **實作細節:** 見 `IMPLEMENTATION_LOG.md`

---

## ⚙️ License

MIT
