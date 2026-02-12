# SBOM Checker

SBOM CSV 交叉驗證工具 — 比對 CMakeLists.txt 輸出與 SBOM 來源參照。

## 專案結構

```
src/sbom_checker/
  cli.py            # argparse 進入點 + 子指令 (check, scan)
  sbom_parser.py    # SBOM CSV 解析 (SbomParser)
  cmake_scanner.py  # CMakeLists.txt 掃描 (CmakeScanner)
  validator.py      # 交叉驗證邏輯 (SbomValidator)
  report.py         # 報表格式化輸出 (ReportFormatter)
```

## 使用方式

```bash
# 僅驗證 SBOM 來源參照
sbom-checker check /path/to/sbom.csv --check-refs-only

# 完整驗證: 來源參照 + CMake 交叉比對
sbom-checker check /path/to/sbom.csv --source-dir /path/to/source --platform linux

# 掃描 CMake 輸出目標
sbom-checker scan /path/to/source --platform linux
```

## 開發

```bash
pipx install -e .
```

## 設計原則

- Pure Python stdlib — 無外部依賴
- Python >= 3.8 (dataclasses)
- 報表語言: 繁體中文
- CSV 解析: 動態 header 偵測，不硬編行號
- CMake 解析: 狀態機平台偵測，跳過 IMPORTED/INTERFACE/OBJECT/ALIAS
