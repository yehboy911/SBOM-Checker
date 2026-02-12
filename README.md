# SBOM Checker

OSC (Open Source Compliance) 流程中，驗證 SBOM CSV 正確性的自動化工具。
透過解析 Source Code 的 CMakeLists.txt 與 SBOM CSV 進行交叉比對，自動找出不一致的項目。

## 功能

- **Check (a) 來源參照驗證**: 檢查每個 Target 輸出項目的 `see "xxx"` 參照是否指向已知的 Source 來源
- **CMake 交叉比對**: 比對 CMakeLists.txt 定義的輸出檔案與 SBOM 中列出的 Target，找出遺漏或多餘項目
- **CMake 掃描**: 獨立掃描 CMakeLists.txt，列出所有 build target 及推算的輸出檔名

## 安裝

```bash
pipx install -e "/path/to/sbom_checker"
```

## 使用方式

```bash
# 僅驗證 SBOM 內部參照 (不需 source code)
sbom-checker check /path/to/sbom.csv --check-refs-only

# 完整驗證: 參照 + CMake 交叉比對
sbom-checker check /path/to/sbom.csv --source-dir /path/to/source --platform linux

# 掃描 CMake 輸出目標
sbom-checker scan /path/to/source --platform linux
```

## 系統需求

- Python >= 3.8
- 無外部依賴（純 Python stdlib）

## License

MIT
