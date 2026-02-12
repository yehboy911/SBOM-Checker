"""SBOM CSV 解析模組 — 提取 Target 輸出項目與 Source 來源項目"""

import csv
import re
from dataclasses import dataclass, field


@dataclass
class TargetEntry:
    """SBOM 中的 Target 輸出項目"""
    component_name: str
    hash_value: str
    license: str
    see_references: list = field(default_factory=list)
    path: str = ""
    filename: str = ""
    section: str = ""


@dataclass
class SourceEntry:
    """SBOM 中的 Source 來源項目"""
    component_name: str
    hash_value: str
    license: str
    link: str = ""
    path: str = ""
    source_dir: str = ""


@dataclass
class SbomData:
    """解析後的 SBOM 資料"""
    targets: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    sections: list = field(default_factory=list)
    ignored_count: int = 0
    platform: str = ""


class SbomParser:
    """解析 SBOM CSV，提取 Target 輸出項目與 Source 來源項目"""

    # 從 Column D 提取 see "path" 參照
    _SEE_REF_PATTERN = re.compile(r'"([^"]+)"')

    def parse(self, csv_path):
        """解析 CSV 檔案，回傳 SbomData"""
        data = SbomData()
        current_section = ""

        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header_found = False
            fmt = None  # "fossa" (Linux flat) or "osc" (Windows sectioned)

            for row in reader:
                if len(row) < 5:
                    continue

                col_a = row[0].strip()

                # 格式偵測: FOSSA 匯出 (Linux) 的 header 首欄為 DEPENDENCY/FILE
                if not header_found and fmt is None:
                    if col_a == "DEPENDENCY/FILE":
                        fmt = "fossa"
                        header_found = True
                        continue  # 跳過 header 行

                # 決定 path 欄位位置
                if fmt == "fossa":
                    col_path = row[5].strip().replace("\\", "/") if len(row) > 5 else ""
                    col_src_ref = ""  # FOSSA 格式無 see "path" 參照
                else:
                    col_path = row[4].strip().replace("\\", "/") if len(row) > 4 else ""
                    col_src_ref = row[3].strip() if len(row) > 3 else ""

                # OSC 格式 header 偵測
                if not header_found:
                    if col_path.startswith("Target") or col_path.startswith("1/"):
                        header_found = True
                        fmt = "osc"
                    else:
                        continue

                # 區段標題: Column A 以 *BUILD OUTPUT 開頭
                if col_a.startswith("*BUILD OUTPUT"):
                    section_name = self._extract_section_name(col_a)
                    current_section = section_name
                    data.sections.append(section_name)
                    continue

                # Column C 含 IGNORE/Ignored → 略過
                col_c = row[2].strip() if len(row) > 2 else ""
                if "IGNORE" in col_c.upper():
                    data.ignored_count += 1
                    continue

                col_b = row[1].strip() if len(row) > 1 else ""

                # 行分類: path 以 Target 開頭 → 輸出項目
                if col_path.startswith("Target"):
                    see_refs = self._parse_see_references(col_src_ref)
                    filename = col_path.split("/")[-1]

                    entry = TargetEntry(
                        component_name=col_a,
                        hash_value=col_b,
                        license=col_c,
                        see_references=see_refs,
                        path=col_path,
                        filename=filename,
                        section=current_section,
                    )
                    data.targets.append(entry)

                # path 以 1/ 開頭 → 來源項目
                elif col_path.startswith("1/"):
                    source_dir = col_path[2:]  # 去掉 1/ 前綴
                    entry = SourceEntry(
                        component_name=col_a,
                        hash_value=col_b,
                        license=col_c,
                        link=col_src_ref,
                        path=col_path,
                        source_dir=source_dir,
                    )
                    data.sources.append(entry)

                else:
                    # 其他項目也視為來源（套件子項目、extlibs 等）
                    entry = SourceEntry(
                        component_name=col_a,
                        hash_value=col_b,
                        license=col_c,
                        link=col_src_ref,
                        path=col_path,
                        source_dir="",
                    )
                    data.sources.append(entry)

        # 自動偵測平台
        data.platform = self._detect_platform(data)
        return data

    def _extract_section_name(self, col_a):
        """從 *BUILD OUTPUT for "Target/xxx" 提取 xxx"""
        match = re.search(r'"([^"]+)"', col_a)
        if match:
            path = match.group(1).replace("\\", "/")
            # 去掉 Target/ 前綴
            if path.startswith("Target/"):
                return path[7:]
            return path
        return col_a

    def _parse_see_references(self, col_d):
        """從 Column D 解析 see "path1"; "path2" 格式的參照"""
        if not col_d:
            return []
        # 只處理含 see 的欄位
        lower = col_d.lower()
        if "see" not in lower and '"' not in col_d:
            return []
        return self._SEE_REF_PATTERN.findall(col_d)

    def _detect_platform(self, data):
        """從 BUILD OUTPUT 區段標題推斷平台"""
        for section in data.sections:
            lower = section.lower()
            if "linux" in lower:
                return "linux"
            if "windows" in lower or "win" in lower:
                return "windows"

        # 從 Target 檔名特徵偵測
        dll_count = sum(1 for t in data.targets if t.filename.endswith(".dll"))
        so_count = sum(1 for t in data.targets if ".so" in t.filename)
        if dll_count > so_count:
            return "windows"
        if so_count > 0:
            return "linux"

        return "unknown"
