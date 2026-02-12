"""交叉驗證邏輯 — SBOM 參照驗證 + CMake 交叉比對"""

import re
from dataclasses import dataclass, field


@dataclass
class SourceRefIssue:
    """來源參照問題"""
    target_name: str
    target_path: str
    missing_ref: str
    section: str = ""


@dataclass
class CmakeCoverageIssue:
    """CMake 交叉比對差異"""
    name: str
    issue_type: str  # "cmake_only" 或 "sbom_only"
    details: str = ""
    category: str = ""  # 分類: test_sample, static_lib, third_party, cmake_internal, etc.


@dataclass
class ValidationResult:
    """驗證結果"""
    ref_issues: list = field(default_factory=list)
    cmake_issues: list = field(default_factory=list)
    target_count: int = 0
    source_count: int = 0
    section_count: int = 0
    ignored_count: int = 0
    refs_checked: int = 0
    refs_valid: int = 0
    platform: str = ""


class SbomValidator:
    """交叉驗證 SBOM 與 CMake 掃描結果"""

    def check_source_references(self, sbom_data):
        """Check (a) — 來源參照驗證

        對每個 TargetEntry 的 see_references，查詢是否存在於已知來源中。
        """
        result = ValidationResult(
            target_count=len(sbom_data.targets),
            source_count=len(sbom_data.sources),
            section_count=len(sbom_data.sections),
            ignored_count=sbom_data.ignored_count,
            platform=sbom_data.platform,
        )

        # 建立來源索引: component_name → SourceEntry
        source_index = {}
        for src in sbom_data.sources:
            name = src.component_name.strip()
            if name:
                source_index[name] = src
                # 同時加入 source_dir 作為別名
                if src.source_dir:
                    source_index[src.source_dir] = src

        # 加入區段名稱作為有效參照目標
        section_set = set(sbom_data.sections)

        # 對每個 Target 的 see_references 進行驗證
        for target in sbom_data.targets:
            if not target.see_references:
                continue

            for ref in target.see_references:
                result.refs_checked += 1
                ref_clean = ref.strip()

                if self._resolve_reference(ref_clean, source_index, section_set):
                    result.refs_valid += 1
                else:
                    issue = SourceRefIssue(
                        target_name=target.component_name,
                        target_path=target.path,
                        missing_ref=ref_clean,
                        section=target.section,
                    )
                    result.ref_issues.append(issue)

        return result

    def _categorize_cmake_issue(self, name, issue_type):
        """根據檔名規則分類 CMake 差異

        Args:
            name: 正規化後的檔名 (如 libfoo.so, test.exe)
            issue_type: 'cmake_only' 或 'sbom_only'

        Returns:
            分類字串: test_sample, static_lib, third_party, cmake_internal,
                    windows_specific, linux_specific, unknown
        """
        name_lower = name.lower()

        # 1. CMake 內部工具/範例 (最高優先)
        if any(x in name_lower for x in ['fortranlib', 'cmake_win', 'cmake_lin']):
            return 'cmake_internal'

        # 2. 測試/範例程式
        if any(x in name_lower for x in ['test', 'sample', 'unittest', 'gtest', 'example']):
            return 'test_sample'

        # 3. 靜態庫 (不出現在最終產品)
        if name.endswith('.a') or name.endswith('.lib'):
            return 'static_lib'

        # 4. 第三方套件 (需確認是否已在其他區段)
        if any(x in name_lower for x in ['third', 'vendor', 'external', 'openssl', 'curl', 'zlib', 'boost']):
            return 'third_party'

        # 5. 平台特定副檔名
        if name.endswith('.exe') or name.endswith('.dll'):
            return 'windows_specific'
        if name.endswith('.so') or name.endswith('.dylib'):
            return 'linux_specific'

        # 6. 未分類
        return 'unknown'

    def check_cmake_coverage(self, sbom_data, cmake_targets, platform=None):
        """CMake 交叉比對

        比對 CMake 掃描到的輸出檔名與 SBOM Target 檔名。
        """
        result = self.check_source_references(sbom_data)

        platform = platform or sbom_data.platform

        # 正規化 SBOM Target 檔名集合
        sbom_filenames = set()
        for target in sbom_data.targets:
            normalized = self._normalize_filename(target.filename)
            if normalized:
                sbom_filenames.add(normalized)

        # 正規化 CMake 輸出檔名集合
        cmake_filenames = set()
        for ct in cmake_targets:
            output = ct.get_output_filename(platform)
            if output:
                normalized = self._normalize_filename(output)
                if normalized:
                    cmake_filenames.add(normalized)

        # 在 CMake 但不在 SBOM
        for name in sorted(cmake_filenames - sbom_filenames):
            result.cmake_issues.append(CmakeCoverageIssue(
                name=name,
                issue_type="cmake_only",
                details="CMake 定義但不在 SBOM 中",
                category=self._categorize_cmake_issue(name, "cmake_only"),
            ))

        # 在 SBOM 但不在 CMake
        for name in sorted(sbom_filenames - cmake_filenames):
            result.cmake_issues.append(CmakeCoverageIssue(
                name=name,
                issue_type="sbom_only",
                details="SBOM 列出但 CMake 未定義",
                category=self._categorize_cmake_issue(name, "sbom_only"),
            ))

        return result

    def _resolve_reference(self, ref, source_index, section_set):
        """嘗試解析一個參照是否指向已知來源或區段"""
        # 直接匹配
        if ref in source_index:
            return True

        # 匹配區段名稱
        if ref in section_set:
            return True

        # 參照含 Target/ 前綴 → 去掉後比對區段名稱
        ref_normalized = ref.replace("\\", "/")
        if ref_normalized.startswith("Target/"):
            section_ref = ref_normalized[7:]
            if section_ref in section_set:
                return True

        # 嘗試去除尾部空白後匹配（CSV 可能有空白）
        ref_stripped = ref.rstrip()
        if ref_stripped in source_index or ref_stripped in section_set:
            return True

        # 嘗試前綴匹配：有些參照可能是路徑前綴
        for name in source_index:
            if name.startswith(ref + "/") or ref.startswith(name + "/"):
                return True

        return False

    def _normalize_filename(self, filename):
        """正規化檔名用於比對

        - .so 版本號 strip: libfoo.so.5.4.0.1 → libfoo.so
        - 去除路徑只取檔名
        """
        if not filename:
            return ""

        # 取最後一段路徑
        name = filename.split("/")[-1].strip()
        if not name or name == "*.*":
            return ""

        # .so 版本號 strip
        match = re.match(r'^(.+\.so)(?:\.\d.+)?$', name)
        if match:
            return match.group(1)

        return name
