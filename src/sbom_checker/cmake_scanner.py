"""CMakeLists.txt 掃描模組 — 解析會產生的輸出檔案"""

import os
import re
from dataclasses import dataclass, field


@dataclass
class CmakeTarget:
    """CMake 定義的 build target"""
    target_name: str
    target_type: str  # SHARED, STATIC, MODULE, EXECUTABLE
    output_name: str = ""
    prefix: str = ""
    suffix: str = ""
    source_file: str = ""
    platform: str = "Common"

    def get_output_filename(self, platform=None):
        """根據平台推算輸出檔名"""
        platform = (platform or self.platform).lower()
        name = self.output_name or self.target_name

        if self.target_type in ("SHARED", "MODULE"):
            if platform == "windows" or platform == "win32":
                prefix = self.prefix if self.prefix else ""
                suffix = self.suffix if self.suffix else ".dll"
                return f"{prefix}{name}{suffix}"
            else:
                prefix = self.prefix if self.prefix else "lib"
                suffix = self.suffix if self.suffix else ".so"
                return f"{prefix}{name}{suffix}"

        elif self.target_type == "EXECUTABLE":
            if platform == "windows" or platform == "win32":
                return f"{name}.exe"
            else:
                return name

        elif self.target_type == "STATIC":
            if platform == "windows" or platform == "win32":
                return f"{name}.lib"
            else:
                prefix = self.prefix if self.prefix else "lib"
                return f"{prefix}{name}.a"

        return name


class CmakeScanner:
    """掃描 CMakeLists.txt，解析會產生的輸出檔案"""

    # CMake 指令 patterns
    _ADD_LIBRARY = re.compile(
        r'add_library\s*\(\s*(\S+)\s+(SHARED|STATIC|MODULE|OBJECT|INTERFACE|IMPORTED|ALIAS)\b',
        re.IGNORECASE,
    )
    _ADD_LIBRARY_DEFAULT = re.compile(
        r'add_library\s*\(\s*(\S+)\s',
        re.IGNORECASE,
    )
    _ADD_EXECUTABLE = re.compile(
        r'add_executable\s*\(\s*(\S+)',
        re.IGNORECASE,
    )
    _SET_TARGET_PROPS = re.compile(
        r'set_target_properties\s*\(\s*(\S+)\s+PROPERTIES\b',
        re.IGNORECASE,
    )
    _OUTPUT_NAME = re.compile(
        r'OUTPUT_NAME\s+["\']?([^"\'\s\)]+)',
        re.IGNORECASE,
    )
    _PREFIX_PROP = re.compile(
        r'PREFIX\s+["\']?([^"\'\s\)]*)',
        re.IGNORECASE,
    )
    _SUFFIX_PROP = re.compile(
        r'SUFFIX\s+["\']?([^"\'\s\)]*)',
        re.IGNORECASE,
    )

    # 需要跳過的類型
    _SKIP_TYPES = {"IMPORTED", "INTERFACE", "OBJECT", "ALIAS"}

    def __init__(self):
        self.targets = {}  # target_name → CmakeTarget
        self.warnings = []

    def scan_directory(self, root_dir):
        """遞迴掃描目錄中的所有 CMakeLists.txt"""
        for dirpath, _dirs, files in os.walk(root_dir):
            for fname in files:
                if fname == "CMakeLists.txt":
                    full_path = os.path.join(dirpath, fname)
                    self._scan_file(full_path)

        return list(self.targets.values())

    def scan_file(self, file_path):
        """掃描單一 CMakeLists.txt"""
        self._scan_file(file_path)
        return list(self.targets.values())

    def _scan_file(self, file_path):
        """解析單一 CMakeLists.txt 檔案"""
        current_platform = "Common"
        short_filename = os.path.basename(os.path.dirname(file_path))
        accumulated_line = ""

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for raw_line in f:
                    line = raw_line.strip()

                    # 跳過註解
                    if line.startswith("#"):
                        continue

                    # 多行指令累積: 如果行尾無右括號且有左括號，繼續累積
                    accumulated_line += " " + line
                    if line.endswith("\\") or (
                        "(" in accumulated_line and ")" not in accumulated_line
                    ):
                        continue

                    full_line = accumulated_line.strip()
                    accumulated_line = ""

                    # --- 狀態機：平台偵測 ---
                    if re.search(r'\bif\s*\(\s*WIN32\b', full_line):
                        current_platform = "Windows"
                        continue
                    elif re.search(r'\belseif\s*\(\s*UNIX\b', full_line):
                        current_platform = "Linux"
                        continue
                    elif re.search(r'\belse\s*\(', full_line):
                        # else() 切換到另一平台
                        if current_platform == "Windows":
                            current_platform = "Linux"
                        elif current_platform == "Linux":
                            current_platform = "Windows"
                        continue
                    elif re.search(r'\bendif\s*\(', full_line):
                        current_platform = "Common"
                        continue

                    # --- add_library ---
                    match = self._ADD_LIBRARY.search(full_line)
                    if match:
                        name = match.group(1)
                        lib_type = match.group(2).upper()

                        # 跳過不產生輸出的類型
                        if lib_type in self._SKIP_TYPES:
                            continue

                        # 跳過含 CMake 變數的名稱
                        if "${" in name:
                            self.warnings.append(
                                f"含 CMake 變數，已跳過: {name} ({file_path})"
                            )
                            continue

                        target = CmakeTarget(
                            target_name=name,
                            target_type=lib_type,
                            source_file=short_filename,
                            platform=current_platform,
                        )
                        self.targets[name] = target
                        continue

                    # add_library 無明確類型 → 預設 SHARED
                    if "add_library" in full_line.lower():
                        match_default = self._ADD_LIBRARY_DEFAULT.search(full_line)
                        if match_default:
                            name = match_default.group(1)
                            if name.upper() not in self._SKIP_TYPES and "${" not in name:
                                if name not in self.targets:
                                    self.warnings.append(
                                        f"add_library 無明確類型，預設 SHARED: {name} ({file_path})"
                                    )
                                    target = CmakeTarget(
                                        target_name=name,
                                        target_type="SHARED",
                                        source_file=short_filename,
                                        platform=current_platform,
                                    )
                                    self.targets[name] = target

                    # --- add_executable ---
                    match = self._ADD_EXECUTABLE.search(full_line)
                    if match:
                        name = match.group(1)
                        if "${" in name:
                            self.warnings.append(
                                f"含 CMake 變數，已跳過: {name} ({file_path})"
                            )
                            continue

                        # 跳過 IMPORTED
                        if "IMPORTED" in full_line.upper():
                            continue

                        target = CmakeTarget(
                            target_name=name,
                            target_type="EXECUTABLE",
                            source_file=short_filename,
                            platform=current_platform,
                        )
                        self.targets[name] = target

                    # --- set_target_properties ---
                    match = self._SET_TARGET_PROPS.search(full_line)
                    if match:
                        target_name = match.group(1)
                        if target_name in self.targets:
                            target = self.targets[target_name]

                            out_match = self._OUTPUT_NAME.search(full_line)
                            if out_match:
                                target.output_name = out_match.group(1)

                            prefix_match = self._PREFIX_PROP.search(full_line)
                            if prefix_match:
                                target.prefix = prefix_match.group(1)

                            suffix_match = self._SUFFIX_PROP.search(full_line)
                            if suffix_match:
                                target.suffix = suffix_match.group(1)

        except Exception as e:
            self.warnings.append(f"讀取錯誤 {file_path}: {e}")
