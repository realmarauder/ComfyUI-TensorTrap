"""Static analysis scanner for ComfyUI custom node source code.

Scans Python files in custom_nodes/ for dangerous patterns:
- eval(), exec(), compile() — code injection
- subprocess, os.system, os.popen — command execution
- importlib — dynamic module loading
- requests, urllib — network access (data exfiltration, SSRF)
- open() with user-controlled paths — arbitrary file access
- pickle.loads — deserialization attacks
- base64/hex decoding — obfuscation
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class NodeFinding:
    """A security finding in a custom node's source code."""

    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # code_injection, command_exec, network, file_access, obfuscation, supply_chain
    message: str
    file_path: str
    line_number: int
    code_snippet: str = ""
    node_package: str = ""


@dataclass
class NodeAuditResult:
    """Audit results for a single custom node package."""

    package_name: str
    package_path: str
    files_scanned: int = 0
    findings: list[NodeFinding] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return not any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    @property
    def max_severity(self) -> str:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        if not self.findings:
            return "SAFE"
        return min(self.findings, key=lambda f: severity_order.get(f.severity, 5)).severity

    def to_dict(self) -> dict:
        return {
            "package_name": self.package_name,
            "package_path": self.package_path,
            "files_scanned": self.files_scanned,
            "is_safe": self.is_safe,
            "max_severity": self.max_severity,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                    "code_snippet": f.code_snippet,
                }
                for f in self.findings
            ],
        }


# --- Dangerous patterns ---

# Direct code execution
CODE_INJECTION_PATTERNS = [
    (r"\beval\s*\(", "CRITICAL", "eval() call — arbitrary code execution"),
    (r"\bexec\s*\(", "CRITICAL", "exec() call — arbitrary code execution"),
    (r"\bcompile\s*\(", "HIGH", "compile() call — may bypass eval/exec detection"),
]

# Command execution
COMMAND_EXEC_PATTERNS = [
    (r"\bos\.system\s*\(", "CRITICAL", "os.system() — shell command execution"),
    (r"\bos\.popen\s*\(", "CRITICAL", "os.popen() — shell command execution"),
    (r"\bsubprocess\.\w+\s*\(", "HIGH", "subprocess call — command execution"),
    (r"\bPopen\s*\(", "HIGH", "Popen() — process execution"),
]

# Network access
NETWORK_PATTERNS = [
    (r"\brequests\.(get|post|put|delete|head|patch)\s*\(", "MEDIUM", "HTTP request — potential data exfiltration or SSRF"),
    (r"\burllib\.request\.\w+\s*\(", "MEDIUM", "urllib request — potential data exfiltration or SSRF"),
    (r"\bhttpx\.\w+\s*\(", "MEDIUM", "httpx request — potential data exfiltration"),
    (r"\bsocket\.\w+\s*\(", "HIGH", "Raw socket access — potential reverse shell or data exfiltration"),
    (r"\bwebsocket\b", "MEDIUM", "WebSocket usage — potential C2 communication"),
]

# File access
FILE_ACCESS_PATTERNS = [
    (r"\bpickle\.loads?\s*\(", "HIGH", "pickle deserialization — arbitrary code execution risk"),
    (r"\bshelve\.open\s*\(", "HIGH", "shelve.open — uses pickle internally"),
    (r"\bmarshal\.loads?\s*\(", "HIGH", "marshal deserialization — code execution risk"),
]

# Dynamic imports
DYNAMIC_IMPORT_PATTERNS = [
    (r"\bimportlib\.import_module\s*\(", "HIGH", "Dynamic module import — can load arbitrary code"),
    (r"\b__import__\s*\(", "HIGH", "Dynamic import — can load arbitrary modules"),
]

# Obfuscation
OBFUSCATION_PATTERNS = [
    (r"\bbase64\.b64decode\s*\(", "MEDIUM", "Base64 decoding — may hide malicious payload"),
    (r"\bcodecs\.decode\s*\(.*rot_13", "MEDIUM", "ROT13 decoding — obfuscation technique"),
    (r"\bbytes\.fromhex\s*\(", "MEDIUM", "Hex decoding — may hide malicious payload"),
    (r"\bzlib\.decompress\s*\(", "LOW", "zlib decompression — may hide obfuscated code"),
]

# Supply chain
SUPPLY_CHAIN_PATTERNS = [
    (r"\bpip\s+install\b", "HIGH", "Runtime pip install — supply chain risk"),
    (r"\bsubprocess.*pip\b", "HIGH", "subprocess pip call — supply chain risk"),
    (r"requirements\.txt", "INFO", "requirements.txt reference — check dependencies"),
]

ALL_PATTERN_GROUPS = [
    ("code_injection", CODE_INJECTION_PATTERNS),
    ("command_exec", COMMAND_EXEC_PATTERNS),
    ("network", NETWORK_PATTERNS),
    ("file_access", FILE_ACCESS_PATTERNS),
    ("dynamic_import", DYNAMIC_IMPORT_PATTERNS),
    ("obfuscation", OBFUSCATION_PATTERNS),
    ("supply_chain", SUPPLY_CHAIN_PATTERNS),
]

# Known safe patterns that trigger false positives
FALSE_POSITIVE_CONTEXTS = [
    # Comments
    r"^\s*#",
    # String definitions / docstrings
    r'^\s*["\']',
    r'^\s*"""',
    r"^\s*'''",
]


def scan_node_package(package_path: Path) -> NodeAuditResult:
    """Scan a single custom node package for dangerous patterns.

    Args:
        package_path: Path to the custom node package directory

    Returns:
        NodeAuditResult with findings
    """
    package_name = package_path.name
    result = NodeAuditResult(
        package_name=package_name,
        package_path=str(package_path),
    )

    if not package_path.is_dir():
        return result

    # Scan all Python files
    for py_file in package_path.rglob("*.py"):
        result.files_scanned += 1
        findings = _scan_python_file(py_file, package_name)
        result.findings.extend(findings)

    # Check for suspicious non-Python files
    _check_suspicious_files(package_path, package_name, result)

    return result


def scan_all_nodes(custom_nodes_dir: Path) -> list[NodeAuditResult]:
    """Scan all installed custom node packages.

    Args:
        custom_nodes_dir: Path to ComfyUI's custom_nodes/ directory

    Returns:
        List of NodeAuditResult for each package
    """
    results = []

    if not custom_nodes_dir.is_dir():
        return results

    for package_dir in sorted(custom_nodes_dir.iterdir()):
        if package_dir.is_dir() and not package_dir.name.startswith("."):
            result = scan_node_package(package_dir)
            results.append(result)

    return results


def _scan_python_file(filepath: Path, package_name: str) -> list[NodeFinding]:
    """Scan a single Python file for dangerous patterns."""
    findings = []

    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    lines = content.splitlines()

    for line_num, line in enumerate(lines, 1):
        # Skip obvious false positives
        stripped = line.strip()
        if any(re.match(fp, stripped) for fp in FALSE_POSITIVE_CONTEXTS):
            continue

        for category, patterns in ALL_PATTERN_GROUPS:
            for pattern, severity, message in patterns:
                if re.search(pattern, line):
                    # Get a clean code snippet
                    snippet = stripped[:120]

                    findings.append(
                        NodeFinding(
                            severity=severity,
                            category=category,
                            message=message,
                            file_path=str(filepath),
                            line_number=line_num,
                            code_snippet=snippet,
                            node_package=package_name,
                        )
                    )

    # AST-based analysis for more accurate detection
    findings.extend(_ast_analysis(content, filepath, package_name))

    return findings


def _ast_analysis(content: str, filepath: Path, package_name: str) -> list[NodeFinding]:
    """Use AST parsing for more accurate detection of dangerous patterns."""
    findings = []

    try:
        tree = ast.parse(content, filename=str(filepath))
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        # Detect eval/exec as function calls (more accurate than regex)
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)

            # Check for dangerous builtins used as function calls
            if func_name == "eval":
                # Check if the argument comes from user input (node inputs)
                findings.append(
                    NodeFinding(
                        severity="CRITICAL",
                        category="code_injection",
                        message="eval() call detected via AST analysis",
                        file_path=str(filepath),
                        line_number=node.lineno,
                        code_snippet=f"eval() at line {node.lineno}",
                        node_package=package_name,
                    )
                )
            elif func_name == "exec":
                findings.append(
                    NodeFinding(
                        severity="CRITICAL",
                        category="code_injection",
                        message="exec() call detected via AST analysis",
                        file_path=str(filepath),
                        line_number=node.lineno,
                        code_snippet=f"exec() at line {node.lineno}",
                        node_package=package_name,
                    )
                )

        # Detect hidden inputs that access PROMPT (workflow inspection)
        if isinstance(node, ast.Dict):
            for key in node.keys:
                if isinstance(key, ast.Constant) and key.value == "hidden":
                    findings.append(
                        NodeFinding(
                            severity="INFO",
                            category="workflow_access",
                            message="Node declares hidden inputs (can access full workflow context)",
                            file_path=str(filepath),
                            line_number=node.lineno,
                            code_snippet=f"hidden input declaration at line {node.lineno}",
                            node_package=package_name,
                        )
                    )

    return findings


def _get_call_name(node: ast.Call) -> str:
    """Extract the function name from a Call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _check_suspicious_files(package_path: Path, package_name: str, result: NodeAuditResult):
    """Check for suspicious non-Python files in a package."""
    suspicious_extensions = {
        ".exe": "CRITICAL",
        ".dll": "CRITICAL",
        ".so": "HIGH",
        ".dylib": "HIGH",
        ".bin": "MEDIUM",
        ".dat": "LOW",
        ".whl": "MEDIUM",
    }

    for filepath in package_path.rglob("*"):
        if filepath.is_file():
            ext = filepath.suffix.lower()
            if ext in suspicious_extensions:
                result.findings.append(
                    NodeFinding(
                        severity=suspicious_extensions[ext],
                        category="suspicious_file",
                        message=f"Suspicious binary file: {filepath.name}",
                        file_path=str(filepath),
                        line_number=0,
                        node_package=package_name,
                    )
                )

            # Check for obfuscated Python (pyarmor, cython compiled)
            if ext == ".pyd" or ext == ".pyc":
                if "pyarmor" in filepath.name.lower():
                    result.findings.append(
                        NodeFinding(
                            severity="HIGH",
                            category="obfuscation",
                            message=f"PyArmor obfuscated file: {filepath.name}",
                            file_path=str(filepath),
                            line_number=0,
                            node_package=package_name,
                        )
                    )
