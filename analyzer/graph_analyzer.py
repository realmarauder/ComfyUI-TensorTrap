"""Workflow graph security analyzer.

Parses ComfyUI workflow JSON and analyzes the node connection graph
for dangerous data flow patterns:
- String outputs flowing into eval/exec nodes
- URLs flowing into download nodes
- Unvalidated inputs reaching file I/O nodes
- Known dangerous node types
- Suspicious node combinations
"""

import base64 as _base64
import json
from dataclasses import dataclass, field
from pathlib import Path

# Known nodes that call pickle.loads() (or equivalent deserializers) on a workflow-supplied
# input. A literal value in the pickle input field of one of these nodes is the exact
# CWE-502 attack pattern: a shared workflow embeds a base64 payload, and running the
# workflow triggers arbitrary code execution. A connection from an unknown source is
# softer-suspicious — verify it came from the matching trusted producer in the same graph.
#
# Add new entries here as TensorTrap audits surface more pickle.loads() exposures.
PICKLE_DESERIALIZER_NODES = {
    "Base64ToConditioning": {
        "pack": "RES4LYF",
        "input_fields": ["data"],          # API-format input names
        "widget_indices": [0],              # UI-format widgets_values positions
        "trusted_producers": {"ConditioningToBase64"},
        "cwe": "CWE-502",
        "reference": "https://github.com/ClownsharkBatwing/RES4LYF/issues/252",
        "node_purpose": "deserializes base64-encoded conditioning data via pickle.loads()",
    },
}

# Known dangerous node types (from CVE research)
DANGEROUS_NODES = {
    # Direct code execution (CVE-2024-21576, CVE-2024-21577)
    "ACE_ExpressionEval": {
        "severity": "CRITICAL",
        "cve": "CVE-2024-21577",
        "message": "Direct eval() on user input — arbitrary code execution",
    },
    "BuildColorRangeHSVAdvanced": {
        "severity": "CRITICAL",
        "cve": "CVE-2024-21576",
        "message": "Eval injection via Bmad-Nodes — bypasses sanitization",
    },
    "FilterContour": {
        "severity": "CRITICAL",
        "cve": "CVE-2024-21576",
        "message": "Eval injection via Bmad-Nodes",
    },
    "FindContour": {
        "severity": "CRITICAL",
        "cve": "CVE-2024-21576",
        "message": "Eval injection via Bmad-Nodes",
    },
    "HueAdjust": {
        "severity": "HIGH",
        "message": "Known eval() usage in image processing",
    },
    # LLM code generation (arbitrary execution)
    "AnyNode": {
        "severity": "HIGH",
        "message": "LLM-generated code execution — insufficient sanitization",
    },
    # Script execution nodes
    "RunPython": {
        "severity": "CRITICAL",
        "message": "Arbitrary Python code execution node",
    },
    "Execute": {
        "severity": "CRITICAL",
        "message": "Command execution node",
    },
    "PythonExpression": {
        "severity": "CRITICAL",
        "message": "Python expression evaluation node",
    },
    "MathExpression": {
        "severity": "HIGH",
        "message": "Math expression evaluation — may use eval() internally",
    },
}

# Node types that accept URLs (download risk)
URL_INPUT_NODES = {
    "LoadImage",
    "LoadVideo",
    "DownloadModel",
    "LoadCheckpoint",
    "LoadLoRA",
    "DownloadAndLoadModel",
    "LoadImageFromUrl",
    "LoadVideoFromUrl",
}

# Node types that produce string outputs that could be injection vectors
STRING_OUTPUT_NODES = {
    "TextInput",
    "StringConstant",
    "TextConcatenate",
    "PromptCompose",
    "ShowText",
}

# Filesystem paths whose mere mention in a workflow input is high-signal for an
# information-disclosure or credential-theft attempt. Matched as substrings, so
# subpaths under these roots also fire.
SENSITIVE_PATHS_HIGH = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.bash_history",
    "/root/.ssh/",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.aws/credentials",
    "/.config/gh/",
    "/.netrc",
    "/proc/self/environ",
    "/proc/self/maps",
    r"\Users\Administrator",
    r"\.ssh\id_rsa",
    r"\.aws\credentials",
    r"\AppData\Roaming\Microsoft\Credentials",
)

# Filesystem paths that are typically untouched by ComfyUI workflows. A mention
# is suspicious but could be benign in some edge cases.
SENSITIVE_PATHS_MEDIUM = (
    "/etc/",
    "/root/",
    "/var/log/",
    "/usr/bin/",
    "/usr/sbin/",
    "/dev/",
    r"\Windows\System32",
    r"\Windows\SysWOW64",
)


@dataclass
class GraphFinding:
    """A security finding in a workflow graph."""

    severity: str
    category: str  # dangerous_node, data_flow, url_injection, suspicious_connection
    message: str
    node_id: str
    node_type: str
    details: dict = field(default_factory=dict)


@dataclass
class GraphAnalysisResult:
    """Results of workflow graph analysis."""

    workflow_source: str  # file path or "inline"
    total_nodes: int = 0
    total_connections: int = 0
    findings: list[GraphFinding] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return not any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    def to_dict(self) -> dict:
        return {
            "workflow_source": self.workflow_source,
            "total_nodes": self.total_nodes,
            "total_connections": self.total_connections,
            "is_safe": self.is_safe,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "message": f.message,
                    "node_id": f.node_id,
                    "node_type": f.node_type,
                    "details": f.details,
                }
                for f in self.findings
            ],
        }


def analyze_workflow(workflow: dict, source: str = "inline") -> GraphAnalysisResult:
    """Analyze a ComfyUI workflow for security issues.

    Args:
        workflow: Parsed workflow JSON (the prompt format ComfyUI uses)
        source: Where the workflow came from (file path, URL, etc.)

    Returns:
        GraphAnalysisResult with findings
    """
    result = GraphAnalysisResult(workflow_source=source)

    # Handle both API format (flat dict of nodes) and UI format (with "nodes" array)
    nodes = _extract_nodes(workflow)
    if not nodes:
        return result

    result.total_nodes = len(nodes)

    # Build connection graph
    connections = _build_connection_graph(nodes)
    result.total_connections = sum(len(v) for v in connections.values())

    # Check for known dangerous nodes
    _check_dangerous_nodes(nodes, result)

    # Check for dangerous data flows
    _check_data_flows(nodes, connections, result)

    # Check for URL injection risks
    _check_url_inputs(nodes, result)

    # Check for pickle-deserializer abuse (CWE-502)
    _check_pickle_deserializers(nodes, result)

    # Check for base64-encoded pickle payloads smuggled into string widgets
    _check_embedded_pickle(nodes, result)

    # Check for sensitive filesystem paths in widget values
    _check_path_traversal(nodes, result)

    # Check for suspicious patterns
    _check_suspicious_patterns(nodes, connections, result)

    return result


def analyze_workflow_file(filepath: Path) -> GraphAnalysisResult:
    """Analyze a workflow JSON file.

    Args:
        filepath: Path to workflow JSON file

    Returns:
        GraphAnalysisResult with findings
    """
    try:
        content = filepath.read_text(encoding="utf-8")
        workflow = json.loads(content)
    except (OSError, json.JSONDecodeError) as e:
        result = GraphAnalysisResult(workflow_source=str(filepath))
        result.findings.append(
            GraphFinding(
                severity="MEDIUM",
                category="parse_error",
                message=f"Failed to parse workflow: {e}",
                node_id="",
                node_type="",
            )
        )
        return result

    return analyze_workflow(workflow, source=str(filepath))


def _extract_nodes(workflow: dict) -> dict:
    """Extract nodes from either API format or UI format workflow."""
    # UI format: {"nodes": [...], "links": [...]} — check first; the API-format check
    # below would otherwise vacuously match if we left a "nodes" list key in place.
    if "nodes" in workflow and isinstance(workflow["nodes"], list):
        # Convert to API-like format
        nodes = {}
        for node in workflow["nodes"]:
            node_id = str(node.get("id", ""))
            node_type = node.get("type", "")
            if node_id and node_type:
                nodes[node_id] = {
                    "class_type": node_type,
                    "inputs": _extract_widget_values(node),
                }
        return nodes

    # Might be wrapped in "prompt" key
    if "prompt" in workflow and isinstance(workflow["prompt"], dict):
        return _extract_nodes(workflow["prompt"])

    # API format: {"1": {"class_type": "...", "inputs": {...}}, "2": {...}}.
    # Require at least one entry and every value to be a class_type dict.
    if workflow and all(isinstance(v, dict) and "class_type" in v for v in workflow.values()):
        return workflow

    return {}


def _extract_widget_values(node: dict) -> dict:
    """Extract input values from a UI-format node."""
    inputs = {}
    widgets = node.get("widgets_values", [])
    # Widget values are positional, we can't map them to names without the node definition
    # but we can still check their content for suspicious patterns
    for i, val in enumerate(widgets):
        if isinstance(val, str):
            inputs[f"widget_{i}"] = val
    return inputs


def _build_connection_graph(nodes: dict) -> dict[str, list[tuple[str, str]]]:
    """Build a graph of node connections.

    Returns:
        Dict mapping node_id -> list of (source_node_id, output_index) connections
    """
    connections: dict[str, list[tuple[str, str]]] = {}

    for node_id, node_data in nodes.items():
        inputs = node_data.get("inputs", {})
        node_connections = []

        for input_name, input_value in inputs.items():
            # Links are represented as [source_node_id, output_index]
            if isinstance(input_value, list) and len(input_value) == 2:
                source_id = str(input_value[0])
                node_connections.append((source_id, input_name))

        if node_connections:
            connections[node_id] = node_connections

    return connections


def _check_dangerous_nodes(nodes: dict, result: GraphAnalysisResult):
    """Check for known dangerous node types."""
    for node_id, node_data in nodes.items():
        class_type = node_data.get("class_type", "")

        if class_type in DANGEROUS_NODES:
            info = DANGEROUS_NODES[class_type]
            details = {"class_type": class_type}
            if "cve" in info:
                details["cve"] = info["cve"]

            result.findings.append(
                GraphFinding(
                    severity=info["severity"],
                    category="dangerous_node",
                    message=f"{class_type}: {info['message']}",
                    node_id=node_id,
                    node_type=class_type,
                    details=details,
                )
            )


def _check_data_flows(nodes: dict, connections: dict, result: GraphAnalysisResult):
    """Check for dangerous data flow patterns.

    Traces connections to find cases where string data flows into
    nodes that might evaluate or execute it.
    """
    # Find all eval/exec capable nodes
    eval_nodes = set()
    for node_id, node_data in nodes.items():
        class_type = node_data.get("class_type", "")
        if class_type in DANGEROUS_NODES:
            eval_nodes.add(node_id)

    # Check if any string-producing node connects to an eval node
    for target_id, sources in connections.items():
        if target_id not in eval_nodes:
            continue

        target_type = nodes[target_id].get("class_type", "")

        for source_id, input_name in sources:
            if source_id in nodes:
                source_type = nodes[source_id].get("class_type", "")

                result.findings.append(
                    GraphFinding(
                        severity="HIGH",
                        category="data_flow",
                        message=(
                            f"Data flows from {source_type} (node {source_id}) "
                            f"into {target_type} (node {target_id}) via '{input_name}' — "
                            f"potential code injection if input is user-controlled"
                        ),
                        node_id=target_id,
                        node_type=target_type,
                        details={
                            "source_node": source_id,
                            "source_type": source_type,
                            "target_node": target_id,
                            "target_type": target_type,
                            "input_name": input_name,
                        },
                    )
                )


def _check_url_inputs(nodes: dict, result: GraphAnalysisResult):
    """Check for nodes with URL inputs that could be attacker-controlled."""
    for node_id, node_data in nodes.items():
        class_type = node_data.get("class_type", "")
        inputs = node_data.get("inputs", {})

        for input_name, input_value in inputs.items():
            if not isinstance(input_value, str):
                continue

            # Check for URLs in input values
            if input_value.startswith(("http://", "https://", "ftp://")):
                severity = "HIGH" if class_type in URL_INPUT_NODES else "MEDIUM"

                result.findings.append(
                    GraphFinding(
                        severity=severity,
                        category="url_injection",
                        message=(
                            f"External URL in {class_type} input '{input_name}': "
                            f"{input_value[:80]}{'...' if len(input_value) > 80 else ''}"
                        ),
                        node_id=node_id,
                        node_type=class_type,
                        details={
                            "input_name": input_name,
                            "url": input_value,
                        },
                    )
                )


def _check_pickle_deserializers(nodes: dict, result: GraphAnalysisResult):
    """Flag nodes that call pickle.loads() (or equivalent) on workflow-supplied input.

    Two patterns trigger findings:
      CRITICAL — the pickle input field holds a literal non-empty string. That is an
                 active CWE-502 payload embedded in the workflow JSON itself.
      MEDIUM   — the pickle input is connected to a node not on the trusted-producers
                 list. The flow may be legitimate but warrants review.
    """
    for node_id, node_data in nodes.items():
        class_type = node_data.get("class_type", "")
        if class_type not in PICKLE_DESERIALIZER_NODES:
            continue

        info = PICKLE_DESERIALIZER_NODES[class_type]
        inputs = node_data.get("inputs", {})

        candidates: list[tuple[str, object]] = []
        for fname in info.get("input_fields", []):
            if fname in inputs:
                candidates.append((fname, inputs[fname]))
        for idx in info.get("widget_indices", []):
            key = f"widget_{idx}"
            if key in inputs:
                candidates.append((key, inputs[key]))

        for field_name, value in candidates:
            if isinstance(value, str) and value.strip():
                result.findings.append(
                    GraphFinding(
                        severity="CRITICAL",
                        category="pickle_deserialization",
                        message=(
                            f"{class_type} ({info['pack']}) {info['node_purpose']}. "
                            f"Its '{field_name}' input holds a literal payload of length {len(value)}. "
                            f"This is the {info['cwe']} attack pattern — running this workflow may "
                            f"execute arbitrary code. See {info['reference']}."
                        ),
                        node_id=node_id,
                        node_type=class_type,
                        details={
                            "cwe": info["cwe"],
                            "reference": info["reference"],
                            "pack": info["pack"],
                            "input_field": field_name,
                            "payload_length": len(value),
                        },
                    )
                )
            elif isinstance(value, list) and len(value) == 2:
                source_id = str(value[0])
                source_type = nodes.get(source_id, {}).get("class_type", "")
                if source_type and source_type not in info["trusted_producers"]:
                    result.findings.append(
                        GraphFinding(
                            severity="MEDIUM",
                            category="pickle_deserialization",
                            message=(
                                f"{class_type}'s '{field_name}' input is connected to "
                                f"{source_type} (node {source_id}). Trusted producers are "
                                f"{sorted(info['trusted_producers'])}. Verify this flow."
                            ),
                            node_id=node_id,
                            node_type=class_type,
                            details={
                                "cwe": info["cwe"],
                                "reference": info["reference"],
                                "input_field": field_name,
                                "source_node": source_id,
                                "source_type": source_type,
                                "trusted_producers": sorted(info["trusted_producers"]),
                            },
                        )
                    )


_BASE64_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def _looks_like_base64(value: str, min_len: int = 60) -> bool:
    """Heuristic: is this string plausibly base64-encoded binary data?"""
    if len(value) < min_len:
        return False
    stripped = value.strip()
    if not stripped:
        return False
    in_alpha = sum(1 for c in stripped if c in _BASE64_ALPHABET)
    return in_alpha / len(stripped) > 0.95


def _decodes_to_pickle(value: str) -> bool:
    """Does this base64 string decode to bytes that start with a pickle opcode?

    Pickle protocols 2-5 start with \\x80 followed by a protocol byte (0x02-0x05).
    Protocol 0/1 streams start with one of the legacy opcodes; we conservatively
    only flag protocol 2+ to keep false-positive rate low.
    """
    try:
        decoded = _base64.b64decode(value, validate=True)
    except (ValueError, _base64.binascii.Error):
        return False
    if len(decoded) < 2:
        return False
    return decoded[0] == 0x80 and decoded[1] in (0x02, 0x03, 0x04, 0x05)


def _check_embedded_pickle(nodes: dict, result: GraphAnalysisResult):
    """Flag widget values that look like base64-encoded pickle streams.

    The pickle-deserializer rule already covers the case where such a payload sits
    in a known deserializer's input field. This rule catches the same payload in
    *any* node's string input — useful when the payload is staged on a generic
    string node before being routed to a deserializer.
    """
    for node_id, node_data in nodes.items():
        class_type = node_data.get("class_type", "")
        inputs = node_data.get("inputs", {})

        for input_name, input_value in inputs.items():
            if not isinstance(input_value, str):
                continue
            if not _looks_like_base64(input_value):
                continue
            if not _decodes_to_pickle(input_value):
                continue

            result.findings.append(
                GraphFinding(
                    severity="HIGH",
                    category="embedded_pickle",
                    message=(
                        f"{class_type} input '{input_name}' contains a base64-encoded pickle "
                        f"stream (length {len(input_value)}). Pickle payloads in workflow widgets "
                        f"are a CWE-502 attack vector — verify this value is intentional."
                    ),
                    node_id=node_id,
                    node_type=class_type,
                    details={
                        "input_name": input_name,
                        "payload_length": len(input_value),
                        "value_preview": input_value[:80] + ("..." if len(input_value) > 80 else ""),
                    },
                )
            )


def _check_path_traversal(nodes: dict, result: GraphAnalysisResult):
    """Flag references to sensitive filesystem paths in widget values."""
    for node_id, node_data in nodes.items():
        class_type = node_data.get("class_type", "")
        inputs = node_data.get("inputs", {})

        for input_name, input_value in inputs.items():
            if not isinstance(input_value, str) or not input_value:
                continue

            hit = None
            for path in SENSITIVE_PATHS_HIGH:
                if path in input_value:
                    hit = ("HIGH", path)
                    break
            if hit is None:
                for path in SENSITIVE_PATHS_MEDIUM:
                    if path in input_value:
                        hit = ("MEDIUM", path)
                        break
            if hit is None and input_value.count("../") >= 3:
                hit = ("MEDIUM", f"{input_value.count('../')} levels of '../' traversal")

            if hit is None:
                continue

            severity, reason = hit
            result.findings.append(
                GraphFinding(
                    severity=severity,
                    category="path_traversal",
                    message=(
                        f"{class_type} input '{input_name}' references a sensitive path: {reason}. "
                        f"Value: {input_value[:120]}{'...' if len(input_value) > 120 else ''}"
                    ),
                    node_id=node_id,
                    node_type=class_type,
                    details={
                        "input_name": input_name,
                        "match": reason,
                    },
                )
            )


def _check_suspicious_patterns(nodes: dict, connections: dict, result: GraphAnalysisResult):
    """Check for suspicious workflow patterns."""
    node_types = {nid: nd.get("class_type", "") for nid, nd in nodes.items()}

    # Check for suspicious string content in inputs
    for node_id, node_data in nodes.items():
        inputs = node_data.get("inputs", {})
        class_type = node_data.get("class_type", "")

        for input_name, input_value in inputs.items():
            if not isinstance(input_value, str):
                continue

            # Check for code-like patterns in string inputs. Narrow + high-confidence
            # patterns first; broader heuristics last so reports stay readable.
            suspicious_patterns = [
                ("__import__", "CRITICAL", "Dynamic import in input value"),
                ("os.system", "CRITICAL", "os.system() in input value"),
                ("subprocess", "CRITICAL", "subprocess reference in input value"),
                ("eval(", "CRITICAL", "eval() in input value"),
                ("exec(", "CRITICAL", "exec() in input value"),
                ("__reduce__", "CRITICAL", "Pickle __reduce__ override in input value"),
                ("__class__.__bases__", "CRITICAL", "Python sandbox-escape pattern in input value"),
                ("__class__.__subclasses__", "CRITICAL", "Python sandbox-escape pattern in input value"),
                ("__builtins__", "HIGH", "__builtins__ reference in input value"),
                ("pickle.loads", "HIGH", "Explicit pickle.loads() reference in input value"),
                ("marshal.loads", "HIGH", "marshal.loads() reference in input value"),
                ("compile(", "HIGH", "compile() builtin in input value"),
                ("runpy", "HIGH", "runpy reference in input value"),
                ("getattr(__builtins__", "CRITICAL", "Pickle gadget pattern in input value"),
                ("open(", "HIGH", "file open() in input value"),
                ("socket.", "HIGH", "Socket reference in input value"),
                (".decode(", "MEDIUM", "Decode call in input value — possible obfuscation"),
                ("base64", "MEDIUM", "Base64 reference in input value"),
            ]

            for pattern, severity, message in suspicious_patterns:
                if pattern in input_value:
                    result.findings.append(
                        GraphFinding(
                            severity=severity,
                            category="suspicious_input",
                            message=f"{message} in {class_type} node '{input_name}'",
                            node_id=node_id,
                            node_type=class_type,
                            details={
                                "input_name": input_name,
                                "pattern": pattern,
                                "value_preview": input_value[:200],
                            },
                        )
                    )
