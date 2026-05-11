"""TensorTrap security nodes for ComfyUI workflows.

Provides nodes that can be added to workflows to scan models
before they're loaded and analyze workflow security.
"""

import json
from pathlib import Path


class TensorTrapScanModel:
    """Scans a model file for security threats before loading.

    Drop this node before any model loader to verify the file
    is safe before it enters your workflow.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "model_path": ("STRING", {"default": "", "multiline": False}),
            },
            "optional": {
                "block_on_threat": ("BOOLEAN", {"default": True}),
                "min_severity": (["CRITICAL", "HIGH", "MEDIUM", "LOW"], {"default": "HIGH"}),
            },
        }

    RETURN_TYPES = ("STRING", "STRING", "BOOLEAN")
    RETURN_NAMES = ("model_path", "scan_report", "is_safe")
    FUNCTION = "scan"
    CATEGORY = "TensorTrap/Security"

    def scan(self, model_path, block_on_threat=True, min_severity="HIGH"):
        scan_report = ""
        is_safe = True

        filepath = Path(model_path).expanduser()

        if not filepath.exists():
            return (model_path, f"File not found: {model_path}", False)

        try:
            from tensortrap.scanner.engine import scan_file

            result = scan_file(filepath, compute_hash=False)
            is_safe = result.is_safe
            scan_report = json.dumps(result.to_dict(), indent=2)

            if not is_safe and block_on_threat:
                severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
                threshold = severity_order.get(min_severity, 1)
                max_sev = result.max_severity
                if max_sev and severity_order.get(max_sev.value, 4) <= threshold:
                    raise Exception(
                        f"TensorTrap blocked model load: {filepath.name} has "
                        f"{max_sev.value.upper()} severity findings. "
                        f"Run 'tensortrap scan {filepath}' for details."
                    )

        except ImportError:
            scan_report = "TensorTrap not installed. Run: pip install tensortrap"

        return (model_path, scan_report, is_safe)


class TensorTrapAuditNodes:
    """Scans all installed custom nodes for dangerous code patterns.

    Run this periodically to check if any installed nodes
    contain eval(), exec(), subprocess, or other dangerous patterns.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {},
            "optional": {
                "trigger": ("*",),
            },
        }

    RETURN_TYPES = ("STRING", "INT", "INT")
    RETURN_NAMES = ("audit_report", "total_packages", "packages_with_issues")
    FUNCTION = "audit"
    CATEGORY = "TensorTrap/Security"

    def audit(self, trigger=None):
        from auditor.node_scanner import scan_all_nodes

        # Find custom_nodes directory
        custom_nodes_dir = Path(__file__).parent.parent.parent
        if not (custom_nodes_dir / "ComfyUI-TensorTrap").exists():
            # Try alternate path
            custom_nodes_dir = Path("custom_nodes")

        results = scan_all_nodes(custom_nodes_dir)
        total = len(results)
        with_issues = sum(1 for r in results if not r.is_safe)

        report_lines = [f"TensorTrap Node Audit: {total} packages scanned\n"]
        report_lines.append(f"Packages with issues: {with_issues}\n\n")

        for r in sorted(results, key=lambda x: x.is_safe):
            if not r.is_safe:
                report_lines.append(f"[{r.max_severity}] {r.package_name}")
                report_lines.append(f"  Files scanned: {r.files_scanned}")
                report_lines.append(f"  Findings: {len(r.findings)}")
                for f in r.findings[:5]:
                    report_lines.append(f"    - [{f.severity}] {f.message}")
                    report_lines.append(f"      {f.file_path}:{f.line_number}")
                if len(r.findings) > 5:
                    report_lines.append(f"    ... and {len(r.findings) - 5} more")
                report_lines.append("")

        return ("\n".join(report_lines), total, with_issues)


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class TensorTrapAnalyzeWorkflow:
    """Analyzes the current workflow for security issues.

    Checks for dangerous node types, suspicious data flows,
    URL injection risks, pickle-deserializer abuse (CWE-502),
    embedded pickle payloads, sensitive filesystem paths,
    and known CVE patterns.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {},
            "optional": {
                "block_on_threat": ("BOOLEAN", {"default": True}),
                "min_severity": (["CRITICAL", "HIGH", "MEDIUM", "LOW"], {"default": "HIGH"}),
            },
            "hidden": {
                "prompt": "PROMPT",
            },
        }

    RETURN_TYPES = ("STRING", "BOOLEAN", "INT")
    RETURN_NAMES = ("analysis_report", "is_safe", "findings_count")
    FUNCTION = "analyze"
    CATEGORY = "TensorTrap/Security"

    def analyze(self, prompt=None, block_on_threat=True, min_severity="HIGH"):
        if prompt is None:
            return ("No workflow data available", True, 0)

        from analyzer.graph_analyzer import analyze_workflow

        result = analyze_workflow(prompt, source="current_workflow")

        report_lines = [
            "TensorTrap Workflow Analysis",
            f"Nodes: {result.total_nodes} | Connections: {result.total_connections}",
            f"Status: {'SAFE' if result.is_safe else 'THREATS DETECTED'}\n",
        ]

        if result.findings:
            for f in result.findings:
                report_lines.append(f"[{f.severity}] {f.message}")
                if f.details.get("cve"):
                    report_lines.append(f"  CVE: {f.details['cve']}")
                if f.details.get("reference"):
                    report_lines.append(f"  Reference: {f.details['reference']}")
                report_lines.append("")

        report_text = "\n".join(report_lines)

        if block_on_threat and result.findings:
            threshold = _SEVERITY_ORDER.get(min_severity, 1)
            worst = min(
                (_SEVERITY_ORDER.get(f.severity, 4) for f in result.findings),
                default=4,
            )
            if worst <= threshold:
                worst_finding = min(
                    result.findings,
                    key=lambda f: _SEVERITY_ORDER.get(f.severity, 4),
                )
                raise Exception(
                    f"TensorTrap blocked workflow: {worst_finding.severity} finding in "
                    f"{worst_finding.node_type} (node {worst_finding.node_id}): "
                    f"{worst_finding.message}\n\n"
                    f"To proceed anyway, set block_on_threat=False on the Analyze Workflow node, "
                    f"or raise min_severity above {worst_finding.severity}."
                )

        return (
            report_text,
            result.is_safe,
            len(result.findings),
        )


class TensorTrapPreflightCheck:
    """One-stop preflight: scans an optional model path, audits installed nodes, and
    analyzes the current workflow. Blocks the queue on any finding at or above
    `min_severity`. Drop one of these in once and the whole workflow is gated.

    Each section can be individually skipped, and the whole node degrades gracefully
    if `tensortrap` (the CLI package) is missing — the section that requires it
    simply reports that it was skipped.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {},
            "optional": {
                "model_path": ("STRING", {"default": "", "multiline": False}),
                "block_on_threat": ("BOOLEAN", {"default": True}),
                "min_severity": (["CRITICAL", "HIGH", "MEDIUM", "LOW"], {"default": "HIGH"}),
                "skip_model_scan": ("BOOLEAN", {"default": False}),
                "skip_node_audit": ("BOOLEAN", {"default": False}),
                "skip_workflow_analysis": ("BOOLEAN", {"default": False}),
            },
            "hidden": {"prompt": "PROMPT"},
        }

    RETURN_TYPES = ("STRING", "BOOLEAN", "INT")
    RETURN_NAMES = ("combined_report", "all_safe", "total_findings")
    FUNCTION = "preflight"
    CATEGORY = "TensorTrap/Security"

    def preflight(
        self,
        model_path: str = "",
        block_on_threat: bool = True,
        min_severity: str = "HIGH",
        skip_model_scan: bool = False,
        skip_node_audit: bool = False,
        skip_workflow_analysis: bool = False,
        prompt: dict | None = None,
    ):
        sections: list[str] = ["TensorTrap Preflight Check"]
        worst_severity_rank = 4   # nothing yet
        worst_finding_summary: str | None = None
        total_findings = 0
        all_safe = True

        threshold = _SEVERITY_ORDER.get(min_severity, 1)

        # --- 1. Model scan (only if a path is provided) ---
        if not skip_model_scan and model_path.strip():
            sections.append("\n[1] Model scan")
            try:
                from pathlib import Path as _Path

                from tensortrap.scanner.engine import scan_file

                filepath = _Path(model_path).expanduser()
                if not filepath.exists():
                    sections.append(f"  Skipped — file not found: {model_path}")
                else:
                    result = scan_file(filepath, compute_hash=False)
                    if result.is_safe:
                        sections.append(f"  SAFE — {filepath.name}")
                    else:
                        all_safe = False
                        max_sev = result.max_severity.value.upper() if result.max_severity else "UNKNOWN"
                        sections.append(f"  {max_sev} — {filepath.name}")
                        for finding in result.findings[:10]:
                            sev = getattr(finding, "severity", None)
                            sev_str = sev.value.upper() if hasattr(sev, "value") else str(sev)
                            sections.append(f"    [{sev_str}] {getattr(finding, 'message', finding)}")
                            rank = _SEVERITY_ORDER.get(sev_str, 4)
                            total_findings += 1
                            if rank < worst_severity_rank:
                                worst_severity_rank = rank
                                worst_finding_summary = f"Model scan {sev_str}: {filepath.name}"
            except ImportError:
                sections.append("  Skipped — tensortrap CLI not installed (pip install tensortrap)")
            except Exception as e:
                sections.append(f"  Error: {e}")
        elif not skip_model_scan:
            sections.append("\n[1] Model scan: skipped (no model_path provided)")
        else:
            sections.append("\n[1] Model scan: skipped (skip_model_scan=True)")

        # --- 2. Installed-node audit ---
        if not skip_node_audit:
            sections.append("\n[2] Installed-node audit")
            try:
                from pathlib import Path as _Path

                from auditor.node_scanner import scan_all_nodes

                custom_nodes_dir = _Path(__file__).resolve().parent.parent.parent
                results = scan_all_nodes(custom_nodes_dir)
                total = len(results)
                with_issues = sum(1 for r in results if not r.is_safe)
                sections.append(f"  {total} packages scanned, {with_issues} flagged")
                for r in sorted(results, key=lambda x: x.is_safe):
                    if r.is_safe:
                        continue
                    sev = str(getattr(r, "max_severity", "UNKNOWN")).upper()
                    sections.append(f"    [{sev}] {r.package_name} ({len(r.findings)} findings)")
                    rank = _SEVERITY_ORDER.get(sev, 4)
                    total_findings += len(r.findings)
                    if rank < worst_severity_rank:
                        worst_severity_rank = rank
                        worst_finding_summary = f"Node audit {sev}: {r.package_name}"
                if with_issues > 0:
                    all_safe = False
            except ImportError as e:
                sections.append(f"  Skipped — auditor module unavailable: {e}")
            except Exception as e:
                sections.append(f"  Error: {e}")
        else:
            sections.append("\n[2] Installed-node audit: skipped (skip_node_audit=True)")

        # --- 3. Workflow analysis ---
        if not skip_workflow_analysis:
            sections.append("\n[3] Workflow analysis")
            if prompt is None:
                sections.append("  Skipped — no workflow context")
            else:
                from analyzer.graph_analyzer import analyze_workflow

                result = analyze_workflow(prompt, source="preflight_check")
                sections.append(
                    f"  {result.total_nodes} nodes, {result.total_connections} connections, "
                    f"{len(result.findings)} findings"
                )
                total_findings += len(result.findings)
                if not result.is_safe:
                    all_safe = False
                for f in result.findings:
                    sections.append(f"    [{f.severity}] {f.node_type}: {f.message}")
                    rank = _SEVERITY_ORDER.get(f.severity, 4)
                    if rank < worst_severity_rank:
                        worst_severity_rank = rank
                        worst_finding_summary = f"Workflow {f.severity}: {f.node_type} (node {f.node_id})"
        else:
            sections.append("\n[3] Workflow analysis: skipped (skip_workflow_analysis=True)")

        sections.append(
            f"\nResult: {'PASS' if all_safe else 'FAIL'} "
            f"(total findings: {total_findings})"
        )
        report = "\n".join(sections)

        if block_on_threat and worst_severity_rank <= threshold:
            raise Exception(
                f"TensorTrap preflight failed: {worst_finding_summary}. "
                f"Lower min_severity, set block_on_threat=False, or fix the finding before "
                f"queueing this workflow."
            )

        return (report, all_safe, total_findings)
