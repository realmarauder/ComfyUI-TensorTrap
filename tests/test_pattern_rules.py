"""Tests for the expanded pattern rules: code-shaped strings, embedded pickle, path traversal.

Run from the repo root:
    python3 -m tests.test_pattern_rules
"""
import base64
import pickle
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.graph_analyzer import (
    _decodes_to_pickle,
    _looks_like_base64,
    analyze_workflow,
)


def _find(result, category, severity=None):
    findings = [f for f in result.findings if f.category == category]
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return findings


# --- Code-shaped string detection ---

def test_dunder_subclasses_is_critical():
    workflow = {
        "1": {
            "class_type": "CLIPTextEncode",
            "inputs": {"text": "''.__class__.__bases__[0].__subclasses__()"},
        },
    }
    result = analyze_workflow(workflow)
    crits = _find(result, "suspicious_input", "CRITICAL")
    assert any("sandbox-escape" in f.message for f in crits), f"got: {result.findings}"
    print("[PASS] __class__.__bases__ -> CRITICAL")


def test_reduce_dunder_is_critical():
    workflow = {
        "1": {"class_type": "TextInput", "inputs": {"text": "class X: __reduce__ = lambda s: (os.system, ('id',))"}},
    }
    result = analyze_workflow(workflow)
    crits = _find(result, "suspicious_input", "CRITICAL")
    assert any("__reduce__" in f.message for f in crits)
    print("[PASS] __reduce__ override -> CRITICAL")


def test_compile_builtin_is_high():
    workflow = {
        "1": {"class_type": "TextInput", "inputs": {"text": "compile(payload, '<str>', 'exec')"}},
    }
    result = analyze_workflow(workflow)
    highs = _find(result, "suspicious_input", "HIGH")
    assert any("compile()" in f.message for f in highs)
    print("[PASS] compile() builtin -> HIGH")


# --- Embedded pickle detection ---

def test_base64_helpers():
    """Confidence check on the heuristic helpers themselves."""
    # Realistically-sized pickle attack payload (longer command)
    payload = pickle.dumps({"data": "x" * 80, "more": [1, 2, 3, 4, 5]}, protocol=4)
    b64 = base64.b64encode(payload).decode()
    assert _looks_like_base64(b64), f"len={len(b64)} should be base64-shaped"
    assert _decodes_to_pickle(b64)
    assert not _looks_like_base64("hello world")
    plain_b64 = base64.b64encode(b"plain text data here that is long enough but is not pickle").decode()
    assert not _decodes_to_pickle(plain_b64)
    print("[PASS] base64 + pickle helpers")


def test_embedded_pickle_in_random_node_is_high():
    """A pickle stream pasted into ANY node's string input is suspicious."""
    payload = pickle.dumps({"data": "x" * 80, "more": [1, 2, 3, 4, 5]}, protocol=4)
    b64 = base64.b64encode(payload).decode()
    workflow = {
        "1": {"class_type": "TextInput", "inputs": {"text": b64}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "embedded_pickle", "HIGH")
    assert len(findings) == 1, f"got: {result.findings}"
    assert findings[0].details["payload_length"] == len(b64)
    print("[PASS] base64 pickle in generic node -> HIGH")


def test_plain_base64_image_is_not_flagged():
    """Plain base64 (not a pickle stream) should not fire the embedded-pickle rule."""
    fake_image_b64 = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"x" * 500).decode()
    workflow = {
        "1": {"class_type": "TextInput", "inputs": {"text": fake_image_b64}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "embedded_pickle")
    assert len(findings) == 0, f"got false positive: {result.findings}"
    print("[PASS] non-pickle base64 -> no embedded_pickle finding")


# --- Path traversal detection ---

def test_etc_passwd_is_high():
    workflow = {
        "1": {"class_type": "LoadImage", "inputs": {"image": "/etc/passwd"}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "path_traversal", "HIGH")
    assert any("/etc/passwd" in f.message for f in findings), f"got: {result.findings}"
    print("[PASS] /etc/passwd reference -> HIGH")


def test_ssh_key_path_is_high():
    workflow = {
        "1": {"class_type": "LoadImage", "inputs": {"image": "/home/user/.ssh/id_rsa"}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "path_traversal", "HIGH")
    assert len(findings) >= 1, f"got: {result.findings}"
    print("[PASS] SSH key path reference -> HIGH")


def test_etc_dir_is_medium():
    workflow = {
        "1": {"class_type": "TextInput", "inputs": {"text": "/etc/hosts"}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "path_traversal", "MEDIUM")
    assert len(findings) >= 1, f"got: {result.findings}"
    print("[PASS] /etc/ subpath -> MEDIUM")


def test_deep_traversal_is_medium():
    workflow = {
        "1": {"class_type": "LoadImage", "inputs": {"image": "../../../../../home/user/secrets.txt"}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "path_traversal", "MEDIUM")
    assert len(findings) >= 1, f"got: {result.findings}"
    assert any("traversal" in f.message for f in findings)
    print("[PASS] 5x '../' traversal -> MEDIUM")


def test_normal_path_is_not_flagged():
    workflow = {
        "1": {"class_type": "LoadImage", "inputs": {"image": "input/photo.png"}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "path_traversal")
    assert len(findings) == 0
    print("[PASS] Normal relative path -> no finding")


def test_single_dotdot_is_not_flagged():
    """Single '../' is common in relative paths and should not fire."""
    workflow = {
        "1": {"class_type": "LoadImage", "inputs": {"image": "../input/photo.png"}},
    }
    result = analyze_workflow(workflow)
    findings = _find(result, "path_traversal")
    assert len(findings) == 0
    print("[PASS] Single '../' -> no finding")


if __name__ == "__main__":
    test_dunder_subclasses_is_critical()
    test_reduce_dunder_is_critical()
    test_compile_builtin_is_high()
    test_base64_helpers()
    test_embedded_pickle_in_random_node_is_high()
    test_plain_base64_image_is_not_flagged()
    test_etc_passwd_is_high()
    test_ssh_key_path_is_high()
    test_etc_dir_is_medium()
    test_deep_traversal_is_medium()
    test_normal_path_is_not_flagged()
    test_single_dotdot_is_not_flagged()
    print("\nAll pattern-rule tests passed.")
