"""Tests for the Analyze Workflow node's blocking behavior.

Run from the repo root:
    python3 -m tests.test_node_blocking
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nodes.security_nodes import TensorTrapAnalyzeWorkflow


def _make_workflow_with_critical():
    return {
        "1": {
            "class_type": "Base64ToConditioning",
            "inputs": {"data": "gASVKgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJsc5SFlFKULg=="},
        },
    }


def _make_workflow_with_medium():
    return {
        "1": {"class_type": "TextInput", "inputs": {"text": "/etc/hosts"}},
    }


def _make_clean_workflow():
    return {
        "1": {"class_type": "KSampler", "inputs": {"seed": 42}},
    }


def test_critical_with_default_block_raises():
    node = TensorTrapAnalyzeWorkflow()
    try:
        node.analyze(prompt=_make_workflow_with_critical())
    except Exception as e:
        assert "TensorTrap blocked workflow" in str(e)
        assert "CRITICAL" in str(e)
        print("[PASS] CRITICAL + default block -> raises")
        return
    raise AssertionError("Did not raise on CRITICAL finding with block_on_threat=True default")


def test_critical_with_block_disabled_returns():
    node = TensorTrapAnalyzeWorkflow()
    report, is_safe, count = node.analyze(
        prompt=_make_workflow_with_critical(),
        block_on_threat=False,
    )
    assert is_safe is False
    assert count >= 1
    assert "CRITICAL" in report
    print("[PASS] CRITICAL + block_on_threat=False -> returns with is_safe=False")


def test_medium_with_default_severity_does_not_block():
    """Default min_severity=HIGH means MEDIUM findings report but don't block."""
    node = TensorTrapAnalyzeWorkflow()
    report, is_safe, count = node.analyze(prompt=_make_workflow_with_medium())
    assert count >= 1, f"Expected at least one MEDIUM finding, got: {report}"
    assert "MEDIUM" in report
    print("[PASS] MEDIUM + min_severity=HIGH -> reports but does not block")


def test_medium_with_min_severity_medium_blocks():
    node = TensorTrapAnalyzeWorkflow()
    try:
        node.analyze(prompt=_make_workflow_with_medium(), min_severity="MEDIUM")
    except Exception as e:
        assert "MEDIUM" in str(e)
        print("[PASS] MEDIUM + min_severity=MEDIUM -> raises")
        return
    raise AssertionError("Did not raise when min_severity lowered to MEDIUM")


def test_clean_workflow_does_not_block():
    node = TensorTrapAnalyzeWorkflow()
    report, is_safe, count = node.analyze(prompt=_make_clean_workflow())
    assert is_safe is True
    assert count == 0
    print("[PASS] Clean workflow -> is_safe=True, no block")


def test_no_prompt_returns_gracefully():
    node = TensorTrapAnalyzeWorkflow()
    report, is_safe, count = node.analyze(prompt=None)
    assert is_safe is True
    assert count == 0
    print("[PASS] prompt=None -> graceful return")


if __name__ == "__main__":
    test_critical_with_default_block_raises()
    test_critical_with_block_disabled_returns()
    test_medium_with_default_severity_does_not_block()
    test_medium_with_min_severity_medium_blocks()
    test_clean_workflow_does_not_block()
    test_no_prompt_returns_gracefully()
    print("\nAll node-blocking tests passed.")
