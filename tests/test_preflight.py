"""Tests for the Preflight Check composite node.

Run from the repo root:
    python3 -m tests.test_preflight
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nodes.security_nodes import TensorTrapPreflightCheck


def _bad_workflow():
    return {
        "1": {
            "class_type": "Base64ToConditioning",
            "inputs": {"data": "gASVKgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJsc5SFlFKULg=="},
        },
    }


def _clean_workflow():
    return {"1": {"class_type": "KSampler", "inputs": {"seed": 42}}}


def test_preflight_blocks_on_critical_workflow():
    node = TensorTrapPreflightCheck()
    try:
        node.preflight(
            prompt=_bad_workflow(),
            skip_model_scan=True,
            skip_node_audit=True,
        )
    except Exception as e:
        assert "TensorTrap preflight failed" in str(e)
        assert "CRITICAL" in str(e)
        print("[PASS] CRITICAL workflow finding -> preflight raises")
        return
    raise AssertionError("Preflight did not raise on CRITICAL workflow finding")


def test_preflight_returns_when_blocking_disabled():
    node = TensorTrapPreflightCheck()
    report, all_safe, count = node.preflight(
        prompt=_bad_workflow(),
        block_on_threat=False,
        skip_model_scan=True,
        skip_node_audit=True,
    )
    assert all_safe is False
    assert count >= 1
    assert "FAIL" in report
    assert "CRITICAL" in report
    print("[PASS] block_on_threat=False -> returns with all_safe=False")


def test_preflight_clean_workflow_passes():
    node = TensorTrapPreflightCheck()
    report, all_safe, count = node.preflight(
        prompt=_clean_workflow(),
        skip_model_scan=True,
        skip_node_audit=True,
    )
    assert all_safe is True
    assert count == 0
    assert "PASS" in report
    print("[PASS] Clean workflow -> preflight passes")


def test_preflight_all_skipped_is_pass():
    node = TensorTrapPreflightCheck()
    report, all_safe, count = node.preflight(
        prompt=_clean_workflow(),
        skip_model_scan=True,
        skip_node_audit=True,
        skip_workflow_analysis=True,
    )
    assert all_safe is True
    assert count == 0
    assert "PASS" in report
    print("[PASS] All-skipped -> preflight passes (no-op)")


def test_preflight_no_model_path_skips_model_scan():
    """Without a model_path, the model scan should be a no-op (not an error)."""
    node = TensorTrapPreflightCheck()
    report, all_safe, count = node.preflight(
        prompt=_clean_workflow(),
        # skip_model_scan defaults False, model_path defaults ""
        skip_node_audit=True,
    )
    assert "no model_path provided" in report
    print("[PASS] Empty model_path -> model scan skipped without error")


def test_preflight_returns_node_classmethod_inputs():
    """Quick sanity check that INPUT_TYPES is wired correctly."""
    inputs = TensorTrapPreflightCheck.INPUT_TYPES()
    assert "optional" in inputs
    assert "model_path" in inputs["optional"]
    assert "block_on_threat" in inputs["optional"]
    assert "min_severity" in inputs["optional"]
    assert "skip_model_scan" in inputs["optional"]
    assert "hidden" in inputs and inputs["hidden"].get("prompt") == "PROMPT"
    print("[PASS] INPUT_TYPES schema looks right")


if __name__ == "__main__":
    test_preflight_blocks_on_critical_workflow()
    test_preflight_returns_when_blocking_disabled()
    test_preflight_clean_workflow_passes()
    test_preflight_all_skipped_is_pass()
    test_preflight_no_model_path_skips_model_scan()
    test_preflight_returns_node_classmethod_inputs()
    print("\nAll preflight tests passed.")
