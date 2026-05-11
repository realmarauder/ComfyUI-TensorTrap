"""Tests for the pickle-deserializer rule (CWE-502).

Run from the repo root:
    python3 -m tests.test_pickle_deserializers
"""
import sys
from pathlib import Path

# Make repo root importable when running this file directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analyzer.graph_analyzer import analyze_workflow


def _find(result, severity, category):
    return [f for f in result.findings if f.severity == severity and f.category == category]


def test_literal_base64_payload_is_critical():
    """A Base64ToConditioning with a literal data string is an active CWE-502 attack."""
    workflow = {
        "1": {
            "class_type": "Base64ToConditioning",
            "inputs": {"data": "gASVKgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjA1lY2hvIHB3bmVklIWUUpQu"},
        },
    }
    result = analyze_workflow(workflow)
    crits = _find(result, "CRITICAL", "pickle_deserialization")
    assert len(crits) == 1, f"Expected 1 CRITICAL pickle finding, got {len(crits)}: {result.findings}"
    assert "CWE-502" in crits[0].message
    assert crits[0].details["payload_length"] > 0
    print("[PASS] Literal base64 payload -> CRITICAL")


def test_connection_from_trusted_producer_is_safe():
    """Base64ToConditioning fed by ConditioningToBase64 (in the same workflow) is the intended flow."""
    workflow = {
        "1": {"class_type": "ConditioningToBase64", "inputs": {}},
        "2": {"class_type": "Base64ToConditioning", "inputs": {"data": ["1", 0]}},
    }
    result = analyze_workflow(workflow)
    pickle_findings = [f for f in result.findings if f.category == "pickle_deserialization"]
    assert len(pickle_findings) == 0, f"Expected zero pickle findings, got: {pickle_findings}"
    print("[PASS] Trusted-producer flow -> no finding")


def test_connection_from_untrusted_source_is_medium():
    """Base64ToConditioning fed by a random String node is suspicious."""
    workflow = {
        "1": {"class_type": "TextInput", "inputs": {"text": "some string"}},
        "2": {"class_type": "Base64ToConditioning", "inputs": {"data": ["1", 0]}},
    }
    result = analyze_workflow(workflow)
    meds = _find(result, "MEDIUM", "pickle_deserialization")
    assert len(meds) == 1, f"Expected 1 MEDIUM pickle finding, got: {result.findings}"
    assert "TextInput" in meds[0].message
    assert meds[0].details["source_type"] == "TextInput"
    print("[PASS] Untrusted-source flow -> MEDIUM")


def test_workflow_without_pickle_node_is_clean():
    workflow = {
        "1": {"class_type": "KSampler", "inputs": {"seed": 42}},
        "2": {"class_type": "VAEDecode", "inputs": {"samples": ["1", 0]}},
    }
    result = analyze_workflow(workflow)
    pickle_findings = [f for f in result.findings if f.category == "pickle_deserialization"]
    assert len(pickle_findings) == 0
    print("[PASS] Workflow with no pickle nodes -> no finding")


def test_ui_format_widget_payload_is_critical():
    """UI-format workflows store the data value as widget_0 instead of named 'data'."""
    workflow = {
        "nodes": [
            {
                "id": 7,
                "type": "Base64ToConditioning",
                "widgets_values": ["gASVKgAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjAJsc5SFlFKULg=="],
            }
        ]
    }
    result = analyze_workflow(workflow)
    crits = _find(result, "CRITICAL", "pickle_deserialization")
    assert len(crits) == 1, f"Expected 1 CRITICAL on UI-format widget, got: {result.findings}"
    assert crits[0].details["input_field"] == "widget_0"
    print("[PASS] UI-format widget payload -> CRITICAL")


def test_empty_string_is_not_flagged():
    """An empty data field is the default state. Don't flag it."""
    workflow = {
        "1": {"class_type": "Base64ToConditioning", "inputs": {"data": ""}},
    }
    result = analyze_workflow(workflow)
    pickle_findings = [f for f in result.findings if f.category == "pickle_deserialization"]
    assert len(pickle_findings) == 0
    print("[PASS] Empty data field -> no finding")


if __name__ == "__main__":
    test_literal_base64_payload_is_critical()
    test_connection_from_trusted_producer_is_safe()
    test_connection_from_untrusted_source_is_medium()
    test_workflow_without_pickle_node_is_clean()
    test_ui_format_widget_payload_is_critical()
    test_empty_string_is_not_flagged()
    print("\nAll pickle-deserializer tests passed.")
