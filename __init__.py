"""
@author: realmarauder (M2 Dynamics)
@title: TensorTrap Security Scanner
@nickname: TensorTrap
@description: Security scanner for ComfyUI — scans model files, audits custom nodes, and analyzes workflow graphs for threats.
"""

from .nodes.security_nodes import (
    TensorTrapAnalyzeWorkflow,
    TensorTrapAuditNodes,
    TensorTrapPreflightCheck,
    TensorTrapScanModel,
)

NODE_CLASS_MAPPINGS = {
    "TensorTrap_ScanModel": TensorTrapScanModel,
    "TensorTrap_AuditNodes": TensorTrapAuditNodes,
    "TensorTrap_AnalyzeWorkflow": TensorTrapAnalyzeWorkflow,
    "TensorTrap_PreflightCheck": TensorTrapPreflightCheck,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "TensorTrap_ScanModel": "Scan Model (TensorTrap)",
    "TensorTrap_AuditNodes": "Audit Installed Nodes (TensorTrap)",
    "TensorTrap_AnalyzeWorkflow": "Analyze Workflow (TensorTrap)",
    "TensorTrap_PreflightCheck": "Preflight Check (TensorTrap)",
}

__all__ = ["NODE_CLASS_MAPPINGS", "NODE_DISPLAY_NAME_MAPPINGS"]
