"""Approval: consent bound to an exact proposed action (interfaces only until V5)."""

from mcp_security_proxy.services.approval.interface import (
    ActionBinding,
    Approval,
    ApprovalHandle,
    ApprovalResult,
    ApprovalStatus,
)

__all__ = ["ActionBinding", "Approval", "ApprovalHandle", "ApprovalResult", "ApprovalStatus"]
