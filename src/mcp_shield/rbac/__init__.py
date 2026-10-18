"""RBAC package."""

from mcp_shield.rbac.roles import Role, ROLE_PERMISSIONS, check_rbac_permission

__all__ = ["Role", "ROLE_PERMISSIONS", "check_rbac_permission"]
