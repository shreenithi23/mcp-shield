"""Layer 1: Role-Based Access Control (RBAC) for Admin and Gateway Console."""

from enum import Enum
from typing import Set


class Role(str, Enum):
    ADMIN = "admin"
    SECURITY_REVIEWER = "security_reviewer"
    DEVELOPER = "developer"
    VIEWER = "viewer"


ROLE_PERMISSIONS = {
    Role.ADMIN: {
        "policy:read",
        "policy:write",
        "tokens:read",
        "tokens:revoke",
        "audit:read",
        "clients:manage",
        "vault:manage",
        "tools:call",
    },
    Role.SECURITY_REVIEWER: {
        "policy:read",
        "tokens:read",
        "tokens:revoke",
        "audit:read",
    },
    Role.DEVELOPER: {
        "tokens:issue",
        "clients:register",
        "tools:call",
        "metadata:read",
    },
    Role.VIEWER: {
        "metadata:read",
    },
}


def check_rbac_permission(role: Role | str, required_permission: str) -> bool:
    """Verifies whether a role possesses a required RBAC permission."""
    try:
        r = Role(role) if isinstance(role, str) else role
    except ValueError:
        return False

    perms: Set[str] = ROLE_PERMISSIONS.get(r, set())
    if "*" in perms or required_permission in perms:
        return True
    return False
