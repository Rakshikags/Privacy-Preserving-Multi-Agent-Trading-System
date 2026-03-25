"""
rbac/access_control.py — Role-Based Access Control (RBAC).

Concepts
--------
• Permission  — a named capability string, e.g. "trade:submit"
• Role        — a named set of permissions
• Principal   — an agent identity bound to a role

The AccessController is the single authority for permission checks.
All broker-side decisions go through :meth:`AccessController.require`.

Usage
-----
    ac = AccessController()
    ac.register("alice", Role.TRADER)
    ac.require("alice", "trade:submit")   # raises if not allowed
"""

from config import Role, MsgType


# ── Permission Registry ───────────────────────────────────────────────────────

# Map each role to its allowed permission strings.
# Adding a new permission only requires editing this dict.
ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.TRADER: {
        "trade:submit",    # place buy / sell orders
        "status:read",     # heartbeat / status checks
    },
    Role.MONITOR: {
        "trade:read",      # observe all transactions
        "anomaly:flag",    # raise an anomaly alert
        "status:read",
    },
    Role.ADMIN: {
        "trade:submit",
        "trade:read",
        "anomaly:flag",
        "agent:manage",    # register / deregister agents
        "status:read",
        "status:write",
    },
}

# Map inbound message types to the permission required to send them.
MSG_TYPE_PERMISSION: dict[str, str] = {
    MsgType.TRADE:   "trade:submit",
    MsgType.ANOMALY: "anomaly:flag",
    MsgType.STATUS:  "status:read",
}


class AccessDeniedError(Exception):
    """Raised when an agent lacks the required permission."""


class AccessController:
    """Thread-safe registry mapping agent IDs → roles, with permission checks."""

    def __init__(self) -> None:
        # agent_id → role string
        self._registry: dict[str, str] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, agent_id: str, role: str) -> None:
        """
        Bind *agent_id* to *role*.

        Raises
        ------
        ValueError
            If *role* is not a known role.
        """
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown role '{role}'. Valid roles: {list(ROLE_PERMISSIONS)}")
        self._registry[agent_id] = role

    def deregister(self, agent_id: str) -> None:
        """Remove *agent_id* from the registry (no-op if unknown)."""
        self._registry.pop(agent_id, None)

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_role(self, agent_id: str) -> str | None:
        """Return the role bound to *agent_id*, or ``None`` if unregistered."""
        return self._registry.get(agent_id)

    def has_permission(self, agent_id: str, permission: str) -> bool:
        """Return ``True`` if *agent_id* holds *permission*."""
        role = self._registry.get(agent_id)
        if role is None:
            return False
        return permission in ROLE_PERMISSIONS.get(role, set())

    def require(self, agent_id: str, permission: str) -> None:
        """
        Assert that *agent_id* holds *permission*.

        Raises
        ------
        AccessDeniedError
            If the agent is unregistered or lacks the permission.
        """
        if not self.has_permission(agent_id, permission):
            role = self._registry.get(agent_id, "<unregistered>")
            raise AccessDeniedError(
                f"Agent '{agent_id}' (role={role}) lacks permission '{permission}'"
            )

    def require_for_message(self, agent_id: str, msg_type: str) -> None:
        """
        Convenience wrapper: look up the permission needed for *msg_type*
        and call :meth:`require`.
        """
        permission = MSG_TYPE_PERMISSION.get(msg_type)
        if permission is None:
            # Message type has no access restriction (e.g. REGISTER)
            return
        self.require(agent_id, permission)
