"""
Lumen v2.0 Enterprise Gateway - MCP 2026-07-28 Lifecycle & Zero-Trust Verifier
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Strict Zero-Dependency Implementation (Python >= 3.11 Standard Library only).
Enforces MCP lifecycle states and constant-time HMAC-SHA256 request attestation.
"""

from __future__ import annotations

import dataclasses
from enum import IntEnum
import hmac
import time
from typing import Any, Dict, List, Optional, Set

from lumen_config import (
    ClearanceLevel,
    JsonRpcErrorCode,
    LumenConfig,
    PrincipalId,
    PriorityTrafficManager,
    TenantId,
    TrafficPriority,
    compute_request_hmac,
)


# -----------------------------------------------------------------------------
# Custom RPC Exception for Zero-Trust Guardrails
# -----------------------------------------------------------------------------
class LumenRpcError(Exception):
    """Structured JSON-RPC 2.0 error carrying an error code and optional payload."""

    def __init__(
        self,
        code: int | JsonRpcErrorCode,
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = message
        self.data = data or {}

    def to_rpc_error(self) -> Dict[str, Any]:
        err: Dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.data:
            err["data"] = self.data
        return err


# -----------------------------------------------------------------------------
# MCP 2026-07-28 Lifecycle State Machine
# -----------------------------------------------------------------------------
class LifecycleState(IntEnum):
    UNINITIALIZED = 0
    INITIALIZING = 1
    OPERATIONAL = 2
    SHUTTING_DOWN = 3


class HandshakeStateMachine:
    """
    Enforces the MCP 2026-07-28 lifecycle state transitions:
      UNINITIALIZED -> INITIALIZING -> OPERATIONAL -> SHUTTING_DOWN
    Protects against premature operational calls, rogue client attestation,
    and duplicate initializations.
    """

    def __init__(self, config: LumenConfig) -> None:
        self.config = config
        self._state: LifecycleState = LifecycleState.UNINITIALIZED
        self._negotiated_client: Optional[Dict[str, Any]] = None
        self._session_start_ns: int = time.monotonic_ns()

    @property
    def state(self) -> LifecycleState:
        return self._state

    @property
    def is_operational(self) -> bool:
        return self._state == LifecycleState.OPERATIONAL

    @property
    def client_info(self) -> Optional[Dict[str, Any]]:
        return self._negotiated_client

    def handle_server_discover(self) -> Dict[str, Any]:
        """
        Stateless discovery probe. Permitted in any lifecycle state.
        Allows callers to inspect protocol capabilities without altering session state.
        """
        return {
            "protocolVersion": self.config.protocol_version,
            "serverInfo": {
                "name": self.config.server_name,
                "version": self.config.server_version,
                "ecosystem": "Alexa+ Enterprise Ecosystem (Hackathon 2026)",
            },
            "status": "HEALTHY",
            "state": self._state.name,
            "zeroTrustCapabilities": {
                "qosTrafficManager": True,
                "hmacAttestation": "HMAC-SHA256",
                "blake2bAuditLedger": True,
                "hitlElicitation": True,
                "maxFrameBytes": self.config.max_frame_bytes,
            },
        }

    def handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process MCP 'initialize' capability negotiation.
        Transitions UNINITIALIZED -> INITIALIZING.
        """
        if self._state != LifecycleState.UNINITIALIZED:
            raise LumenRpcError(
                JsonRpcErrorCode.INVALID_REQUEST,
                f"Cannot initialize session: session is already in state '{self._state.name}'."
            )

        client_info = params.get("clientInfo", {})
        client_name = client_info.get("name", "")

        # Strict Zero-Trust Client Attestation Whitelist Check
        if client_name not in self.config.allowed_client_names:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
                f"Rogue client attestation rejected: client '{client_name}' is not in allowed enterprise whitelist.",
                data={"allowedClients": list(self.config.allowed_client_names)},
            )

        protocol_version = params.get("protocolVersion", "")
        # Record client and advance to INITIALIZING
        self._negotiated_client = client_info
        self._state = LifecycleState.INITIALIZING

        return {
            "protocolVersion": self.config.protocol_version,
            "capabilities": {
                "tools": {"listChanged": False},
                "prompts": {},
                "resources": {},
                "logging": {},
                "zeroTrust": {
                    "qosPriority": True,
                    "hmacSha256": True,
                    "hitl": True,
                    "blake2bAudit": True,
                },
            },
            "serverInfo": {
                "name": self.config.server_name,
                "version": self.config.server_version,
                "ecosystem": "Alexa+ Enterprise Ecosystem (Hackathon 2026)",
            },
            "instructions": (
                "Lumen v2.0 Zero-Trust Gateway initialized. "
                "Send notifications/initialized to transition to OPERATIONAL."
            ),
        }

    def handle_initialized_notification(self) -> None:
        """
        Process MCP 'notifications/initialized' notification.
        Transitions INITIALIZING -> OPERATIONAL.
        """
        if self._state == LifecycleState.INITIALIZING:
            self._state = LifecycleState.OPERATIONAL
        elif self._state == LifecycleState.OPERATIONAL:
            # Idempotent
            pass
        else:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_UNINITIALIZED_SESSION,
                f"Invalid lifecycle transition: received initialized notification in '{self._state.name}' state."
            )

    def assert_operational(self, method: str) -> None:
        """
        Ensure session is OPERATIONAL before executing any operational tool or resource call.
        """
        if self._state != LifecycleState.OPERATIONAL:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_UNINITIALIZED_SESSION,
                f"MCP session is not operational (current state: '{self._state.name}'). "
                f"Method '{method}' requires completing the initialize handshake first."
            )

    def shutdown(self) -> None:
        """Mark session as shutting down."""
        self._state = LifecycleState.SHUTTING_DOWN

    def reset_for_test(self) -> None:
        """Reset handshake machine back to UNINITIALIZED."""
        self._state = LifecycleState.UNINITIALIZED
        self._negotiated_client = None


# -----------------------------------------------------------------------------
# Security Context & Verification
# -----------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class SecurityContext:
    """Authenticated caller identity and operational privileges."""
    principal_id: PrincipalId
    tenant_id: TenantId
    clearance: ClearanceLevel
    scopes: Set[str]
    priority: TrafficPriority
    timestamp_ns: int
    signature: str

    def has_scope(self, required_scope: str) -> bool:
        return required_scope in self.scopes

    def has_clearance(self, min_level: ClearanceLevel) -> bool:
        return self.clearance >= min_level


def verify_request_security_context(
    params: Dict[str, Any],
    method: str,
    config: LumenConfig,
    traffic_mgr: PriorityTrafficManager,
) -> SecurityContext:
    """
    Extract, authenticate, and authorize caller credentials:
      1. Verifies presence of _meta["lumen.security"].
      2. Validates clock skew against max_clock_skew_ns (+/- 30s).
      3. Verifies constant-time HMAC-SHA256 signature against canonical string.
      4. Dispatches to PriorityTrafficManager to consume QoS lane tokens.
    """
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            "Zero-Trust failure: missing '_meta' envelope in request params.",
        )

    sec_obj = meta.get("lumen.security")
    if not isinstance(sec_obj, dict):
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            "Zero-Trust failure: missing 'lumen.security' block in _meta.",
        )

    # Required fields
    principal_id_raw = sec_obj.get("principalId")
    tenant_id_raw = sec_obj.get("tenantId")
    clearance_raw = sec_obj.get("clearance")
    scopes_raw = sec_obj.get("scopes", [])
    priority_raw = sec_obj.get("priority", "NORMAL")
    timestamp_ns = sec_obj.get("timestampNs")
    signature = sec_obj.get("signature", "")

    if not principal_id_raw or not tenant_id_raw or timestamp_ns is None or not signature:
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            "Zero-Trust failure: incomplete security context fields (principalId, tenantId, timestampNs, signature).",
        )

    # Validate clock skew
    now_ns = time.time_ns()
    skew_ns = abs(now_ns - int(timestamp_ns))
    if skew_ns > config.max_clock_skew_ns:
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            f"Zero-Trust clock skew violation: skew of {skew_ns / 1e9:.2f}s exceeds limit of {config.max_clock_skew_ns / 1e9:.1f}s.",
            data={"clockSkewSec": round(skew_ns / 1e9, 3), "maxAllowedSec": config.max_clock_skew_ns / 1e9},
        )

    # Normalize clearance and priority
    try:
        clearance = ClearanceLevel.from_str(clearance_raw)
    except Exception as exc:
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            f"Invalid clearance level specified: {clearance_raw}",
        ) from exc

    try:
        priority = TrafficPriority.from_str(priority_raw)
    except Exception as exc:
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            f"Invalid traffic priority specified: {priority_raw}",
        ) from exc

    # Normalize scopes
    if isinstance(scopes_raw, str):
        scopes_list = [s.strip() for s in scopes_raw.split(",") if s.strip()]
    elif isinstance(scopes_raw, (list, tuple, set)):
        scopes_list = [str(s).strip() for s in scopes_raw if str(s).strip()]
    else:
        scopes_list = []
    scopes_set = set(scopes_list)
    scopes_csv = ",".join(sorted(scopes_set))

    # Verify HMAC-SHA256 signature in constant time
    canonical_string = (
        f"{principal_id_raw}|{tenant_id_raw}|{clearance.name.upper()}|"
        f"{scopes_csv}|{priority.name.upper()}|{timestamp_ns}|{method}"
    )
    expected_signature = compute_request_hmac(config.hmac_secret, canonical_string)

    if not hmac.compare_digest(signature, expected_signature):
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED,
            "Zero-Trust failure: HMAC-SHA256 signature mismatch. Request untrusted or tampered.",
        )

    # QoS Priority Traffic Limiter Check & Token Consumption
    allowed, remaining, retry_after_ms = traffic_mgr.check_and_consume(
        principal_id=principal_id_raw,
        priority=priority,
        cost=1.0,
    )
    if not allowed:
        raise LumenRpcError(
            JsonRpcErrorCode.ERR_RATE_LIMIT_EXCEEDED,
            f"Rate limit exceeded on QoS priority lane '{priority.name}'.",
            data={
                "priority": priority.name,
                "remainingTokens": remaining,
                "retryAfterMs": retry_after_ms,
            },
        )

    return SecurityContext(
        principal_id=PrincipalId(str(principal_id_raw)),
        tenant_id=TenantId(str(tenant_id_raw)),
        clearance=clearance,
        scopes=scopes_set,
        priority=priority,
        timestamp_ns=int(timestamp_ns),
        signature=str(signature),
    )
