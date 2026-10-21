"""
Lumen v2.0 Enterprise Gateway - Installable Enterprise Python Client SDK
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Strict Zero-Dependency Implementation (Python >= 3.11 Standard Library only).
Provides dual in-memory and subprocess stdio transports, automatic HMAC-SHA256
request signing, QoS traffic lane tagging, and ergonomic async APIs.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Union

from lumen_config import (
    ClearanceLevel,
    LumenConfig,
    PrincipalId,
    TenantId,
    TrafficPriority,
    compute_request_hmac,
)
from lumen_handshake import LumenRpcError


# -----------------------------------------------------------------------------
# Enterprise Client Credentials
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class LumenCredentials:
    principal_id: str
    tenant_id: str
    clearance: ClearanceLevel
    scopes: Sequence[str]
    hmac_secret: str
    client_name: str = "lumen-enterprise-sdk"
    client_version: str = "2.0.0"

    def __post_init__(self) -> None:
        if not isinstance(self.clearance, ClearanceLevel):
            self.clearance = ClearanceLevel.from_str(self.clearance)
        self.scopes = list(self.scopes)


# -----------------------------------------------------------------------------
# Enterprise Client SDK
# -----------------------------------------------------------------------------
class LumenEnterpriseClient:
    """
    High-performance, zero-dependency async client SDK for the Lumen v2.0 Gateway.
    Supports in-memory zero-copy dispatch as well as stdio child process IPC.
    """

    def __init__(
        self,
        credentials: LumenCredentials,
        config: Optional[LumenConfig] = None,
        dispatcher: Optional[Any] = None,
        subprocess_cmd: Optional[List[str]] = None,
    ) -> None:
        self.credentials = credentials
        self.config = config or LumenConfig()
        self._dispatcher = dispatcher
        self._subprocess_cmd = subprocess_cmd
        self._process: Optional[asyncio.subprocess.Process] = None
        self._msg_id: int = 0
        self._is_connected: bool = False

    @classmethod
    def in_memory(
        cls,
        credentials: LumenCredentials,
        config: Optional[LumenConfig] = None,
        dispatcher: Optional[Any] = None,
    ) -> LumenEnterpriseClient:
        """Create an in-memory client sharing the local dispatcher for sub-microsecond latency."""
        if dispatcher is None:
            # Avoid circular import at top level
            from lumen_engine import LumenJsonRpcDispatcher
            dispatcher = LumenJsonRpcDispatcher(config=config)
        return cls(credentials=credentials, config=config, dispatcher=dispatcher)

    @classmethod
    def from_stdio_subprocess(
        cls,
        credentials: LumenCredentials,
        engine_script_path: str = "lumen_engine.py",
        python_bin: Optional[str] = None,
        config: Optional[LumenConfig] = None,
    ) -> LumenEnterpriseClient:
        """Create a client managing a background stdio gateway subprocess."""
        py = python_bin or sys.executable
        cmd = [py, engine_script_path, "--mode", "stdio"]
        return cls(credentials=credentials, config=config, subprocess_cmd=cmd)

    async def connect(self) -> Dict[str, Any]:
        """
        Connect to gateway and complete the MCP 2026-07-28 handshake:
          1. Spawn stdio subprocess if configured.
          2. Send 'initialize' capability negotiation.
          3. Send 'notifications/initialized' transition.
        """
        if self._subprocess_cmd and self._process is None:
            self._process = await asyncio.create_subprocess_exec(
                *self._subprocess_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        # 1. MCP initialize capability negotiation
        init_res = await self._send_request(
            method="initialize",
            params={
                "protocolVersion": self.config.protocol_version,
                "clientInfo": {
                    "name": self.credentials.client_name,
                    "version": self.credentials.client_version,
                },
            },
            skip_auth=True,
        )

        # 2. MCP notifications/initialized
        await self._send_notification(
            method="notifications/initialized",
            params={},
        )

        self._is_connected = True
        return init_res

    async def discover(self) -> Dict[str, Any]:
        """Stateless server discovery probe."""
        return await self._send_request(
            method="server/discover",
            params={},
            skip_auth=True,
        )

    async def list_tools(
        self,
        priority: Union[str, TrafficPriority] = TrafficPriority.NORMAL,
    ) -> List[Dict[str, Any]]:
        """Query scope-filtered tools authorized for caller's security clearance."""
        p_enum = TrafficPriority.from_str(priority)
        res = await self._send_request(
            method="tools/list",
            params={},
            priority=p_enum,
        )
        return res.get("tools", [])

    async def query_secure_records(
        self,
        department: str,
        tenant_id: Optional[str] = None,
        filter_query: Optional[str] = None,
        limit: int = 10,
        priority: Union[str, TrafficPriority] = TrafficPriority.NORMAL,
    ) -> Dict[str, Any]:
        """Query read-only enterprise records with automatic tenant isolation & PII redaction."""
        target_tenant = tenant_id or self.credentials.tenant_id
        args: Dict[str, Any] = {
            "department": department,
            "tenantId": target_tenant,
            "limit": limit,
        }
        if filter_query:
            args["filterQuery"] = filter_query

        p_enum = TrafficPriority.from_str(priority)
        call_res = await self._send_request(
            method="tools/call",
            params={"name": "query_secure_records", "arguments": args},
            priority=p_enum,
        )
        return call_res.get("structured", {})

    async def execute_vendor_payout(
        self,
        vendor_id: str,
        invoice_id: str,
        amount_usd: float,
        purpose: str,
        priority: Union[str, TrafficPriority] = TrafficPriority.HIGH,
        approver_role: Optional[str] = None,
        mfa_code: Optional[str] = None,
        request_state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute or authorize vendor payout.
        Amounts <= $1,000 auto-execute; amounts > $1,000 pause for HITL MFA approval.
        """
        args: Dict[str, Any] = {
            "vendorId": vendor_id,
            "invoiceId": invoice_id,
            "amountUsd": round(float(amount_usd), 2),
            "purpose": purpose,
        }
        if approver_role and mfa_code:
            args["inputResponses"] = {
                "approverRole": approver_role,
                "mfaCode": mfa_code,
            }
        if request_state:
            args["requestState"] = request_state

        p_enum = TrafficPriority.from_str(priority)
        call_res = await self._send_request(
            method="tools/call",
            params={"name": "execute_vendor_payout", "arguments": args},
            priority=p_enum,
        )
        return call_res.get("structured", {})

    async def close(self) -> None:
        """Close client resources and terminate subprocess if running."""
        if self._process:
            if self._process.stdin:
                self._process.stdin.close()
            try:
                self._process.terminate()
                await self._process.wait()
            except Exception:
                pass
            self._process = None
        self._is_connected = False

    async def __aenter__(self) -> LumenEnterpriseClient:
        await self.connect()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()

    # -------------------------------------------------------------------------
    # Internal Request & Notification Framing
    # -------------------------------------------------------------------------
    def _next_id(self) -> int:
        self._msg_id += 1
        return self._msg_id

    def _build_security_meta(self, method: str, priority: TrafficPriority) -> Dict[str, Any]:
        now_ns = time.time_ns()
        scopes_csv = ",".join(sorted(self.credentials.scopes))
        clearance_name = self.credentials.clearance.name.upper()
        priority_name = priority.name.upper()

        canonical = (
            f"{self.credentials.principal_id}|{self.credentials.tenant_id}|"
            f"{clearance_name}|{scopes_csv}|{priority_name}|{now_ns}|{method}"
        )
        sig = compute_request_hmac(self.credentials.hmac_secret, canonical)

        return {
            "lumen.security": {
                "principalId": self.credentials.principal_id,
                "tenantId": self.credentials.tenant_id,
                "clearance": self.credentials.clearance.name,
                "scopes": list(self.credentials.scopes),
                "priority": priority.name,
                "timestampNs": now_ns,
                "signature": sig,
            }
        }

    async def _send_request(
        self,
        method: str,
        params: Dict[str, Any],
        priority: TrafficPriority = TrafficPriority.NORMAL,
        skip_auth: bool = False,
    ) -> Dict[str, Any]:
        req_id = self._next_id()
        p = dict(params)
        if not skip_auth:
            p["_meta"] = self._build_security_meta(method, priority)

        payload = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": p,
        }
        frame_bytes = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")

        # Transport 1: In-Memory
        if self._dispatcher is not None:
            resp_bytes = self._dispatcher.handle_raw_payload(frame_bytes)
            if not resp_bytes:
                return {}
            resp = json.loads(resp_bytes.decode("utf-8"))
            if "error" in resp:
                err = resp["error"]
                raise LumenRpcError(err["code"], err["message"], err.get("data"))
            return resp.get("result", {})

        # Transport 2: Stdio Subprocess
        if self._process and self._process.stdin and self._process.stdout:
            self._process.stdin.write(frame_bytes)
            await self._process.stdin.drain()
            resp_line = await self._process.stdout.readline()
            if not resp_line:
                raise LumenRpcError(-32603, "Subprocess EOF received without response.")
            resp = json.loads(resp_line.decode("utf-8"))
            if "error" in resp:
                err = resp["error"]
                raise LumenRpcError(err["code"], err["message"], err.get("data"))
            return resp.get("result", {})

        raise RuntimeError("No active transport configured for LumenEnterpriseClient.")

    async def _send_notification(self, method: str, params: Dict[str, Any]) -> None:
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        frame_bytes = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")

        if self._dispatcher is not None:
            self._dispatcher.handle_raw_payload(frame_bytes)
            return

        if self._process and self._process.stdin:
            self._process.stdin.write(frame_bytes)
            await self._process.stdin.drain()
