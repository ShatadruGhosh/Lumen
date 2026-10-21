"""
Lumen v2.0 Enterprise Gateway - Asyncio Byte-Stream Framer, JSON-RPC 2.0 Dispatcher & 14-Gate Verification Suite
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Strict Zero-Dependency Implementation (Python >= 3.11 Standard Library only).
Provides sub-millisecond (< 1,000 us p99) message framing, circuit breaking,
zero-trust dispatching, and self-testing verification suite.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import socket
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from lumen_config import (
    AuditLogger,
    ClearanceLevel,
    JsonRpcErrorCode,
    LumenConfig,
    PrincipalId,
    PriorityTrafficManager,
    TenantId,
    TrafficPriority,
    compute_request_hmac,
)
from lumen_handshake import (
    HandshakeStateMachine,
    LifecycleState,
    LumenRpcError,
    SecurityContext,
    verify_request_security_context,
)
from lumen_tools import ToolRegistry


# -----------------------------------------------------------------------------
# Byte-Stream Framer with 64 KB Circuit Breaker
# -----------------------------------------------------------------------------
class FrameTooLargeError(Exception):
    """Raised when an un-delimited frame exceeds the maximum allowable byte threshold."""
    pass


class LumenByteStreamFramer:
    """
    Sub-microsecond line-delimited (0x0A) byte-stream reassembler.
    Reassembles arbitrary chunk fragments and trips a circuit breaker
    if any individual frame exceeds max_frame_bytes.
    """

    def __init__(self, max_frame_bytes: int = 65536) -> None:
        self.max_frame_bytes = max_frame_bytes
        self._buffer = bytearray()

    def feed(self, chunk: bytes) -> List[bytes]:
        """
        Feed an incoming byte chunk and return any completed frames.
        Raises FrameTooLargeError if buffer exceeds max_frame_bytes without a delimiter.
        """
        frames: List[bytes] = []
        self._buffer.extend(chunk)

        while True:
            newline_idx = self._buffer.find(b"\n")
            if newline_idx != -1:
                frame = bytes(self._buffer[:newline_idx])
                # Remove the frame and the newline from buffer
                del self._buffer[: newline_idx + 1]

                if len(frame) > self.max_frame_bytes:
                    raise FrameTooLargeError(
                        f"Frame length {len(frame)} exceeds maximum allowed {self.max_frame_bytes} bytes."
                    )
                # Strip optional trailing carriage return \r
                if frame.endswith(b"\r"):
                    frame = frame[:-1]
                if frame:
                    frames.append(frame)
            else:
                # No newline found in buffer yet
                if len(self._buffer) > self.max_frame_bytes:
                    overflow_len = len(self._buffer)
                    self._buffer.clear()
                    raise FrameTooLargeError(
                        f"Unterminated frame exceeded {self.max_frame_bytes} bytes (reached {overflow_len} bytes)."
                    )
                break

        return frames


# -----------------------------------------------------------------------------
# JSON-RPC 2.0 Dispatcher
# -----------------------------------------------------------------------------
class LumenJsonRpcDispatcher:
    """
    Zero-Trust MCP JSON-RPC 2.0 Core Dispatcher.
    Coordinates handshake state, security context verification,
    tool execution, and tamper-evident BLAKE2b audit logging.
    """

    def __init__(
        self,
        config: Optional[LumenConfig] = None,
        traffic_mgr: Optional[PriorityTrafficManager] = None,
        audit_logger: Optional[AuditLogger] = None,
        tool_registry: Optional[ToolRegistry] = None,
    ) -> None:
        self.config = config or LumenConfig()
        self.traffic_mgr = traffic_mgr or PriorityTrafficManager(
            base_capacity=self.config.base_burst_capacity,
            base_refill_rate=self.config.base_refill_rate_per_sec,
        )
        self.audit_logger = audit_logger or AuditLogger(emit_to_stderr=True)
        self.handshake = HandshakeStateMachine(self.config)
        self.tools = tool_registry or ToolRegistry(self.config)

    def handle_raw_payload(self, raw_bytes: bytes) -> Optional[bytes]:
        """
        Synchronously dispatch a raw JSON-RPC frame and return raw response bytes.
        Returns None for notifications (where no response is produced).
        """
        t0_ns = time.monotonic_ns()
        req_id: Any = None
        method = "unknown"
        principal_id = "anonymous"
        tenant_id = "none"

        try:
            try:
                text = raw_bytes.decode("utf-8")
                payload = json.loads(text)
            except Exception as exc:
                raise LumenRpcError(
                    JsonRpcErrorCode.PARSE_ERROR,
                    f"Invalid JSON payload: {str(exc)}",
                ) from exc

            if not isinstance(payload, dict):
                raise LumenRpcError(
                    JsonRpcErrorCode.INVALID_REQUEST,
                    "JSON-RPC 2.0 request must be a JSON object.",
                )

            if payload.get("jsonrpc") != "2.0":
                raise LumenRpcError(
                    JsonRpcErrorCode.INVALID_REQUEST,
                    "Invalid jsonrpc version: must be exactly '2.0'.",
                )

            req_id = payload.get("id")
            method = payload.get("method", "")
            params = payload.get("params") or {}
            is_notification = req_id is None

            if not isinstance(method, str) or not method:
                raise LumenRpcError(
                    JsonRpcErrorCode.INVALID_REQUEST,
                    "Missing or invalid 'method' string in JSON-RPC request.",
                )

            # Route 1: Stateless server/discover probe
            if method == "server/discover":
                res = self.handshake.handle_server_discover()
                self._record_audit("SERVER_DISCOVER", "probe", "none", method, "SUCCESS", res)
                return self._pack_success(req_id, res) if not is_notification else None

            # Route 2: MCP initialize handshake
            if method == "initialize":
                res = self.handshake.handle_initialize(params)
                client_name = params.get("clientInfo", {}).get("name", "unknown")
                self._record_audit("INITIALIZE", client_name, "none", method, "SUCCESS", {"clientInfo": params.get("clientInfo")})
                return self._pack_success(req_id, res) if not is_notification else None

            # Route 3: MCP notifications/initialized
            if method == "notifications/initialized":
                self.handshake.handle_initialized_notification()
                self._record_audit("INITIALIZED", "system", "none", method, "SUCCESS", {})
                return None  # Notifications MUST NOT receive a response

            # Route 4: MCP ping
            if method == "ping":
                return self._pack_success(req_id, {}) if not is_notification else None

            # All subsequent methods require OPERATIONAL lifecycle state
            self.handshake.assert_operational(method)

            # Authenticate and Authorize Security Context (HMAC + QoS)
            sec_ctx = verify_request_security_context(
                params=params,
                method=method,
                config=self.config,
                traffic_mgr=self.traffic_mgr,
            )
            principal_id = sec_ctx.principal_id
            tenant_id = sec_ctx.tenant_id

            # Route 5: tools/list
            if method == "tools/list":
                authorized_tools = self.tools.list_authorized_tools(sec_ctx)
                res = {"tools": authorized_tools}
                self._record_audit("TOOLS_LIST", principal_id, tenant_id, method, "SUCCESS", {"toolCount": len(authorized_tools)})
                return self._pack_success(req_id, res) if not is_notification else None

            # Route 6: tools/call
            if method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments") or {}

                if not tool_name or not isinstance(tool_name, str):
                    raise LumenRpcError(
                        JsonRpcErrorCode.INVALID_PARAMS,
                        "Missing or invalid 'name' in tools/call params.",
                    )

                tool_result = self.tools.execute_tool(
                    name=tool_name,
                    arguments=tool_args,
                    sec_ctx=sec_ctx,
                )

                # Format MCP CallToolResult
                is_input_required = tool_result.get("resultType") == "input_required"
                is_error = tool_result.get("isError", False)
                res = {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(tool_result, separators=(",", ":")),
                        }
                    ],
                    "isError": is_error,
                    "structured": tool_result,
                }
                status_label = "INPUT_REQUIRED" if is_input_required else "SUCCESS"
                self._record_audit(f"TOOL_CALL:{tool_name}", principal_id, tenant_id, method, status_label, {
                    "tool": tool_name,
                    "resultType": tool_result.get("resultType", "complete"),
                    "approvalMode": tool_result.get("approvalMode"),
                })
                return self._pack_success(req_id, res) if not is_notification else None

            # Unknown Method
            raise LumenRpcError(
                JsonRpcErrorCode.METHOD_NOT_FOUND,
                f"Method '{method}' not recognized by Lumen v2.0 Gateway.",
            )

        except LumenRpcError as lre:
            self._record_audit("RPC_ERROR", principal_id, tenant_id, method, f"ERR_{lre.code}", {"message": lre.message, "data": lre.data})
            return self._pack_error(req_id, lre.code, lre.message, lre.data)
        except FrameTooLargeError as fle:
            self._record_audit("FRAME_ERROR", principal_id, tenant_id, method, "ERR_FRAME_TOO_LARGE", {"message": str(fle)})
            return self._pack_error(req_id, JsonRpcErrorCode.ERR_FRAME_TOO_LARGE, str(fle), {})
        except Exception as exc:
            self._record_audit("INTERNAL_ERROR", principal_id, tenant_id, method, "ERR_INTERNAL", {"exception": str(exc)})
            return self._pack_error(req_id, JsonRpcErrorCode.INTERNAL_ERROR, f"Internal server error: {str(exc)}", {})

    def _pack_success(self, req_id: Any, result: Any) -> bytes:
        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }
        return (json.dumps(resp, separators=(",", ":")) + "\n").encode("utf-8")

    def _pack_error(self, req_id: Any, code: int, message: str, data: Optional[Dict[str, Any]] = None) -> bytes:
        err_obj: Dict[str, Any] = {"code": code, "message": message}
        if data:
            err_obj["data"] = data
        resp = {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err_obj,
        }
        return (json.dumps(resp, separators=(",", ":")) + "\n").encode("utf-8")

    def _record_audit(
        self,
        event: str,
        principal_id: str,
        tenant_id: str,
        method: str,
        status: str,
        details: Dict[str, Any],
    ) -> None:
        self.audit_logger.log(
            event=event,
            principal_id=principal_id,
            tenant_id=tenant_id,
            method=method,
            status=status,
            details=details,
        )


# -----------------------------------------------------------------------------
# Asyncio Byte-Stream Protocol
# -----------------------------------------------------------------------------
class LumenByteStreamProtocol(asyncio.Protocol):
    """Asyncio TCP / stdio streaming protocol implementation."""

    def __init__(self, dispatcher: LumenJsonRpcDispatcher) -> None:
        self.dispatcher = dispatcher
        self.framer = LumenByteStreamFramer(max_frame_bytes=dispatcher.config.max_frame_bytes)
        self.transport: Optional[asyncio.BaseTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        # Optimize local socket: disable Nagle's algorithm for sub-millisecond response
        sock = transport.get_extra_info("socket")
        if sock is not None and hasattr(socket, "TCP_NODELAY"):
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

    def data_received(self, data: bytes) -> None:
        try:
            frames = self.framer.feed(data)
            for frame in frames:
                response = self.dispatcher.handle_raw_payload(frame)
                if response and self.transport and not self.transport.is_closing():
                    if hasattr(self.transport, "write"):
                        self.transport.write(response)  # type: ignore[attr-defined]
        except FrameTooLargeError as fle:
            err_resp = self.dispatcher._pack_error(
                None,
                JsonRpcErrorCode.ERR_FRAME_TOO_LARGE,
                str(fle),
            )
            if self.transport and hasattr(self.transport, "write"):
                self.transport.write(err_resp)  # type: ignore[attr-defined]

    def connection_lost(self, exc: Optional[Exception]) -> None:
        self.transport = None


# -----------------------------------------------------------------------------
# 14-Gate Self-Test & 500-Iteration Microsecond Benchmark Suite
# -----------------------------------------------------------------------------
def run_selftest_and_benchmark(quiet_audit: bool = True) -> Dict[str, Any]:
    """
    Executes the 14-Gate Verification Matrix and 500-Iteration Performance Benchmark.
    Returns comprehensive verification and percentile metrics.
    """
    t_start = time.perf_counter()
    audit_logger = AuditLogger(emit_to_stderr=not quiet_audit)
    config = LumenConfig()
    dispatcher = LumenJsonRpcDispatcher(config=config, audit_logger=audit_logger)

    results: List[Dict[str, Any]] = []

    def log_gate(gate_num: int, title: str, passed: bool, details: Dict[str, Any]) -> None:
        results.append({
            "gate": gate_num,
            "title": title,
            "passed": passed,
            "details": details,
        })
        if not passed:
            raise RuntimeError(f"Verification GATE {gate_num} FAILED: {title} | Details: {details}")

    # Helper: build signed request
    def build_request(
        req_id: Any,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        principal_id: str = "principal-lead-secops",
        tenant_id: str = "tenant-alpha",
        clearance: ClearanceLevel = ClearanceLevel.RESTRICTED,
        scopes: Optional[List[str]] = None,
        priority: TrafficPriority = TrafficPriority.NORMAL,
        skew_offset_ns: int = 0,
        tamper_sig: bool = False,
    ) -> bytes:
        p = dict(params or {})
        now_ns = time.time_ns() + skew_offset_ns
        scopes_list = scopes if scopes is not None else ["records:read", "records:read:pii", "finance:payout"]
        scopes_csv = ",".join(sorted(scopes_list))

        canonical = (
            f"{principal_id}|{tenant_id}|{clearance.name.upper()}|"
            f"{scopes_csv}|{priority.name.upper()}|{now_ns}|{method}"
        )
        sig = compute_request_hmac(config.hmac_secret, canonical)
        if tamper_sig:
            sig = "0" * 64

        p["_meta"] = {
            "lumen.security": {
                "principalId": principal_id,
                "tenantId": tenant_id,
                "clearance": clearance.name,
                "scopes": scopes_list,
                "priority": priority.name,
                "timestampNs": now_ns,
                "signature": sig,
            }
        }
        obj = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": p}
        return (json.dumps(obj) + "\n").encode("utf-8")

    # -------------------------------------------------------------------------
    # GATE 1: Pre-Init Tool Call Blocked (-32001)
    # -------------------------------------------------------------------------
    raw_req = build_request(1, "tools/list")
    resp_raw = dispatcher.handle_raw_payload(raw_req)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    gate1_pass = resp.get("error", {}).get("code") == JsonRpcErrorCode.ERR_UNINITIALIZED_SESSION
    log_gate(1, "Pre-Init Tool Call Blocked (-32001)", gate1_pass, {"errorCode": resp.get("error", {}).get("code")})

    # -------------------------------------------------------------------------
    # GATE 2: Stateless server/discover Probe
    # -------------------------------------------------------------------------
    disc_req = (json.dumps({"jsonrpc": "2.0", "id": 2, "method": "server/discover"}) + "\n").encode("utf-8")
    resp_raw = dispatcher.handle_raw_payload(disc_req)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    gate2_pass = (
        resp.get("result", {}).get("protocolVersion") == "2026-07-28"
        and resp.get("result", {}).get("status") == "HEALTHY"
        and dispatcher.handshake.state == LifecycleState.UNINITIALIZED
    )
    log_gate(2, "Stateless server/discover Probe", gate2_pass, {"protocolVersion": resp.get("result", {}).get("protocolVersion")})

    # -------------------------------------------------------------------------
    # GATE 3: Rogue Client Attestation Blocked (-32003)
    # -------------------------------------------------------------------------
    rogue_init = (json.dumps({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "initialize",
        "params": {"clientInfo": {"name": "unauthorized-malicious-agent"}},
    }) + "\n").encode("utf-8")
    resp_raw = dispatcher.handle_raw_payload(rogue_init)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    gate3_pass = resp.get("error", {}).get("code") == JsonRpcErrorCode.ERR_ZERO_TRUST_AUTH_FAILED
    log_gate(3, "Rogue Client Attestation Blocked (-32003)", gate3_pass, {"errorCode": resp.get("error", {}).get("code")})

    # -------------------------------------------------------------------------
    # GATE 4: Valid initialize + notifications/initialized Handshake (via Framer)
    # -------------------------------------------------------------------------
    valid_init_json = json.dumps({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "initialize",
        "params": {
            "protocolVersion": "2026-07-28",
            "clientInfo": {"name": "lumen-selftest-client", "version": "2.0.0"},
        },
    }) + "\n"
    # Feed fragmented into 7-byte chunks
    framer = LumenByteStreamFramer()
    init_bytes = valid_init_json.encode("utf-8")
    extracted_frames: List[bytes] = []
    chunk_size = 7
    for i in range(0, len(init_bytes), chunk_size):
        extracted_frames.extend(framer.feed(init_bytes[i : i + chunk_size]))

    assert len(extracted_frames) == 1
    resp_raw = dispatcher.handle_raw_payload(extracted_frames[0])
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    init_ok = (
        resp.get("result", {}).get("protocolVersion") == "2026-07-28"
        and dispatcher.handshake.state == LifecycleState.INITIALIZING
    )

    # Send notifications/initialized
    init_notif = (json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }) + "\n").encode("utf-8")
    notif_resp = dispatcher.handle_raw_payload(init_notif)
    gate4_pass = init_ok and (notif_resp is None) and (dispatcher.handshake.state == LifecycleState.OPERATIONAL)
    log_gate(4, "Valid initialize Handshake via Fragmented Frames", gate4_pass, {"state": dispatcher.handshake.state.name})

    # -------------------------------------------------------------------------
    # GATE 5: Duplicate initialize Rejected (-32600)
    # -------------------------------------------------------------------------
    dup_init = (json.dumps({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "initialize",
        "params": {"clientInfo": {"name": "lumen-selftest-client"}},
    }) + "\n").encode("utf-8")
    resp_raw = dispatcher.handle_raw_payload(dup_init)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    gate5_pass = resp.get("error", {}).get("code") == JsonRpcErrorCode.INVALID_REQUEST
    log_gate(5, "Duplicate initialize Rejected (-32600)", gate5_pass, {"errorCode": resp.get("error", {}).get("code")})

    # -------------------------------------------------------------------------
    # GATE 6: Scope-Filtered tools/list Discovery
    # -------------------------------------------------------------------------
    # Call with only records:read scope (finance:payout excluded)
    scoped_list_req = build_request(6, "tools/list", scopes=["records:read"], clearance=ClearanceLevel.INTERNAL)
    resp_raw = dispatcher.handle_raw_payload(scoped_list_req)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    tools_returned = resp.get("result", {}).get("tools", [])
    tool_names = [t["name"] for t in tools_returned]
    gate6_pass = ("query_secure_records" in tool_names) and ("execute_vendor_payout" not in tool_names)
    log_gate(6, "Scope-Filtered tools/list Discovery", gate6_pass, {"visibleTools": tool_names})

    # -------------------------------------------------------------------------
    # GATE 7: Authorized query_secure_records with Automatic PII Redaction
    # -------------------------------------------------------------------------
    query_req = build_request(
        7,
        "tools/call",
        params={
            "name": "query_secure_records",
            "arguments": {"department": "FINANCE", "tenantId": "tenant-alpha"},
        },
        clearance=ClearanceLevel.INTERNAL,
        scopes=["records:read"],  # No PII scope
    )
    resp_raw = dispatcher.handle_raw_payload(query_req)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    structured = resp.get("result", {}).get("structured", {})
    records = structured.get("records", [])
    has_redacted_pii = (
        len(records) > 0
        and records[0].get("ssnLast4") == "***REDACTED***"
        and records[0].get("wireRoutingToken") == "***REDACTED***"
        and structured.get("piiRedacted") is True
    )
    log_gate(7, "Authorized Query with Automatic PII Redaction", has_redacted_pii, {
        "recordCount": len(records),
        "sampleSsn": records[0].get("ssnLast4") if records else None,
    })

    # -------------------------------------------------------------------------
    # GATE 8: RESTRICTED Clearance + records:read:pii Unmasked Read
    # -------------------------------------------------------------------------
    unmask_req = build_request(
        8,
        "tools/call",
        params={
            "name": "query_secure_records",
            "arguments": {"department": "FINANCE", "tenantId": "tenant-alpha"},
        },
        clearance=ClearanceLevel.RESTRICTED,
        scopes=["records:read", "records:read:pii"],
    )
    resp_raw = dispatcher.handle_raw_payload(unmask_req)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    structured = resp.get("result", {}).get("structured", {})
    records = structured.get("records", [])
    has_unmasked_pii = (
        len(records) > 0
        and records[0].get("ssnLast4") != "***REDACTED***"
        and structured.get("piiRedacted") is False
    )
    log_gate(8, "RESTRICTED Clearance + PII Unmasked Read", has_unmasked_pii, {
        "unmaskedSsnSample": records[0].get("ssnLast4") if records else None,
    })

    # -------------------------------------------------------------------------
    # GATE 9: Cross-Tenant Access Blocked (-32005) & SQL Injection Blocked (-32007)
    # -------------------------------------------------------------------------
    # 9a: Cross-tenant attempt
    cross_tenant_req = build_request(
        91,
        "tools/call",
        params={
            "name": "query_secure_records",
            "arguments": {"department": "FINANCE", "tenantId": "tenant-beta"},
        },
        tenant_id="tenant-alpha",  # Caller is tenant-alpha, attempting to read tenant-beta
    )
    resp9a_raw = dispatcher.handle_raw_payload(cross_tenant_req)
    assert resp9a_raw is not None
    resp9a = json.loads(resp9a_raw.decode("utf-8"))
    cross_tenant_blocked = resp9a.get("error", {}).get("code") == JsonRpcErrorCode.ERR_RBAC_CLEARANCE_DENIED

    # 9b: SQL Injection attempt
    sqli_req = build_request(
        92,
        "tools/call",
        params={
            "name": "query_secure_records",
            "arguments": {
                "department": "FINANCE",
                "tenantId": "tenant-alpha",
                "filterQuery": "UNION SELECT * FROM credentials; --",
            },
        },
    )
    resp9b_raw = dispatcher.handle_raw_payload(sqli_req)
    assert resp9b_raw is not None
    resp9b = json.loads(resp9b_raw.decode("utf-8"))
    sqli_blocked = resp9b.get("error", {}).get("code") == JsonRpcErrorCode.ERR_INJECTION_DETECTED

    gate9_pass = cross_tenant_blocked and sqli_blocked
    log_gate(9, "Cross-Tenant Blocked & SQLi Blocked", gate9_pass, {
        "crossTenantCode": resp9a.get("error", {}).get("code"),
        "sqliCode": resp9b.get("error", {}).get("code"),
    })

    # -------------------------------------------------------------------------
    # GATE 10: Low-Value Vendor Payout ($450.00 <= $1000.00) Auto-Executed
    # -------------------------------------------------------------------------
    payout_low = build_request(
        10,
        "tools/call",
        params={
            "name": "execute_vendor_payout",
            "arguments": {
                "vendorId": "VEND-AWS-001",
                "invoiceId": "INV-2026-9041",
                "amountUsd": 450.00,
                "purpose": "Cloud compute staging subscription",
            },
        },
        clearance=ClearanceLevel.CONFIDENTIAL,
        scopes=["finance:payout"],
    )
    resp_raw = dispatcher.handle_raw_payload(payout_low)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    struct_payout = resp.get("result", {}).get("structured", {})
    gate10_pass = (
        struct_payout.get("resultType") == "complete"
        and struct_payout.get("approvalMode") == "AUTO_POLICY_UNDER_THRESHOLD"
        and struct_payout.get("status") == "SETTLED"
    )
    log_gate(10, "Low-Value Payout Auto-Executed ($450.00)", gate10_pass, {
        "approvalMode": struct_payout.get("approvalMode"),
        "payoutId": struct_payout.get("payoutId"),
    })

    # -------------------------------------------------------------------------
    # GATE 11: High-Value Vendor Payout ($18,500.00) Paused (HITL) & Settled
    # -------------------------------------------------------------------------
    # 11a: Initial high-value payout request (elicitation pause expected)
    payout_high = build_request(
        111,
        "tools/call",
        params={
            "name": "execute_vendor_payout",
            "arguments": {
                "vendorId": "VEND-AWS-GLOBAL",
                "invoiceId": "INV-2026-EXECUTIVE-88",
                "amountUsd": 18500.00,
                "purpose": "Hardware rack delivery settlement",
            },
        },
        clearance=ClearanceLevel.CONFIDENTIAL,
        scopes=["finance:payout"],
    )
    resp_raw = dispatcher.handle_raw_payload(payout_high)
    assert resp_raw is not None
    resp = json.loads(resp_raw.decode("utf-8"))
    struct_hitl = resp.get("result", {}).get("structured", {})
    paused_ok = (
        struct_hitl.get("resultType") == "input_required"
        and struct_hitl.get("approvalMode") == "HITL_EXECUTIVE_APPROVAL_REQUIRED"
        and bool(struct_hitl.get("requestState"))
    )
    request_state = struct_hitl.get("requestState")

    # 11b: Retry with invalid MFA code -> must be rejected with -32009
    payout_bad_mfa = build_request(
        112,
        "tools/call",
        params={
            "name": "execute_vendor_payout",
            "arguments": {
                "vendorId": "VEND-AWS-GLOBAL",
                "invoiceId": "INV-2026-EXECUTIVE-88",
                "amountUsd": 18500.00,
                "purpose": "Hardware rack delivery settlement",
                "requestState": request_state,
                "inputResponses": {
                    "approverRole": "CFO",
                    "mfaCode": "BAD-MFA-000",
                },
            },
        },
        clearance=ClearanceLevel.CONFIDENTIAL,
        scopes=["finance:payout"],
    )
    resp_bad_mfa = dispatcher.handle_raw_payload(payout_bad_mfa)
    assert resp_bad_mfa is not None
    resp_bad = json.loads(resp_bad_mfa.decode("utf-8"))
    bad_mfa_blocked = resp_bad.get("error", {}).get("code") == JsonRpcErrorCode.ERR_HITL_APPROVAL_INVALID

    # 11c: Retry with valid MFA and executive approval -> settles
    payout_valid_mfa = build_request(
        113,
        "tools/call",
        params={
            "name": "execute_vendor_payout",
            "arguments": {
                "vendorId": "VEND-AWS-GLOBAL",
                "invoiceId": "INV-2026-EXECUTIVE-88",
                "amountUsd": 18500.00,
                "purpose": "Hardware rack delivery settlement",
                "requestState": request_state,
                "inputResponses": {
                    "approverRole": "CFO",
                    "mfaCode": "LUMEN-MFA-2026-OK",
                },
            },
        },
        clearance=ClearanceLevel.CONFIDENTIAL,
        scopes=["finance:payout"],
    )
    resp_valid = dispatcher.handle_raw_payload(payout_valid_mfa)
    assert resp_valid is not None
    resp_good = json.loads(resp_valid.decode("utf-8"))
    struct_settled = resp_good.get("result", {}).get("structured", {})
    settled_ok = (
        struct_settled.get("resultType") == "complete"
        and struct_settled.get("approvalMode") == "HITL_EXECUTIVE_MFA"
        and struct_settled.get("status") == "SETTLED"
    )

    gate11_pass = paused_ok and bad_mfa_blocked and settled_ok
    log_gate(11, "High-Value Payout HITL Elicitation & MFA Settle", gate11_pass, {
        "pausedOk": paused_ok,
        "badMfaBlocked": bad_mfa_blocked,
        "settledOk": settled_ok,
    })

    # -------------------------------------------------------------------------
    # GATE 12: Priority Traffic Manager (QoS Rate Limiter & Preemption)
    # -------------------------------------------------------------------------
    # LOW priority bucket has 5.0 tokens (10.0 * 0.5)
    runaway_principal = "principal-batch-agent"
    dispatcher.traffic_mgr.reset_bucket(runaway_principal, TrafficPriority.LOW)
    dispatcher.traffic_mgr.reset_bucket(runaway_principal, TrafficPriority.CRITICAL)

    low_throttled = False
    for i in range(7):
        req = build_request(
            120 + i,
            "tools/list",
            principal_id=runaway_principal,
            priority=TrafficPriority.LOW,
        )
        r_raw = dispatcher.handle_raw_payload(req)
        assert r_raw is not None
        r = json.loads(r_raw.decode("utf-8"))
        if r.get("error", {}).get("code") == JsonRpcErrorCode.ERR_RATE_LIMIT_EXCEEDED:
            low_throttled = True
            break

    # Send CRITICAL priority request with the same principal (should immediately pass!)
    crit_req = build_request(
        129,
        "tools/list",
        principal_id=runaway_principal,
        priority=TrafficPriority.CRITICAL,
    )
    crit_raw = dispatcher.handle_raw_payload(crit_req)
    assert crit_raw is not None
    crit_res = json.loads(crit_raw.decode("utf-8"))
    critical_succeeded = "result" in crit_res

    gate12_pass = low_throttled and critical_succeeded
    log_gate(12, "QoS Traffic Manager (Low Throttled & Critical Preempted)", gate12_pass, {
        "lowThrottled": low_throttled,
        "criticalPreempted": critical_succeeded,
    })

    # -------------------------------------------------------------------------
    # GATE 13: Enterprise Python SDK Integration Verification
    # -------------------------------------------------------------------------
    from lumen_sdk import LumenCredentials, LumenEnterpriseClient

    sdk_creds = LumenCredentials(
        principal_id="principal-sdk-operator",
        tenant_id="tenant-alpha",
        clearance=ClearanceLevel.RESTRICTED,
        scopes=["records:read", "records:read:pii", "finance:payout"],
        hmac_secret=config.hmac_secret,
    )
    sdk_dispatcher = LumenJsonRpcDispatcher(config=config, audit_logger=AuditLogger(emit_to_stderr=not quiet_audit))
    sdk_client = LumenEnterpriseClient.in_memory(credentials=sdk_creds, config=config, dispatcher=sdk_dispatcher)

    async def _run_sdk_test() -> bool:
        await sdk_client.connect()
        tools_list = await sdk_client.list_tools()
        query_out = await sdk_client.query_secure_records(department="FINANCE", tenant_id="tenant-alpha")
        payout_out = await sdk_client.execute_vendor_payout(
            vendor_id="VEND-SDK-01",
            invoice_id="INV-SDK-100",
            amount_usd=250.00,
            purpose="SDK Integration test voucher",
        )
        return (
            len(tools_list) >= 2
            and len(query_out.get("records", [])) > 0
            and payout_out.get("status") == "SETTLED"
        )

    sdk_pass = asyncio.run(_run_sdk_test())
    log_gate(13, "Enterprise Python SDK End-to-End Integration", sdk_pass, {"sdkIntegration": "SUCCESS"})

    # -------------------------------------------------------------------------
    # GATE 14: BLAKE2b Hash-Chained Audit Ledger Cryptographic Verification
    # -------------------------------------------------------------------------
    initial_chain_valid = audit_logger.verify_chain_integrity()
    # Tamper with record #2 to verify detection
    tamper_success = audit_logger.tamper_for_test(2)
    tamper_detected = not audit_logger.verify_chain_integrity()
    # Restore entry and verify chain valid again
    audit_logger.restore_tampered_entry(2)
    restored_valid = audit_logger.verify_chain_integrity()

    gate14_pass = initial_chain_valid and tamper_success and tamper_detected and restored_valid
    log_gate(14, "BLAKE2b Hash-Chained Audit Ledger Cryptographic Integrity", gate14_pass, {
        "recordsLogged": audit_logger.count,
        "initialValid": initial_chain_valid,
        "tamperDetected": tamper_detected,
        "restoredValid": restored_valid,
    })

    # -------------------------------------------------------------------------
    # 500-Iteration Microsecond Benchmark
    # -------------------------------------------------------------------------
    iterations = 500
    latencies_us: List[float] = []

    # Prepare signed query frame
    bench_payload = build_request(
        999,
        "tools/call",
        params={
            "name": "query_secure_records",
            "arguments": {"department": "FINANCE", "tenantId": "tenant-alpha"},
        },
    )

    for i in range(iterations):
        t0 = time.perf_counter_ns()
        resp_b = dispatcher.handle_raw_payload(bench_payload)
        t1 = time.perf_counter_ns()
        assert resp_b is not None
        latencies_us.append((t1 - t0) / 1000.0)

    latencies_us.sort()
    p50_us = round(latencies_us[int(iterations * 0.50)], 2)
    p95_us = round(latencies_us[int(iterations * 0.95)], 2)
    p99_us = round(latencies_us[int(iterations * 0.99)], 2)
    min_us = round(latencies_us[0], 2)
    max_us = round(latencies_us[-1], 2)
    mean_us = round(sum(latencies_us) / len(latencies_us), 2)
    sub_ms_sla = p99_us < 1000.0

    t_end = time.perf_counter()

    return {
        "status": "ALL_14_VERIFICATION_GATES_PASSED",
        "subMillisecondSlaMet": sub_ms_sla,
        "totalDurationSec": round(t_end - t_start, 3),
        "auditLedgerRecords": audit_logger.count,
        "benchmark": {
            "iterations": iterations,
            "minLatencyUs": min_us,
            "meanLatencyUs": mean_us,
            "p50LatencyUs": p50_us,
            "p95LatencyUs": p95_us,
            "p99LatencyUs": p99_us,
            "maxLatencyUs": max_us,
            "subMillisecondSlaMet": sub_ms_sla,
        },
        "gates": results,
    }


# -----------------------------------------------------------------------------
# CLI Entrypoint
# -----------------------------------------------------------------------------
def run_stdio_server() -> None:
    """Run pure stdio JSON-RPC 2.0 streaming gateway."""
    dispatcher = LumenJsonRpcDispatcher()
    framer = LumenByteStreamFramer()

    # Read binary chunks from sys.stdin.buffer
    while True:
        chunk = sys.stdin.buffer.read(4096)
        if not chunk:
            break
        try:
            frames = framer.feed(chunk)
            for frame in frames:
                resp = dispatcher.handle_raw_payload(frame)
                if resp:
                    sys.stdout.buffer.write(resp)
                    sys.stdout.buffer.flush()
        except FrameTooLargeError as fle:
            err_resp = dispatcher._pack_error(None, JsonRpcErrorCode.ERR_FRAME_TOO_LARGE, str(fle))
            sys.stdout.buffer.write(err_resp)
            sys.stdout.buffer.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="Lumen v2.0 Enterprise MCP Zero-Trust Gateway")
    parser.add_argument(
        "--mode",
        choices=["selftest", "stdio"],
        default="selftest",
        help="Execution mode (default: selftest)",
    )
    args = parser.parse_args()

    if args.mode == "selftest":
        res = run_selftest_and_benchmark(quiet_audit=True)
        print(json.dumps(res, indent=2))
        if res.get("status") == "ALL_14_VERIFICATION_GATES_PASSED" and res.get("subMillisecondSlaMet"):
            sys.exit(0)
        else:
            sys.exit(1)
    elif args.mode == "stdio":
        run_stdio_server()


if __name__ == "__main__":
    main()
