"""
Lumen v2.0 Enterprise Gateway - Full-Stack HTTP Bridge & Telemetry Server
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Strict Zero-Dependency Implementation (Python >= 3.11 Standard Library only).
Bridges web browser UI to live in-memory LumenJsonRpcDispatcher, telemetry,
cryptographic audit verification, and selftest suite on 127.0.0.1:8080.
"""

from __future__ import annotations

import argparse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import time
from typing import Any, Dict, Optional

from lumen_config import (
    AuditLogger,
    ClearanceLevel,
    LumenConfig,
    PriorityTrafficManager,
    TrafficPriority,
    compute_request_hmac,
)
from lumen_engine import (
    LumenByteStreamFramer,
    LumenJsonRpcDispatcher,
    run_selftest_and_benchmark,
)
from lumen_handshake import LifecycleState


class LumenHttpBridgeHandler(BaseHTTPRequestHandler):
    """Zero-dependency HTTP Handler servicing the Web Console and REST/RPC endpoints."""

    dispatcher: LumenJsonRpcDispatcher
    config: LumenConfig
    console_html_path: str

    # Suppress default noisy access logs on stdout
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?")[0]

        # Route 1: Serve Console HTML
        if path in ("/", "/index.html", "/console"):
            self._serve_console_html()
            return

        # Route 2: Run 14-Gate Self-Test & Benchmark
        if path == "/api/selftest":
            self._handle_selftest()
            return

        # Route 3: Live Telemetry & QoS snapshot
        if path == "/api/telemetry":
            self._handle_telemetry()
            return

        # Route 4: Audit records query
        if path == "/api/audit":
            self._handle_audit_records()
            return

        # 404 Not Found
        self.send_error(HTTPStatus.NOT_FOUND, "Resource not found")

    def do_POST(self) -> None:
        path = self.path.split("?")[0]

        # Route 1: Direct JSON-RPC Dispatcher execution
        if path in ("/api/rpc", "/rpc"):
            self._handle_rpc()
            return

        # Route 2: Cryptographic HMAC signing helper
        if path == "/api/sign":
            self._handle_sign()
            return

        # Route 3: Audit chain tampering simulation
        if path == "/api/audit/tamper":
            self._handle_audit_tamper()
            return

        # Route 4: Audit chain restore
        if path == "/api/audit/restore":
            self._handle_audit_restore()
            return

        # 404 Not Found
        self.send_error(HTTPStatus.NOT_FOUND, "Endpoint not found")

    # -------------------------------------------------------------------------
    # Route Handlers
    # -------------------------------------------------------------------------
    def _serve_console_html(self) -> None:
        if not os.path.exists(self.console_html_path):
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Console HTML file not found at {self.console_html_path}")
            return

        try:
            with open(self.console_html_path, "rb") as f:
                content = f.read()

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(content)
        except Exception as exc:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))

    def _handle_selftest(self) -> None:
        try:
            results = run_selftest_and_benchmark(quiet_audit=True)
            self._send_json(HTTPStatus.OK, results)
        except Exception as exc:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def _handle_telemetry(self) -> None:
        traffic_metrics = self.dispatcher.traffic_mgr.snapshot_metrics()
        chain_valid = self.dispatcher.audit_logger.verify_chain_integrity()

        telemetry = {
            "status": "OPERATIONAL" if self.dispatcher.handshake.is_operational else self.dispatcher.handshake.state.name,
            "serverInfo": {
                "name": self.config.server_name,
                "version": self.config.server_version,
                "protocolVersion": self.config.protocol_version,
                "ecosystem": "Alexa+ Enterprise Ecosystem (Hackathon 2026)",
            },
            "qos": traffic_metrics,
            "audit": {
                "totalRecords": self.dispatcher.audit_logger.count,
                "latestHash": self.dispatcher.audit_logger.latest_hash,
                "chainIntegrityValid": chain_valid,
            },
        }
        self._send_json(HTTPStatus.OK, telemetry)

    def _handle_audit_records(self) -> None:
        records = self.dispatcher.audit_logger.get_records(limit=100)
        chain_valid = self.dispatcher.audit_logger.verify_chain_integrity()
        payload = {
            "records": records,
            "chainIntegrityValid": chain_valid,
            "totalRecords": self.dispatcher.audit_logger.count,
        }
        self._send_json(HTTPStatus.OK, payload)

    def _handle_audit_tamper(self) -> None:
        body = self._read_json_body()
        index = int(body.get("index", 0))
        success = self.dispatcher.audit_logger.tamper_for_test(index)
        chain_valid = self.dispatcher.audit_logger.verify_chain_integrity()
        self._send_json(HTTPStatus.OK, {
            "tampered": success,
            "index": index,
            "chainIntegrityValid": chain_valid,
            "message": f"Simulated adversary tampering on record index {index}. Cryptographic chain broken.",
        })

    def _handle_audit_restore(self) -> None:
        body = self._read_json_body()
        index = int(body.get("index", 0))
        success = self.dispatcher.audit_logger.restore_tampered_entry(index)
        chain_valid = self.dispatcher.audit_logger.verify_chain_integrity()
        self._send_json(HTTPStatus.OK, {
            "restored": success,
            "index": index,
            "chainIntegrityValid": chain_valid,
            "message": f"Cryptographic integrity restored for record index {index}.",
        })

    def _handle_sign(self) -> None:
        body = self._read_json_body()
        principal_id = body.get("principalId", "principal-admin")
        tenant_id = body.get("tenantId", "tenant-alpha")
        clearance = body.get("clearance", "RESTRICTED").upper()
        scopes = body.get("scopes", ["records:read", "records:read:pii", "finance:payout"])
        priority = body.get("priority", "NORMAL").upper()
        timestamp_ns = int(body.get("timestampNs") or time.time_ns())
        method = body.get("method", "tools/call")

        scopes_csv = ",".join(sorted(scopes if isinstance(scopes, list) else [s.strip() for s in scopes.split(",")]))
        canonical = f"{principal_id}|{tenant_id}|{clearance}|{scopes_csv}|{priority}|{timestamp_ns}|{method}"
        sig = compute_request_hmac(self.config.hmac_secret, canonical)

        self._send_json(HTTPStatus.OK, {
            "principalId": principal_id,
            "tenantId": tenant_id,
            "clearance": clearance,
            "scopes": scopes,
            "priority": priority,
            "timestampNs": timestamp_ns,
            "method": method,
            "canonicalString": canonical,
            "signature": sig,
        })

    def _handle_rpc(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_len)

        try:
            req_obj = json.loads(raw_body.decode("utf-8"))
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(exc)}"},
            }
            self._send_json(HTTPStatus.BAD_REQUEST, err_resp)
            return

        # Auto-sign if request has credentials helper block or lacks _meta
        if isinstance(req_obj, dict) and "method" in req_obj:
            method = req_obj.get("method", "")
            params = req_obj.get("params") or {}

            # If UI sends credentials directly without _meta, construct canonical HMAC
            if "_meta" not in params and method not in ("initialize", "server/discover", "notifications/initialized", "ping"):
                auth_info = req_obj.get("callerAuth") or {}
                principal_id = auth_info.get("principalId", "principal-alexa-enterprise")
                tenant_id = auth_info.get("tenantId", "tenant-alpha")
                clearance = auth_info.get("clearance", "RESTRICTED").upper()
                scopes = auth_info.get("scopes", ["records:read", "records:read:pii", "finance:payout"])
                priority = auth_info.get("priority", "NORMAL").upper()
                timestamp_ns = time.time_ns()

                scopes_csv = ",".join(sorted(scopes))
                canonical = f"{principal_id}|{tenant_id}|{clearance}|{scopes_csv}|{priority}|{timestamp_ns}|{method}"
                sig = compute_request_hmac(self.config.hmac_secret, canonical)

                params["_meta"] = {
                    "lumen.security": {
                        "principalId": principal_id,
                        "tenantId": tenant_id,
                        "clearance": clearance,
                        "scopes": scopes,
                        "priority": priority,
                        "timestampNs": timestamp_ns,
                        "signature": sig,
                    }
                }
                req_obj["params"] = params

        # Dispatch via core engine and measure latency
        t0 = time.perf_counter_ns()
        prepared_frame = (json.dumps(req_obj) + "\n").encode("utf-8")
        resp_bytes = self.dispatcher.handle_raw_payload(prepared_frame)
        t1 = time.perf_counter_ns()
        latency_us = round((t1 - t0) / 1000.0, 2)

        if resp_bytes is None:
            # Notification with no content
            self.send_response(HTTPStatus.NO_CONTENT)
            self._send_cors_headers()
            self.end_headers()
            return

        resp_obj = json.loads(resp_bytes.decode("utf-8"))
        self._send_json(
            HTTPStatus.OK,
            resp_obj,
            extra_headers={
                "X-Lumen-Latency-Us": str(latency_us),
                "X-Lumen-Sub-Millisecond": "true" if latency_us < 1000.0 else "false",
            },
        )

    # -------------------------------------------------------------------------
    # Helper Serialization
    # -------------------------------------------------------------------------
    def _read_json_body(self) -> Dict[str, Any]:
        content_len = int(self.headers.get("Content-Length", 0))
        if content_len <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(content_len).decode("utf-8"))
        except Exception:
            return {}

    def _send_json(self, status: int, data: Any, extra_headers: Optional[Dict[str, str]] = None) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._send_cors_headers()
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(payload)


def create_initialized_dispatcher(config: Optional[LumenConfig] = None) -> LumenJsonRpcDispatcher:
    """Creates a dispatcher and completes initial MCP handshake so it is OPERATIONAL out of the box."""
    cfg = config or LumenConfig()
    audit = AuditLogger(emit_to_stderr=True)
    dispatcher = LumenJsonRpcDispatcher(config=cfg, audit_logger=audit)

    # Pre-initialize into OPERATIONAL state for immediate UI readiness
    init_req = (json.dumps({
        "jsonrpc": "2.0",
        "id": "bootstrap-init",
        "method": "initialize",
        "params": {
            "protocolVersion": cfg.protocol_version,
            "clientInfo": {"name": "lumen-web-console", "version": "2.0.0"},
        },
    }) + "\n").encode("utf-8")
    dispatcher.handle_raw_payload(init_req)

    notif_req = (json.dumps({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }) + "\n").encode("utf-8")
    dispatcher.handle_raw_payload(notif_req)

    return dispatcher


def run_http_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Launch the HTTP server bridging the console to the live gateway."""
    config = LumenConfig()
    dispatcher = create_initialized_dispatcher(config)

    html_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lumen_console.html")

    # Bind handler class attributes
    LumenHttpBridgeHandler.dispatcher = dispatcher
    LumenHttpBridgeHandler.config = config
    LumenHttpBridgeHandler.console_html_path = html_file

    server = ThreadingHTTPServer((host, port), LumenHttpBridgeHandler)
    print(f"\n==========================================================================")
    print(f"  LUMEN v2.0 ZERO-TRUST MCP GATEWAY & INTERACTIVE OPERATIONS CONSOLE")
    print(f"  Amazon Developer Hackathon 2026 ('Build, Ship, Shape')")
    print(f"==========================================================================")
    print(f"  Web Console URL  : http://{host}:{port}/")
    print(f"  REST / RPC URL   : http://{host}:{port}/api/rpc")
    print(f"  Telemetry URL    : http://{host}:{port}/api/telemetry")
    print(f"  Self-Test URL    : http://{host}:{port}/api/selftest")
    print(f"  Audit Ledger     : http://{host}:{port}/api/audit")
    print(f"  Server State     : OPERATIONAL (Zero-Trust Guardrails Active)")
    print(f"==========================================================================\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Lumen v2.0 HTTP Bridge...")
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Lumen v2.0 Enterprise HTTP Bridge & Web Console")
    parser.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default: 8080)")
    args = parser.parse_args()

    run_http_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
