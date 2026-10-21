"""
Lumen v2.0 Enterprise Gateway - Custom Client ML Plugin Template
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Demonstrates how enterprise client companies register custom proprietary ML tools
(e.g., Real-time Fraud Detection Model) into the Lumen ToolRegistry with schema
validation, RBAC scoping, clearance ceilings, PII/IP masking, and invokes them
using the installable LumenEnterpriseClient SDK.
"""

from __future__ import annotations

import asyncio
import json
import math
import sys
import time
from typing import Any, Dict

from lumen_config import (
    AuditLogger,
    ClearanceLevel,
    LumenConfig,
    PriorityTrafficManager,
    ToolName,
    TrafficPriority,
)
from lumen_engine import LumenJsonRpcDispatcher
from lumen_handshake import LumenRpcError, SecurityContext
from lumen_sdk import LumenCredentials, LumenEnterpriseClient
from lumen_tools import ToolDefinition, ToolRegistry


# -----------------------------------------------------------------------------
# Proprietary Client ML Fraud Detection Handler
# -----------------------------------------------------------------------------
def handle_run_fraud_detection_model(
    arguments: Dict[str, Any],
    sec_ctx: SecurityContext,
    config: LumenConfig,
) -> Dict[str, Any]:
    """
    Simulated Enterprise ML Fraud Detection Inference Engine.
    Executes sub-millisecond heuristic scoring with automatic IP masking
    based on caller security clearance.
    """
    t0_ns = time.perf_counter_ns()
    tenant_id = arguments["tenantId"]
    transaction_id = arguments["transactionId"]
    amount_usd = float(arguments["amountUsd"])
    cardholder_ip = arguments["cardholderIp"]

    # Strict multi-tenant isolation check
    if tenant_id != sec_ctx.tenant_id:
        raise LumenRpcError(
            -32005,
            f"Cross-tenant inference prohibited: caller tenant '{sec_ctx.tenant_id}' cannot execute model on tenant '{tenant_id}' payload.",
        )

    # Heuristic scoring simulation
    base_score = min(0.95, amount_usd / 25000.0)
    ip_risk = 0.25 if not (cardholder_ip.startswith("192.168.") or cardholder_ip.startswith("10.")) else 0.04
    fraud_score = round(min(0.99, base_score + ip_risk), 3)

    if fraud_score < 0.35:
        verdict = "ALLOW"
        recommendation = "Low risk transaction. Auto-approved."
    elif fraud_score < 0.70:
        verdict = "CHALLENGE_STEP_UP"
        recommendation = "Moderate risk. Require secondary voice verification or SMS OTP."
    else:
        verdict = "BLOCK_DECLINE"
        recommendation = "High risk anomaly detected. Block transaction and trigger SecOps alert."

    # Sensitive PII / IP Address Masking Policy:
    # Cardholder IP is visible only to RESTRICTED clearance callers; masked for CONFIDENTIAL
    if sec_ctx.clearance >= ClearanceLevel.RESTRICTED:
        masked_ip = cardholder_ip
        ip_masked = False
    else:
        masked_ip = "***.***.***.REDACTED"
        ip_masked = True

    t1_ns = time.perf_counter_ns()
    inference_latency_us = round((t1_ns - t0_ns) / 1000.0, 2)

    return {
        "resultType": "complete",
        "modelName": "Alexa-Enterprise-FraudNet-v4",
        "modelVersion": "2026.4.1-rc2",
        "transactionId": transaction_id,
        "tenantId": tenant_id,
        "fraudScore": fraud_score,
        "verdict": verdict,
        "recommendation": recommendation,
        "cardholderIp": masked_ip,
        "ipAddressMasked": ip_masked,
        "callerClearance": sec_ctx.clearance.name,
        "inferenceLatencyUs": inference_latency_us,
    }


# -----------------------------------------------------------------------------
# Demo Runner
# -----------------------------------------------------------------------------
async def run_custom_plugin_demo() -> Dict[str, Any]:
    # 1. Setup Custom Gateway Instance with ToolRegistry
    config = LumenConfig()
    tool_registry = ToolRegistry(config)

    # 2. Register Client ML Model into Registry
    fraud_model_tool = ToolDefinition(
        name=ToolName("run_fraud_detection_model"),
        description="Proprietary Enterprise ML inference tool assessing transaction fraud risk and velocity anomalies.",
        input_schema={
            "type": "object",
            "properties": {
                "tenantId": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 64,
                },
                "transactionId": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 64,
                },
                "amountUsd": {
                    "type": "number",
                    "minimum": 0.01,
                    "maximum": 1000000.00,
                },
                "cardholderIp": {
                    "type": "string",
                    "minLength": 7,
                    "maxLength": 45,
                },
            },
            "required": ["tenantId", "transactionId", "amountUsd", "cardholderIp"],
            "additionalProperties": False,
        },
        required_scope="ml:fraud:score",
        min_clearance=ClearanceLevel.CONFIDENTIAL,
        handler=handle_run_fraud_detection_model,
    )
    tool_registry.register(fraud_model_tool)

    # 3. Create Dispatcher sharing the custom tool registry
    audit_logger = AuditLogger(emit_to_stderr=False)
    dispatcher = LumenJsonRpcDispatcher(
        config=config,
        audit_logger=audit_logger,
        tool_registry=tool_registry,
    )

    # 4. Test Case A: Confidential Operator (IP address masked)
    creds_confidential = LumenCredentials(
        principal_id="principal-fraud-analyst-01",
        tenant_id="tenant-alpha",
        clearance=ClearanceLevel.CONFIDENTIAL,
        scopes=["ml:fraud:score"],
        hmac_secret=config.hmac_secret,
    )
    dispatcher_a = LumenJsonRpcDispatcher(config=config, audit_logger=audit_logger, tool_registry=tool_registry)
    client_a = LumenEnterpriseClient.in_memory(
        credentials=creds_confidential,
        config=config,
        dispatcher=dispatcher_a,
    )
    await client_a.connect()

    # Call custom ML tool via SDK
    res_a_call = await client_a._send_request(
        method="tools/call",
        params={
            "name": "run_fraud_detection_model",
            "arguments": {
                "tenantId": "tenant-alpha",
                "transactionId": "TX-99042-US",
                "amountUsd": 1420.50,
                "cardholderIp": "198.51.100.42",
            },
        },
        priority=TrafficPriority.HIGH,
    )
    res_a = res_a_call.get("structured", {})

    # 5. Test Case B: Restricted SecOps Officer (IP address unmasked)
    creds_restricted = LumenCredentials(
        principal_id="principal-secops-director",
        tenant_id="tenant-alpha",
        clearance=ClearanceLevel.RESTRICTED,
        scopes=["ml:fraud:score"],
        hmac_secret=config.hmac_secret,
    )
    dispatcher_b = LumenJsonRpcDispatcher(config=config, audit_logger=audit_logger, tool_registry=tool_registry)
    client_b = LumenEnterpriseClient.in_memory(
        credentials=creds_restricted,
        config=config,
        dispatcher=dispatcher_b,
    )
    await client_b.connect()

    res_b_call = await client_b._send_request(
        method="tools/call",
        params={
            "name": "run_fraud_detection_model",
            "arguments": {
                "tenantId": "tenant-alpha",
                "transactionId": "TX-99043-INTL",
                "amountUsd": 18500.00,
                "cardholderIp": "203.0.113.88",
            },
        },
        priority=TrafficPriority.CRITICAL,
    )
    res_b = res_b_call.get("structured", {})

    # 6. Test Case C: Unauthorized Client (Lacking required_scope -> Rejected)
    creds_unauthorized = LumenCredentials(
        principal_id="principal-guest-user",
        tenant_id="tenant-alpha",
        clearance=ClearanceLevel.CONFIDENTIAL,
        scopes=["records:read"],  # Missing ml:fraud:score!
        hmac_secret=config.hmac_secret,
    )
    dispatcher_c = LumenJsonRpcDispatcher(config=config, audit_logger=audit_logger, tool_registry=tool_registry)
    client_c = LumenEnterpriseClient.in_memory(
        credentials=creds_unauthorized,
        config=config,
        dispatcher=dispatcher_c,
    )
    await client_c.connect()

    rbac_blocked = False
    try:
        await client_c._send_request(
            method="tools/call",
            params={
                "name": "run_fraud_detection_model",
                "arguments": {
                    "tenantId": "tenant-alpha",
                    "transactionId": "TX-ILLEGAL",
                    "amountUsd": 10.0,
                    "cardholderIp": "127.0.0.1",
                },
            },
            priority=TrafficPriority.NORMAL,
        )
    except LumenRpcError as exc:
        if exc.code == -32005:
            rbac_blocked = True

    # Validate Assertions
    passed_masking = (res_a.get("cardholderIp") == "***.***.***.REDACTED") and (res_a.get("ipAddressMasked") is True)
    passed_unmasked = (res_b.get("cardholderIp") == "203.0.113.88") and (res_b.get("ipAddressMasked") is False)
    all_passed = passed_masking and passed_unmasked and rbac_blocked

    return {
        "customPluginDemo": "SUCCESS" if all_passed else "FAILED",
        "registeredTool": "run_fraud_detection_model",
        "testCaseA_Confidential": {
            "transactionId": res_a.get("transactionId"),
            "verdict": res_a.get("verdict"),
            "fraudScore": res_a.get("fraudScore"),
            "cardholderIp": res_a.get("cardholderIp"),
            "ipAddressMasked": res_a.get("ipAddressMasked"),
        },
        "testCaseB_Restricted": {
            "transactionId": res_b.get("transactionId"),
            "verdict": res_b.get("verdict"),
            "fraudScore": res_b.get("fraudScore"),
            "cardholderIp": res_b.get("cardholderIp"),
            "ipAddressMasked": res_b.get("ipAddressMasked"),
        },
        "testCaseC_RbacEnforced": {
            "unauthorizedCallBlocked": rbac_blocked,
            "errorCode": -32005,
        },
    }


def main() -> None:
    result = asyncio.run(run_custom_plugin_demo())
    print(json.dumps(result, indent=2))
    if result.get("customPluginDemo") == "SUCCESS":
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
