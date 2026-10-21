"""
Lumen v2.0 Enterprise Gateway - JSON Schema 2020-12, Injection Firewall & Enterprise Tools
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Strict Zero-Dependency Implementation (Python >= 3.11 Standard Library only).
Sub-millisecond input validation, lexical AST-free firewall, tenant-isolated DB tool,
and HITL financial elicitation tool.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import re
import time
from typing import Any, Callable, Dict, List, Optional, Pattern, Set, Tuple

from lumen_config import (
    ClearanceLevel,
    JsonRpcErrorCode,
    LumenConfig,
    PrincipalId,
    TenantId,
    ToolName,
)
from lumen_handshake import LumenRpcError, SecurityContext

# -----------------------------------------------------------------------------
# Zero-Dependency JSON Schema 2020-12 Validator
# -----------------------------------------------------------------------------
def validate_against_schema(instance: Any, schema: Dict[str, Any], path: str = "$") -> None:
    """
    Sub-microsecond JSON Schema validator enforcing:
      - strict primitive type checking (disallowing bool for int/float)
      - required fields presence
      - additionalProperties: false
      - string minLength, maxLength, pattern, enum
      - numeric minimum, maximum
      - array maxItems, items
    Raises LumenRpcError(ERR_SCHEMA_GUARDRAIL_VIOLATION) on any violation.
    """
    expected_type = schema.get("type")

    # Primitive type validation
    if expected_type is not None:
        if expected_type == "object":
            if not isinstance(instance, dict):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: expected object, got {type(instance).__name__}.",
                )
        elif expected_type == "array":
            if not isinstance(instance, (list, tuple)):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: expected array, got {type(instance).__name__}.",
                )
        elif expected_type == "string":
            if not isinstance(instance, str):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: expected string, got {type(instance).__name__}.",
                )
        elif expected_type == "integer":
            # Python bool is a subclass of int (isinstance(True, int) is True), explicitly reject!
            if isinstance(instance, bool) or not isinstance(instance, int):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: expected integer, got {type(instance).__name__}.",
                )
        elif expected_type == "number":
            if isinstance(instance, bool) or not isinstance(instance, (int, float)):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: expected number, got {type(instance).__name__}.",
                )
        elif expected_type == "boolean":
            if not isinstance(instance, bool):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: expected boolean, got {type(instance).__name__}.",
                )

    # Object properties & required fields
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        for req_prop in required:
            if req_prop not in instance:
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                    f"Schema violation at {path}: missing required property '{req_prop}'.",
                )

        # Enforce additionalProperties: false
        if schema.get("additionalProperties") is False:
            allowed_keys = set(properties.keys())
            for key in instance:
                if key not in allowed_keys:
                    raise LumenRpcError(
                        JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                        f"Schema violation at {path}: unexpected additional property '{key}' is forbidden.",
                    )

        # Validate sub-properties
        for prop_name, prop_val in instance.items():
            if prop_name in properties:
                validate_against_schema(prop_val, properties[prop_name], f"{path}.{prop_name}")

    # String constraints
    elif isinstance(instance, str):
        min_len = schema.get("minLength")
        if min_len is not None and len(instance) < min_len:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: length {len(instance)} is less than minLength {min_len}.",
            )

        max_len = schema.get("maxLength")
        if max_len is not None and len(instance) > max_len:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: length {len(instance)} exceeds maxLength {max_len}.",
            )

        enum_vals = schema.get("enum")
        if enum_vals is not None and instance not in enum_vals:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: value '{instance}' not in allowed enum {enum_vals}.",
            )

        pattern = schema.get("pattern")
        if pattern is not None and not re.search(pattern, instance):
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: value does not match regex pattern '{pattern}'.",
            )

    # Number constraints
    elif isinstance(instance, (int, float)) and not isinstance(instance, bool):
        min_val = schema.get("minimum")
        if min_val is not None and instance < min_val:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: value {instance} is less than minimum {min_val}.",
            )

        max_val = schema.get("maximum")
        if max_val is not None and instance > max_val:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: value {instance} exceeds maximum {max_val}.",
            )

    # Array constraints
    elif isinstance(instance, (list, tuple)):
        max_items = schema.get("maxItems")
        if max_items is not None and len(instance) > max_items:
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_SCHEMA_GUARDRAIL_VIOLATION,
                f"Schema violation at {path}: array length {len(instance)} exceeds maxItems {max_items}.",
            )

        items_schema = schema.get("items")
        if items_schema is not None:
            for idx, item in enumerate(instance):
                validate_against_schema(item, items_schema, f"{path}[{idx}]")


# -----------------------------------------------------------------------------
# Lexical AST-Free SQLi & Shell Injection Firewall
# -----------------------------------------------------------------------------
_INJECTION_PATTERNS: List[Tuple[Pattern[str], str]] = [
    # SQL Tautologies & Stacked Commands
    (re.compile(r"(?i)\bUNION\s+(?:ALL\s+)?SELECT\b"), "SQL Injection: UNION SELECT"),
    (re.compile(r"(?i)\bDROP\s+TABLE\b"), "SQL Injection: DROP TABLE"),
    (re.compile(r"(?i)\bINSERT\s+INTO\b"), "SQL Injection: INSERT INTO"),
    (re.compile(r"(?i)\bDELETE\s+FROM\b"), "SQL Injection: DELETE FROM"),
    (re.compile(r"(?i)\bUPDATE\s+\w+\s+SET\b"), "SQL Injection: UPDATE SET"),
    (re.compile(r"(?i)\bOR\s+['\"]?1['\"]?\s*=\s*['\"]?1\b"), "SQL Injection: Tautology OR 1=1"),
    (re.compile(r"(?i)\bOR\s+true\b"), "SQL Injection: Tautology OR TRUE"),
    (re.compile(r";\s*--"), "SQL Injection: Stacked Comment"),
    (re.compile(r";\s*(?:DROP|SELECT|INSERT|DELETE|UPDATE|TRUNCATE)\b", re.IGNORECASE), "SQL Injection: Stacked Query"),

    # SQL Comments
    (re.compile(r"--(?:\s+|$|\r|\n)"), "SQL Comment Sequence: --"),
    (re.compile(r"/\*[\s\S]*?\*/"), "SQL Multi-line Comment: /* ... */"),

    # Path Traversal & Null Bytes
    (re.compile(r"(?:\.\./|\.\.\\)"), "Directory Traversal: Relative path escape"),
    (re.compile(r"\x00"), "Null Byte Injection"),

    # Shell Metacharacters & Subcommands
    (re.compile(r"\$\([^\)]*\)"), "Shell Command Substitution: $(...)"),
    (re.compile(r"`[^`]*`"), "Shell Command Backticks: `...`"),
    (re.compile(r"(?:;|\|\||&&)\s*(?:rm|cat|curl|wget|bash|sh|powershell|cmd)\b", re.IGNORECASE), "Shell Command Chaining"),
    (re.compile(r"\|\s*(?:rm|cat|curl|wget|bash|sh)\b", re.IGNORECASE), "Shell Pipeline Injection"),
]


def inspect_string_for_injection(value: Any, param_name: str = "arg") -> None:
    """
    Recursively scans strings and container items against high-entropy
    SQLi, Path Traversal, and Shell Injection patterns.
    Raises LumenRpcError(ERR_INJECTION_DETECTED) immediately upon detection.
    """
    if isinstance(value, str):
        for pattern, desc in _INJECTION_PATTERNS:
            match = pattern.search(value)
            if match:
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_INJECTION_DETECTED,
                    f"Malicious payload intercepted in '{param_name}': {desc}.",
                    data={"patternMatched": match.group(0), "category": desc, "param": param_name},
                )
    elif isinstance(value, dict):
        for k, v in value.items():
            inspect_string_for_injection(k, f"{param_name}.<key>")
            inspect_string_for_injection(v, f"{param_name}.{k}")
    elif isinstance(value, (list, tuple)):
        for idx, item in enumerate(value):
            inspect_string_for_injection(item, f"{param_name}[{idx}]")


# -----------------------------------------------------------------------------
# Enterprise Mock Database Records
# -----------------------------------------------------------------------------
_MOCK_ENTERPRISE_RECORDS: List[Dict[str, Any]] = [
    {
        "recordId": "REC-FIN-001",
        "tenantId": "tenant-alpha",
        "department": "FINANCE",
        "title": "Q3 Corporate Earnings Audit",
        "classification": ClearanceLevel.INTERNAL,
        "employeeName": "Alice Vance",
        "ssnLast4": "4829",
        "wireRoutingToken": "ROUT-9921-US",
        "amount": 1450000.00,
    },
    {
        "recordId": "REC-FIN-002",
        "tenantId": "tenant-alpha",
        "department": "FINANCE",
        "title": "Mergers & Acquisitions Confidential Target Brief",
        "classification": ClearanceLevel.CONFIDENTIAL,
        "employeeName": "Marcus Sterling",
        "ssnLast4": "1194",
        "wireRoutingToken": "ROUT-3388-CH",
        "amount": 28000000.00,
    },
    {
        "recordId": "REC-FIN-003",
        "tenantId": "tenant-alpha",
        "department": "FINANCE",
        "title": "Executive Compensations & Cayman Holding Trust",
        "classification": ClearanceLevel.RESTRICTED,
        "employeeName": "Elena Rostova",
        "ssnLast4": "9812",
        "wireRoutingToken": "ROUT-7714-KY",
        "amount": 8200000.00,
    },
    {
        "recordId": "REC-ENG-001",
        "tenantId": "tenant-alpha",
        "department": "ENGINEERING",
        "title": "Alexa+ Distributed Core Architecture Spec",
        "classification": ClearanceLevel.INTERNAL,
        "employeeName": "David K.",
        "ssnLast4": "3045",
        "wireRoutingToken": "ROUT-1100-US",
        "amount": 0.00,
    },
    {
        "recordId": "REC-HR-001",
        "tenantId": "tenant-alpha",
        "department": "HR",
        "title": "Annual Executive Performance Reviews",
        "classification": ClearanceLevel.CONFIDENTIAL,
        "employeeName": "Sarah Jenkins",
        "ssnLast4": "7721",
        "wireRoutingToken": "ROUT-4455-US",
        "amount": 0.00,
    },
    # Tenant Beta Record (Cross-Tenant Isolation Test)
    {
        "recordId": "REC-FIN-BETA-001",
        "tenantId": "tenant-beta",
        "department": "FINANCE",
        "title": "Tenant Beta Secret Liquidity Pool",
        "classification": ClearanceLevel.RESTRICTED,
        "employeeName": "Bob Beta",
        "ssnLast4": "9999",
        "wireRoutingToken": "ROUT-9999-EU",
        "amount": 9999999.00,
    },
]


# -----------------------------------------------------------------------------
# Tool Definition & Registry
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class ToolDefinition:
    name: ToolName
    description: str
    input_schema: Dict[str, Any]
    required_scope: str
    min_clearance: ClearanceLevel
    handler: Callable[[Dict[str, Any], SecurityContext, LumenConfig], Dict[str, Any]]

    def to_mcp_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class ToolRegistry:
    """Registry managing available zero-trust enterprise tools."""

    def __init__(self, config: LumenConfig) -> None:
        self.config = config
        self._tools: Dict[ToolName, ToolDefinition] = {}
        self._register_default_tools()

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        return self._tools.get(ToolName(name))

    def list_authorized_tools(self, sec_ctx: SecurityContext) -> List[Dict[str, Any]]:
        """
        Scope-filtered tool discovery: returns only tools where the caller has
        the required scope AND clearance ceiling.
        """
        visible: List[Dict[str, Any]] = []
        for tool in self._tools.values():
            if sec_ctx.has_scope(tool.required_scope) and sec_ctx.has_clearance(tool.min_clearance):
                visible.append(tool.to_mcp_dict())
        return visible

    def execute_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        sec_ctx: SecurityContext,
    ) -> Dict[str, Any]:
        """Validate, inspect, authorize, and execute a tool."""
        tool = self.get(name)
        if not tool:
            raise LumenRpcError(
                JsonRpcErrorCode.METHOD_NOT_FOUND,
                f"Unknown tool '{name}'. Available authorized tools can be queried via tools/list.",
            )

        # 1. RBAC Clearance & Scope Checks
        if not sec_ctx.has_scope(tool.required_scope):
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_RBAC_CLEARANCE_DENIED,
                f"RBAC authorization failure: caller missing required scope '{tool.required_scope}' for tool '{name}'.",
                data={"requiredScope": tool.required_scope, "callerScopes": list(sec_ctx.scopes)},
            )

        if not sec_ctx.has_clearance(tool.min_clearance):
            raise LumenRpcError(
                JsonRpcErrorCode.ERR_RBAC_CLEARANCE_DENIED,
                f"Clearance ceiling failure: tool '{name}' requires {tool.min_clearance.name} (level {tool.min_clearance.value}), caller has {sec_ctx.clearance.name} (level {sec_ctx.clearance.value}).",
                data={"minClearance": tool.min_clearance.name, "callerClearance": sec_ctx.clearance.name},
            )

        # 2. Lexical Injection Firewall
        inspect_string_for_injection(arguments, param_name="arguments")

        # 3. JSON Schema 2020-12 Validation
        validate_against_schema(arguments, tool.input_schema, path="arguments")

        # 4. Tool Execution Handler
        return tool.handler(arguments, sec_ctx, self.config)

    def _register_default_tools(self) -> None:
        """Register the built-in enterprise tools."""

        # ---------------------------------------------------------------------
        # Tool #1: query_secure_records (Read-Only Enterprise DB)
        # ---------------------------------------------------------------------
        def handle_query_secure_records(
            args: Dict[str, Any],
            sec_ctx: SecurityContext,
            config: LumenConfig,
        ) -> Dict[str, Any]:
            target_tenant = args["tenantId"]
            department = args["department"]
            filter_query = args.get("filterQuery", "").lower()
            limit = int(args.get("limit", 10))

            # Enforce Strict Multi-Tenant Isolation
            if target_tenant != sec_ctx.tenant_id:
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_RBAC_CLEARANCE_DENIED,
                    f"Cross-tenant access violation: caller tenant '{sec_ctx.tenant_id}' cannot access records belonging to tenant '{target_tenant}'.",
                    data={"callerTenant": sec_ctx.tenant_id, "targetTenant": target_tenant},
                )

            # Check if caller has PII unmasking privileges
            has_pii_access = (
                sec_ctx.has_clearance(ClearanceLevel.RESTRICTED)
                and sec_ctx.has_scope("records:read:pii")
            )

            # Query and filter mock database
            matched_records: List[Dict[str, Any]] = []
            for rec in _MOCK_ENTERPRISE_RECORDS:
                # Multi-tenant boundary
                if rec["tenantId"] != target_tenant:
                    continue
                # Department filter
                if rec["department"] != department:
                    continue
                # Clearance ceiling filter (caller cannot see records classified higher than their clearance)
                if rec["classification"] > sec_ctx.clearance:
                    continue
                # Optional query search
                if filter_query:
                    title_match = filter_query in rec["title"].lower()
                    emp_match = filter_query in rec["employeeName"].lower()
                    if not (title_match or emp_match):
                        continue

                # Prepare record copy with PII redaction policy applied
                out_rec = {
                    "recordId": rec["recordId"],
                    "tenantId": rec["tenantId"],
                    "department": rec["department"],
                    "title": rec["title"],
                    "classification": rec["classification"].name,
                    "employeeName": rec["employeeName"],
                    "amount": rec["amount"],
                    "ssnLast4": rec["ssnLast4"] if has_pii_access else "***REDACTED***",
                    "wireRoutingToken": rec["wireRoutingToken"] if has_pii_access else "***REDACTED***",
                }
                matched_records.append(out_rec)
                if len(matched_records) >= limit:
                    break

            return {
                "records": matched_records,
                "count": len(matched_records),
                "callerTenant": sec_ctx.tenant_id,
                "department": department,
                "piiRedacted": not has_pii_access,
                "clearanceApplied": sec_ctx.clearance.name,
            }

        self.register(
            ToolDefinition(
                name=ToolName("query_secure_records"),
                description="Read-only enterprise database query tool with tenant isolation and PII redaction.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "department": {
                            "type": "string",
                            "enum": ["FINANCE", "ENGINEERING", "HR", "LEGAL", "OPERATIONS"],
                        },
                        "tenantId": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": 64,
                        },
                        "filterQuery": {
                            "type": "string",
                            "maxLength": 256,
                        },
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 100,
                        },
                    },
                    "required": ["department", "tenantId"],
                    "additionalProperties": False,
                },
                required_scope="records:read",
                min_clearance=ClearanceLevel.INTERNAL,
                handler=handle_query_secure_records,
            )
        )

        # ---------------------------------------------------------------------
        # Tool #2: execute_vendor_payout (Mutating Financial Tool with HITL)
        # ---------------------------------------------------------------------
        def handle_execute_vendor_payout(
            args: Dict[str, Any],
            sec_ctx: SecurityContext,
            config: LumenConfig,
        ) -> Dict[str, Any]:
            vendor_id = args["vendorId"]
            invoice_id = args["invoiceId"]
            amount_usd = float(args["amountUsd"])
            purpose = args["purpose"]
            input_responses = args.get("inputResponses")
            request_state = args.get("requestState")

            # Canonical token binding string for state integrity
            canonical_state_binding = (
                f"{sec_ctx.principal_id}|{sec_ctx.tenant_id}|"
                f"{vendor_id}|{invoice_id}|{amount_usd:.2f}"
            )

            # Policy 1: Low-Risk Payouts (<= $1,000.00) Auto-Execute
            if amount_usd <= 1000.00:
                payout_id = f"PAY-{hashlib.sha256(f'{canonical_state_binding}:{time.time_ns()}'.encode()).hexdigest()[:8].upper()}"
                return {
                    "resultType": "complete",
                    "approvalMode": "AUTO_POLICY_UNDER_THRESHOLD",
                    "payoutId": payout_id,
                    "vendorId": vendor_id,
                    "invoiceId": invoice_id,
                    "amountUsd": amount_usd,
                    "status": "SETTLED",
                    "details": f"Autonomous approval: ${amount_usd:,.2f} is within the $1,000.00 auto-execution limit.",
                }

            # Policy 2: High-Risk Payouts (> $1,000.00) Require Human-In-The-Loop Approval
            if not input_responses or not request_state:
                # Generate tamper-resistant requestState binding token
                state_sig = hmac.new(
                    config.hmac_secret.encode("utf-8"),
                    canonical_state_binding.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                bound_token = f"{canonical_state_binding}:{state_sig}"

                # Return MCP elicitation pause result
                return {
                    "resultType": "input_required",
                    "approvalMode": "HITL_EXECUTIVE_APPROVAL_REQUIRED",
                    "requestState": bound_token,
                    "message": (
                        f"High-value payout of ${amount_usd:,.2f} exceeds auto-approval threshold ($1,000.00). "
                        "Executive MFA authorization required."
                    ),
                    "elicitation": {
                        "prompt": "Enter Executive Approver Role and MFA Verification Code",
                        "schema": {
                            "type": "object",
                            "properties": {
                                "approverRole": {
                                    "type": "string",
                                    "enum": ["CFO", "TREASURY_DIRECTOR", "VP_FINANCE"],
                                },
                                "mfaCode": {
                                    "type": "string",
                                    "minLength": 6,
                                    "maxLength": 32,
                                },
                            },
                            "required": ["approverRole", "mfaCode"],
                            "additionalProperties": False,
                        },
                    },
                }

            # Policy 2b: Process HITL Submission
            # Verify requestState token integrity
            parts = request_state.rsplit(":", 1)
            if len(parts) != 2:
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_HITL_APPROVAL_INVALID,
                    "Invalid requestState format: expected '<canonical_binding>:<signature>'.",
                )
            passed_binding, passed_sig = parts

            # Ensure binding matches current payload and caller exactly
            if passed_binding != canonical_state_binding:
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_HITL_APPROVAL_INVALID,
                    "Tampered requestState detected: payout payload does not match original authorization pause.",
                )

            expected_sig = hmac.new(
                config.hmac_secret.encode("utf-8"),
                canonical_state_binding.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(passed_sig, expected_sig):
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_HITL_APPROVAL_INVALID,
                    "Tampered requestState cryptographic token binding.",
                )

            # Validate inputResponses schema
            approver_role = input_responses.get("approverRole")
            mfa_code = input_responses.get("mfaCode")

            if approver_role not in ["CFO", "TREASURY_DIRECTOR", "VP_FINANCE"]:
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_HITL_APPROVAL_INVALID,
                    f"Approver role '{approver_role}' is not authorized for executive wire release.",
                )

            # Verify MFA Token
            if mfa_code != "LUMEN-MFA-2026-OK":
                raise LumenRpcError(
                    JsonRpcErrorCode.ERR_HITL_APPROVAL_INVALID,
                    "Invalid Executive MFA authorization code provided.",
                    data={"providedRole": approver_role},
                )

            # Settle High-Risk Payout
            payout_id = f"PAY-{hashlib.sha256(f'{canonical_state_binding}:{time.time_ns()}'.encode()).hexdigest()[:8].upper()}"
            return {
                "resultType": "complete",
                "approvalMode": "HITL_EXECUTIVE_MFA",
                "payoutId": payout_id,
                "vendorId": vendor_id,
                "invoiceId": invoice_id,
                "amountUsd": amount_usd,
                "approverRole": approver_role,
                "status": "SETTLED",
                "details": f"High-risk payout of ${amount_usd:,.2f} authorized via Executive MFA by {approver_role}.",
            }

        self.register(
            ToolDefinition(
                name=ToolName("execute_vendor_payout"),
                description="Mutating financial payout action with policy-driven Human-In-The-Loop (HITL) approval.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "vendorId": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": 64,
                        },
                        "invoiceId": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": 64,
                        },
                        "amountUsd": {
                            "type": "number",
                            "minimum": 0.01,
                            "maximum": 1000000.00,
                        },
                        "purpose": {
                            "type": "string",
                            "minLength": 3,
                            "maxLength": 256,
                        },
                        "inputResponses": {
                            "type": "object",
                            "properties": {
                                "approverRole": {
                                    "type": "string",
                                    "enum": ["CFO", "TREASURY_DIRECTOR", "VP_FINANCE"],
                                },
                                "mfaCode": {
                                    "type": "string",
                                    "minLength": 6,
                                    "maxLength": 32,
                                },
                            },
                            "required": ["approverRole", "mfaCode"],
                            "additionalProperties": False,
                        },
                        "requestState": {
                            "type": "string",
                        },
                    },
                    "required": ["vendorId", "invoiceId", "amountUsd", "purpose"],
                    "additionalProperties": False,
                },
                required_scope="finance:payout",
                min_clearance=ClearanceLevel.CONFIDENTIAL,
                handler=handle_execute_vendor_payout,
            )
        )
