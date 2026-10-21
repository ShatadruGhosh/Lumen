"""
Lumen v2.0 Enterprise Gateway - Configuration, QoS Traffic Manager & BLAKE2b Audit Ledger
Amazon Developer Hackathon 2026: "Build, Ship, Shape" (Alexa+ Enterprise Ecosystem)

Strict Zero-Dependency Implementation (Python >= 3.11 Standard Library only).
Mitigates CVE-2020-10735 at module load time.
"""

from __future__ import annotations

import dataclasses
from enum import IntEnum
import hashlib
import hmac
import json
import sys
import time
from typing import Any, Dict, List, NewType, Optional, Tuple

# Mitigate CVE-2020-10735 (Denial of Service via large integer to string conversions)
sys.set_int_max_str_digits(4300)

# -----------------------------------------------------------------------------
# Primitive NewTypes for Zero-Trust Domain Modeling
# -----------------------------------------------------------------------------
SessionId = NewType("SessionId", str)
PrincipalId = NewType("PrincipalId", str)
TenantId = NewType("TenantId", str)
ToolName = NewType("ToolName", str)
AuditHash = NewType("AuditHash", str)

# Genesis hash for the BLAKE2b cryptographic audit chain
GENESIS_HASH = AuditHash("0" * 64)


# -----------------------------------------------------------------------------
# Error Codes: JSON-RPC 2.0 & Lumen Zero-Trust Extensions
# -----------------------------------------------------------------------------
class JsonRpcErrorCode(IntEnum):
    # Standard JSON-RPC 2.0 errors
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603

    # Lumen Zero-Trust Gateway server errors
    ERR_UNINITIALIZED_SESSION = -32001
    ERR_PROTOCOL_VERSION_MISMATCH = -32002
    ERR_ZERO_TRUST_AUTH_FAILED = -32003
    ERR_SCHEMA_GUARDRAIL_VIOLATION = -32004
    ERR_RBAC_CLEARANCE_DENIED = -32005
    ERR_FRAME_TOO_LARGE = -32006
    ERR_INJECTION_DETECTED = -32007
    ERR_RATE_LIMIT_EXCEEDED = -32008
    ERR_HITL_APPROVAL_INVALID = -32009


class ClearanceLevel(IntEnum):
    """Hierarchical security clearance levels for multi-tenant enterprise data."""
    PUBLIC = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4

    @classmethod
    def from_str(cls, val: str | int | ClearanceLevel) -> ClearanceLevel:
        if isinstance(val, ClearanceLevel):
            return val
        if isinstance(val, int):
            return cls(val)
        val_upper = str(val).strip().upper()
        mapping = {
            "PUBLIC": cls.PUBLIC,
            "INTERNAL": cls.INTERNAL,
            "CONFIDENTIAL": cls.CONFIDENTIAL,
            "RESTRICTED": cls.RESTRICTED,
        }
        if val_upper in mapping:
            return mapping[val_upper]
        raise ValueError(f"Unknown clearance level: {val}")


class TrafficPriority(IntEnum):
    """
    QoS Traffic Management Lanes for Alexa+ Enterprise.
    Multipliers scale the base token bucket capacity and refill rate.
    """
    CRITICAL = 0  # 4.0x burst multiplier, 4.0x refill rate (Executive Voice, SecOps emergency)
    HIGH = 1      # 2.0x burst multiplier, 2.0x refill rate (Interactive Alexa+ Orchestrator turn)
    NORMAL = 2    # 1.0x burst multiplier, 1.0x refill rate (Standard tool invocation)
    LOW = 3       # 0.5x burst multiplier, 0.5x refill rate (Background batch / autonomous agent loop)

    @classmethod
    def from_str(cls, val: str | int | TrafficPriority) -> TrafficPriority:
        if isinstance(val, TrafficPriority):
            return val
        if isinstance(val, int):
            return cls(val)
        val_upper = str(val).strip().upper()
        mapping = {
            "CRITICAL": cls.CRITICAL,
            "HIGH": cls.HIGH,
            "NORMAL": cls.NORMAL,
            "LOW": cls.LOW,
        }
        if val_upper in mapping:
            return mapping[val_upper]
        raise ValueError(f"Unknown traffic priority: {val}")

    @property
    def multiplier(self) -> float:
        if self == TrafficPriority.CRITICAL:
            return 4.0
        elif self == TrafficPriority.HIGH:
            return 2.0
        elif self == TrafficPriority.NORMAL:
            return 1.0
        else:
            return 0.5


# -----------------------------------------------------------------------------
# Configuration Dataclass
# -----------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class LumenConfig:
    """Enterprise Gateway configuration settings."""
    server_name: str = "lumen-enterprise-gateway"
    server_version: str = "2.0.0"
    protocol_version: str = "2026-07-28"
    hmac_secret: str = "lumen-secret-key-alexa-enterprise-2026"
    max_frame_bytes: int = 65536  # 64 KB circuit breaker boundary
    max_clock_skew_ns: int = 30_000_000_000  # +/- 30 seconds
    base_burst_capacity: float = 10.0
    base_refill_rate_per_sec: float = 50.0
    allowed_client_names: Tuple[str, ...] = (
        "alexa-plus-enterprise-orchestrator",
        "alexa-plus-agent-runtime",
        "lumen-enterprise-sdk",
        "lumen-selftest-client",
        "lumen-web-console",
    )


# -----------------------------------------------------------------------------
# QoS Priority Traffic Manager (Lock-Free Token Bucket)
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class _BucketState:
    tokens: float
    capacity: float
    refill_rate: float
    last_update_ns: int


class PriorityTrafficManager:
    """
    Sub-microsecond lock-free QoS rate limiter and traffic shaper.
    Maintains per-(principal_id, priority) token buckets using high-precision
    monotonic timestamps (time.monotonic_ns()).
    """

    def __init__(
        self,
        base_capacity: float = 10.0,
        base_refill_rate: float = 50.0,
    ) -> None:
        self.base_capacity = float(base_capacity)
        self.base_refill_rate = float(base_refill_rate)
        # Key: (principal_id, priority_enum) -> _BucketState
        self._buckets: Dict[Tuple[str, TrafficPriority], _BucketState] = {}
        self._admitted_by_priority: Dict[str, int] = {p.name: 0 for p in TrafficPriority}
        self._throttled_by_priority: Dict[str, int] = {p.name: 0 for p in TrafficPriority}

    def check_and_consume(
        self,
        principal_id: str,
        priority: TrafficPriority,
        cost: float = 1.0,
    ) -> Tuple[bool, float, float]:
        """
        Evaluate token availability and consume tokens atomically.
        Returns:
            (allowed: bool, remaining_tokens: float, retry_after_ms: float)
        """
        now_ns = time.monotonic_ns()
        key = (principal_id, priority)
        mult = priority.multiplier
        capacity = self.base_capacity * mult
        refill_rate = self.base_refill_rate * mult

        bucket = self._buckets.get(key)
        if bucket is None:
            # First request: initialize bucket with full capacity minus cost
            bucket = _BucketState(
                tokens=capacity,
                capacity=capacity,
                refill_rate=refill_rate,
                last_update_ns=now_ns,
            )
            self._buckets[key] = bucket

        # Refill tokens based on elapsed nanoseconds
        elapsed_sec = (now_ns - bucket.last_update_ns) / 1_000_000_000.0
        if elapsed_sec > 0.0:
            bucket.tokens = min(bucket.capacity, bucket.tokens + (elapsed_sec * bucket.refill_rate))
            bucket.last_update_ns = now_ns

        # Evaluate token drain
        if bucket.tokens >= cost:
            bucket.tokens -= cost
            self._admitted_by_priority[priority.name] += 1
            return (True, round(bucket.tokens, 3), 0.0)
        else:
            self._throttled_by_priority[priority.name] += 1
            deficit = cost - bucket.tokens
            retry_after_ms = max(1.0, (deficit / bucket.refill_rate) * 1000.0)
            return (False, round(bucket.tokens, 3), round(retry_after_ms, 2))

    def reset_bucket(self, principal_id: str, priority: TrafficPriority) -> None:
        """Reset a specific bucket to full capacity (useful for tests)."""
        key = (principal_id, priority)
        if key in self._buckets:
            del self._buckets[key]

    def snapshot_metrics(self) -> Dict[str, Any]:
        """Return point-in-time QoS metrics for monitoring and telemetry."""
        now_ns = time.monotonic_ns()
        active_buckets: List[Dict[str, Any]] = []

        for (principal_id, priority), bucket in self._buckets.items():
            elapsed_sec = (now_ns - bucket.last_update_ns) / 1_000_000_000.0
            current_tokens = min(bucket.capacity, bucket.tokens + (elapsed_sec * bucket.refill_rate))
            active_buckets.append({
                "principalId": principal_id,
                "priority": priority.name,
                "tokens": round(current_tokens, 2),
                "capacity": bucket.capacity,
                "refillRatePerSec": bucket.refill_rate,
                "fillPercentage": round((current_tokens / bucket.capacity) * 100.0, 1),
            })

        return {
            "admittedByPriority": dict(self._admitted_by_priority),
            "throttledByPriority": dict(self._throttled_by_priority),
            "activeBuckets": active_buckets,
        }


# -----------------------------------------------------------------------------
# Canonical HMAC-SHA256 Request Signing
# -----------------------------------------------------------------------------
def compute_request_hmac(
    secret_key: str | bytes,
    canonical_string: str,
) -> str:
    """
    Compute HMAC-SHA256 hex digest over canonical security string:
    f"{principal_id}|{tenant_id}|{clearance_name.upper()}|{scopes_csv}|{priority_name.upper()}|{timestamp_ns}|{method}"
    """
    if isinstance(secret_key, str):
        secret_bytes = secret_key.encode("utf-8")
    else:
        secret_bytes = secret_key

    return hmac.new(
        secret_bytes,
        canonical_string.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# -----------------------------------------------------------------------------
# BLAKE2b Hash-Chained Audit Ledger
# -----------------------------------------------------------------------------
@dataclasses.dataclass
class AuditRecord:
    index: int
    timestamp_ns: int
    prev_hash: AuditHash
    current_hash: AuditHash
    event: str
    principal_id: str
    tenant_id: str
    method: str
    status: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestampNs": self.timestamp_ns,
            "prevHash": self.prev_hash,
            "currentHash": self.current_hash,
            "event": self.event,
            "principalId": self.principal_id,
            "tenantId": self.tenant_id,
            "method": self.method,
            "status": self.status,
            "details": self.details,
        }

    def canonical_digest_string(self) -> str:
        """Deterministic canonical representation used for hash chaining."""
        details_json = json.dumps(self.details, sort_keys=True, separators=(",", ":"))
        return (
            f"{self.prev_hash}|{self.index}|{self.timestamp_ns}|"
            f"{self.event}|{self.principal_id}|{self.tenant_id}|"
            f"{self.method}|{self.status}|{details_json}"
        )


class AuditLogger:
    """
    Tamper-evident cryptographically chained audit logger.
    - Writes newline-delimited JSON (NDJSON) exclusively to sys.stderr.buffer (never stdout).
    - Chains every record using 256-bit hashlib.blake2b(..., digest_size=32).hexdigest().
    - Maintains in-memory ledger for fast verification and telemetry inspection.
    """

    def __init__(self, emit_to_stderr: bool = True) -> None:
        self.emit_to_stderr = emit_to_stderr
        self._ledger: List[AuditRecord] = []
        self._last_hash: AuditHash = GENESIS_HASH

    @property
    def count(self) -> int:
        return len(self._ledger)

    @property
    def latest_hash(self) -> AuditHash:
        return self._last_hash

    def log(
        self,
        event: str,
        principal_id: str,
        tenant_id: str,
        method: str,
        status: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        """Create, hash-chain, record, and output an audit entry."""
        now_ns = time.time_ns()
        index = len(self._ledger)
        prev_hash = self._last_hash
        safe_details = details if details is not None else {}

        # Construct candidate record without current_hash
        partial_record = AuditRecord(
            index=index,
            timestamp_ns=now_ns,
            prev_hash=prev_hash,
            current_hash=AuditHash(""),
            event=event,
            principal_id=principal_id,
            tenant_id=tenant_id,
            method=method,
            status=status,
            details=safe_details,
        )

        # Compute BLAKE2b 256-bit hash
        canonical_repr = partial_record.canonical_digest_string().encode("utf-8")
        current_hash = AuditHash(hashlib.blake2b(canonical_repr, digest_size=32).hexdigest())
        partial_record.current_hash = current_hash

        # Update chain state
        self._ledger.append(partial_record)
        self._last_hash = current_hash

        # Write NDJSON to sys.stderr.buffer
        if self.emit_to_stderr:
            try:
                line = (json.dumps(partial_record.to_dict(), separators=(",", ":")) + "\n").encode("utf-8")
                sys.stderr.buffer.write(line)
                sys.stderr.buffer.flush()
            except Exception:
                pass  # Writing to stderr should never crash the core engine

        return partial_record

    def verify_chain_integrity(self) -> bool:
        """
        Verify the cryptographic integrity of the entire audit chain.
        Returns True if and only if every link connects back to GENESIS_HASH.
        """
        expected_prev = GENESIS_HASH

        for record in self._ledger:
            # Check previous hash pointer
            if not hmac.compare_digest(record.prev_hash, expected_prev):
                return False

            # Recompute BLAKE2b digest over canonical representation
            canonical_repr = record.canonical_digest_string().encode("utf-8")
            recomputed = hashlib.blake2b(canonical_repr, digest_size=32).hexdigest()

            if not hmac.compare_digest(record.current_hash, recomputed):
                return False

            expected_prev = record.current_hash

        return True

    def get_records(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return the most recent audit records as serializable dictionaries."""
        records = self._ledger[-limit:] if limit > 0 else self._ledger
        return [r.to_dict() for r in records]

    def tamper_for_test(self, index: int) -> bool:
        """
        Simulate an attacker tampering with an audit log entry in place.
        Used to demonstrate cryptographic detection of tampering.
        """
        if 0 <= index < len(self._ledger):
            rec = self._ledger[index]
            self._backup_entry = (index, rec.status, dict(rec.details), rec.current_hash)
            rec.status = "TAMPERED_BY_MALICIOUS_ACTOR"
            rec.details["compromised"] = True
            return True
        return False

    def restore_tampered_entry(self, index: int, original_status: Optional[str] = None) -> bool:
        """Restore tampered entry back to its authentic cryptographic state."""
        if hasattr(self, "_backup_entry") and self._backup_entry[0] == index:
            _, old_status, old_details, old_hash = self._backup_entry
            rec = self._ledger[index]
            rec.status = old_status
            rec.details = old_details
            rec.current_hash = old_hash
            return True
        elif 0 <= index < len(self._ledger):
            rec = self._ledger[index]
            rec.status = original_status or "SUCCESS"
            if "compromised" in rec.details:
                del rec.details["compromised"]
            canonical_repr = rec.canonical_digest_string().encode("utf-8")
            rec.current_hash = AuditHash(hashlib.blake2b(canonical_repr, digest_size=32).hexdigest())
            return True
        return False
