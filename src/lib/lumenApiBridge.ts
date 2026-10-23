export type Priority = "CRITICAL" | "HIGH" | "NORMAL" | "LOW";

export type GatewayRequest = {
  toolName: string;
  arguments: Record<string, unknown>;
  priority: Priority;
  clearanceOverride: boolean;
};

export type GatewayResult = {
  data: unknown;
  mode: "live" | "fallback" | "preview";
  status?: number;
  error?: string;
};

export const apiBaseUrl = () => "/api/lumen";

const demoResponses: Record<string, unknown> = {
  query_secure_records: {
    resultType: "success",
    elapsed_us: 8.04,
    records: [{ id: "REC-1001", owner: "A. Patel", ssn: "***-**-4821", wire: "•••• 0912" }],
    pii_masked: true,
  },
  blocked_injection: {
    resultType: "blocked",
    error: { code: -32007, message: "Unsafe SQL syntax detected" },
    elapsed_us: 18.9,
    policy: "lexical_sql_firewall",
  },
  create_vendor_payout: {
    resultType: "input_required",
    payout: "$25,000.00",
    requiredAction: "executive_mfa",
    message: "High-value payout paused for human approval.",
  },
  run_fraud_detection_model: {
    resultType: "success",
    elapsed_us: 53.03,
    riskScore: 0.07,
    decision: "allow",
  },
};

function previewResponse(request: GatewayRequest) {
  const values = Object.values(request.arguments).filter((value): value is string => typeof value === "string");
  const looksLikeInjection = values.some((value) => /\b(drop\s+table|union\s+select|or\s+['"\d])/i.test(value));
  const key = looksLikeInjection ? "blocked_injection" : request.toolName;
  return demoResponses[key] ?? { resultType: "preview", accepted: true };
}

export async function runGatewayScenario(
  request: GatewayRequest,
  accessToken?: string,
): Promise<GatewayResult> {
  if (!accessToken) {
    return { data: previewResponse(request), mode: "preview" };
  }

  try {
    const response = await fetch(`${apiBaseUrl()}/api/v1/gateway/proxy`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(12000),
    });
    const data = await response.json().catch(() => ({ message: "The gateway returned an unreadable response." }));
    return { data, mode: "live", status: response.status };
  } catch (error) {
    return {
      data: previewResponse(request),
      mode: "fallback",
      error: error instanceof Error ? error.message : "Gateway unavailable",
    };
  }
}

export async function fetchExport(format: string, accessToken?: string): Promise<GatewayResult> {
  if (!accessToken) {
    return { data: sampleExports[format] ?? "Preview export", mode: "preview" };
  }

  try {
    const response = await fetch(`${apiBaseUrl()}/api/export?format=${encodeURIComponent(format)}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      signal: AbortSignal.timeout(12000),
    });
    if (!response.ok) throw new Error(`Export returned ${response.status}`);
    return { data: await response.text(), mode: "live", status: response.status };
  } catch (error) {
    return {
      data: sampleExports[format] ?? "Preview export",
      mode: "fallback",
      error: error instanceof Error ? error.message : "Export service unavailable",
    };
  }
}

export const sampleExports: Record<string, string> = {
  aws_bedrock: JSON.stringify({ version: "1.0", tools: [{ name: "query_secure_records", description: "Query records through the Lumen policy gateway." }] }, null, 2),
  csv: "timestamp,tool,decision,latency_us\n2026-10-22T10:42:08Z,query_secure_records,allow,8.04\n2026-10-22T10:42:09Z,query_untrusted_records,blocked,18.9",
  ndjson: '{"event":"gateway.request","tool":"query_secure_records","decision":"allow","elapsed_us":8.04}\n{"event":"gateway.request","tool":"query_untrusted_records","decision":"blocked","elapsed_us":18.9}',
  mcp_config: JSON.stringify({ mcpServers: { lumen: { command: "python", args: ["lumen_sdk.py"], env: { LUMEN_API_URL: "https://your-gateway.example" } } } }, null, 2),
  compliance_report: "# Lumen Gateway — Executive control summary\n\n- Requests are authenticated with user Supabase sessions.\n- High-value actions pause for human approval.\n- Gateway decisions are recorded in a hash-chained audit ledger.\n\n*Sample preview. Live report content comes from the configured gateway.*",
};
