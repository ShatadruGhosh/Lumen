"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { ArrowDownToLine, ArrowLeft, ArrowRight, ArrowUpRight, BadgeCheck, BookOpen, Check, ChevronDown, CircleHelp, CloudDownload, Code2, Copy, Database, Download, Eye, FileArchive, FileCode2, FileJson2, FileSpreadsheet, FileText, Fingerprint, Gauge, KeyRound, Layers3, LockKeyhole, Play, ShieldAlert, ShieldCheck, Sparkles, X, Zap } from "lucide-react";
import { apiBaseUrl, fetchExport, runGatewayScenario, type GatewayRequest, type GatewayResult, type Priority } from "@/lib/lumenApiBridge";
import { getSupabaseClient, hasSupabaseConfig, recordLumenAuditLog } from "@/lib/supabaseClient";

type Scenario = {
  id: string;
  name: string;
  label: string;
  summary: string;
  request: Omit<GatewayRequest, "priority">;
  icon: typeof ShieldCheck;
};

const scenarios: Scenario[] = [
  {
    id: "records",
    name: "Authorized record query",
    label: "ALLOW",
    summary: "Sensitive fields are masked before the result returns.",
    request: { toolName: "query_secure_records", arguments: { recordId: "REC-1001", fields: ["owner", "ssn", "wire"] }, clearanceOverride: false },
    icon: Database,
  },
  {
    id: "injection",
    name: "Lexical injection attempt",
    label: "BLOCK",
    summary: "An unsafe query is stopped at the gateway boundary.",
    request: { toolName: "query_secure_records", arguments: { recordId: "REC-1002' OR '1'='1; DROP TABLE records;--" }, clearanceOverride: false },
    icon: ShieldAlert,
  },
  {
    id: "payout",
    name: "High-value vendor payout",
    label: "HUMAN CHECK",
    summary: "A $25,000 payout pauses until an executive approves it.",
    request: { toolName: "create_vendor_payout", arguments: { vendorId: "VEN-208", amount: 25000, currency: "USD" }, clearanceOverride: false },
    icon: KeyRound,
  },
  {
    id: "fraud",
    name: "Fraud detection model",
    label: "ALLOW",
    summary: "A model run executes inside the same policy envelope.",
    request: { toolName: "run_fraud_detection_model", arguments: { transactionId: "TXN-774201", includeSignals: true }, clearanceOverride: false },
    icon: Gauge,
  },
];

const exports = [
  { id: "aws_bedrock", name: "Amazon Bedrock", detail: "Tool bundle", type: "JSON", icon: FileJson2, color: "mint" },
  { id: "csv", name: "Audit ledger", detail: "Excel · QuickSight", type: "CSV", icon: FileSpreadsheet, color: "blue" },
  { id: "ndjson", name: "Event stream", detail: "CloudWatch · S3", type: "NDJSON", icon: FileCode2, color: "lavender" },
  { id: "mcp_config", name: "MCP host config", detail: "Host · sidecar", type: "JSON", icon: Code2, color: "amber" },
  { id: "compliance_report", name: "Control summary", detail: "Executive report", type: "MD", icon: FileText, color: "pink" },
];

const stringify = (value: unknown) => typeof value === "string" ? value : JSON.stringify(value, null, 2);

export default function PortalWorkspace() {
  const [session, setSession] = useState<Session | null>(null);
  const [profileName, setProfileName] = useState("");
  const [authReady, setAuthReady] = useState(false);
  const [tab, setTab] = useState<"overview" | "sandbox" | "exports">("overview");
  const [priority, setPriority] = useState<Priority>("NORMAL");
  const [activeScenario, setActiveScenario] = useState(scenarios[0]);
  const [result, setResult] = useState<GatewayResult | null>(null);
  const [running, setRunning] = useState(false);
  const [toast, setToast] = useState("");
  const [modal, setModal] = useState<{ title: string; content: string; filename?: string } | null>(null);
  const [mfaOpen, setMfaOpen] = useState(false);
  const [exportModes, setExportModes] = useState<Record<string, string>>({});
  const [exportBusy, setExportBusy] = useState<string | null>(null);

  const configured = hasSupabaseConfig();
  const live = Boolean(session?.access_token);
  const displayName = String(profileName || session?.user.user_metadata?.full_name || session?.user.email || "Workspace user");
  const initials = useMemo(() => displayName.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((part) => part[0].toUpperCase()).join("") || "L", [displayName]);

  useEffect(() => {
    const supabase = getSupabaseClient();
    if (!supabase) {
      setAuthReady(true);
      return;
    }

    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setAuthReady(true);
    });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setAuthReady(true);
    });
    return () => listener.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    setProfileName("");
    if (!session?.user.id) return;
    const supabase = getSupabaseClient();
    if (!supabase) return;
    let mounted = true;
    supabase.from("profiles").select("full_name").eq("id", session.user.id).maybeSingle().then(({ data }) => {
      if (mounted && data?.full_name) setProfileName(data.full_name);
    });
    return () => { mounted = false; };
  }, [session?.user.id]);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(""), 3200);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  const executeScenario = async (scenario: Scenario) => {
    setActiveScenario(scenario);
    setRunning(true);
    setResult(null);
    const request: GatewayRequest = { ...scenario.request, priority };
    const response = await runGatewayScenario(request, session?.access_token);
    setResult(response);
    setRunning(false);
    const responseType = (response.data as { resultType?: string } | null)?.resultType;
    if (responseType === "input_required") setMfaOpen(true);

    if (session?.user) {
      const elapsed = typeof (response.data as { elapsed_us?: number })?.elapsed_us === "number"
        ? (response.data as { elapsed_us?: number }).elapsed_us
        : null;
      recordLumenAuditLog({
        user_id: session.user.id,
        user_email: session.user.email ?? null,
        tool_name: request.toolName,
        priority: request.priority,
        arguments: request.arguments,
        result: response.data,
        decision: responseType || (response.mode === "live" ? "allow" : "preview"),
        latency_us: elapsed,
        mode: response.mode,
      }).catch((err) => console.warn("Failed to record audit log:", err));
    }
  };

  const chooseScenario = (scenario: Scenario) => {
    setActiveScenario(scenario);
    setResult(null);
  };

  const choosePriority = (value: Priority) => {
    setPriority(value);
    setResult(null);
  };

  const openExportPreview = async (id: string) => {
    setExportBusy(id);
    const exportResult = await fetchExport(id, session?.access_token);
    const content = stringify(exportResult.data);
    setExportModes((current) => ({ ...current, [id]: exportResult.mode }));
    setModal({ title: exports.find((item) => item.id === id)?.name ?? "Export preview", content, filename: `${id}.${id === "csv" ? "csv" : id === "ndjson" ? "ndjson" : id === "compliance_report" ? "md" : "json"}` });
    setExportBusy(null);
  };

  const copyText = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setToast(`${label} copied to clipboard.`);
    } catch {
      setToast("Clipboard access is unavailable in this browser.");
    }
  };

  const downloadContent = (content: string, filename: string, mime = "text/plain") => {
    const url = URL.createObjectURL(new Blob([content], { type: mime }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
    setToast(`${filename} downloaded.`);
  };

  const downloadExport = async (id: string) => {
    setExportBusy(id);
    const exportResult = await fetchExport(id, session?.access_token);
    const ext = id === "csv" ? "csv" : id === "ndjson" ? "ndjson" : id === "compliance_report" ? "md" : "json";
    downloadContent(stringify(exportResult.data), `lumen_${id}.${ext}`, ext === "json" ? "application/json" : "text/plain");
    setExportModes((current) => ({ ...current, [id]: exportResult.mode }));
    setExportBusy(null);
  };

  const downloadSdk = async () => {
    if (!session?.access_token) {
      setToast("Sign in to download the authenticated SDK bundle.");
      return;
    }
    try {
      const response = await fetch(`${apiBaseUrl()}/api/v1/sdk/download`, { headers: { Authorization: `Bearer ${session.access_token}` }, signal: AbortSignal.timeout(15000) });
      if (!response.ok) throw new Error(`SDK download returned ${response.status}`);
      const url = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "lumen_client_sdk_bundle.zip";
      anchor.click();
      URL.revokeObjectURL(url);
      setToast("SDK bundle downloaded.");
    } catch (error) {
      setToast(error instanceof Error ? error.message : "The SDK bundle could not be downloaded.");
    }
  };

  if (!authReady) {
    return <main className="portal-loading"><span className="brand-mark"><span /><span /><span /></span><p>Opening your workspace…</p></main>;
  }

  const requestPayload: GatewayRequest = { ...activeScenario.request, priority };
  const proofRequest = {
    method: "POST",
    endpoint: "/api/v1/gateway/proxy",
    headers: { Authorization: live ? "Bearer [session token masked]" : "Not sent · preview mode", "Content-Type": "application/json" },
    body: requestPayload,
  };

  return (
    <main className="portal-shell">
      <header className="portal-header">
        <div className="portal-header-left"><Link className="portal-back" href="/"><ArrowLeft size={16} /><span>BACK TO LUMEN</span></Link><span className="portal-header-divider" /><Link className="brand" href="/"><span className="brand-mark"><span /><span /><span /></span><span>lumen<span className="brand-dot">.</span></span></Link><span className="portal-console-label">CONTROL ROOM</span></div>
        <div className="portal-header-right"><div className={live ? "connection-state is-live" : "connection-state is-preview"}><span className="live-dot" />{live ? "LIVE SESSION" : "PREVIEW MODE"}</div><Link className="avatar-button" title={live ? "Open profile" : "Sign in"} href={live ? "/profile" : "/login?next=%2Fportal"}>{live ? initials : <Fingerprint size={16} />}</Link></div>
      </header>

      {!configured && <div className="preview-banner"><Sparkles size={15} /><span><strong>Local preview.</strong> Connect Supabase in <code>.env.local</code> and add your gateway URL to enable live authentication and requests.</span><button onClick={() => setModal({ title: "Connect your workspace", content: "Copy frontend/.env.example to frontend/.env.local, then restart the development server. The example is preconfigured for the Lumen Supabase project.\n\nConfigure Google Auth in Supabase and allow http://localhost:3000/** under Authentication → URL Configuration." })}>Setup guide <ArrowUpRight size={13} /></button></div>}
      {configured && !live && <div className="preview-banner"><LockKeyhole size={15} /><span><strong>Not signed in.</strong> The console is showing sample data; gateway actions remain local until your Supabase session is active.</span><Link href="/login?next=%2Fportal">Sign in <ArrowUpRight size={13} /></Link></div>}

      <div className="portal-layout">
        <aside className="portal-sidebar">
          <div className="sidebar-workspace"><span className="workspace-icon"><Layers3 size={17} /></span><span><small>WORKSPACE</small><strong>Lumen Sandbox</strong></span><ChevronDownIcon /></div>
          <span className="sidebar-label">OPERATIONS</span>
          <button className={tab === "overview" ? "sidebar-link is-active" : "sidebar-link"} onClick={() => setTab("overview")}><Gauge size={16} />Overview</button>
          <button className={tab === "sandbox" ? "sidebar-link is-active" : "sidebar-link"} onClick={() => setTab("sandbox")}><Zap size={16} />Agent sandbox<span className="sidebar-new">LIVE</span></button>
          <button className={tab === "exports" ? "sidebar-link is-active" : "sidebar-link"} onClick={() => setTab("exports")}><ArrowDownToLine size={16} />Export hub</button>
          <div className="sidebar-spacer" />
          <div className="sidebar-security"><div className="security-mark"><ShieldCheck size={17} /></div><strong>Zero exposure</strong><p>Secrets stay in the server vault. Always.</p><a href="#proof" onClick={() => setTab("sandbox")}>View security proof <ArrowRight size={13} /></a></div>
          <div className="sidebar-footer"><span className="live-dot" /> GATEWAY OPERATIONAL <span>v2.1</span></div>
        </aside>

        <section className="portal-main">
          <div className="portal-titlebar"><div><div className="portal-breadcrumb"><span>WORKSPACE</span><span>/</span><strong>{tab === "overview" ? "OVERVIEW" : tab === "sandbox" ? "AGENT SANDBOX" : "EXPORT HUB"}</strong></div><h1>{tab === "overview" ? "Good morning, operator." : tab === "sandbox" ? "Run a controlled scenario." : "Your data, ready to travel."}</h1><p>{tab === "overview" ? "A clear view of every action moving through Lumen." : tab === "sandbox" ? "See how policy behaves before your agents do." : "Take the audit trail and tool definitions wherever they need to go."}</p></div><div className="portal-title-actions"><button className="button button-secondary button-compact" onClick={downloadSdk}><CloudDownload size={15} />Download SDK</button><button className="help-button" title="About this workspace" onClick={() => setModal({ title: "About the Lumen workspace", content: "This console demonstrates the Lumen gateway boundary. In preview mode, scenarios use local sample responses and never send a request. With a Supabase session, calls send the access token and the selected tool arguments to your configured gateway." })}><CircleHelp size={17} /></button></div></div>

          {tab === "overview" && <OverviewPanel live={live} onOpenSandbox={() => setTab("sandbox")} onOpenExports={() => setTab("exports")} />}
          {tab === "sandbox" && <SandboxPanel priority={priority} setPriority={choosePriority} activeScenario={activeScenario} setActiveScenario={chooseScenario} executeScenario={executeScenario} running={running} result={result} requestPayload={requestPayload} proofRequest={proofRequest} copyText={copyText} live={live} />}
          {tab === "exports" && <ExportsPanel openExportPreview={openExportPreview} downloadExport={downloadExport} downloadSdk={downloadSdk} exportBusy={exportBusy} exportModes={exportModes} />}

          <div className="portal-footerline"><span>Protected by the Lumen server vault</span><span><span className="live-dot" /> {live ? "Authenticated request path" : "Local sample data"}</span></div>
        </section>
      </div>

      {toast && <div className="portal-toast"><Check size={15} />{toast}<button onClick={() => setToast("")} aria-label="Dismiss"><X size={14} /></button></div>}
      {modal && <div className="portal-modal-backdrop" onClick={() => setModal(null)}><section className="portal-modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" onClick={(event) => event.stopPropagation()}><div className="modal-header"><div><span className="modal-kicker">LUMEN WORKSPACE</span><h2 id="modal-title">{modal.title}</h2></div><button className="icon-button" onClick={() => setModal(null)} aria-label="Close"><X size={18} /></button></div><pre className="modal-code">{modal.content}</pre><div className="modal-actions"><button className="button button-secondary button-compact" onClick={() => copyText(modal.content, modal.filename ?? "Text") }><Copy size={14} />Copy</button>{modal.filename && <button className="button button-primary button-compact" onClick={() => downloadContent(modal.content, modal.filename!, "text/plain")}><Download size={14} />Download</button>}</div></section></div>}
      {mfaOpen && <div className="portal-modal-backdrop" onClick={() => setMfaOpen(false)}><section className="portal-modal mfa-modal" role="dialog" aria-modal="true" aria-labelledby="mfa-title" onClick={(event) => event.stopPropagation()}><div className="mfa-emblem"><LockKeyhole size={22} /></div><span className="modal-kicker">HUMAN APPROVAL GATE</span><h2 id="mfa-title">The payout is paused.</h2><p>A $25,000 vendor payout needs executive MFA before the gateway can continue. No funds have moved.</p><div className="mfa-state"><span className="live-dot" />{result?.mode === "live" ? "Gateway requested executive approval" : "Preview of the executive approval gate"}</div><button className="button button-secondary button-compact" onClick={() => setMfaOpen(false)}>Close gate</button></section></div>}
    </main>
  );
}

function ChevronDownIcon() {
  return <span className="workspace-chevron"><ChevronDown size={13} /></span>;
}

function OverviewPanel({ live, onOpenSandbox, onOpenExports }: { live: boolean; onOpenSandbox: () => void; onOpenExports: () => void }) {
  return (
    <div className="overview-panel">
      <div className="overview-grid">
        <div className="overview-card hero-overview-card"><div className="overview-card-top"><span className="overview-icon mint-icon"><Zap size={17} /></span><span className="metric-window">LAST 24 HOURS <ArrowUpRight size={13} /></span></div><div className="large-metric">142<span>.86</span><i>μs</i></div><p>Median gateway decision time <span className="metric-trend">−8.4%</span></p><div className="sparkline"><span style={{ height: "29%" }} /><span style={{ height: "42%" }} /><span style={{ height: "36%" }} /><span style={{ height: "58%" }} /><span style={{ height: "46%" }} /><span style={{ height: "73%" }} /><span style={{ height: "55%" }} /><span style={{ height: "66%" }} /><span style={{ height: "49%" }} /><span style={{ height: "82%" }} /><span style={{ height: "71%" }} /><span style={{ height: "92%" }} /><span style={{ height: "63%" }} /><span style={{ height: "88%" }} /><span style={{ height: "74%" }} /><span style={{ height: "100%" }} /><span style={{ height: "79%" }} /><span style={{ height: "91%" }} /></div></div>
        <div className="overview-card"><div className="overview-card-top"><span className="overview-icon lavender-icon"><ShieldCheck size={17} /></span><span className="metric-window">POLICY STATUS</span></div><div className="status-word">Protected<span className="live-dot" /></div><p>Zero-trust boundary active</p><div className="subtle-divider" /><div className="inline-status"><BadgeCheck size={14} /><span>All security layers online</span></div></div>
        <div className="overview-card"><div className="overview-card-top"><span className="overview-icon amber-icon"><Fingerprint size={17} /></span><span className="metric-window">IDENTITY</span></div><div className="status-word">{live ? "Verified" : "Preview"}</div><p>{live ? "Supabase session is active" : "No session token is being sent"}</p><div className="subtle-divider" /><div className="inline-status"><LockKeyhole size={14} /><span>{live ? "Signing keys stay server-side" : "Connect to enable live calls"}</span></div></div>
      </div>
      <div className="overview-lower"><div className="recent-panel"><div className="panel-heading"><div><span className="panel-kicker">CONTROL SURFACE</span><h2>Run a scenario</h2></div><button className="text-link" onClick={onOpenSandbox}>Open sandbox <ArrowRight size={14} /></button></div><div className="quick-scenario-row">{scenarios.slice(0, 3).map((scenario) => <button className="quick-scenario" key={scenario.id} onClick={onOpenSandbox}><span className={`scenario-icon scenario-${scenario.id}`}><scenario.icon size={15} /></span><span><strong>{scenario.name}</strong><small>{scenario.label}</small></span><ArrowRight size={14} /></button>)}</div></div><div className="download-card"><div className="download-card-orb"><FileArchive size={21} /></div><span className="panel-kicker">UNIVERSAL EXPORT BRIDGE</span><h3>Everything, portable.</h3><p>Take your tool bundles and audit trail wherever your stack needs them.</p><button className="text-link" onClick={onOpenExports}>Open export hub <ArrowRight size={14} /></button></div></div>
      <div className="overview-footnote"><span><span className="live-dot" /> SYSTEM NOMINAL</span><span>REQUESTS ARE INSPECTED BEFORE THEY MOVE</span><span>REGION · AP-SOUTH-1</span></div>
    </div>
  );
}

function SandboxPanel({ priority, setPriority, activeScenario, setActiveScenario, executeScenario, running, result, requestPayload, proofRequest, copyText, live }: {
  priority: Priority;
  setPriority: (value: Priority) => void;
  activeScenario: Scenario;
  setActiveScenario: (value: Scenario) => void;
  executeScenario: (scenario: Scenario) => void;
  running: boolean;
  result: GatewayResult | null;
  requestPayload: GatewayRequest;
  proofRequest: unknown;
  copyText: (value: string, label: string) => void;
  live: boolean;
}) {
  const resultText = result ? stringify(result.data) : "Select a scenario and run it to inspect the sanitized response.";
  return (
    <div className="sandbox-panel">
      <div className="sandbox-toolbar"><div><span className="panel-kicker">SIMULATION ENVIRONMENT</span><strong><span className="live-dot" /> {result?.mode === "live" ? "LIVE GATEWAY" : "ISOLATED PREVIEW"}</strong></div><label className="priority-control"><span>QOS PRIORITY</span><select value={priority} onChange={(event) => setPriority(event.target.value as Priority)}>{["CRITICAL", "HIGH", "NORMAL", "LOW"].map((level) => <option key={level}>{level}</option>)}</select></label></div>
      <div className="sandbox-workspace"><div className="scenario-panel"><div className="scenario-panel-heading"><span className="panel-kicker">AVAILABLE SCENARIOS</span><span>04 TESTS</span></div><div className="scenario-list">{scenarios.map((scenario) => <button key={scenario.id} onClick={() => setActiveScenario(scenario)} className={activeScenario.id === scenario.id ? "scenario-option is-selected" : "scenario-option"}><span className={`scenario-icon scenario-${scenario.id}`}><scenario.icon size={16} /></span><span className="scenario-option-copy"><strong>{scenario.name}</strong><small>{scenario.summary}</small></span><span className={`scenario-badge badge-${scenario.id}`}>{scenario.label}</span></button>)}</div><button className="button button-primary run-button" onClick={() => executeScenario(activeScenario)} disabled={running}>{running ? <span className="button-spinner" /> : <Play size={15} fill="currentColor" />}{running ? "Running through gateway…" : "Run selected scenario"}<ArrowRight size={15} /></button><div className="sandbox-note"><LockKeyhole size={13} /><span>Preview mode uses local sample results. A live request requires an active Supabase session.</span></div></div>
        <div className="proof-column" id="proof"><div className="proof-panel"><div className="proof-heading"><div><span className="panel-kicker">01 / OUTBOUND REQUEST</span><strong>Browser → Gateway</strong></div><button className="icon-button" title="Copy request" onClick={() => copyText(JSON.stringify(proofRequest, null, 2), "Request proof")}><Copy size={14} /></button></div><div className="proof-request-meta"><span className="code-method">POST</span> <span className="code-url">/api/v1/gateway/proxy</span><br /><span className="code-muted">Authorization:</span> <span className="code-token">{live ? "Bearer [session token masked]" : "not sent · preview"}</span></div><pre className="proof-code">{JSON.stringify(requestPayload, null, 2)}</pre><div className="proof-caption"><LockKeyhole size={12} /><span>The actual session token is never shown in this inspector.</span></div></div>
          <div className="proof-panel response-panel"><div className="proof-heading"><div><span className="panel-kicker">02 / SANITIZED RESPONSE</span><strong>Gateway → Browser</strong></div>{result && <span className={`response-mode mode-${result.mode}`}>{result.mode === "live" ? "LIVE" : result.mode === "fallback" ? "FALLBACK" : "SAMPLE"}</span>}</div><pre className="response-code">{running ? <span className="response-wait"><span className="button-spinner" /> Evaluating policy…</span> : resultText}</pre>{result?.error && <div className="fallback-caption"><CircleHelp size={12} /> Gateway unreachable. This is a local sample response.</div>}</div>
        </div></div>
    </div>
  );
}

function ExportsPanel({ openExportPreview, downloadExport, downloadSdk, exportBusy, exportModes }: { openExportPreview: (id: string) => void; downloadExport: (id: string) => void; downloadSdk: () => void; exportBusy: string | null; exportModes: Record<string, string> }) {
  return (
    <div className="exports-panel"><div className="exports-summary"><div className="exports-summary-icon"><FileArchive size={19} /></div><div><strong>One bridge. Five useful formats.</strong><p>Preview, copy, or download from the gateway. Local previews are clearly marked until you connect a live session.</p></div><span className="exports-count">5 FORMATS</span></div><div className="export-grid">{exports.map((item) => <article className={`export-card export-${item.color}`} key={item.id}><div className="export-card-top"><span className="export-icon"><item.icon size={18} /></span><span className="export-type">.{item.type.toLowerCase()}</span></div><div><span className="export-detail">{item.detail}</span><h3>{item.name}</h3></div><div className="export-card-actions"><button className="export-preview-button" onClick={() => openExportPreview(item.id)} disabled={exportBusy === item.id}><Eye size={14} />{exportBusy === item.id ? "Loading…" : "Preview"}</button><button className="icon-button" title={`Download ${item.name}`} onClick={() => downloadExport(item.id)} disabled={exportBusy === item.id}><Download size={14} /></button></div>{exportModes[item.id] && <div className={`export-mode mode-${exportModes[item.id]}`}>{exportModes[item.id] === "live" ? "FROM LIVE GATEWAY" : exportModes[item.id] === "fallback" ? "LOCAL FALLBACK" : "SAMPLE PREVIEW"}</div>}</article>)}</div><div className="sdk-banner"><div className="sdk-icon"><BookOpen size={19} /></div><div><span className="panel-kicker">CLIENT SDK + CLI</span><h3>Take Lumen with you.</h3><p>Download the authenticated bundle with <code>lumen_sdk.py</code>, host config, and a plugin example.</p></div><button className="button button-secondary button-compact" onClick={downloadSdk}><Download size={15} />Download SDK</button></div><p className="exports-footnote"><LockKeyhole size={13} />Every live export is fetched with your Supabase session. Secret keys never enter the browser.</p></div>
  );
}
