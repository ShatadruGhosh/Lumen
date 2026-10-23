import { createBrowserClient } from "@supabase/ssr";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "./database.types";

let browserClient: SupabaseClient<Database> | null = null;

export function hasSupabaseConfig() {
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL &&
      (process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
        process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY),
  );
}

function getPublishableKey() {
  return (
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    ""
  );
}

export function getSupabaseClient() {
  if (typeof window === "undefined" || !hasSupabaseConfig()) return null;

  if (!browserClient) {
    browserClient = createBrowserClient<Database>(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      getPublishableKey(),
    );
  }

  return browserClient;
}

function safeRedirectPath(path: string) {
  if (!path.startsWith("/") || path.startsWith("//") || path.startsWith("/\\")) {
    return "/portal";
  }

  try {
    return new URL(path, window.location.origin).origin === window.location.origin
      ? path
      : "/portal";
  } catch {
    return "/portal";
  }
}

export async function signInWithGoogle(redirectPath = "/portal") {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return { error: new Error("Add the Supabase URL and publishable key to enable sign in.") };
  }

  const next = safeRedirectPath(redirectPath);
  const callback = new URL("/auth/callback", window.location.origin);
  callback.searchParams.set("next", next);

  return supabase.auth.signInWithOAuth({
    provider: "google",
    options: { redirectTo: callback.toString() },
  });
}

export type LumenAuditLogEntry = {
  user_id?: string | null;
  user_email?: string | null;
  tool_name: string;
  priority?: string;
  arguments?: Record<string, unknown> | null;
  result?: unknown;
  decision?: string | null;
  latency_us?: number | null;
  mode?: string;
};

export async function recordLumenAuditLog(entry: LumenAuditLogEntry) {
  const supabase = getSupabaseClient();
  if (!supabase) {
    return { error: new Error("Supabase client is unavailable.") };
  }

  try {
    const { data: sessionData } = await supabase.auth.getSession();
    const currentUser = sessionData?.session?.user;
    const userId = entry.user_id ?? currentUser?.id ?? null;
    const userEmail = entry.user_email ?? currentUser?.email ?? null;

    const { data, error } = await supabase.from("lumen_audit_logs").insert({
      user_id: userId,
      user_email: userEmail,
      tool_name: entry.tool_name,
      priority: entry.priority || "NORMAL",
      arguments: (entry.arguments ?? null) as Database["public"]["Tables"]["lumen_audit_logs"]["Insert"]["arguments"],
      result: (entry.result ?? null) as Database["public"]["Tables"]["lumen_audit_logs"]["Insert"]["result"],
      decision: entry.decision ?? "allow",
      latency_us: entry.latency_us ?? null,
      mode: entry.mode || "live",
    });

    if (error) {
      console.warn("Audit logging warning:", error.message);
      return { error };
    }
    return { data };
  } catch (err) {
    console.warn("Audit logging exception:", err);
    return { error: err instanceof Error ? err : new Error(String(err)) };
  }
}
