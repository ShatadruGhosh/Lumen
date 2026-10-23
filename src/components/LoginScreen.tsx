"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useEffect, useState } from "react";
import { ArrowLeft, ArrowRight, Fingerprint, LockKeyhole, Mail, ShieldCheck, Sparkles, UserRound } from "lucide-react";
import { getSupabaseClient, hasSupabaseConfig, signInWithGoogle } from "@/lib/supabaseClient";

type AuthMode = "sign-in" | "sign-up" | "forgot-password" | "reset-password";

function safeNextPath(value: string | null) {
  if (!value?.startsWith("/") || value.startsWith("//") || value.startsWith("/\\")) return "/portal";
  try {
    return new URL(value, window.location.origin).origin === window.location.origin ? value : "/portal";
  } catch {
    return "/portal";
  }
}

function authCallbackUrl(next: string) {
  const callback = new URL("/auth/callback", window.location.origin);
  callback.searchParams.set("next", next);
  return callback.toString();
}

function GoogleMark() {
  return (
    <svg aria-hidden="true" viewBox="0 0 48 48" className="google-mark">
      <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5Z" transform="translate(0 4)" />
      <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.77 7.18l7.73 6C44.41 38.03 46.98 31.9 46.98 24.55Z" />
      <path fill="#FBBC05" d="M10.53 28.59a14.43 14.43 0 0 1 0-9.18l-7.98-6.19a23.99 23.99 0 0 0 0 21.56l7.98-6.19Z" transform="translate(0 4)" />
      <path fill="#34A853" d="M24 48c6.48 0 11.94-2.13 15.92-5.8l-7.73-6c-2.14 1.44-4.88 2.3-8.19 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48Z" />
    </svg>
  );
}

export default function LoginScreen() {
  const router = useRouter();
  const [mode, setMode] = useState<AuthMode>("sign-in");
  const [nextPath, setNextPath] = useState("/portal");
  const [authReady, setAuthReady] = useState(false);
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const configured = hasSupabaseConfig();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const destination = safeNextPath(params.get("next"));
    const requestedMode = params.get("mode") === "reset-password" ? "reset-password" : "sign-in";
    setNextPath(destination);
    setMode(requestedMode);
    if (params.get("error") === "auth_callback") {
      setError("Sign-in could not be completed. Please try again, and make sure this site is in Supabase’s redirect allow list.");
    }

    const supabase = getSupabaseClient();
    if (!supabase) {
      setAuthReady(true);
      return;
    }

    let mounted = true;
    supabase.auth.getSession().then(({ data }) => {
      if (!mounted) return;
      setAuthReady(true);
      if (data.session && requestedMode !== "reset-password") router.replace(destination);
    }).catch((authError: unknown) => {
      if (!mounted) return;
      setAuthReady(true);
      setError(authError instanceof Error ? authError.message : "Could not connect to Supabase Auth.");
    });

    const { data: listener } = supabase.auth.onAuthStateChange((event, session) => {
      if (!mounted) return;
      if (event === "PASSWORD_RECOVERY") {
        setMode("reset-password");
        setAuthReady(true);
      } else if (session && requestedMode !== "reset-password") {
        router.replace(destination);
      }
    });

    return () => {
      mounted = false;
      listener.subscription.unsubscribe();
    };
  }, [router]);

  const changeMode = (nextMode: AuthMode) => {
    setMode(nextMode);
    setMessage("");
    setError("");
  };

  const handleGoogle = async () => {
    setPending(true);
    setError("");
    try {
      const { error: authError } = await signInWithGoogle(nextPath);
      if (authError) setError(authError.message);
    } catch (authError) {
      setError(authError instanceof Error ? authError.message : "Google sign-in could not be started.");
    } finally {
      setPending(false);
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");
    setMessage("");
    const supabase = getSupabaseClient();
    if (!supabase) {
      setError("Supabase is not configured for this frontend yet.");
      return;
    }

    if (mode === "sign-up" && password !== confirmPassword) {
      setError("Your passwords do not match.");
      return;
    }

    setPending(true);
    try {
      if (mode === "sign-in") {
        const { data, error: authError } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
        if (authError) throw authError;
        if (data.session) router.replace(nextPath);
      } else if (mode === "sign-up") {
        const { data, error: authError } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: {
            emailRedirectTo: authCallbackUrl(nextPath),
            data: { full_name: fullName.trim() },
          },
        });
        if (authError) throw authError;
        if (data.session) router.replace(nextPath);
        else setMessage("Check your inbox for a confirmation link. Your Lumen profile will be created when you verify your email.");
      } else if (mode === "forgot-password") {
        const { error: authError } = await supabase.auth.resetPasswordForEmail(email.trim(), {
          redirectTo: authCallbackUrl(`/login?mode=reset-password&next=${encodeURIComponent(nextPath)}`),
        });
        if (authError) throw authError;
        setMessage("If an account exists for that email, a password reset link is on its way.");
      } else {
        const { error: authError } = await supabase.auth.updateUser({ password });
        if (authError) throw authError;
        setPassword("");
        setConfirmPassword("");
        changeMode("sign-in");
        setMessage("Password updated. Sign in with your new password.");
      }
    } catch (authError) {
      setError(authError instanceof Error ? authError.message : "Authentication failed. Please try again.");
    } finally {
      setPending(false);
    }
  };

  const heading = mode === "sign-up" ? "Create your account" : mode === "forgot-password" ? "Reset your password" : mode === "reset-password" ? "Choose a new password" : "Welcome back";
  const isPasswordOnly = mode === "reset-password";

  return (
    <main className="account-page">
      <div className="account-grid-glow" />
      <header className="account-topbar">
        <Link className="brand" href="/" aria-label="Lumen home">
          <span className="brand-mark"><span /><span /><span /></span>
          <span>lumen<span className="brand-dot">.</span></span>
          <span className="brand-version">02.1</span>
        </Link>
        <Link className="account-back" href="/"><ArrowLeft size={15} /> Back to Lumen</Link>
      </header>

      <div className="account-frame">
        <section className="account-story">
          <div className="account-orbit account-orbit-one" />
          <div className="account-orbit account-orbit-two" />
          <div className="account-story-copy">
            <span className="account-kicker"><span className="live-dot" /> YOUR CONTROL ROOM, READY</span>
            <h1>Good work needs<br />a <span>safer room.</span></h1>
            <p>Sign in to your Lumen workspace to run controlled scenarios, inspect the gateway boundary, and manage your profile.</p>
          </div>
          <div className="account-visual" aria-hidden="true">
            <div className="account-visual-ring account-ring-a" />
            <div className="account-visual-ring account-ring-b" />
            <div className="account-visual-core"><Fingerprint size={40} strokeWidth={1.2} /></div>
            <span className="account-visual-label account-label-top"><span className="live-dot" /> IDENTITY VERIFIED</span>
            <span className="account-visual-label account-label-bottom">AUTH · POLICY · AUDIT</span>
          </div>
          <div className="account-proof-row">
            <span><ShieldCheck size={15} /> Private by default</span>
            <span><Sparkles size={15} /> Built for agentic systems</span>
          </div>
        </section>

        <section className="account-card" aria-labelledby="account-title">
          <div className="account-card-top">
            <span className="account-card-icon"><LockKeyhole size={16} /></span>
            <span className="account-card-state"><span className={configured ? "live-dot" : "account-dot-muted"} />{configured ? "SECURE SIGN IN" : "LOCAL PREVIEW"}</span>
          </div>
          <h2 id="account-title">{heading}</h2>
          <p className="account-card-subtitle">
            {mode === "sign-up" ? "Set up your workspace identity in a few seconds." : mode === "forgot-password" ? "We’ll send you a secure link to reset your password." : mode === "reset-password" ? "Choose a strong password for your account." : "Continue to your Lumen gateway workspace."}
          </p>

          {!authReady ? <div className="account-loading"><span className="brand-mark"><span /><span /><span /></span><span>Connecting securely…</span></div> : <>
            {!configured && <div className="account-config-note">This preview has no Supabase credentials. Add the project URL and publishable key to <code>.env.local</code> to enable sign in.</div>}
            {message && <div className="account-message" role="status">{message}</div>}
            {error && <div className="account-message is-error" role="alert">{error}</div>}

            {configured && !isPasswordOnly && mode !== "forgot-password" && <>
              <button className="google-login-button" type="button" onClick={handleGoogle} disabled={pending}>
                <GoogleMark />
                <span>{pending ? "Connecting…" : "Continue with Google"}</span>
                <ArrowRight size={15} />
              </button>
              <div className="account-divider"><span />OR CONTINUE WITH EMAIL<span /></div>
            </>}

            <form className="account-form" onSubmit={handleSubmit}>
              {mode === "sign-up" && <label className="account-field">
                <span>FULL NAME</span>
                <span className="account-input-wrap"><UserRound size={15} /><input autoComplete="name" value={fullName} onChange={(event) => setFullName(event.target.value)} placeholder="Your name" maxLength={120} required disabled={!configured || pending} /></span>
              </label>}

              {!isPasswordOnly && <label className="account-field">
                <span>EMAIL ADDRESS</span>
                <span className="account-input-wrap"><Mail size={15} /><input type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" required disabled={!configured || pending} /></span>
              </label>}

              {mode !== "forgot-password" && <label className="account-field">
                <span>{isPasswordOnly ? "NEW PASSWORD" : "PASSWORD"}</span>
                <span className="account-input-wrap"><LockKeyhole size={15} /><input type="password" autoComplete={mode === "sign-in" ? "current-password" : "new-password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder={isPasswordOnly ? "At least 8 characters" : "Enter your password"} minLength={mode === "sign-in" ? undefined : 8} required disabled={!configured || pending} /></span>
              </label>}

              {mode === "sign-up" && <label className="account-field">
                <span>CONFIRM PASSWORD</span>
                <span className="account-input-wrap"><LockKeyhole size={15} /><input type="password" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Re-enter your password" minLength={8} required disabled={!configured || pending} /></span>
              </label>}

              {mode === "sign-in" && <button className="account-forgot" type="button" onClick={() => changeMode("forgot-password")}>Forgot password?</button>}
              <button className="account-submit" type="submit" disabled={!configured || pending}>
                {pending ? "Please wait…" : mode === "sign-up" ? "Create account" : mode === "forgot-password" ? "Send reset link" : isPasswordOnly ? "Update password" : "Sign in with email"}
                {!pending && <ArrowRight size={16} />}
              </button>
            </form>

            {configured && !isPasswordOnly && mode !== "forgot-password" && <p className="account-switch">
              {mode === "sign-in" ? "New to Lumen?" : "Already have an account?"}{" "}
              <button type="button" onClick={() => changeMode(mode === "sign-in" ? "sign-up" : "sign-in")}>{mode === "sign-in" ? "Create an account" : "Sign in"}</button>
            </p>}
            {(mode === "forgot-password" || isPasswordOnly) && <p className="account-switch"><button type="button" onClick={() => changeMode("sign-in")}>Back to sign in</button></p>}
          </>}

          <div className="account-card-footer"><span className="live-dot" /> Protected by Supabase Auth <span>·</span> Your credentials never reach the Lumen gateway.</div>
        </section>
      </div>

      <footer className="account-footer"><span>LUMEN GATEWAY · IDENTITY LAYER</span><span>CONTROLLED AUTONOMY, BY DESIGN</span></footer>
    </main>
  );
}
