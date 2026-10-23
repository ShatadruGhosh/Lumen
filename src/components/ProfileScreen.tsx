"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { type FormEvent, useEffect, useMemo, useState } from "react";
import type { User } from "@supabase/supabase-js";
import { ArrowLeft, ArrowRight, BriefcaseBusiness, Check, LogOut, Mail, Save, ShieldCheck, UserRound } from "lucide-react";
import { getSupabaseClient, hasSupabaseConfig } from "@/lib/supabaseClient";

type Profile = {
  full_name: string | null;
  avatar_url: string | null;
  company: string | null;
  job_title: string | null;
  bio: string | null;
};

const emptyProfile: Profile = { full_name: "", avatar_url: "", company: "", job_title: "", bio: "" };

export default function ProfileScreen() {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<Profile>(emptyProfile);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const configured = hasSupabaseConfig();

  useEffect(() => {
    const supabase = getSupabaseClient();
    if (!supabase) {
      setReady(true);
      return;
    }

    let mounted = true;
    supabase.auth.getSession().then(async ({ data }) => {
      if (!mounted) return;
      if (!data.session) {
        router.replace("/login?next=%2Fprofile");
        setReady(true);
        return;
      }

      setUser(data.session.user);
      const { data: row, error: queryError } = await supabase
        .from("profiles")
        .select("full_name, avatar_url, company, job_title, bio")
        .eq("id", data.session.user.id)
        .maybeSingle();
      if (!mounted) return;
      if (queryError) setError(`Profile could not be loaded: ${queryError.message}`);
      else if (row) setProfile({ ...emptyProfile, ...row });
      else setError("Your profile row is missing. Sign out and back in after the database migration is applied.");
      setReady(true);
    }).catch((authError: unknown) => {
      if (!mounted) return;
      setError(authError instanceof Error ? authError.message : "Could not load your Supabase session.");
      setReady(true);
    });

    return () => { mounted = false; };
  }, [router]);

  const initials = useMemo(() => {
    const label = profile.full_name || user?.email || "Lumen user";
    return label.split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((part) => part[0].toUpperCase()).join("") || "L";
  }, [profile.full_name, user?.email]);

  const saveProfile = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!user) return;
    const supabase = getSupabaseClient();
    if (!supabase) return;
    setBusy(true);
    setError("");
    setNotice("");
    const { error: updateError } = await supabase
      .from("profiles")
      .update({
        full_name: profile.full_name?.trim() || null,
        avatar_url: profile.avatar_url?.trim() || null,
        company: profile.company?.trim() || null,
        job_title: profile.job_title?.trim() || null,
        bio: profile.bio?.trim() || null,
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);
    setBusy(false);
    if (updateError) setError(`Profile could not be saved: ${updateError.message}`);
    else setNotice("Your profile has been saved.");
  };

  const signOut = async () => {
    await getSupabaseClient()?.auth.signOut();
    router.replace("/login");
  };

  const updateField = (key: keyof Profile, value: string) => {
    setProfile((current) => ({ ...current, [key]: value }));
    setNotice("");
  };

  return (
    <main className="account-page profile-page">
      <div className="account-grid-glow" />
      <header className="account-topbar">
        <Link className="brand" href="/" aria-label="Lumen home"><span className="brand-mark"><span /><span /><span /></span><span>lumen<span className="brand-dot">.</span></span><span className="brand-version">02.1</span></Link>
        <Link className="account-back" href="/portal"><ArrowLeft size={15} /> Back to workspace</Link>
      </header>

      <div className="profile-frame">
        <section className="profile-heading">
          <span className="account-kicker"><span className="live-dot" /> IDENTITY & ACCESS</span>
          <h1>Your <span>profile.</span></h1>
          <p>Keep your workspace identity current. Your profile is private to your account and protected by row-level security.</p>
        </section>

        <section className="profile-card" aria-labelledby="profile-title">
          {!ready ? <div className="account-loading"><span className="brand-mark"><span /><span /><span /></span><span>Loading your profile…</span></div> : !configured ? <div className="profile-empty-state"><ShieldCheck size={25} /><h2 id="profile-title">Connect your workspace</h2><p>Set the Supabase project URL and publishable key in <code>.env.local</code> to load a profile.</p><Link className="account-submit profile-return" href="/login">Go to sign in <ArrowRight size={16} /></Link></div> : user ? <>
            <div className="profile-card-heading">
              <div className="profile-avatar">{initials}</div>
              <div><span className="account-kicker">LUMEN ACCOUNT</span><h2 id="profile-title">Profile details</h2><p>Signed in as <strong>{user.email}</strong></p></div>
              <button className="profile-signout" type="button" onClick={signOut}><LogOut size={15} /> Sign out</button>
            </div>

            {notice && <div className="account-message profile-success" role="status"><Check size={15} />{notice}</div>}
            {error && <div className="account-message is-error" role="alert">{error}</div>}

            <form className="profile-form" onSubmit={saveProfile}>
              <label className="profile-field"><span>FULL NAME</span><input value={profile.full_name ?? ""} onChange={(event) => updateField("full_name", event.target.value)} placeholder="Your name" maxLength={120} autoComplete="name" /></label>
              <label className="profile-field"><span>EMAIL ADDRESS</span><span className="profile-readonly"><Mail size={15} /><input value={user.email ?? ""} readOnly aria-readonly="true" /><small>Managed by sign-in</small></span></label>
              <div className="profile-field-row">
                <label className="profile-field"><span>COMPANY</span><span className="profile-input-icon"><BriefcaseBusiness size={15} /><input value={profile.company ?? ""} onChange={(event) => updateField("company", event.target.value)} placeholder="Company or team" maxLength={120} autoComplete="organization" /></span></label>
                <label className="profile-field"><span>ROLE</span><span className="profile-input-icon"><UserRound size={15} /><input value={profile.job_title ?? ""} onChange={(event) => updateField("job_title", event.target.value)} placeholder="Job title" maxLength={120} autoComplete="organization-title" /></span></label>
              </div>
              <label className="profile-field"><span>AVATAR URL <small>OPTIONAL</small></span><input type="url" value={profile.avatar_url ?? ""} onChange={(event) => updateField("avatar_url", event.target.value)} placeholder="https://…" /></label>
              <label className="profile-field"><span>SHORT BIO <small>OPTIONAL · 500 CHARACTERS</small></span><textarea value={profile.bio ?? ""} onChange={(event) => updateField("bio", event.target.value)} placeholder="A little about what you build…" maxLength={500} rows={4} /></label>
              <div className="profile-actions"><span><ShieldCheck size={14} /> Only you can read or edit this profile.</span><button className="account-submit profile-save" type="submit" disabled={busy}>{busy ? "Saving…" : "Save profile"}<Save size={15} /></button></div>
            </form>
          </> : <div className="profile-empty-state"><UserRound size={25} /><h2 id="profile-title">Sign in to view your profile</h2><p>Your profile is available once you sign in to your Lumen workspace.</p><Link className="account-submit profile-return" href="/login?next=%2Fprofile">Continue to sign in <ArrowRight size={16} /></Link></div>}
        </section>
      </div>
      <footer className="account-footer"><span>LUMEN GATEWAY · IDENTITY LAYER</span><span>YOUR PROFILE STAYS YOURS</span></footer>
    </main>
  );
}
