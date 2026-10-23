"use client";

import dynamic from "next/dynamic";
import Link from "next/link";
import { ArrowDown, ArrowRight, ArrowUpRight, AudioLines, Blocks, Check, ChevronDown, Fingerprint, LockKeyhole, Menu, Orbit, Shield, Sparkles, X, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import ArchitectureDiagramSvg from "@/components/ArchitectureDiagramSvg";

const ThreeCore = dynamic(() => import("@/components/ThreeZeroTrustCore"), { ssr: false });

const chapters = [
  {
    number: "01",
    title: "Keep the stream moving.",
    eyebrow: "NON-BLOCKING FRAMER · ~8 μs",
    copy: "Shape every byte before it leaves the room. A 64 KiB overflow breaker keeps runaway streams contained without slowing the work that matters.",
    color: "mint",
    icon: AudioLines,
    metric: "64 KiB",
    metricLabel: "hard overflow boundary",
    code: "frame → inspect → release",
  },
  {
    number: "02",
    title: "Identity stays server-side.",
    eyebrow: "HMAC-SHA256 + KMS · ~22 μs",
    copy: "The browser carries a Supabase session. Signing keys and cloud identity stay inside the gateway vault, where they belong.",
    color: "lavender",
    icon: Fingerprint,
    metric: "±30 sec",
    metricLabel: "replay window",
    code: "session → vault → signed call",
  },
  {
    number: "03",
    title: "Priority with a pulse.",
    eyebrow: "FOUR-LANE TRAFFIC CONTROL",
    copy: "Critical work gets a clear path. Monotonic token buckets give each lane a fair ceiling and keep runaway agents from flooding the room.",
    color: "blue",
    icon: Orbit,
    metric: "4 lanes",
    metricLabel: "critical · high · normal · low",
    code: "CRITICAL / HIGH / NORMAL / LOW",
  },
  {
    number: "04",
    title: "A pause where judgment matters.",
    eyebrow: "LEXICAL FIREWALL · <5 μs",
    copy: "Injection patterns stop at the edge. Actions over $1,000 wait for a human to look, decide, and approve.",
    color: "amber",
    icon: LockKeyhole,
    metric: "$1k+",
    metricLabel: "human approval threshold",
    code: "inspect → challenge → approve",
  },
  {
    number: "05",
    title: "Every decision leaves a trace.",
    eyebrow: "BLAKE2B · HASH-CHAINED LEDGER",
    copy: "An append-only account of what happened, why it happened, and how fast. Ready for CloudWatch, S3 Object Lock, and the people who ask hard questions.",
    color: "pink",
    icon: Blocks,
    metric: "256-bit",
    metricLabel: "tamper-evident chain",
    code: "event → hash → immutable record",
  },
];

export default function HomePage() {
  const [activeStage, setActiveStage] = useState(0);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const nodes = Array.from(document.querySelectorAll<HTMLElement>("[data-stage]"));
    const observer = new IntersectionObserver((entries) => {
      const visible = entries.filter((entry) => entry.isIntersecting).sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
      if (visible) setActiveStage(Number((visible.target as HTMLElement).dataset.stage ?? 0));
    }, { threshold: [0.15, 0.35, 0.6] });
    nodes.forEach((node) => observer.observe(node));
    return () => observer.disconnect();
  }, []);

  const closeMenu = () => setMenuOpen(false);

  return (
    <main className="site-shell">
      <div className="ambient-orbit ambient-orbit-one" />
      <div className="ambient-orbit ambient-orbit-two" />
      <header className="site-header">
        <Link className="brand" href="#top" aria-label="Lumen home" onClick={closeMenu}>
          <span className="brand-mark"><span /><span /><span /></span>
          <span>lumen<span className="brand-dot">.</span></span>
          <span className="brand-version">02.1</span>
        </Link>
        <nav className={menuOpen ? "site-nav is-open" : "site-nav"}>
          <a href="#platform" onClick={closeMenu}>Platform</a>
          <a href="#architecture" onClick={closeMenu}>Architecture</a>
          <a href="#trust" onClick={closeMenu}>Trust</a>
          <Link className="mobile-console-link" href="/login?next=%2Fportal" onClick={closeMenu}>Sign in <ArrowUpRight size={15} /></Link>
        </nav>
        <Link className="header-cta" href="/login?next=%2Fportal">Sign in <ArrowUpRight size={15} /></Link>
        <button className="menu-toggle" aria-label={menuOpen ? "Close menu" : "Open menu"} onClick={() => setMenuOpen(!menuOpen)}>
          {menuOpen ? <X size={20} /> : <Menu size={20} />}
        </button>
      </header>

      <section className="hero-section" id="top" data-stage="0">
        <div className="hero-copy">
          <div className="eyebrow-pill"><span className="live-dot" /> CONTROL PLANE FOR AUTONOMOUS SYSTEMS <span className="pill-divider" /> V2.1</div>
          <h1>Let agents move.<br /><span>Keep control.</span></h1>
          <p className="hero-lede">The zero-trust gateway that gives autonomous work a place to run—fast, bounded, and accountable by design.</p>
          <div className="hero-actions">
            <a className="button button-primary" href="#platform">Explore the gateway <ArrowRight size={17} /></a>
            <Link className="button button-quiet" href="/portal"><span className="play-glyph">↗</span> Open live console</Link>
          </div>
          <div className="hero-footnote"><span className="micro-label">BUILT FOR MCP</span><span className="hero-footnote-line" /><span className="micro-label">MADE FOR THE SPEED OF THOUGHT</span></div>
        </div>

        <div className="hero-stage" aria-label="Animated 3D Lumen prism">
          <div className="stage-grid" />
          <div className="stage-vignette" />
          <div className="stage-label stage-label-top"><span className="stage-label-dot" /> POLICY ENGINE <span className="stage-label-index">{String(activeStage + 1).padStart(2, "0")} / 05</span></div>
          <div className="stage-canvas"><ThreeCore stage={activeStage} /></div>
          <div className="stage-readout readout-latency"><span className="readout-icon"><Zap size={14} /></span><span><small>GATEWAY LATENCY</small><strong>142.86 <i>μs</i></strong></span><span className="readout-pulse" /></div>
          <div className="stage-readout readout-trust"><span className="readout-icon shield-icon"><Shield size={14} /></span><span><small>TRUST STATE</small><strong>VERIFIED <i>·</i> ACTIVE</strong></span></div>
          <div className="stage-label stage-label-bottom"><span>01</span><span className="coordinate-line" /><span>37° 46′ 49.0″ N</span><span>122° 25′ 09.0″ W</span></div>
        </div>
        <a className="scroll-cue" href="#platform"><span>SCROLL TO EXPLORE</span><ArrowDown size={14} /></a>
      </section>

      <section className="signal-strip" aria-label="Gateway performance">
        <div className="signal-intro"><span className="live-dot" /> A CONTROL PLANE THAT KEEPS ITS PROMISES</div>
        <div className="signal-item"><strong>142.86<span> μs</span></strong><small>P50 DECISION TIME</small></div>
        <div className="signal-item"><strong>Zero<span>-trust</span></strong><small>BY DEFAULT</small></div>
        <div className="signal-item"><strong>256<span>-bit</span></strong><small>HASH-CHAINED AUDIT</small></div>
      </section>

      <section className="platform-intro section-wrap" id="platform">
        <div className="section-kicker"><span>01 — THE GATEWAY</span><span className="kicker-rule" /></div>
        <div className="intro-grid">
          <h2>All the speed.<br /><span>None of the blind spots.</span></h2>
          <div className="intro-copy"><p>Agents are powerful. Giving them direct access to sensitive tools is not a strategy. Lumen puts a small, fast, inspectable boundary around every action.</p><a href="#architecture" className="text-link">See how it works <ArrowDown size={14} /></a></div>
        </div>
        <div className="intro-rail">
          <div><span className="rail-index">A.</span><h3>Shape the request</h3><p>Frame the stream, inspect the intent, and stop unsafe inputs before they reach a tool.</p></div>
          <div><span className="rail-index">B.</span><h3>Bind the identity</h3><p>Authenticate the person in the browser. Keep privileged signing keys inside the server vault.</p></div>
          <div><span className="rail-index">C.</span><h3>Keep the receipt</h3><p>Record the decision in a chain that is built to stand up to scrutiny.</p></div>
        </div>
      </section>

      <section className="chapter-section section-wrap" id="architecture">
        <div className="section-kicker"><span>02 — FIVE LAYERS. ONE CLEAR PATH.</span><span className="kicker-rule" /></div>
        <div className="chapter-heading"><h2>A little more room<br />to <span>think.</span></h2><p>Each layer does one job. Together they make the space safe for useful autonomy.</p></div>
        <div className="chapter-stack">
          {chapters.map((chapter, index) => {
            const Icon = chapter.icon;
            return (
              <article className={`chapter-card chapter-${chapter.color}`} key={chapter.number} data-stage={index}>
                <div className="chapter-index"><span>{chapter.number}</span><i /></div>
                <div className="chapter-content">
                  <span className="chapter-eyebrow"><span className="chapter-icon"><Icon size={15} /></span>{chapter.eyebrow}</span>
                  <h3>{chapter.title}</h3>
                  <p>{chapter.copy}</p>
                  <code>{chapter.code}</code>
                </div>
                <div className="chapter-metric"><div className="metric-orb"><span /><span /><span /></div><strong>{chapter.metric}</strong><small>{chapter.metricLabel}</small></div>
              </article>
            );
          })}
        </div>
      </section>

      <section className="architecture-section section-wrap" id="trust" data-stage="4">
        <div className="section-kicker"><span>03 — CLEAR BY CONSTRUCTION</span><span className="kicker-rule" /></div>
        <div className="architecture-heading"><div><h2>One request.<br /><span>Every boundary visible.</span></h2></div><p>No secret in the bundle. No mystery hop. One session, one policy decision, one traceable path into the systems you trust.</p></div>
        <ArchitectureDiagramSvg />
        <div className="security-notes"><div><Check size={15} /><span>Browser carries only a Supabase session token and the requested tool parameters.</span></div><div><Check size={15} /><span>Signing material and cloud identity stay in server memory.</span></div><div><Check size={15} /><span>High-impact actions pause for a human decision.</span></div></div>
      </section>

      <section className="closing-section section-wrap" data-stage="4">
        <div className="closing-glow" />
        <div className="closing-copy"><span className="closing-kicker"><Sparkles size={14} /> READY WHEN YOUR AGENTS ARE</span><h2>Give autonomy<br /><span>a safer room.</span></h2><p>Explore the controls, run a sample scenario, and see what a good boundary feels like.</p><Link href="/portal" className="button button-primary">Enter the console <ArrowRight size={17} /></Link></div>
        <div className="closing-visual"><div className="closing-ring ring-a" /><div className="closing-ring ring-b" /><div className="closing-core"><span className="brand-mark"><span /><span /><span /></span></div><div className="closing-callout"><span className="live-dot" /> YOUR TOOLS, WITH ROOM TO BREATHE</div></div>
      </section>

      <footer className="site-footer">
        <Link className="brand" href="#top"><span className="brand-mark"><span /><span /><span /></span><span>lumen<span className="brand-dot">.</span></span></Link>
        <span className="footer-note">THE CONTROL ROOM FOR AUTONOMOUS WORK</span>
        <div className="footer-right"><span>V2.1 · 2026</span><a href="#top">BACK TO TOP <ChevronDown size={13} /></a></div>
      </footer>
    </main>
  );
}
