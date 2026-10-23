"use client";

export default function ArchitectureDiagramSvg() {
  return (
    <div className="architecture-diagram" aria-label="Secure request flow: browser to Supabase Auth to Lumen Gateway to enterprise tools">
      <svg viewBox="0 0 1120 284" role="img" aria-labelledby="flow-title flow-description">
        <title id="flow-title">Lumen request path</title>
        <desc id="flow-description">User session and tool request pass through Supabase Auth and the Lumen Gateway before reaching protected systems.</desc>
        <defs>
          <linearGradient id="flow-line" x1="0" x2="1">
            <stop offset="0" stopColor="#62e4d0" />
            <stop offset=".58" stopColor="#a09aff" />
            <stop offset="1" stopColor="#f4be78" />
          </linearGradient>
          <filter id="flow-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        <path className="diagram-track" d="M120 142H1000" />
        <path className="diagram-flow" d="M120 142H1000" />
        <g className="diagram-node" transform="translate(118 142)">
          <circle r="48" className="diagram-halo" />
          <circle r="34" className="diagram-ring" />
          <path d="M-11-10h22v18h-22zM-6-15h12M-6 13h12" className="diagram-icon" />
          <text y="76" textAnchor="middle">VERCEL FRONTEND</text>
          <text y="98" textAnchor="middle" className="diagram-subtitle">Request + intent</text>
        </g>
        <g className="diagram-node" transform="translate(414 142)">
          <circle r="48" className="diagram-halo" />
          <circle r="34" className="diagram-ring" />
          <path d="M0-17 15-10v12c0 10-7 16-15 20C-8 18-15 12-15 2v-12zM-7 0l5 5 10-11" className="diagram-icon" />
          <text y="76" textAnchor="middle">SUPABASE AUTH</text>
          <text y="98" textAnchor="middle" className="diagram-subtitle">Google OAuth · session JWT</text>
        </g>
        <g className="diagram-node diagram-gateway" transform="translate(710 142)">
          <circle r="58" className="diagram-halo" />
          <circle r="43" className="diagram-ring" />
          <path d="M-14-15h28v30h-28zM-8-8h16M-8-1h16M-8 6h10" className="diagram-icon" />
          <text y="84" textAnchor="middle">LUMEN GATEWAY</text>
          <text y="106" textAnchor="middle" className="diagram-subtitle">Policy · priority · audit</text>
        </g>
        <g className="diagram-node" transform="translate(1000 142)">
          <circle r="48" className="diagram-halo" />
          <circle r="34" className="diagram-ring" />
          <path d="M-15-10h30v8h-30zM-15 2h30v8h-30zM-15 14h30" className="diagram-icon" />
          <text y="76" textAnchor="middle">PRIVATE SYSTEMS</text>
          <text y="98" textAnchor="middle" className="diagram-subtitle">Bedrock · tools · data</text>
        </g>
        <circle className="diagram-packet" r="4" filter="url(#flow-glow)">
          <animateMotion dur="4.8s" repeatCount="indefinite" path="M120 142H1000" />
        </circle>
        <circle className="diagram-packet packet-delay" r="3" filter="url(#flow-glow)">
          <animateMotion dur="4.8s" begin="-2.4s" repeatCount="indefinite" path="M120 142H1000" />
        </circle>
      </svg>
    </div>
  );
}
