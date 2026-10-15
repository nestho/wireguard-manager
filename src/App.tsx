import { useMemo, useState, type ReactNode } from "react";
import { Activity, ArrowDownToLine, ArrowUpFromLine, Cable, Check, ChevronDown, CircleHelp, Command, Cpu, Gauge, Globe2, LayoutDashboard, LifeBuoy, ListChecks, LockKeyhole, Menu, MoreHorizontal, Network, Plus, Router, Search, Settings2, ShieldCheck, ShieldOff, Users, Wifi, X } from "lucide-react";

type Peer = { name: string; device: string; router: string; address: string; status: "Online" | "Offline"; lastSeen: string; traffic: string };
const peers: Peer[] = [
  { name: "Alex Morgan", device: "MacBook Pro", router: "Edge Router · Lab", address: "10.10.20.2/32", status: "Online", lastSeen: "Connected now", traffic: "2.4 GB" },
  { name: "Sam Rivera", device: "iPhone 15", router: "Edge Router · Lab", address: "10.10.20.3/32", status: "Online", lastSeen: "Connected now", traffic: "846 MB" },
  { name: "Jordan Lee", device: "ThinkPad X1", router: "Remote Office", address: "10.20.30.8/32", status: "Offline", lastSeen: "2 hours ago", traffic: "5.1 GB" },
  { name: "Taylor Kim", device: "Pixel 9", router: "Remote Office", address: "10.20.30.9/32", status: "Online", lastSeen: "Connected now", traffic: "1.2 GB" },
  { name: "Morgan Chen", device: "Ubuntu Workstation", router: "Edge Router · Lab", address: "10.10.20.6/32", status: "Offline", lastSeen: "Yesterday", traffic: "12.8 GB" }
];
const nav = [
  { label: "Overview", icon: LayoutDashboard },
  { label: "Routers", icon: Router, count: "2" },
  { label: "Users & devices", icon: Users },
  { label: "Diagnostics", icon: Activity },
  { label: "Audit log", icon: ListChecks }
];

function App() {
  const [active, setActive] = useState("Overview");
  const [query, setQuery] = useState("");
  const [showDemo, setShowDemo] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const filteredPeers = useMemo(() => peers.filter(p => [p.name, p.device, p.router, p.address].join(" ").toLowerCase().includes(query.toLowerCase())), [query]);
  const online = peers.filter(p => p.status === "Online").length;
  return <div className="app-shell">
    <aside className={mobileNav ? "sidebar mobile-open" : "sidebar"}>
      <div className="brand"><div className="brand-mark"><Cable size={21}/></div><div><strong>WireGuard<span>Manager</span></strong><small>MIKROTIK CONTROL PLANE</small></div><button className="icon-button mobile-close" onClick={() => setMobileNav(false)} aria-label="Close menu"><X size={18}/></button></div>
      <div className="workspace"><div className="workspace-icon"><ShieldCheck size={18}/></div><div><b>Local workspace</b><small>Demo environment</small></div><ChevronDown size={15}/></div>
      <div className="nav-label">WORKSPACE</div>
      <nav>{nav.map(item => <button key={item.label} className={active === item.label ? "nav-item active" : "nav-item"} onClick={() => {setActive(item.label); setMobileNav(false);}}><item.icon size={18}/><span>{item.label}</span>{item.count && <small>{item.count}</small>}</button>)}</nav>
      <div className="nav-label management-label">MANAGEMENT</div>
      <button className="nav-item" onClick={() => setActive("Settings")}><Settings2 size={18}/><span>Settings</span></button>
      <div className="sidebar-bottom"><div className="help-card"><div className="help-icon"><LifeBuoy size={17}/></div><b>Need a hand?</b><p>Explore setup guides and safe deployment tips.</p><a href="https://github.com/nestho/wireguard-manager" target="_blank" rel="noreferrer">Read documentation <span>↗</span></a></div><div className="profile"><div className="avatar">NW</div><div><b>Network Admin</b><small>Local administrator</small></div><MoreHorizontal size={19}/></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><button className="icon-button mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open menu"><Menu size={20}/></button><div className="breadcrumbs">Workspace <span>/</span> <b>{active}</b></div><div className="top-actions"><div className="secure-label"><span className="secure-dot"/> Local mode</div><button className="icon-button" aria-label="Help"><CircleHelp size={18}/></button><div className="top-avatar">NW</div></div></header>
      <div className="content">
        {showDemo && <div className="demo-banner"><div className="demo-symbol"><LockKeyhole size={17}/></div><div><b>Demo mode is active</b><span>All routers, peers, and traffic below are synthetic sample data. No live router is connected.</span></div><button onClick={() => setShowDemo(false)} aria-label="Dismiss demo notice"><X size={17}/></button></div>}
        <div className="page-heading"><div><div className="eyebrow">NETWORK OPERATIONS <span>•</span> OVERVIEW</div><h1>Good morning, Admin <span>✦</span></h1><p>Here’s what’s happening across your WireGuard network.</p></div><div className="heading-actions"><button className="button secondary" onClick={() => setActive("Diagnostics")}><Activity size={16}/> Run diagnostics</button><button className="button primary" onClick={() => setShowAdd(true)}><Plus size={17}/> Add device</button></div></div>
        <div className="metrics">
          <Metric icon={<Router size={18}/>} label="Connected routers" value="2" meta="Both responding" good="Operational" />
          <Metric icon={<Users size={18}/>} label="Total devices" value="12" meta="Across 2 routers" />
          <Metric icon={<Wifi size={18}/>} label="Online peers" value={String(online)} meta="Of 12 registered devices" good="Live status is demo" />
          <Metric icon={<ArrowDownToLine size={18}/>} label="Data transferred" value="24.8 GB" meta="Across sample peers" />
        </div>
        <div className="section-grid">
          <section className="panel router-panel"><div className="panel-heading"><div><h2>Router health</h2><p>Connection and WireGuard interface status</p></div><button className="text-button" onClick={() => setActive("Routers")}>View routers <span>→</span></button></div>
            <div className="router-row"><div className="router-icon"><Router size={20}/></div><div className="router-info"><b>Edge Router <span className="tag">LAB</span></b><small>192.0.2.1 · RouterOS 7.16</small><div className="router-chips"><span><Check size={12}/> SSH reachable</span><span><Check size={12}/> wg-main active</span></div></div><div className="health"><span className="status-dot"/><b>Healthy</b><small>12 sec ago</small></div><button className="icon-button" aria-label="Router actions"><MoreHorizontal size={18}/></button></div>
            <div className="router-row"><div className="router-icon purple"><Router size={20}/></div><div className="router-info"><b>Remote Office</b><small>198.51.100.10 · RouterOS 7.15</small><div className="router-chips"><span><Check size={12}/> SSH reachable</span><span><Check size={12}/> wg-office active</span></div></div><div className="health"><span className="status-dot"/><b>Healthy</b><small>1 min ago</small></div><button className="icon-button" aria-label="Router actions"><MoreHorizontal size={18}/></button></div>
            <div className="router-footer"><span><span className="legend-dot"/> 2 operational</span><span><span className="legend-dot muted"/> 0 attention needed</span><button onClick={() => setActive("Routers")}>Manage routers ↗</button></div>
          </section>
          <section className="panel traffic-panel"><div className="panel-heading"><div><h2>Network activity</h2><p>Illustrative traffic over the last 7 days</p></div><button className="period-select">7 days <ChevronDown size={14}/></button></div><div className="traffic-total"><strong>8.42 <small>GB</small></strong><span><ArrowUpFromLine size={14}/> Sample traffic</span></div><div className="chart"><div className="y-labels"><span>3 GB</span><span>2 GB</span><span>1 GB</span><span>0</span></div><div className="chart-area"><div className="grid-lines"><i/><i/><i/><i/></div><svg viewBox="0 0 440 142" preserveAspectRatio="none" role="img" aria-label="Illustrative traffic line chart"><defs><linearGradient id="area" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stopColor="#7c6cf4" stopOpacity=".25"/><stop offset="100%" stopColor="#7c6cf4" stopOpacity="0"/></linearGradient></defs><path d="M0,108 C22,101 29,82 55,89 S89,108 110,76 S151,83 165,63 S199,82 220,58 S249,68 275,43 S315,57 331,35 S362,57 385,23 S420,35 440,12 L440,142 L0,142Z" fill="url(#area)"/><path d="M0,108 C22,101 29,82 55,89 S89,108 110,76 S151,83 165,63 S199,82 220,58 S249,68 275,43 S315,57 331,35 S362,57 385,23 S420,35 440,12" fill="none" stroke="#8b7cf6" strokeWidth="2.5" vectorEffect="non-scaling-stroke"/></svg><div className="x-labels"><span>Mon</span><span>Tue</span><span>Wed</span><span>Thu</span><span>Fri</span><span>Sat</span><span>Sun</span></div></div></div><div className="traffic-legend"><span><i className="legend-upload"/> Upload <b>3.1 GB</b></span><span><i className="legend-download"/> Download <b>5.3 GB</b></span></div></section>
        </div>
        <section className="panel devices-panel"><div className="panel-heading device-heading"><div><h2>Recent devices</h2><p>Peer status across your configured routers</p></div><div className="table-actions"><label className="search-box"><Search size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search devices..." /></label><button className="button secondary compact" onClick={() => setActive("Users & devices")}>View all devices <span>→</span></button></div></div>
          <div className="table-wrap"><table><thead><tr><th>DEVICE / USER</th><th>ASSIGNED ADDRESS</th><th>ROUTER</th><th>STATUS</th><th>LAST HANDSHAKE</th><th>TRANSFERRED</th><th></th></tr></thead><tbody>{filteredPeers.map(peer => <tr key={peer.address}><td><div className="peer-cell"><div className="peer-avatar">{peer.name.split(" ").map(s=>s[0]).join("")}</div><div><b>{peer.name}</b><small>{peer.device}</small></div></div></td><td className="mono">{peer.address}</td><td><span className="router-mini"><Router size={13}/>{peer.router}</span></td><td><span className={peer.status === "Online" ? "status-pill online" : "status-pill offline"}><i/>{peer.status}</span></td><td className="last-seen">{peer.lastSeen}</td><td className="transfer">{peer.traffic}</td><td><button className="icon-button" aria-label={`Actions for ${peer.name}`}><MoreHorizontal size={17}/></button></td></tr>)}</tbody></table>{filteredPeers.length === 0 && <div className="empty-state">No devices match “{query}”.</div>}</div>
          <div className="table-footer"><span>Showing <b>{filteredPeers.length}</b> of <b>{peers.length}</b> sample devices</span><button className="text-button" onClick={() => setQuery("")}>Clear search</button></div>
        </section>
        <footer className="footer"><span><span className="footer-dot"/> Demo workspace · no live router connection</span><span>WireGuard Manager <b>v0.1.0</b> <span className="footer-sep">·</span> <a href="https://github.com/nestho/wireguard-manager" target="_blank" rel="noreferrer">GitHub repository ↗</a></span></footer>
      </div>
    </main>
    {showAdd && <div className="modal-backdrop" onClick={() => setShowAdd(false)}><div className="modal" onClick={e => e.stopPropagation()}><button className="modal-close icon-button" onClick={() => setShowAdd(false)} aria-label="Close dialog"><X size={18}/></button><div className="modal-icon"><Plus size={20}/></div><h2>Add a device</h2><p>This preview uses synthetic data. Device creation and router changes are not connected yet.</p><label>Device owner<input placeholder="e.g. Alex Morgan" /></label><label>Device name<input placeholder="e.g. Work laptop" /></label><div className="modal-note"><ShieldOff size={16}/> No keys are generated and no router configuration is changed in demo mode.</div><div className="modal-actions"><button className="button secondary" onClick={() => setShowAdd(false)}>Cancel</button><button className="button primary" onClick={() => setShowAdd(false)}><Check size={16}/> Got it</button></div></div></div>}
  </div>;
}

function Metric({ icon, label, value, meta, good }: { icon: ReactNode; label: string; value: string; meta: string; good?: string }) {
  return <div className="metric-card"><div className="metric-top"><div className="metric-icon">{icon}</div>{good && <span className="metric-badge"><span/> {good}</span>}</div><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-meta">{meta}</div></div>;
}
export default App;