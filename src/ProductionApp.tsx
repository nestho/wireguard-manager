import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";

type User = { username: string; role: string };
type RouterItem = { id: number; name: string; host: string; port: number; username: string; tls_verify: boolean; last_status: string; created_at: string };
type LinuxServer = { id: number; name: string; host: string; port: number; username: string; distro_id?: string | null; distro_version?: string | null; package_manager?: string | null; wireguard_installed: boolean; last_status: string; last_check_at?: string | null };
type ApiError = { detail?: string };
const api = async <T,>(path: string, init: RequestInit = {}, token?: string): Promise<T> => {
  const headers = new Headers(init.headers); headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", "Bearer " + token);
  const response = await fetch(path, { ...init, headers, credentials: "same-origin", cache: "no-store" });
  if (!response.ok) {
    let message = "Request failed (" + response.status + ")";
    try { const body = await response.json() as ApiError; if (body.detail) message = body.detail; } catch { /* non-JSON error */ }
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
};

export default function ProductionApp() {
  const [user, setUser] = useState<User | null>(null);
  const [access, setAccess] = useState(() => sessionStorage.getItem("wgm_access") || "");
  const [refresh, setRefresh] = useState(() => sessionStorage.getItem("wgm_refresh") || "");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [routers, setRouters] = useState<RouterItem[]>([]);
  const [servers, setServers] = useState<LinuxServer[]>([]);
  const [selectedRouter, setSelectedRouter] = useState<number | null>(null);
  const [routerDetail, setRouterDetail] = useState<unknown>(null);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [view, setView] = useState<"routers" | "linux">("routers");
  const [adding, setAdding] = useState<"router" | "linux" | null>(null);
  const [health, setHealth] = useState("Checking API…");

  const clearSession = useCallback(() => {
    sessionStorage.removeItem("wgm_access"); sessionStorage.removeItem("wgm_refresh");
    setAccess(""); setRefresh(""); setUser(null); setRouters([]); setServers([]); setRouterDetail(null);
  }, []);
  const loadData = useCallback(async (token: string) => {
    const [me, routerList, serverList] = await Promise.all([
      api<User & { is_active: boolean }>("/api/v1/auth/me", {}, token),
      api<RouterItem[]>("/api/v1/routers", {}, token),
      api<LinuxServer[]>("/api/v1/linux-servers", {}, token),
    ]);
    setUser({ username: me.username, role: me.role }); setRouters(routerList); setServers(serverList);
    setHealth("Connected to production API");
  }, []);

  useEffect(() => { api<{status:string}>("/api/v1/health").then(() => setHealth("API healthy")).catch(() => setHealth("API unavailable")); }, []);
  useEffect(() => {
    if (!access) return;
    loadData(access).catch(async () => {
      if (!refresh) { clearSession(); return; }
      try {
        const rotated = await api<{access_token:string;refresh_token:string}>("/api/v1/auth/refresh", { method:"POST", body:JSON.stringify({refresh_token:refresh}) });
        sessionStorage.setItem("wgm_access", rotated.access_token); sessionStorage.setItem("wgm_refresh", rotated.refresh_token);
        setAccess(rotated.access_token); setRefresh(rotated.refresh_token); await loadData(rotated.access_token);
      } catch { clearSession(); }
    });
  }, [access, refresh, loadData, clearSession]);

  const login = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(""); setNotice("");
    try {
      const result = await api<{access_token:string;refresh_token:string;user:User}>("/api/v1/auth/login", { method:"POST", body:JSON.stringify({username,password}) });
      sessionStorage.setItem("wgm_access", result.access_token); sessionStorage.setItem("wgm_refresh", result.refresh_token);
      setAccess(result.access_token); setRefresh(result.refresh_token); setPassword(""); await loadData(result.access_token);
    } catch (e) { setError(e instanceof Error ? e.message : "Login failed"); }
    finally { setBusy(false); }
  };
  const logout = async () => {
    try { if (refresh) await api("/api/v1/auth/logout", { method:"POST", body:JSON.stringify({refresh_token:refresh}) }); } catch { /* clear local session even if API is unavailable */ }
    clearSession(); setNotice("Signed out.");
  };
  const inspectRouter = async (id: number) => {
    setSelectedRouter(id); setRouterDetail(null); setError("");
    try { setRouterDetail(await api("/api/v1/routers/" + id + "/wireguard/peers", {}, access)); }
    catch (e) { setError(e instanceof Error ? e.message : "Unable to read router"); }
  };
  const refreshInventory = async () => {
    setBusy(true); setError("");
    try { await loadData(access); setNotice("Inventory refreshed from the API."); }
    catch (e) { setError(e instanceof Error ? e.message : "Refresh failed"); }
    finally { setBusy(false); }
  };
  const registerResource = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!adding) return;
    setBusy(true); setError("");
    const form = new FormData(event.currentTarget);
    try {
      if (adding === "router") {
        await api("/api/v1/routers", { method:"POST", body:JSON.stringify({
          name:String(form.get("name") || "").trim(),
          host:String(form.get("host") || "").trim(),
          port:Number(form.get("port") || 443),
          username:String(form.get("username") || "").trim(),
          password:String(form.get("password") || ""),
          tls_verify:true
        }) }, access);
      } else {
        await api("/api/v1/linux-servers", { method:"POST", body:JSON.stringify({
          name:String(form.get("name") || "").trim(),
          host:String(form.get("host") || "").trim(),
          port:Number(form.get("port") || 22),
          username:String(form.get("username") || "").trim(),
          ssh_private_key:String(form.get("ssh_private_key") || ""),
          host_key_fingerprint:String(form.get("host_key_fingerprint") || "").trim()
        }) }, access);
      }
      setAdding(null);
      await loadData(access);
      setNotice(adding === "router" ? "Router registered. Connection status remains unverified until tested." : "Linux server registered. SSH host-key pinning is saved; run an inspection before operations.");
    } catch (e) { setError(e instanceof Error ? e.message : "Registration failed"); }
    finally { setBusy(false); }
  };

  return <main className="prod-shell">
    <header className="prod-header"><div className="prod-brand"><span className="prod-mark">WG</span><div><h1>WireGuard Manager</h1><p>Production control plane · live API data only</p></div></div><span className="prod-health">{health}</span></header>
    {error && <div className="prod-alert prod-error" role="alert">{error}<button onClick={() => setError("")} aria-label="Dismiss error">×</button></div>}
    {notice && <div className="prod-alert prod-success">{notice}<button onClick={() => setNotice("")} aria-label="Dismiss notice">×</button></div>}
    {!user ? <section className="prod-login"><div className="prod-kicker">AUTHENTICATED MANAGEMENT</div><h2>Sign in to your workspace</h2><p>No sample inventory is loaded in production mode. This view displays only records returned by your API.</p><form onSubmit={login}>
      <label>Username<input autoComplete="username" value={username} onChange={e=>setUsername(e.target.value)} required /></label>
      <label>Password<input type="password" autoComplete="current-password" value={password} onChange={e=>setPassword(e.target.value)} required /></label>
      <button className="prod-primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form><small>Initial admin is provisioned once by the deployment script.</small></section>
    : <><section className="prod-welcome"><div><div className="prod-kicker">LIVE WORKSPACE</div><h2>Welcome, {user.username}</h2><p>Role: <b>{user.role}</b> · Inventory is read directly from the API.</p></div><div className="prod-actions"><button onClick={refreshInventory} disabled={busy}>{busy ? "Refreshing…" : "Refresh inventory"}</button><button onClick={logout}>Sign out</button></div></section>
    <section className="prod-stats"><article><span>Registered routers</span><strong>{routers.length}</strong><small>Persisted in backend database</small></article><article><span>Linux servers</span><strong>{servers.length}</strong><small>Persisted in backend database</small></article><article><span>Healthy routers</span><strong>{routers.filter(r=>r.last_status==="healthy").length}</strong><small>Last recorded status, not a live probe</small></article><article><span>WireGuard servers ready</span><strong>{servers.filter(s=>s.wireguard_installed).length}</strong><small>Based on last server inspection</small></article></section>
    <section className="prod-panel"><div className="prod-panel-toolbar"><div><strong>Infrastructure inventory</strong><small>Live records from the backend database</small></div>{((view==="routers" && (user.role==="admin" || user.role==="operator")) || (view==="linux" && user.role==="admin")) && <button className="prod-primary" onClick={()=>setAdding(view==="routers"?"router":"linux")}>Register {view==="routers"?"router":"Linux server"}</button>}</div><div className="prod-tabs"><button className={view==="routers"?"active":""} onClick={()=>{setView("routers");setRouterDetail(null)}}>RouterOS routers ({routers.length})</button><button className={view==="linux"?"active":""} onClick={()=>{setView("linux");setRouterDetail(null)}}>Linux servers ({servers.length})</button></div>
    {view==="routers" ? <div className="prod-table-wrap"><table><thead><tr><th>Name</th><th>Host</th><th>Account</th><th>Last status</th><th>Action</th></tr></thead><tbody>{routers.map(r=><tr key={r.id}><td>{r.name}</td><td><code>{r.host}:{r.port}</code></td><td>{r.username}</td><td><span className={"prod-badge "+r.last_status}>{r.last_status}</span></td><td><button onClick={()=>inspectRouter(r.id)}>Read WireGuard peers</button></td></tr>)}{!routers.length&&<tr><td colSpan={5} className="prod-empty">No routers registered. The database is empty; no sample data is substituted.</td></tr>}</tbody></table></div>
    : <div className="prod-table-wrap"><table><thead><tr><th>Name</th><th>Host</th><th>SSH account</th><th>Distribution</th><th>WireGuard</th><th>Status</th></tr></thead><tbody>{servers.map(s=><tr key={s.id}><td>{s.name}</td><td><code>{s.host}:{s.port}</code></td><td>{s.username}</td><td>{s.distro_id || "Not inspected"} {s.distro_version || ""}</td><td>{s.wireguard_installed?"Installed":"Unknown / absent"}</td><td><span className={"prod-badge "+s.last_status}>{s.last_status}</span></td></tr>)}{!servers.length&&<tr><td colSpan={6} className="prod-empty">No Linux servers registered. No sample data is substituted.</td></tr>}</tbody></table></div>}
    </section>
    {adding && <div className="prod-modal-backdrop"><section className="prod-modal" role="dialog" aria-modal="true" aria-labelledby="prod-modal-title"><div className="prod-panel-title"><h3 id="prod-modal-title">Register {adding==="router"?"RouterOS router":"Linux server"}</h3><button type="button" onClick={()=>setAdding(null)} disabled={busy}>Cancel</button></div><p>Credentials are sent directly to the API over this same origin and are not saved in browser storage.</p><form className="prod-register-form" onSubmit={registerResource}>
      <label>Display name<input name="name" maxLength={120} required /></label>
      <label>Private management IP<input name="host" placeholder="192.168.1.10" inputMode="decimal" required /></label>
      <label>{adding==="router"?"RouterOS HTTPS port":"SSH port"}<input name="port" type="number" min="1" max="65535" defaultValue={adding==="router"?443:22} required /></label>
      <label>{adding==="router"?"RouterOS account":"SSH account"}<input name="username" autoComplete="off" required /></label>
      {adding==="router" ? <label>RouterOS password<input name="password" type="password" autoComplete="new-password" required /></label> : <><label>SSH private key<textarea name="ssh_private_key" rows={7} autoComplete="off" spellCheck={false} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" required /></label><label>Verified SSH host-key fingerprint<input name="host_key_fingerprint" placeholder="SHA256:…" required /></label><small>Verify the SHA256 fingerprint through a trusted channel before registering the server.</small></>}
      <div className="prod-form-actions"><button type="button" onClick={()=>setAdding(null)} disabled={busy}>Cancel</button><button className="prod-primary" disabled={busy}>{busy?"Registering…":"Register"}</button></div>
    </form></section></div>}
    {routerDetail !== null && <section className="prod-panel"><div className="prod-panel-title"><h3>Live WireGuard data · Router #{selectedRouter}</h3><button onClick={()=>setRouterDetail(null)}>Close</button></div><p>Read-only result from the registered router. Treat peer metadata as sensitive operational data.</p><pre>{JSON.stringify(routerDetail,null,2)}</pre></section>}
    <p className="prod-footnote">Production mode does not use browser local storage, synthetic routers, sample peers, or demo audit events. Router peer reads are read-only. Mutations are not exposed in this initial production UI.</p></>}
  </main>;
}
