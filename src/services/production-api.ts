const API_BASE = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/$/, "");

export type Session = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  user: { username: string; role: "admin" | "operator" | "viewer" };
};
let session: Session | null = (() => { try { const raw = sessionStorage.getItem("wgm-production-session"); return raw ? JSON.parse(raw) as Session : null; } catch { return null; } })();
let refreshTimer: number | undefined;

export function getSession() { return session; }
export function setSession(value: Session | null) {
  session = value;
  try { if (value) sessionStorage.setItem("wgm-production-session", JSON.stringify(value)); else sessionStorage.removeItem("wgm-production-session"); } catch { /* Private browsing may disable storage; in-memory auth still works. */ }
  if (refreshTimer) window.clearTimeout(refreshTimer);
  if (value) {
    // Refresh shortly before the 15-minute access token expires.
    refreshTimer = window.setTimeout(() => { void refreshSession(); }, Math.max(30, value.expires_in - 60) * 1000);
  }
}
async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (session?.access_token && path !== "/v1/auth/login" && path !== "/v1/auth/refresh") headers.set("Authorization", `Bearer ${session.access_token}`);
  const response = await fetch(`${API_BASE}${path.startsWith("/") ? path : `/${path}`}`, { ...init, headers, credentials: "same-origin" });
  if (response.status === 401 && retry && session?.refresh_token && path !== "/v1/auth/refresh") {
    await refreshSession();
    return request<T>(path, init, false);
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `${response.status} ${response.statusText}`);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}
async function refreshSession() {
  if (!session?.refresh_token) { setSession(null); throw new Error("Session expired. Sign in again."); }
  const refreshed = await request<Session>("/v1/auth/refresh", { method: "POST", body: JSON.stringify({ refresh_token: session.refresh_token }) }, false);
  setSession(refreshed);
  return refreshed;
}
export async function login(username: string, password: string) {
  const value = await request<Session>("/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }, false);
  setSession(value); return value;
}
export async function logout() {
  const token = session?.refresh_token;
  try { if (token) await request<void>("/v1/auth/logout", { method: "POST", body: JSON.stringify({ refresh_token: token }) }, false); }
  finally { setSession(null); }
}
export const api = {
  health: () => request<{status:string;service:string}>("/v1/health"),
  routers: () => request<RouterRecord[]>("/v1/routers"),
  addRouter: (body: {name:string;host:string;port:number;username:string;password:string;tls_verify:true}) =>
    request<RouterRecord>("/v1/routers", {method:"POST",body:JSON.stringify(body)}),
  testRouter: (id:number|string) => request<{status:string;identity:unknown;resource:Record<string,unknown>}>(`/v1/routers/${id}/test`,{method:"POST"}),
  routerPeers: (id:number|string) => request<{router_id:number;interfaces:Record<string,unknown>[];peers:Record<string,unknown>[];read_only:boolean;retrieved_at:string}>(`/v1/routers/${id}/wireguard/peers`),
  routerTraffic: (id:number|string) => request<{router_id:number;historical:false;peers:TrafficPeer[]}>(`/v1/routers/${id}/traffic`),
  routerDiagnostics: (id:number|string) => request<{router_id:number;status:string;checks:{name:string;status:string;duration_ms:number;item_count:number|null}[]}>(`/v1/routers/${id}/diagnostics`,{method:"POST"}),
  linuxServers: () => request<LinuxServer[]>("/v1/linux-servers"),
  registerLinux: (body: {name:string;host:string;port:number;username:string;ssh_private_key:string;host_key_fingerprint:string}) =>
    request<LinuxServer>("/v1/linux-servers",{method:"POST",body:JSON.stringify(body)}),
  inspectLinux: (id:number|string) => request<{server:LinuxServer;supported:boolean;wireguard_installed:boolean;install_plan:{step:string;command:string}[]}>(`/v1/linux-servers/${id}/inspect`,{method:"POST"}),
  linuxPeers: (id:number|string) => request<LinuxPeer[]>(`/v1/linux-servers/${id}/peers`),
  remoteLinuxPeers: (id:number|string) => request<{server_id:number;interfaces:string[];peers:Record<string,unknown>[];historical:false}>(`/v1/linux-servers/${id}/peers/remote`),
  auditRouter: (id:number|string) => request<Record<string,unknown>>(`/v1/routers/${id}/audit`),
  createUser: (body:{username:string;password:string;role:"admin"|"operator"|"viewer"}) => request<{id:number;username:string;role:string;is_active:boolean}>("/v1/auth/users",{method:"POST",body:JSON.stringify(body)}),
};
export type RouterRecord = {id:number;name:string;host:string;port:number;username:string;tls_verify:boolean;last_status:string;created_at:string};
export type LinuxServer = {id:number;name:string;host:string;port:number;username:string;distro_id:string|null;distro_version:string|null;package_manager:string|null;wireguard_installed:boolean;last_status:string;last_check_at:string|null;created_at:string};
export type LinuxPeer = {id:number;server_id:number;interface_name:string;name:string;public_key:string;allowed_address:string;access_networks:string[];access_control_applied:boolean;status:string;created_at:string};
export type TrafficPeer = {router_peer_id:string;name:string;public_key:string;allowed_address:string;rx_bytes:number;tx_bytes:number;last_handshake:string|null;disabled:boolean;collected_at:string};
