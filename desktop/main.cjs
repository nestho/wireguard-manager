const { app, BrowserWindow, ipcMain, shell } = require("electron");
const path = require("node:path");

function validateBaseUrl(value) {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("API URL must be a plain HTTP(S) origin without credentials, query, or fragment.");
  }
  if (url.pathname !== "/" && url.pathname !== "") {
    throw new Error("API URL must be an origin only, without a path.");
  }
  return url.origin;
}

function allowedRequest(pathname, method) {
  if (pathname === "/api/v1/auth/login" && method === "POST") return true;
  if (pathname === "/api/v1/routers" && method === "GET") return true;
  return /^\/api\/v1\/routers\/\d+\/audit$/.test(pathname) && method === "GET";
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1180,
    height: 860,
    minWidth: 760,
    minHeight: 600,
    title: "WireGuard Manager — Read-only Audit",
    backgroundColor: "#0b1020",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, "index.html"));
}

ipcMain.handle("wgm:request", async (_event, input) => {
  if (!input || typeof input !== "object") throw new Error("Invalid request.");
  const baseUrl = validateBaseUrl(String(input.baseUrl || ""));
  const method = String(input.method || "GET").toUpperCase();
  const pathname = String(input.path || "");
  if (!allowedRequest(pathname, method)) throw new Error("This desktop client permits only login, router inventory, and read-only audit requests.");
  const headers = { Accept: "application/json" };
  if (input.token) {
    if (typeof input.token !== "string" || input.token.length > 8192) throw new Error("Invalid session token.");
    headers.Authorization = "Bearer " + input.token;
  }
  const options = { method, headers, redirect: "error", signal: AbortSignal.timeout(90000) };
  if (method === "POST") {
    const body = input.body;
    if (!body || typeof body.username !== "string" || typeof body.password !== "string") throw new Error("Invalid login payload.");
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify({ username: body.username, password: body.password });
  }
  const response = await fetch(baseUrl + pathname, options);
  const text = await response.text();
  let payload = {};
  if (text) {
    try { payload = JSON.parse(text); }
    catch { throw new Error("API returned a non-JSON response (HTTP " + response.status + ")."); }
  }
  if (!response.ok) {
    const message = payload && typeof payload.detail === "string" ? payload.detail : "API request failed (HTTP " + response.status + ").";
    throw new Error(message);
  }
  return payload;
});

ipcMain.handle("wgm:open-docs", async (_event, value) => {
  const origin = validateBaseUrl(String(value || ""));
  await shell.openExternal(origin + "/docs");
});
ipcMain.handle("wgm:close", (event) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  if (win) win.close();
});

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});
app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
