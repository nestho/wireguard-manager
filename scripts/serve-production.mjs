import http from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { extname, resolve, sep } from "node:path";

const root = resolve(process.env.WGM_WEB_ROOT || "dist-production");
const port = Number(process.env.WGM_WEB_PORT || 4173);
const apiHost = process.env.WGM_API_HOST || "127.0.0.1";
const apiPort = Number(process.env.WGM_API_PORT || 8000);
const types = {".html":"text/html; charset=utf-8",".js":"text/javascript; charset=utf-8",".css":"text/css; charset=utf-8",".svg":"image/svg+xml",".png":"image/png",".ico":"image/x-icon",".woff2":"font/woff2",".json":"application/json; charset=utf-8"};

const server = http.createServer((req,res) => {
  const pathname = new URL(req.url || "/", "http://localhost").pathname;
  if (pathname === "/healthz") { res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"}); res.end(JSON.stringify({status:"ok",service:"wireguard-manager-web"})); return; }
  if (pathname === "/api" || pathname.startsWith("/api/")) {
    const upstream = http.request({hostname:apiHost,port:apiPort,path:req.url,method:req.method,headers:{...req.headers,host:apiHost+":"+apiPort}}, response => {
      res.writeHead(response.statusCode || 502, response.headers); response.pipe(res);
    });
    upstream.on("error",()=>{if(!res.headersSent){res.writeHead(502,{"content-type":"application/json","cache-control":"no-store"});}res.end(JSON.stringify({detail:"Backend API unavailable"}));});
    req.pipe(upstream); return;
  }
  let requested;
  try { requested=decodeURIComponent(pathname); } catch { res.writeHead(400);res.end("Bad request");return; }
  let file=resolve(root,"."+requested);
  if(file!==root && !file.startsWith(root+sep)){res.writeHead(403);res.end("Forbidden");return;}
  if(!existsSync(file)||!statSync(file).isFile()) file=resolve(root,"index.production.html");
  if(!existsSync(file)){res.writeHead(503);res.end("Production frontend is not built");return;}
  const ext=extname(file);
  const headers={"content-type":types[ext]||"application/octet-stream","x-content-type-options":"nosniff","referrer-policy":"same-origin","x-frame-options":"DENY","content-security-policy":"default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'","cache-control":ext===".html"?"no-store":"public, max-age=3600"};
  res.writeHead(200,headers);createReadStream(file).pipe(res);
});
server.listen(port,"127.0.0.1",()=>console.log(`wireguard-manager-web listening on 127.0.0.1:${port}; static root ${root}`));
for(const signal of ["SIGTERM","SIGINT"])process.on(signal,()=>server.close(()=>process.exit(0)));
