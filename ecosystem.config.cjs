module.exports = {
  apps: [{
    name: "wireguard-manager",
    cwd: __dirname,
    script: "./.venv/bin/uvicorn",
    args: "wireguard_manager_api.main:app --app-dir backend --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1",
    interpreter: "none",
    instances: 1,
    exec_mode: "fork",
    autorestart: true,
    watch: false,
    max_memory_restart: "500M",
    min_uptime: "10s",
    max_restarts: 10,
    restart_delay: 3000,
    time: true,
    out_file: "./logs/pm2-out.log",
    error_file: "./logs/pm2-error.log",
    merge_logs: true,
    env: { PYTHONUNBUFFERED: "1", WGM_ENV: "production" }
  }]
};
