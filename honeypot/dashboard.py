try:
    from fastapi import FastAPI, Request, HTTPException, Depends
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.templating import Jinja2Templates
    import uvicorn
    import asyncio
    import threading
    from pathlib import Path
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
from . import config
from . import db


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SSH Honeypot Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; }
        .header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; }
        .header h1 { font-size: 24px; color: #58a6ff; }
        .header .subtitle { color: #8b949e; font-size: 14px; margin-top: 4px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .stat-card .value { font-size: 32px; font-weight: 600; color: #58a6ff; }
        .stat-card .label { color: #8b949e; font-size: 14px; margin-top: 4px; }
        .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 24px; }
        .section h2 { font-size: 18px; color: #f0f6fc; margin-bottom: 16px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 14px; }
        th { color: #8b949e; font-weight: 600; text-transform: uppercase; font-size: 12px; letter-spacing: 0.5px; }
        td { color: #c9d1d9; }
        .truncate { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .severity-critical { color: #f85149; }
        .severity-high { color: #d29922; }
        .severity-medium { color: #58a6ff; }
        .severity-low { color: #8b949e; }
        .refresh { color: #58a6ff; text-decoration: none; font-size: 14px; margin-left: 12px; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
        .badge-password { background: #1f6feb22; color: #58a6ff; border: 1px solid #1f6feb44; }
        .badge-publickey { background: #d2992222; color: #d29922; border: 1px solid #d2992244; }
        .badge-exec { background: #f8514922; color: #f85149; border: 1px solid #f8514944; }
        .loading { text-align: center; padding: 40px; color: #8b949e; }
        @media (max-width: 768px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
    </style>
</head>
<body>
    <div class="header">
        <h1>SSH Honeypot Dashboard</h1>
        <div class="subtitle">Real-time attack monitoring & analysis <a href="#" class="refresh" onclick="location.reload()">&#8635; Refresh</a></div>
    </div>
    <div class="container">
        <div class="stats-grid" id="stats"></div>
        <div class="section">
            <h2>Recent Attacks</h2>
            <div style="overflow-x: auto;"><table><thead><tr>
                <th>Time</th><th>IP</th><th>Username</th><th>Password/Key</th><th>Method</th><th>Location</th>
            </tr></thead><tbody id="recent"></tbody></table></div>
        </div>
        <div class="section">
            <h2>Top Usernames</h2>
            <table><thead><tr><th>Username</th><th>Attempts</th></tr></thead><tbody id="usernames"></tbody></table>
        </div>
        <div class="section">
            <h2>Top Passwords</h2>
            <table><thead><tr><th>Password</th><th>Attempts</th></tr></thead><tbody id="passwords"></tbody></table>
        </div>
        <div class="section">
            <h2>Top IPs</h2>
            <table><thead><tr><th>IP</th><th>Attempts</th></tr></thead><tbody id="ips"></tbody></table>
        </div>
    </div>
    <script>
        async function load() {
            try {
                const r = await fetch('/api/stats');
                if (!r.ok) throw new Error('Auth required');
                const d = await r.json();
                document.getElementById('stats').innerHTML = `
                    <div class="stat-card"><div class="value">${d.total_attempts}</div><div class="label">Total Auth Attempts</div></div>
                    <div class="stat-card"><div class="value">${d.unique_ips}</div><div class="label">Unique IPs</div></div>
                    <div class="stat-card"><div class="value">${d.recent?.length || 0}</div><div class="label">Recent (50)</div></div>
                `;
                const recentTbody = document.getElementById('recent');
                recentTbody.innerHTML = (d.recent || []).map(r => {
                    const methodBadge = `badge-${r.method}`;
                    return `<tr>
                        <td style="white-space:nowrap">${r.timestamp?.split('T')[1]?.split('.')[0] || ''}</td>
                        <td><b>${r.ip}</b></td>
                        <td class="truncate">${r.username || ''}</td>
                        <td class="truncate">${r.password || ''}</td>
                        <td><span class="badge ${methodBadge}">${r.method}</span></td>
                        <td>${r.city || ''}${r.city && r.country ? ', ' : ''}${r.country || ''}</td>
                    </tr>`;
                }).join('');
                const userTbody = document.getElementById('usernames');
                userTbody.innerHTML = (d.top_usernames || []).map(u =>
                    `<tr><td><b>${u.username}</b></td><td>${u.count}</td></tr>`
                ).join('');
                const passTbody = document.getElementById('passwords');
                passTbody.innerHTML = (d.top_passwords || []).map(p =>
                    `<tr><td class="truncate">${p.password}</td><td>${p.count}</td></tr>`
                ).join('');
                const ipTbody = document.getElementById('ips');
                ipTbody.innerHTML = (d.top_ips || []).map(i =>
                    `<tr><td><b>${i.ip}</b></td><td>${i.count}</td></tr>`
                ).join('');
            } catch(e) {
                document.querySelector('.container').innerHTML = '<div class="loading">Unable to load dashboard. Is the database initialized?</div>';
            }
        }
        load();
        setInterval(load, 10000);
    </script>
</body>
</html>"""


class DashboardServer:

    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._app = None

    def _create_app(self):
        app = FastAPI(title="SSH Honeypot Dashboard")
        @app.get("/api/stats")
        async def get_stats(request: Request):
            auth = request.headers.get("Authorization", "")
            if not self._check_auth(auth):
                raise HTTPException(status_code=401, headers={"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'})
            return db.get_stats()
        @app.get("/")
        async def dashboard(request: Request):
            return HTMLResponse(_HTML_TEMPLATE)
        return app
    def _check_auth(self, auth: str) -> bool:
        import base64
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode()
            user, pwd = decoded.split(":", 1)
            return user == config.DASHBOARD_USER and pwd == config.DASHBOARD_PASSWORD
        except Exception:
            return False

    def start(self):
        if not _FASTAPI_AVAILABLE:
            print("[!] FastAPI/uvicorn not installed. Dashboard disabled.")
            print("    Install with: pip install fastapi uvicorn")
            return

        def run():
            try:
                app = self._create_app()
                uvicorn.run(app, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT, log_level="warning")
            except Exception as e:
                print(f"[!] Dashboard error: {e}")

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        print(f"[*] Dashboard started at http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")

    def stop(self):
        pass


_dashboard_instance: Optional[DashboardServer] = None


def get_dashboard() -> DashboardServer:
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = DashboardServer()
    return _dashboard_instance
