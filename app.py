from flask import Flask, jsonify, request, g
import os, re, time, datetime, collections

app = Flask(__name__)

# ---------- 看门狗（只防不攻） ----------
# 作用：发现扫描/注入/爆破等可疑请求就记日志、拉黑 IP、返回 403，
# 并在 /watchdog 里留一条报警记录。绝不反向攻击对方：
# 对方 IP 可能是伪造的、跳板机或无辜主机，反攻违法且会误伤。
BLOCK_MINUTES = 60
RATE_LIMIT_PER_MIN = 120          # 同一 IP 每分钟最多 120 次
SUSPICIOUS_TO_BLOCK = 3           # 10 分钟内 3 次可疑请求就拉黑

SUSPICIOUS_PATTERNS = [
    r"\.\./", r"%2e%2e", r"<script", r"union\s+select", r"select\s+.*\s+from",
    r"drop\s+table", r"insert\s+into", r"'\s*or\s+'1'\s*=\s*'1", r"or\s+1=1",
    r"eval\(", r"base64_decode", r"\$\{", r"__proto__", r"/etc/passwd",
    r"cmd=", r"shell", r"wget\s+http", r"curl\s+http",
]
SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.IGNORECASE)
SCAN_PATHS = {"/.env", "/.git/config", "/wp-admin", "/wp-login.php",
              "/phpmyadmin", "/admin", "/.aws/credentials", "/config.php",
              "/actuator/env", "/.svn/entries"}

_hits = collections.defaultdict(list)       # ip -> [timestamps]
_suspicious = collections.defaultdict(list) # ip -> [timestamps]
_blocked_until = {}                          # ip -> epoch
_alerts = collections.deque(maxlen=100)      # 最近 100 条报警


def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "unknown")


def _alert(ip, kind, detail):
    rec = {"time_utc": datetime.datetime.utcnow().isoformat() + "Z",
           "ip": ip, "kind": kind, "path": request.path, "detail": detail}
    _alerts.appendleft(rec)
    print(f"[WATCHDOG ALERT] {rec}", flush=True)
    return rec


def _block(ip, kind):
    _blocked_until[ip] = time.time() + BLOCK_MINUTES * 60
    _alert(ip, kind, f"IP 已拉黑 {BLOCK_MINUTES} 分钟，期间全部请求返回 403")


@app.before_request
def watchdog():
    g.ip = _client_ip()
    # /health 是 Render 的健康检查，/watchdog 是查报警用的，
    # 这两条路本身不拉黑，否则健康检查会失败、报警也看不到。
    if request.path in ("/health", "/watchdog"):
        return None
    now = time.time()
    # 已拉黑
    if _blocked_until.get(g.ip, 0) > now:
        return jsonify({"ok": False, "error": "blocked by watchdog"}), 403
    # 限流
    _hits[g.ip] = [t for t in _hits[g.ip] if now - t < 60]
    _hits[g.ip].append(now)
    if len(_hits[g.ip]) > RATE_LIMIT_PER_MIN:
        _block(g.ip, "rate-limit")
        return jsonify({"ok": False, "error": "blocked by watchdog"}), 403
    # 可疑特征：路径、参数、User-Agent 一起查
    haystack = request.path + "?" + request.query_string.decode("utf-8", "ignore") \
        + " " + request.headers.get("User-Agent", "")
    if request.path in SCAN_PATHS or SUSPICIOUS_RE.search(haystack):
        _suspicious[g.ip] = [t for t in _suspicious[g.ip] if now - t < 600]
        _suspicious[g.ip].append(now)
        _alert(g.ip, "suspicious-request", haystack[:200])
        if len(_suspicious[g.ip]) >= SUSPICIOUS_TO_BLOCK:
            _block(g.ip, "suspicious-request")
        return jsonify({"ok": False, "error": "blocked by watchdog"}), 403


@app.route("/")
def index():
    return jsonify({
        "name": "gangtiexia-worker",
        "status": "online",
        "time_utc": datetime.datetime.utcnow().isoformat() + "Z",
        "note": "免费 Render 实例，给钢铁侠分担轻量任务",
        "watchdog": "on",
    })


@app.route("/health")
def health():
    return jsonify({"ok": True})


@app.route("/run")
def run():
    # 这里以后接真正的分担任务：比如拉 GitHub 更新、跑个小爬虫测试
    return jsonify({"ok": True, "job": "test-run", "result": "hello from free server"})


@app.route("/watchdog")
def watchdog_status():
    now = time.time()
    blocked = [ip for ip, until in _blocked_until.items() if until > now]
    return jsonify({
        "watchdog": "on",
        "blocked_ips": blocked,
        "blocked_count": len(blocked),
        "alert_count": len(_alerts),
        "recent_alerts": list(_alerts)[:20],
        "policy": "detect + block + alert only, never counter-attack",
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
