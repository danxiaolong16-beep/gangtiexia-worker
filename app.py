from flask import Flask, jsonify, request, g
import os, re, time, datetime, collections, ipaddress, socket
import urllib.request, urllib.error
from urllib.parse import urlparse

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


# ---------- HTTP 中转 /relay（只转公开网址，不做 VPN/隧道） ----------
# 用途：VM 里的浏览器出不了网，Render 能正常出网，所以让 Render 代抓
# 公开网页/API（比如 X 新闻榜单的镜像站、GitHub API），结果原样返回。
# 安全边界（对应刚学完的 SSRF 防法）：
#   * 只允许白名单里的公开 host，别的域名一律 403；
#   * 只允许 https，http 一律拒绝；
#   * 发请求前先解析域名，解析到内网/保留地址（127/10/172.16/192.168/
#     169.254 云元数据等）一律拒绝，防 SSRF 打内网；
#   * 只做 GET，超时 20 秒，正文最多 1MB，超了截断并标注；
#   * 可选口令：Render 里设置了 RELAY_TOKEN 环境变量后，调用必须带
#     X-Relay-Token 请求头；没设时只靠白名单（任何人都能转白名单站，
#     滥用价值很低，但建议还是设一个口令）。
#   * 每次调用都记一条 relay 记录，可在 /watchdog 里看到。
RELAY_ALLOWED_HOSTS = {
    "www.neteye.dev", "neteye.dev",          # X 热榜镜像站（X 新闻动态供料用）
    "whatstrends.com", "www.whatstrends.com",  # X 热榜镜像站（备用）
    "api.github.com", "raw.githubusercontent.com",  # GitHub API / 原始文件
}
RELAY_TIMEOUT_SECS = 20
RELAY_MAX_BYTES = 1_000_000


def _relay_reject(reason):
    _alert(g.ip, "relay-rejected", reason[:200])
    return jsonify({"ok": False, "error": reason}), 403


@app.route("/relay", methods=["POST"])
def relay():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    token = os.environ.get("RELAY_TOKEN", "")
    if token and request.headers.get("X-Relay-Token", "") != token:
        return _relay_reject("missing or wrong X-Relay-Token")
    if not url:
        return jsonify({"ok": False, "error": "need JSON {\"url\": \"https://...\"}"}), 400
    try:
        parsed = urlparse(url)
    except Exception:
        return _relay_reject("bad url")
    if parsed.scheme != "https" or not parsed.hostname:
        return _relay_reject("only https URLs are allowed")
    host = parsed.hostname.lower()
    if host not in RELAY_ALLOWED_HOSTS:
        return _relay_reject(f"host not in relay allowlist: {host}")
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return _relay_reject(f"cannot resolve host: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local \
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return _relay_reject(f"host resolves to non-public IP: {ip}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "gangtiexia-worker-relay/1.0"})
        with urllib.request.urlopen(req, timeout=RELAY_TIMEOUT_SECS) as resp:
            raw = resp.read(RELAY_MAX_BYTES + 1)
            charset = resp.headers.get_content_charset() or "utf-8"
            truncated = len(raw) > RELAY_MAX_BYTES
            text = raw[:RELAY_MAX_BYTES].decode(charset, errors="replace")
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        return jsonify({"ok": False, "error": f"upstream HTTP {e.code}"}), 502
    except Exception as e:
        return jsonify({"ok": False, "error": f"fetch failed: {type(e).__name__}"}), 502
    _alert(g.ip, "relay", f"fetched {url[:150]} -> {status}, truncated={truncated}")
    return jsonify({"ok": True, "url": url, "status": status,
                    "content_type": content_type, "truncated": truncated,
                    "text": text})


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
