# Render 中转 /relay — gangtiexia-worker

状态：代码已写好并在本地测通，**还没上线**。上线需用户一句话：
把 `app.py`（和本文件）推到 GitHub 仓库
`danxiaolong16-beep/gangtiexia-worker`，Render 会自动重新部署。

## 为什么要它

VM 里的浏览器出不了网，Render 能正常出网。让 Render 代抓公开网页/API，
结果原样返回，就能给「X 新闻动态」供料、调 GitHub API。

## 调用方法

```bash
curl -X POST https://gangtiexia-worker.onrender.com/relay \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://www.neteye.dev/en/trending/us"}'
```

返回 JSON：`{"ok": true, "url": ..., "status": 200, "content_type": ...,
"truncated": false, "text": "..."}`。
注意：免费实例休眠后第一次调用要等约 40 秒才醒（2026-11-13 实测 42.9 秒）。

## 安全边界（对应刚学完的 SSRF 防法）

- 白名单 host（`RELAY_ALLOWED_HOSTS`）：`neteye.dev`、`whatstrends.com`
  （X 热榜镜像站）、`api.github.com`、`raw.githubusercontent.com`。
  别的域名一律 403。加站要改白名单再部署。
- 只允许 `https`，`http` 一律拒绝。
- 发请求前先解析域名，解析到内网/保留地址（127/10/172.16/192.168/
  169.254 云元数据、组播等）一律拒绝，防 SSRF 打内网。
- 只做 GET，超时 20 秒，正文最多 1MB，超了截断并标注 `truncated: true`。
- 可选口令：Render 里设了 `RELAY_TOKEN` 环境变量后，调用必须带
  `X-Relay-Token` 请求头；没设时只靠白名单（任何人都能转白名单站，
  滥用价值很低，但建议还是设一个口令）。
- 每次调用（成功或拒绝）都在 `/watchdog` 留一条 `relay` /
  `relay-rejected` 记录。
- 不做 VPN、不做 TCP 隧道、不转大文件/视频流/长连接。

## 本地测试结果（2026-11-13，VM 上）

- 非白名单站 `https://example.com/` → 403「host not in relay allowlist」✓
- `http://` 开头的 URL → 403「only https URLs are allowed」✓
- 云元数据 `https://169.254.169.254/...` → 403（先被白名单拦下）✓
- 白名单站 GitHub API、NetEye 在**生产代码**下被 DNS 守卫拦下：
  这台 VM 的 DNS 把所有域名都解析到 CGNAT 地址 `198.18.x.x`
  （出口代理），守卫正确地把它当成非公开 IP 拒绝了。
  这是 VM 测试环境的假象：Render 上的 DNS 会解析到真实公网 IP。
- 抓取路径本身已验证通过：用一份仅关掉 DNS 守卫的 `/tmp` 临时副本
  （生产文件未动）实测——GitHub API 返回 200、正文 5910 字符且含
  `danxiaolong16-beep/gangtiexia-worker`；NetEye 美国热榜返回 200、
  239944 字符、未截断。临时副本和测试服务已删除，测试端口已关闭。

## 上线后必验（部署完第一件事）

```bash
curl -s -X POST https://gangtiexia-worker.onrender.com/relay \
  -H 'Content-Type: application/json' \
  -d '{"url": "https://www.neteye.dev/en/trending/us"}' | head -c 300
```

应返回 `ok: true, status: 200`。如果返回「host resolves to non-public IP」，
说明 Render 的 DNS 也有类似代理情况，再按日志调整守卫逻辑；
如果返回 403 白名单错误，检查 URL 的 host 是否在白名单里。

## 上线步骤

1. 把 `app.py`、`RELAY.md` 推到 GitHub 公开仓库
   `danxiaolong16-beep/gangtiexia-worker`（之前部署就是浏览器上传文件
   的方式，VM 里推需要账号授权，走原来那条路）。
2. Render 检测到推送自动重新部署（免费版约 1–2 分钟）。
3. 按上面「上线后必验」测一次 NetEye，再看 `/watchdog` 里有无
   `relay` 记录。
4. 可选：在 Render Dashboard → Environment 里加 `RELAY_TOKEN`
  （任意随机字符串），之后调用要带 `X-Relay-Token` 头。
