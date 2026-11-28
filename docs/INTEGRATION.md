# Integrating EasyPot

EasyPot needs three connections to work fully:

1. **Traffic in.** Requests to the site must pass through EasyPot. This is the only required step.
2. **Detections out.** Alerts go to the tools your security team already watches.
3. **Blocks out.** Caught attackers are blocked beyond EasyPot too: at the firewall, and on every server.

```
                         ┌───────────── EasyPot ─────────────┐
 visitor → TLS / CDN / LB│ decoys · tripwires · honeytokens  │→ your app      (1) traffic in
                         │ scoring · tarpit · labyrinth · block│
                         └──────┬──────────────┬─────────────┘
                                ↓              ↓
              (2) Wazuh, SIEM, Slack, SOAR   (3) firewall feeds, Wazuh active response
```

## 1. Traffic in

EasyPot is a reverse proxy. It goes between whatever terminates TLS and your application. Set `upstream` to your app and `trustProxy` to the number of proxies in front of EasyPot.

| Your setup | Put EasyPot | `trustProxy` |
|---|---|---|
| Docker Compose | A service in front of the app service; publish EasyPot's port instead of the app's | `1` if a proxy sits in front, else `false` |
| nginx, Caddy or HAProxy | Between the proxy and the app: the proxy's upstream becomes EasyPot, EasyPot's upstream is the app | `1` |
| Cloud load balancer (AWS ALB, GCP, Azure) | As the load balancer's target | `1` |
| Cloudflare straight to your server | On the origin, receiving Cloudflare's traffic | `1` |
| Cloudflare → load balancer → EasyPot | Behind the load balancer | `2` |
| Kubernetes | As a sidecar in the app's pod, with the Service pointing at EasyPot's port | `1` for the ingress controller, plus 1 if a cloud load balancer in front also appends `X-Forwarded-For` |

**`trustProxy` matters.** EasyPot reads the client address that many entries from the right of `X-Forwarded-For`, and ignores anything further left, which the client can forge. Set it too low and every visitor looks like your proxy. Set it too high and attackers can choose their own address.

Your app receives `X-Real-IP` (the client), `X-EasyPot-Score` and `X-EasyPot-Class` on every request it gets, so it can make its own decisions, such as requiring a second factor for risky sessions.

### nginx (tested)

```nginx
upstream easypot { server 127.0.0.1:8080; keepalive 64; }
server {
    listen 443 ssl;
    # ssl_certificate ...;
    location / {
        proxy_pass http://easypot;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

With EasyPot's `upstream` set to the app (for example `http://127.0.0.1:3000`) and `trustProxy: 1`.

### Kubernetes sidecar (example, not yet tested on a cluster)

```yaml
# In the app's Deployment: add EasyPot next to the app container.
containers:
  - name: app
    image: your-app
    ports: [{ containerPort: 3000 }]
  - name: easypot
    image: ghcr.io/your-org/easypot:latest      # build from this repo's Dockerfile
    ports: [{ containerPort: 8080 }, { containerPort: 8081 }]
    env:
      - { name: EASYPOT_UPSTREAM, value: "http://127.0.0.1:3000" }
      - { name: EASYPOT_TRUST_PROXY, value: "1" }
      - { name: EASYPOT_SECRET, valueFrom: { secretKeyRef: { name: easypot, key: secret } } }
      - { name: EASYPOT_ADMIN_TOKEN, valueFrom: { secretKeyRef: { name: easypot, key: admin-token } } }
      - { name: EASYPOT_FEED_TOKEN, valueFrom: { secretKeyRef: { name: easypot, key: feed-token } } }
    readinessProbe: { httpGet: { path: /healthz, port: 8081 } }
    volumeMounts: [{ name: easypot-data, mountPath: /var/lib/easypot }]
# The Service's targetPort becomes 8080. Never expose 8081 through the Ingress.
```

Each pod keeps its own state, so a visitor blocked by one replica isn't yet blocked by the others. Your firewall closes that gap: every replica publishes a feed, and the firewall blocks the union.

### Before going live

- Decoys that would clash with a real page are switched off automatically at startup. Check the startup log for the list.
- Watch the dashboard for a day before relying on blocks. If a real integration or monitor trips a detector, add its address to `allowlist`.
- Keep the dashboard (port 8081) private: a VPN, an SSH tunnel or an internal network only.

## 2. Detections out

| Destination | How | Setup |
|---|---|---|
| Wazuh | JSON event log read by the Wazuh agent, plus EasyPot's rules (levels 10–14, MITRE-tagged) | [integrations/README.md](../integrations/README.md#wazuh) |
| Splunk, Elastic, Graylog | Syslog, JSON format | `integrations.syslog` with `"format": "json"` |
| Microsoft Sentinel, QRadar, ArcSight | Syslog, CEF format | `integrations.syslog` with `"format": "cef"` |
| Slack | Webhook, one alert per visitor per signal every 10 minutes | `integrations.webhooks` with `"type": "slack"` |
| SOAR (Tines, Shuffle, XSOAR, TheHive) | Generic webhook carrying the same JSON record as the log | `integrations.webhooks` with `"type": "generic"` |
| MISP, OpenCTI | STIX 2.1 bundle of blocked addresses | `/feeds/stix.json` |

Every event carries a MITRE ATT&CK technique ID, the visitor's risk score and what EasyPot did about it.

## 3. Blocks out

EasyPot blocks attackers itself, at the proxy. To block them everywhere else too:

| Where | How |
|---|---|
| Palo Alto | External Dynamic List pointed at `/feeds/blocklist.txt` |
| FortiGate | Threat Feed (IP address) pointed at the same URL |
| pfSense, OPNsense | URL Table alias |
| Sophos XG | IP host list with scheduled import |
| Linux servers | `integrations/firewall/easypot-ipset-sync.sh` from cron |
| Every Wazuh-managed server | Wazuh active response (`firewall-drop`) on EasyPot's rules |

Feeds need the feed token, as a query string, a bearer header or a Basic auth password. Blocks expire after `blockTtlMinutes` (24 hours by default) and drop off the feeds automatically.

## What isn't there yet

- **One instance per site.** State lives in SQLite. Several replicas each detect and block independently; a shared store is on the roadmap.
- **No middleware or edge versions.** Express, Next.js and Cloudflare Worker integrations are on the roadmap; today EasyPot has to sit in the traffic path as a proxy.
- **One admin token.** The dashboard has no user accounts, SSO or roles.
- **Untested against live third-party systems.** The Wazuh, syslog, webhook and feed outputs are covered by tests of what EasyPot produces, not yet against a running Wazuh manager, SIEM or firewall.
