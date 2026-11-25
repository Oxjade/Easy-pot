# EasyPot

**A deception layer that catches AI hacking agents, scanners and bots before they find your real weaknesses.**

Firewalls have to recognise an attack before they can block it. AI agents get around that by rewording payloads, rotating residential IPs and pacing like people. EasyPot doesn't need to recognise anything. It fills your site with traps that no legitimate visitor ever touches. The first touch identifies the attacker, and EasyPot blocks it and passes it to your firewall, Wazuh and SIEM.

```
            ┌──────────────────────── EasyPot ────────────────────────┐
 visitor →  │ fingerprint → detectors → decoys / tripwires → score   │ → your app
            │                     ↓                                    │
            │        allow · tarpit · labyrinth · block               │
            └───────┬──────────────┬──────────────┬───────────────────┘
                    ↓              ↓              ↓
               Wazuh / SIEM   firewall feeds   Slack / SOAR
```

## What it does

| Layer | How it catches attackers |
|---|---|
| **LLM-agent tripwires** | Hidden natural-language instructions in every HTML page, `robots.txt`, `llms.txt` and decoy API docs tell "automated agents" to register at a canary URL. People never see them and classic scanners ignore them, but LLM agents follow them, and often report their model and task in the request. A canary hit is conclusive and the visitor is blocked instantly. |
| **Decoys** | Realistic fake `.env`, `.git/config`, SQL dumps, AWS credentials, Spring actuator, phpinfo, admin, WordPress and phpMyAdmin logins, internal APIs and OpenAPI docs. Decoys are tailored to your stack, and any decoy that would collide with a real page is switched off automatically at startup. |
| **Honeytokens** | Every visitor gets **unique** fake credentials. If one is ever used, EasyPot knows the source is hostile and which earlier visitor leaked it, even if the attacker switched IPs. |
| **CVE traps** | A data-driven CVE pack (`rules/cve-pack.json`) imitates vulnerable endpoints for well-known exploits such as Log4Shell, Spring4Shell, Apache 2.4.49, Citrix, F5, Fortinet, Ivanti, PAN-OS and the Next.js middleware bypass. Add a new CVE as a JSON entry, with no code release. |
| **Behaviour** | SQLi, XSS, traversal, command injection, SSTI, NoSQLi and SSRF payloads; object-ID enumeration; 404 bursts; machine-regular timing; scanner, headless and library user agents. |
| **Response** | Each visitor has a decaying risk score that moves it through **tarpit** (slow responses), **labyrinth** (an endless maze of plausible docs that wastes the agent's time and tokens) and **block**. Decoys are always served even when they trigger a block, so the trap isn't revealed. |
| **Attribution** | Every tripwire URL carries a per-visitor signature, so an agent that reads a page from one IP and follows the trap from another gets both identities blocked. |

## Quick start

```bash
npm install
npm run build
cp easypot.config.example.json easypot.config.json   # set upstream, tokens, stack
npm start
```

- Public traffic goes to **:8080** and is proxied to `upstream`.
- The dashboard and feeds are on **:8081**. It binds to `127.0.0.1` by default; keep it private.

Try it with simulated attacks:

```bash
npm run build && node scripts/demo.mjs
# dashboard: http://127.0.0.1:8081   token: demo-admin-token
```

Docker:

```bash
EASYPOT_ADMIN_TOKEN=… EASYPOT_FEED_TOKEN=… EASYPOT_SECRET=… docker compose up --build
```

## Deploying in front of a site

EasyPot is a reverse proxy. Put it wherever your traffic already flows:

- **Behind Cloudflare, a load balancer or nginx:** set `trustProxy: true` so it reads the real client IP from `CF-Connecting-IP` or `X-Forwarded-For`.
- **Directly on the edge:** terminate TLS in front of it (Caddy, nginx or a cloud LB) and forward to `:8080`.

Your app receives `X-EasyPot-Score` and `X-EasyPot-Class` on every request. You can use them for your own decisions, such as step-up auth for risky sessions.

> Pages carry per-visitor tripwires. If a CDN caches HTML publicly, detection still works, but attribution may point at the visitor who warmed the cache.

## Integrations

Wazuh (rules plus active response), syslog JSON/CEF for Splunk, Elastic, Sentinel and QRadar, firewall blocklist feeds (Palo Alto EDL, FortiGate, pfSense/OPNsense, ipset), STIX 2.1, and Slack and generic webhooks. See **[integrations/README.md](integrations/README.md)**.

## Admin API

All endpoints need `Authorization: Bearer <admin.token>`.

| Endpoint | |
|---|---|
| `GET /api/overview?hours=24` | KPIs, timeline, signal breakdown, self-reported agents |
| `GET /api/events?limit=&severity=&signal=&actor=` | Event log |
| `GET /api/actors?class=llm_agent` · `GET /api/actors/:id` | Visitors and full timelines |
| `GET/POST /api/blocks` · `DELETE /api/blocks/:target` | Manage blocks |
| `GET /api/decoys` · `GET /api/config` | Deployed traps, active policy |
| `GET /api/stream` | Server-sent events (live) |
| `GET /feeds/blocklist.txt` · `.json` · `/feeds/stix.json` | Feed token or admin token |

## Limits

- An attacker who goes straight to a real vulnerability without touching a decoy won't be caught by the traps. Behaviour detection is the backstop. EasyPot works alongside a WAF and good app security; it doesn't replace them.
- Prompt-injection tripwires depend on agents following embedded instructions. Newer models and harnesses are being trained to resist this, which is why decoys, honeytokens and behaviour scoring don't rely on it.
- The `passwordHint` on decoy logins keeps only the first two characters. EasyPot never stores attempted passwords in full.
- The data store is SQLite (Node's built-in `node:sqlite`, Node ≥ 22.13), which suits one instance per site. A shared store is on the roadmap for clusters.

## Roadmap

- Edge/middleware variants: Cloudflare Worker, Vercel and Next.js middleware, Express/Fastify, nginx module
- Shared threat network: an agent caught on one site is blocked on all of them
- Out-of-band honeytokens (DNS and cloud-key canaries) to catch secrets used outside the site
- Virtual patching: push blocking rules for new CVEs to the real endpoints
- Multi-tenant SaaS: customers link their domain via CNAME

## Development

```bash
npm test    # builds, then runs the end-to-end suite (human, AI agent and scanner simulations)
```

---
Built by [Syntrei](https://github.com/Oxjade).
