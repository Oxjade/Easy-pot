# Connecting EasyPot to your security stack

EasyPot works in three directions: it **sends detections out** to your SIEM, it **pushes blocks out** to your firewalls, and it **shares threat intel** with other platforms.

## Wazuh

1. Make sure the JSON event log is on in `easypot.config.json`:
   ```json
   "integrations": { "fileLog": { "enabled": true, "path": "/var/lib/easypot/events.jsonl", "minSeverity": "low" } }
   ```
2. On the Wazuh **agent** on the EasyPot host, add the `<localfile>` block from [`wazuh/ossec.conf.snippet.xml`](wazuh/ossec.conf.snippet.xml).
3. On the Wazuh **manager**, copy [`wazuh/easypot_rules.xml`](wazuh/easypot_rules.xml) to `/var/ossec/etc/rules/`. Add the `<active-response>` block from the snippet, then restart the manager.

When EasyPot catches an AI agent, a honeytoken replay or a CVE exploit, Wazuh raises a level 13–14 alert tagged with MITRE ATT&CK. It then runs `firewall-drop` on every agent, so that IP is blocked across all the customer's servers.

| Rule | Level | Fires on |
|---|---|---|
| 100710 | 13 | AI agent followed injected instructions |
| 100711 | 14 | Stolen decoy credential used |
| 100712 | 13 | CVE exploit attempt |
| 100713 | 10 | EasyPot blocked an IP |
| 100714 | 11 | Login attempt on a decoy panel |
| 100715 | 10 | Decoy secrets / DB dump / source retrieved |
| 100730 | 12 | 5+ high-severity events from one IP within 5 minutes |

## Splunk, Elastic, Sentinel, QRadar, and other SIEMs (syslog)

```json
"syslog": { "enabled": true, "host": "siem.internal", "port": 514, "protocol": "udp", "format": "cef", "minSeverity": "low" }
```
- `format: "cef"` for ArcSight, QRadar or Sentinel (CEF connector).
- `format: "json"` for Splunk, Elastic or Graylog.

Messages are framed as RFC 5424 using facility local0. Each event carries MITRE ATT&CK technique IDs.

## Firewalls (pull-based blocklist)

The admin server publishes a live list of blocked IPs, one per line:

```
https://<easypot-admin>/feeds/blocklist.txt?token=<feedToken>
```

| Firewall | Where to add it |
|---|---|
| Palo Alto | Objects → External Dynamic Lists → IP List, then use it in a deny policy |
| FortiGate | Security Fabric → External Connectors → Threat Feeds → IP Address |
| pfSense / OPNsense | Firewall → Aliases → URL Table (IPs) |
| Sophos XG | Hosts and services → IP host list (scheduled import) |
| Linux hosts | [`firewall/easypot-ipset-sync.sh`](firewall/easypot-ipset-sync.sh) from cron |

If the firewall can't add a query string, the feed also accepts the token as an `Authorization: Bearer` header or as the password in HTTP Basic auth.

## Threat intel (STIX 2.1)

```
/feeds/stix.json     STIX 2.1 bundle of IP indicators (MISP, OpenCTI, TAXII ingest)
/feeds/blocklist.json  blocklist with reasons and expiry
```

## Alerts (Slack and webhooks)

```json
"webhooks": [
  { "url": "https://hooks.slack.com/services/…", "type": "slack", "minSeverity": "high" },
  { "url": "https://soar.example.com/hooks/easypot", "type": "generic", "minSeverity": "medium" }
]
```
`generic` posts the same JSON record that goes to the event log, so it works directly with Shuffle, TheHive, Tines or XSOAR playbooks. Alerts are limited to one per visitor, per signal, every 10 minutes.
