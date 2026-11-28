# Deploying the live demo

This puts the EasyPot attack range on its own server with HTTPS: visitors open `https://<demo domain>/try`, and their agents attack `https://<target domain>`. It needs about 30 minutes.

**Only on a dedicated server.** The target is a built-in fake app. Never run playground mode in front of a real site.

## What you need

- A Linux server with Docker and the Compose plugin: 1 vCPU and 1 GB of RAM is enough for a demo (for example a small DigitalOcean, Hetzner or Lightsail instance).
- Two DNS names pointing at the server's public IP, for example `demo.example.com` and `target.example.com`.
- Ports 80 and 443 open to the internet. Port 8081 must stay closed.

## Steps

```bash
git clone https://github.com/Oxjade/Easy-pot.git && cd Easy-pot/deploy/playground
cp .env.example .env
# Fill in .env: the two domains, and three secrets made with `openssl rand -hex 24`
docker compose up -d --build
docker compose ps        # easypot should show "healthy" within about 30 seconds
```

Caddy fetches Let's Encrypt certificates on first start. The DNS records have to resolve to the server before then.

## Check it before you present

1. Open `https://<demo domain>/try`, click **Start a run**, then **Run simulated agent**. The report should fill in within about 10 seconds and end with "Agent blocked".
2. Copy the target URL and open it in a browser: you should see the Northwind Pay site.
3. Open the dashboard through an SSH tunnel: `ssh -L 8081:127.0.0.1:8081 you@server`, then http://127.0.0.1:8081 with `EASYPOT_ADMIN_TOKEN`.

## Operating it

- Logs: `docker compose logs -f easypot`
- Update: `git pull && docker compose up -d --build`
- Runs are kept in memory for 20 minutes; blocks, events and the dashboard history are kept in the `easypot-data` volume.
- To clear all blocks after a demo: `docker compose down && docker volume rm playground_easypot-data && docker compose up -d`.
