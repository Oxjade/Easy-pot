// EasyPot landing page. Motion explains something or it isn't there: the field sets the scene,
// the diagram walks through how EasyPot works, the log shows a catch. All of it pauses off-screen
// and holds still for people who prefer reduced motion.
document.documentElement.classList.add('js');
const $ = s => document.querySelector(s);
const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const onScreen = (el, cb, threshold = 0.15) => {
  if (!('IntersectionObserver' in window)) { cb(true); return; }
  new IntersectionObserver(es => es.forEach(e => cb(e.isIntersecting)), { threshold }).observe(el);
};

// ---------------- nav ----------------
const nav = $('#nav');
const onScroll = () => nav.classList.toggle('scrolled', window.scrollY > 12);
window.addEventListener('scroll', onScroll, { passive: true });
onScroll();

// ---------------- hero: stippled landscape ----------------
// Points sampled over a heightfield: a valley where the beam lands, hills rising either side.
// Drawn straight into a pixel buffer so thousands of points stay cheap.
(function field() {
  const canvas = $('#field');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const small = window.innerWidth < 700;
  const N = small ? 9000 : 22000;
  const pts = new Float32Array(N * 3);
  for (let i = 0; i < N; i++) {
    pts[i * 3] = Math.random() * 2 - 1;            // across, as a share of the visible width at that depth
    pts[i * 3 + 1] = Math.pow(Math.random(), 0.8); // depth, denser near the camera
    pts[i * 3 + 2] = Math.random();               // per-point sparkle phase
  }
  const stars = Array.from({ length: small ? 50 : 110 }, () => [Math.random(), Math.random() * 0.35, Math.random()]);
  let W = 0, H = 0, img = null, buf = null, visible = true, mx = 0, tmx = 0, raf = 0, last = 0;

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, small ? 1.5 : 1.75);
    W = Math.max(1, Math.floor(canvas.clientWidth * dpr));
    H = Math.max(1, Math.floor(canvas.clientHeight * dpr));
    canvas.width = W; canvas.height = H;
    img = ctx.createImageData(W, H);
    buf = new Uint32Array(img.data.buffer);
  };
  // Valley floor where the beam lands; hills rise steeply on both sides and roll with time.
  const height = (x, z, t) => {
    const ridge = Math.max(0, Math.abs(x) - 0.35 - 0.08 * z);
    return 0.55 * ridge * ridge * (1 + 0.22 * Math.sin(z * 1.6 + t * 0.3 + x * 0.8))
      + 0.05 * Math.sin(x * 5 + z * 3 - t * 0.5) + 0.04 * Math.sin(z * 7 + x * 2 + t * 0.35);
  };
  const plot = (px, py, a, size) => {
    for (let dy = 0; dy < size; dy++) for (let dx = 0; dx < size; dx++) {
      const X = px + dx, Y = py + dy;
      if (X < 0 || Y < 0 || X >= W || Y >= H) continue;
      const i = Y * W + X;
      const na = Math.min(255, (buf[i] >>> 24) + a);
      buf[i] = (na << 24) | 0xffffff; // white, accumulated alpha (little-endian ABGR)
    }
  };
  const draw = now => {
    raf = 0;
    if (!visible) return;
    if (!reduce && now - last < 33) { raf = requestAnimationFrame(draw); return; } // ~30 fps is plenty
    last = now;
    const t = reduce ? 2 : now / 1000;
    mx += (tmx - mx) * 0.05;
    buf.fill(0);
    const cx = W / 2, horizon = H * 0.3, fx = W * 0.5, fy = H * 0.95, camY = 0.42;
    for (let i = 0; i < N; i++) {
      const u = pts[i * 3], v = pts[i * 3 + 1], ph = pts[i * 3 + 2];
      const z = 0.9 + v * 6.5;
      const x = u * 1.25 * z + mx * 0.12 * z;
      const h = height(x, z, t);
      const sx = Math.round(cx + (x / z) * fx);
      const sy = Math.round(horizon + ((camY - h) / z) * fy);
      if (sy < -2 || sy > H + 2) continue;
      // light: crests facing the centre catch it, the beam lights the valley, distance fades it
      const slope = (h - height(x - Math.sign(x) * 0.03, z, t)) * 22;
      const beam = Math.exp(-(x * x) / (0.06 * z)) * Math.exp(-((z - 2.4) ** 2) / 2.2);
      let a = (0.22 + Math.min(0.9, Math.max(0, slope)) + beam * 1.1) * Math.min(1, 3 / z) * 255;
      a *= 0.8 + 0.2 * Math.sin(t * 1.4 + ph * 40);
      if (a > 8) plot(sx, sy, Math.min(255, a | 0), z < 2.2 ? 2 : 1);
    }
    for (const [sx, sy, ph] of stars) plot((sx * W) | 0, (sy * H) | 0, (50 + 110 * Math.abs(Math.sin(t * 0.6 + ph * 30))) | 0, 1);
    ctx.putImageData(img, 0, 0);
    if (!reduce) raf = requestAnimationFrame(draw);
  };
  const start = () => { if (!raf) raf = requestAnimationFrame(draw); };
  resize();
  start();
  window.addEventListener('resize', () => { resize(); start(); });
  onScreen(canvas, v => { visible = v; if (v) start(); }, 0);
  document.addEventListener('visibilitychange', () => { visible = !document.hidden; if (visible) start(); });
  if (!reduce) window.addEventListener('pointermove', e => { tmx = (e.clientX / window.innerWidth - 0.5) * 2; }, { passive: true });
})();

// ---------------- how it works: node diagram ----------------
(function diagram() {
  const root = $('#diagram');
  if (!root) return;
  const STEPS = [
    { wires: ['w-human', 'w-app'], nodes: ['human', 'app'], pulses: ['w-human', 'w-app'],
      log: 'GET /pricing → forwarded to your app' },
    { wires: ['w-human', 'w-app'], nodes: ['human', 'app'], pulses: ['w-human', 'w-app'],
      log: 'decoys planted: /.env  /.git/config  /backup.sql  /openapi.json  /wp-login.php' },
    { wires: ['w-agent', 'w-scan', 'w-bot', 'w-human', 'w-app'], nodes: ['agent', 'scan', 'bot', 'human', 'app'], pulses: ['w-agent', 'w-scan', 'w-bot'],
      log: 'GET /.env → decoy served, fake AWS key issued to 41.58.12.9' },
    { wires: ['w-siem', 'w-fw', 'w-slack', 'w-human', 'w-app'], cut: ['w-agent', 'w-scan', 'w-bot'], nodes: ['siem', 'fw', 'slack', 'human', 'app'], caught: ['agent', 'scan', 'bot'],
      pulses: ['w-siem', 'w-fw', 'w-slack', 'w-human', 'w-app'], red: ['w-siem', 'w-fw', 'w-slack'],
      log: '<span class="blk">BLOCK</span> 41.58.12.9 → firewall feed, Wazuh, Slack' },
  ];
  const STEP_MS = 4200;
  const buttons = [...root.querySelectorAll('.steps button')];
  const log = $('#diagram-log');
  const layer = $('#pulses');
  const paths = Object.fromEntries([...root.querySelectorAll('.wire')].map(p => [p.id, { el: p, len: p.getTotalLength() }]));
  let step = 0, timer = 0, visible = false, auto = true, raf = 0, pulses = [], lastSpawn = 0;

  const set = n => {
    step = n;
    const s = STEPS[n];
    root.dataset.step = String(n);
    root.querySelectorAll('.wire').forEach(w => { w.classList.toggle('on', s.wires.includes(w.id)); w.classList.toggle('cut', !!s.cut?.includes(w.id)); });
    root.querySelectorAll('.node').forEach(g => { g.classList.toggle('on', s.nodes.includes(g.dataset.node)); g.classList.toggle('caught', !!s.caught?.includes(g.dataset.node)); });
    buttons.forEach((b, i) => b.setAttribute('aria-pressed', String(i === n)));
    log.innerHTML = s.log;
    // restart the progress line on the active step
    root.classList.remove('playing'); void root.offsetWidth;
    if (auto && visible && !reduce) root.classList.add('playing');
    pulses.forEach(p => p.c.remove()); pulses = [];
    if (reduce) drawStatic();
  };
  const schedule = () => {
    clearTimeout(timer);
    if (auto && visible && !reduce) timer = setTimeout(() => { set((step + 1) % STEPS.length); schedule(); }, STEP_MS);
  };
  const spawn = id => {
    const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    c.setAttribute('r', '3.2');
    c.setAttribute('class', STEPS[step].red?.includes(id) ? 'pulse red' : 'pulse');
    layer.appendChild(c);
    pulses.push({ c, id, born: performance.now() });
  };
  const tick = now => {
    raf = 0;
    if (!visible) return;
    if (now - lastSpawn > 700) { lastSpawn = now; STEPS[step].pulses.forEach(spawn); }
    pulses = pulses.filter(p => {
      const k = (now - p.born) / 1500;
      if (k >= 1) { p.c.remove(); return false; }
      const { el, len } = paths[p.id];
      const pt = el.getPointAtLength(len * k);
      p.c.setAttribute('cx', pt.x.toFixed(1));
      p.c.setAttribute('cy', pt.y.toFixed(1));
      p.c.setAttribute('opacity', String(Math.sin(Math.PI * k).toFixed(2)));
      return true;
    });
    raf = requestAnimationFrame(tick);
  };
  // Reduced motion: one still dot halfway along each active wire.
  const drawStatic = () => { STEPS[step].pulses.forEach(id => { spawn(id); const p = pulses.at(-1); const pt = paths[id].el.getPointAtLength(paths[id].len / 2); p.c.setAttribute('cx', pt.x); p.c.setAttribute('cy', pt.y); }); };

  root.style.setProperty('--step-ms', `${STEP_MS}ms`);
  buttons.forEach((b, i) => b.addEventListener('click', () => { auto = false; root.classList.remove('playing'); clearTimeout(timer); set(i); }));
  set(0);
  onScreen(root, v => {
    visible = v;
    if (v) { set(step); schedule(); if (!reduce && !raf) raf = requestAnimationFrame(tick); }
    else { clearTimeout(timer); root.classList.remove('playing'); }
  }, 0.35);
})();

// ---------------- out of the box: feature orbs ----------------
(function features() {
  const F = [
    ['Decoys', 'Exposed .env files, .git directories, database dumps, admin logins and internal API docs, matched to your stack. Any decoy that would clash with a real page is switched off at startup.'],
    ['Honeytokens', 'Every visitor that opens a decoy gets its own fake AWS keys, database passwords and API tokens. If one is ever used, EasyPot knows who leaked it and blocks both identities.'],
    ['Prompt-injection tripwires', 'Pages carry instructions only an LLM agent acts on. An agent that follows them is caught on the spot, and often reports its model and its task.'],
    ['CVE emulation', 'Imitates Log4Shell, Spring4Shell, Citrix, Fortinet, Ivanti and more. A new CVE is one JSON entry, with no release needed.'],
    ['Tarpit and labyrinth', 'Suspicious visitors are slowed down, then fed an endless maze of plausible documentation that burns an agent’s time and tokens.'],
    ['Firewall feeds', 'Caught addresses go to a blocklist that Palo Alto, FortiGate, pfSense and OPNsense pull every minute, with STIX 2.1 for threat intel.'],
  ];
  const orbs = [...document.querySelectorAll('.orb')];
  if (!orbs.length) return;
  const show = i => {
    orbs.forEach((o, j) => o.setAttribute('aria-pressed', String(i === j)));
    $('#feature-name').textContent = F[i][0];
    $('#feature-text').textContent = F[i][1];
  };
  orbs.forEach((o, i) => { o.addEventListener('click', () => show(i)); o.addEventListener('mouseenter', () => show(i)); o.addEventListener('focus', () => show(i)); });
  show(0);
})();

// ---------------- integrate: code tabs and copy ----------------
(function tabs() {
  const tabs = [...document.querySelectorAll('.tabs [role="tab"]')];
  if (!tabs.length) return;
  const select = t => {
    tabs.forEach(x => {
      const on = x === t;
      x.setAttribute('aria-selected', String(on));
      x.tabIndex = on ? 0 : -1;
      document.getElementById(x.getAttribute('aria-controls')).hidden = !on;
    });
  };
  tabs.forEach((t, i) => {
    t.addEventListener('click', () => select(t));
    t.addEventListener('keydown', e => {
      const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      const n = tabs[(i + d + tabs.length) % tabs.length];
      select(n); n.focus();
    });
  });
  const btn = $('#copy-code');
  btn.addEventListener('click', async () => {
    const panel = document.querySelector('.code-card [role="tabpanel"]:not([hidden])');
    const label = btn.lastElementChild;
    try { await navigator.clipboard.writeText(panel.textContent.trim()); label.textContent = 'Copied'; }
    catch { label.textContent = 'Select to copy'; }
    setTimeout(() => { label.textContent = 'Copy'; }, 1800);
  });
})();

// ---------------- live demo: the request log plays once when it comes into view ----------------
(function demoLog() {
  const lines = [...document.querySelectorAll('.log li')];
  if (!lines.length) return;
  if (reduce) { lines.forEach(l => l.classList.add('in')); return; }
  let played = false;
  onScreen(document.querySelector('.intercept'), v => {
    if (!v || played) return;
    played = true;
    lines.forEach((l, i) => setTimeout(() => l.classList.add('in'), 250 + i * 420));
  }, 0.4);
})();

// ---------------- pricing ----------------
(function pricing() {
  const buttons = [...document.querySelectorAll('.billing button')];
  if (!buttons.length) return;
  const P = { month: ['$10', '/ month', 'We run EasyPot for you. Cancel anytime.'], year: ['$100', '/ year', 'Two months free compared with paying monthly.'] };
  buttons.forEach(b => b.addEventListener('click', () => {
    buttons.forEach(x => x.setAttribute('aria-pressed', String(x === b)));
    const [amount, per, note] = P[b.dataset.bill];
    $('#price-amount').textContent = amount;
    $('#price-per').textContent = per;
    $('#price-note').textContent = note;
  }));
})();
