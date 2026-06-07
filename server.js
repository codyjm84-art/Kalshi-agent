// ─────────────────────────────────────────────────────────────────────────────
// Kalshi 24/7 Trading Agent Server
// Deploy on Railway.app — iPhone dashboard at your Railway URL
// ─────────────────────────────────────────────────────────────────────────────

import express  from 'express';
import fetch    from 'node-fetch';
import crypto   from 'crypto';
import { createServer }  from 'http';


const app    = express();
const server = createServer(app);
// WebSocket removed — dashboard uses HTTP polling
const PORT = parseInt(process.env.PORT) || 8080;
console.log('PORT env var:', process.env.PORT);
console.log('Using port:', PORT);

app.use(express.json());
// Dashboard served inline — no static files needed

// ─── Environment variables (set in Railway → Variables) ───────────────────────
function normalizePrivKey(k) {
  if (!k) return '';
  const NL = String.fromCharCode(10);
  // Convert literal backslash-n to real newline
  k = k.split('\\n').join(NL);
  // If still no newlines, insert them
  if (k.indexOf(NL) === -1) {
    k = k
      .split('-----BEGIN PRIVATE KEY-----').join('-----BEGIN PRIVATE KEY-----' + NL)
      .split('-----END PRIVATE KEY-----').join(NL + '-----END PRIVATE KEY-----')
      .split('-----BEGIN RSA PRIVATE KEY-----').join('-----BEGIN RSA PRIVATE KEY-----' + NL)
      .split('-----END RSA PRIVATE KEY-----').join(NL + '-----END RSA PRIVATE KEY-----');
    var parts = k.split(NL);
    var out = parts.map(function(p) {
      if (p.indexOf('-----') === 0) return p;
      var chunks = [];
      for (var i = 0; i < p.length; i += 64) chunks.push(p.slice(i, i + 64));
      return chunks.join(NL);
    });
    k = out.join(NL);
  }
  return k.trim();
}

const ENV = {
  KALSHI_KEY_ID: process.env.KALSHI_KEY_ID || '',
  // Normalize private key — Railway strips line breaks when pasting
  KALSHI_PRIVATE_KEY: normalizePrivKey(process.env.KALSHI_PRIVATE_KEY || ''),
};

const KALSHI_BASE = 'https://api.elections.kalshi.com/trade-api/v2';

// ─── Category keyword filters ─────────────────────────────────────────────────
const CAT_KW = {
  Politics:  ['election','president','congress','senate','trump','vote','govern','ukraine','iran','nato','fed','rate','tariff'],
  Sports:    ['nba','nfl','nhl','mlb','soccer','super bowl','world cup','championship','playoff','finals','league'],
  Crypto:    ['bitcoin','btc','eth','ethereum','crypto','interest rate','cpi','inflation','fed'],
  Economics: ['gdp','inflation','cpi','unemployment','fed','recession','earnings','jobs'],
};

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  running:   false,
  status:    'Stopped',
  lastTick:  null,
  errors:    [],
  balance:   0,
  pnl:       0,
  secured:   0,
  slHits:    0,
  openOrders: [],
  orderLog:  [],
  markets:   [],
  followedTraders: [],
  settings: {
    minOdds:    35,
    stopLoss:   0.30,
    pullTarget: 78,
    resetTo:    39,
    autoCopy:   false,
    categories: ['Politics','Sports','Crypto'],
  },
  model: {
    maxOpen:      10,
    copyPct:      0.02,
    successRate:  null,
    estMins:      null,
    optimizing:   false,
    sessionWins:  0,
    sessionLosses:0,
    totalGain:    0,
    totalLoss:    0,
    lastOptAt:    0,
  },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────
function broadcast(event, data) {
  // Dashboard uses HTTP polling — broadcast is a no-op
}
function setStatus(s) {
  state.status = s;
  broadcast('status', s);
  console.log('[Kalshi]', s);
}
function logError(e) {
  const msg = String(e?.message || e).slice(0, 200);
  state.errors.unshift({ msg, ts: Date.now() });
  state.errors = state.errors.slice(0, 20);
  broadcast('error', msg);
  console.error('[Error]', msg);
}

// ─── Kalshi API signing (RSA-PSS SHA-256) ─────────────────────────────────────
function kalshiSign(method, path) {
  const ts  = Date.now().toString();
  const msg = ts + method + '/trade-api/v2' + path;
  const key = crypto.createPrivateKey(ENV.KALSHI_PRIVATE_KEY);
  const sig = crypto.sign('sha256', Buffer.from(msg), {
    key,
    padding:    crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  return { ts, sig: sig.toString('base64') };
}

async function kalFetch(method, path, body = null) {
  const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
  if (ENV.KALSHI_KEY_ID && ENV.KALSHI_PRIVATE_KEY) {
    const { ts, sig } = kalshiSign(method, path);
    headers['KALSHI-ACCESS-KEY']       = ENV.KALSHI_KEY_ID;
    headers['KALSHI-ACCESS-SIGNATURE'] = sig;
    headers['KALSHI-ACCESS-TIMESTAMP'] = ts;
  }
  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(KALSHI_BASE + path, opts);
  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Kalshi ${res.status}: ${txt.slice(0, 120)}`);
  }
  return res.json();
}

// ─── Balance ──────────────────────────────────────────────────────────────────
async function loadBalance() {
  if (!ENV.KALSHI_KEY_ID) return;
  try {
    const data  = await kalFetch('GET', '/portfolio/balance');
    state.balance = (data.balance || 0) / 100; // Kalshi returns cents
    broadcast('balance', state.balance);
  } catch(e) { logError(e); }
}

// ─── Markets ──────────────────────────────────────────────────────────────────
async function loadMarkets() {
  try {
    setStatus('Loading markets…');

    // Try events endpoint first (has readable titles + categories)
    let markets = [];
    try {
      const evRes = await kalFetch('GET', '/events?limit=200&status=open&with_nested_markets=true');
      const events = evRes.events || [];
      for (const ev of events) {
        const evTitle = ev.title || ev.event_ticker || '';
        const cat = (ev.category || '').toLowerCase();
        for (const m of (ev.markets || [])) {
          const yes = m.yes_bid_dollars ? Math.round(parseFloat(m.yes_bid_dollars)*100)
                    : m.yes_bid || 50;
          if (yes < state.settings.minOdds || yes > 100 - state.settings.minOdds) continue;
          const sub = m.yes_sub_title || '';
          markets.push({
            ticker:     m.ticker,
            title:      sub ? `${evTitle}: ${sub}` : evTitle,
            yes_bid:    yes,
            no_bid:     100 - yes,
            volume:     parseFloat(m.volume_fp || 0),
            volume_24h: parseFloat(m.volume_24h_fp || 0),
            category:   cat,
          });
        }
      }
      setStatus(`${markets.length} markets loaded`);
    } catch(evErr) {
      // Fallback: markets endpoint only has yes_sub_title as the question
      logError('Events fallback: ' + evErr.message);
      const mRes = await kalFetch('GET', '/markets?limit=1000&status=open');
      const raw = mRes.markets || [];
      markets = raw
        .filter(m => {
          const yes = m.yes_bid_dollars ? Math.round(parseFloat(m.yes_bid_dollars)*100)
                    : m.yes_bid || 50;
          return yes >= state.settings.minOdds && yes <= 100 - state.settings.minOdds;
        })
        .map(m => {
          const yes = m.yes_bid_dollars ? Math.round(parseFloat(m.yes_bid_dollars)*100)
                    : m.yes_bid || 50;
          // yes_sub_title is the actual readable question on Kalshi
          const title = m.yes_sub_title || m.title || m.ticker;
          return {
            ticker:     m.ticker,
            title,
            yes_bid:    yes,
            no_bid:     100 - yes,
            volume:     parseFloat(m.volume_fp || 0),
            volume_24h: parseFloat(m.volume_24h_fp || 0),
            category:   (m.category || '').toLowerCase(),
          };
        });
      setStatus(`${markets.length} markets loaded (fallback)`);
    }

    state.markets = markets;
    broadcast('markets', state.markets.slice(0, 200));
  } catch(e) {
    logError(e);
    setStatus('Markets failed: ' + e.message.slice(0, 50));
  }
}

// ─── Place order ──────────────────────────────────────────────────────────────
async function placeOrder(ticker, side, priceInCents) {
  if (!ENV.KALSHI_KEY_ID) throw new Error('KALSHI_KEY_ID not set in Railway Variables');
  const stake = Math.max(0.01, +(state.balance * state.model.copyPct).toFixed(2));
  const count = Math.max(1, Math.floor(stake * 100 / priceInCents));

  const body = {
    ticker,
    action:        'buy',
    type:          'limit',
    side,
    count,
    yes_price:     side === 'yes' ? priceInCents : 100 - priceInCents,
    no_price:      side === 'no'  ? priceInCents : 100 - priceInCents,
    expiration_ts: Math.floor(Date.now() / 1000) + 86400, // 24h expiry
  };

  const data = await kalFetch('POST', '/portfolio/orders', body);
  state.balance -= stake;

  const entry = {
    id:     data.order?.order_id || 'unknown',
    ticker, side, stake,
    price:  priceInCents,
    count,
    ts:     Date.now(),
    status: 'open',
  };
  state.openOrders.push(entry);
  state.orderLog.unshift(entry);
  state.orderLog = state.orderLog.slice(0, 100);

  broadcast('order',   entry);
  broadcast('balance', state.balance);
  setStatus(`Order placed: ${side.toUpperCase()} ${ticker} · $${stake} · ${count} contracts`);
  return data;
}

// ─── Stop loss monitor ────────────────────────────────────────────────────────
async function checkStopLosses() {
  for (const order of state.openOrders.filter(o => o.status === 'open')) {
    try {
      const data = await kalFetch('GET', `/markets/${order.ticker}`);
      const m    = data.market || {};
      const cur  = order.side === 'yes' ? (m.yes_bid || order.price) : (m.no_bid || order.price);
      if (cur <= order.price * (1 - state.settings.stopLoss)) {
        // Cancel the order
        await kalFetch('DELETE', `/portfolio/orders/${order.id}`).catch(() => {});
        order.status = 'stopped';
        const recovered = +(order.stake * (cur / order.price)).toFixed(2);
        const lost      = +(order.stake - recovered).toFixed(2);
        state.balance  += recovered;
        state.pnl      -= lost;
        state.slHits++;
        broadcast('sl_hit', { order, recovered, lost });
        broadcast('balance', state.balance);
        setStatus(`Stop loss: ${order.ticker} · recovered $${recovered}`);
      }
    } catch(e) { /* silently continue */ }
  }
}

// ─── Profit pull ──────────────────────────────────────────────────────────────
function checkProfitPull() {
  if (state.balance >= state.settings.pullTarget) {
    const pulled     = +(state.balance - state.settings.resetTo).toFixed(2);
    state.balance    = state.settings.resetTo;
    state.secured   += pulled;
    broadcast('profit_pull', { pulled, total: state.secured });
    setStatus(`💰 Profit pulled: $${pulled} · total secured: $${state.secured.toFixed(2)}`);
  }
}

// ─── Monte Carlo optimizer ────────────────────────────────────────────────────
function runOptimizer() {
  const m = state.model;
  const settled = m.sessionWins + m.sessionLosses;
  if (settled < 5 || settled % 10 !== 0 || m.lastOptAt === settled || m.optimizing) return;

  m.optimizing = true;
  m.lastOptAt  = settled;
  broadcast('optimizing', true);

  const wr = m.sessionWins / settled;
  const ag = m.sessionWins > 0 ? m.totalGain / m.sessionWins : 0.92;

  const COMBOS = [];
  for (const maxOpen of [3, 5, 8, 10, 12, 15, 20])
    for (const copyPct of [0.01, 0.015, 0.02, 0.025, 0.03, 0.04, 0.05])
      COMBOS.push({ maxOpen, copyPct });

  let best = { maxOpen: 10, copyPct: 0.02, score: -Infinity, successRate: 0, estMins: 999 };

  for (const { maxOpen, copyPct } of COMBOS) {
    let successes = 0, totalSettled = 0;
    for (let r = 0; r < 500; r++) {
      let bal = state.settings.resetTo, stakes = [], settled2 = 0;
      while (bal < state.settings.pullTarget && settled2 < 2000) {
        while (stakes.length < maxOpen) {
          const cost = Math.max(0.01, +(bal * copyPct).toFixed(2));
          if (bal < cost) break;
          bal = +(bal - cost).toFixed(2);
          stakes.push(cost);
        }
        if (!stakes.length) break;
        const stake = stakes.shift();
        if (Math.random() < wr) bal = +(bal + stake + stake * ag).toFixed(2);
        settled2++;
      }
      if (bal >= state.settings.pullTarget) successes++;
      totalSettled += settled2;
    }
    const sr    = successes / 500;
    const spm   = (maxOpen / 7) * 60;
    const em    = (totalSettled / 500) / spm;
    const score = sr * 100 - em * 0.5;
    if (score > best.score)
      best = { maxOpen, copyPct, score, successRate: +(sr * 100).toFixed(1), estMins: +em.toFixed(2) };
  }

  m.maxOpen     = best.maxOpen;
  m.copyPct     = best.copyPct;
  m.successRate = best.successRate;
  m.estMins     = best.estMins;
  m.optimizing  = false;
  broadcast('model_updated', state.model);
  setStatus(`Model updated: ${best.maxOpen} positions · ${(best.copyPct*100).toFixed(1)}% · ${best.successRate}% success`);
}

// ─── Main agent tick (every 15 seconds) ──────────────────────────────────────
async function agentTick() {
  if (!state.running) return;
  state.lastTick = new Date().toISOString();
  try {
    await loadBalance();
    checkProfitPull();
    await checkStopLosses();
    runOptimizer();
    broadcast('tick', {
      balance: state.balance,
      pnl:     state.pnl,
      secured: state.secured,
      slHits:  state.slHits,
      ts:      state.lastTick,
    });
  } catch(e) { logError(e); }
}

// ─── REST API ─────────────────────────────────────────────────────────────────
// Debug endpoint — shows which env vars are detected
// Health check — Railway uses this to verify app is running
app.get('/healthz', (req, res) => res.send('OK'));
app.get('/health', (req, res) => res.send('OK'));

app.get('/api/debug', (req, res) => res.json({
  hasKeyId:     !!ENV.KALSHI_KEY_ID,
  keyIdLength:  ENV.KALSHI_KEY_ID.length,
  hasPrivKey:   !!ENV.KALSHI_PRIVATE_KEY,
  privKeyStart: ENV.KALSHI_PRIVATE_KEY.slice(0,30)||'NOT SET',
  nodeVersion:  process.version,
  uptime:       Math.floor(process.uptime())+'s',
}));

app.get('/api/state', (req, res) => res.json({
  ...state,
  config: { hasKeys: !!(ENV.KALSHI_KEY_ID && ENV.KALSHI_PRIVATE_KEY) },
}));

app.post('/api/agent/start', async (req, res) => {
  if (!ENV.KALSHI_KEY_ID)
    return res.status(400).json({ error: 'KALSHI_KEY_ID not set in Railway Variables' });
  if (!ENV.KALSHI_PRIVATE_KEY)
    return res.status(400).json({ error: 'KALSHI_PRIVATE_KEY not set in Railway Variables' });
  // Test the key works before starting
  try {
    await loadBalance();
  } catch(e) {
    return res.status(400).json({ error: 'Kalshi auth failed: '+e.message.slice(0,100) });
  }
  state.running = true;
  setStatus('Agent started');
  await loadMarkets();
  res.json({ ok: true, balance: state.balance });
});

app.post('/api/agent/stop', (req, res) => {
  state.running = false;
  setStatus('Agent stopped');
  res.json({ ok: true });
});

app.post('/api/settings', (req, res) => {
  const { minOdds, stopLoss, pullTarget, resetTo, autoCopy, categories } = req.body;
  if (minOdds    !== undefined) state.settings.minOdds    = minOdds;
  if (stopLoss   !== undefined) state.settings.stopLoss   = stopLoss;
  if (pullTarget !== undefined) state.settings.pullTarget = pullTarget;
  if (resetTo    !== undefined) state.settings.resetTo    = resetTo;
  if (autoCopy   !== undefined) state.settings.autoCopy   = autoCopy;
  if (categories !== undefined) state.settings.categories = categories;
  broadcast('settings', state.settings);
  res.json({ ok: true, settings: state.settings });
});

app.post('/api/trade', async (req, res) => {
  const { ticker, side, price } = req.body;
  if (!ticker || !side || !price)
    return res.status(400).json({ error: 'ticker, side, and price are required' });
  try {
    const result = await placeOrder(ticker, side, price);
    res.json({ ok: true, result });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/markets', (req, res) => res.json(state.markets));
app.get('/api/orders',  (req, res) => res.json(state.orderLog));
app.post('/api/markets/refresh', async (req, res) => {
  await loadMarkets();
  res.json({ ok: true, count: state.markets.length });
});

// Add manual trader to follow
app.post('/api/traders/follow', (req, res) => {
  const { wallet, name } = req.body;
  if (!wallet) return res.status(400).json({ error: 'wallet required' });
  if (!state.followedTraders.find(t => t.wallet === wallet)) {
    state.followedTraders.push({ wallet, name: name || wallet.slice(0, 10) });
  }
  broadcast('traders', state.followedTraders);
  res.json({ ok: true, traders: state.followedTraders });
});

app.post('/api/traders/unfollow', (req, res) => {
  const { wallet } = req.body;
  state.followedTraders = state.followedTraders.filter(t => t.wallet !== wallet);
  broadcast('traders', state.followedTraders);
  res.json({ ok: true });
});

// WebSocket removed — clients poll /api/state directly

// ─── Serve dashboard ──────────────────────────────────────────────────────────
// Dashboard embedded inline — no file system needed
const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"/>
<meta name="apple-mobile-web-app-capable" content="yes"/>
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent"/>
<title>Kalshi Agent</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;background:#07080f;font-family:monospace;color:#d0d8f0;font-size:13px}
body{overscroll-behavior:none;-webkit-tap-highlight-color:transparent}
button{font-family:monospace;cursor:pointer;-webkit-appearance:none}
.app{display:flex;flex-direction:column;height:100vh}
.topbar{background:#0a0c16;border-bottom:1px solid #151830;padding:12px 16px;display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;flex-shrink:0}
.logo{width:30px;height:30px;border-radius:5px;background:linear-gradient(135deg,#4a9eff,#00e5a0);display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0}
.title{font-size:13px;font-weight:700;color:#fff}.title span{color:#4a9eff}
.sub{font-size:9px;color:#444870;letter-spacing:1px}
.pill{padding:3px 8px;border-radius:20px;font-size:9px;letter-spacing:1px}
.pill-g{background:#00e5a011;border:1px solid #00e5a044;color:#00e5a0}
.pill-b{background:#4a9eff11;border:1px solid #4a9eff44;color:#4a9eff}
.pill-gray{background:#151830;border:1px solid #252850;color:#666}
.statbar{background:#090b14;border-bottom:1px solid #151830;padding:10px 14px;display:flex;gap:0;overflow-x:auto;flex-shrink:0}
.stat{padding:0 14px;border-right:1px solid #151830;flex-shrink:0}
.stat:first-child{padding-left:0}
.sl{font-size:9px;color:#444870;letter-spacing:1px;text-transform:uppercase;margin-bottom:2px}
.sv{font-size:15px;font-weight:700;letter-spacing:-.5px}
.pw{padding:0 14px;flex-shrink:0;min-width:130px}
.pb{height:5px;background:#151830;border-radius:3px;margin:4px 0 3px}
.pf{height:100%;border-radius:3px;background:linear-gradient(90deg,#4a9eff66,#00e5a0);transition:width .4s}
.model-bar{background:#060e08;border-bottom:1px solid #00e5a022;padding:5px 14px;font-size:10px;color:#00e5a0;flex-shrink:0}
.statusbar{background:#07080f;border-bottom:1px solid #151830;padding:5px 14px;font-size:10px;color:#555;flex-shrink:0}
.tabbar{border-bottom:1px solid #151830;display:flex;background:#090b14;overflow-x:auto;flex-shrink:0}
.tab{background:none;border:none;padding:10px 14px;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#444870;border-bottom:2px solid transparent;white-space:nowrap;flex-shrink:0}
.tab.active{color:#4a9eff;border-bottom-color:#4a9eff}
.badge{background:#252850;color:#777;font-size:8px;padding:1px 4px;border-radius:8px;font-weight:700;margin-left:3px}
.tab.active .badge{background:#4a9eff;color:#000}
.panel{flex:1;overflow-y:auto;padding:12px 14px;display:none}
.panel.active{display:block}
.empty{text-align:center;padding:40px 20px;color:#333355;font-size:10px;letter-spacing:2px}
.btn{display:block;width:100%;padding:11px;border-radius:6px;border:none;font-size:13px;font-weight:700;margin-bottom:8px;text-align:center;-webkit-appearance:none;cursor:pointer}
.btn-blue{background:linear-gradient(135deg,#4a9eff,#0055cc);color:#fff}
.btn-gold{background:linear-gradient(135deg,#f5a623,#e08800);color:#000}
.btn-red{background:linear-gradient(135deg,#ff4455,#cc2233);color:#fff}
.btn-ghost{background:transparent;border:1px solid #252850;color:#666}
.warn{background:#0a0800;border:1px solid #f5a62333;border-radius:6px;padding:10px 12px;color:#f5a623;font-size:10px;margin-bottom:10px;line-height:1.6}
.inp{width:100%;padding:10px 12px;border-radius:6px;border:1px solid #252850;background:#151830;color:#fff;font-size:12px;outline:none;margin-bottom:8px}
.inp:focus{border-color:#4a9eff88}
.row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid #111525}
.row:last-child{border:none}
.seg{display:flex;gap:3px}
.sb{padding:4px 9px;font-size:10px;border-radius:3px;border:1px solid #252850;background:transparent;color:#555;font-family:monospace;cursor:pointer}
.sb.ab{border-color:#4a9eff88;background:#4a9eff18;color:#4a9eff}
.sb.ar{border-color:#ff445588;background:#ff445518;color:#ff4455}
.tog{width:34px;height:17px;border-radius:9px;position:relative;cursor:pointer;transition:background .2s;flex-shrink:0;border:none}
.tok{position:absolute;top:2px;width:13px;height:13px;border-radius:50%;background:#fff;transition:left .2s}
.flash{position:fixed;top:0;left:0;right:0;z-index:999;padding:9px 16px;font-size:11px;font-weight:700;display:none;animation:sd .2s ease}
@keyframes sd{from{opacity:0;transform:translateY(-6px)}to{opacity:1}}
.fs{background:#00e5a022;border-bottom:1px solid #00e5a066;color:#00e5a0}
.fe{background:#ff445522;border-bottom:1px solid #ff445566;color:#ff4455}
.fw{background:#f5a62322;border-bottom:1px solid #f5a62366;color:#f5a623}
</style>
</head>
<body>
<div class="app">
<div id="flash" class="flash"></div>

<div class="topbar">
  <div style="display:flex;align-items:center;gap:10px">
    <div class="logo">📈</div>
    <div><div class="title">KALSHI <span>AGENT</span></div><div class="sub">CFTC · USD · 24/7</div></div>
  </div>
  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
    <div id="ws-pill" class="pill pill-gray">○ Connecting</div>
    <div id="bal-pill" class="pill pill-gray">— USD</div>
    <button id="agent-btn" class="btn btn-gold" style="width:auto;padding:6px 14px;margin:0;font-size:11px" onclick="toggleAgent()">▶ START</button>
    <button class="btn btn-ghost" style="width:auto;padding:6px 10px;margin:0;font-size:10px" onclick="refreshAll()">↺</button>
  </div>
</div>

<div class="statbar">
  <div class="stat"><div class="sl">Balance</div><div class="sv" id="s-bal" style="color:#fff">$0.00</div></div>
  <div class="stat"><div class="sl">Target</div><div class="sv" id="s-target" style="color:#4a9eff">$78.00</div></div>
  <div class="stat"><div class="sl">P&L</div><div class="sv" id="s-pnl" style="color:#888">$0.00</div></div>
  <div class="stat"><div class="sl">Orders</div><div class="sv" id="s-ord" style="color:#4a9eff">0</div></div>
  <div class="stat"><div class="sl">SL Hits</div><div class="sv" id="s-sl" style="color:#888">0</div></div>
  <div class="stat"><div class="sl">Secured</div><div class="sv" id="s-sec" style="color:#888">$0.00</div></div>
  <div class="pw">
    <div class="sl">TO TARGET</div>
    <div class="pb"><div class="pf" id="prog" style="width:0%"></div></div>
    <div style="font-size:9px;color:#4a9eff" id="prog-txt">$0.00 / $78.00</div>
  </div>
</div>

<div class="model-bar" id="model-bar">🧠 Adaptive model · waiting for trades</div>
<div class="statusbar" id="status-bar">● Connecting…</div>

<div class="tabbar">
  <button class="tab active" onclick="switchTab('markets',this)">Markets<span class="badge" id="bm">0</span></button>
  <button class="tab" onclick="switchTab('orders',this)">Orders<span class="badge" id="bo">0</span></button>
  <button class="tab" onclick="switchTab('settings',this)">Settings</button>
</div>

<!-- MARKETS -->
<div id="panel-markets" class="panel active">
  <div style="margin-bottom:8px">
    <button class="btn btn-ghost" style="font-size:11px;padding:8px" onclick="loadMarketsPublic()">📊 Browse Markets (no keys needed)</button>
  </div>
  <div id="no-keys-warn" class="warn" style="display:none">
    ⚠ <b>API keys not set</b> — agent cannot start yet.<br><br>
    1. Go to <b style="color:#fff">railway.app</b> → your project → <b style="color:#fff">Variables</b><br>
    2. Add <b style="color:#fff">KALSHI_KEY_ID</b> and <b style="color:#fff">KALSHI_PRIVATE_KEY</b><br>
    3. Railway redeploys in ~30 seconds → refresh this page → tap START
  </div>
  <div style="display:flex;gap:4px;flex-wrap:wrap;margin-bottom:8px" id="cat-bar"></div>
  <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center">
    <div style="font-size:9px;color:#444870;flex:1" id="mkt-count"></div>
    <button onclick="sortBy('volume')" id="sort-vol" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #4a9eff66;background:#4a9eff18;color:#4a9eff;font-family:monospace;cursor:pointer">↓ Vol</button>
    <button onclick="sortBy('odds')" id="sort-odds" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #252850;background:transparent;color:#555;font-family:monospace;cursor:pointer">50/50</button>
    <button onclick="sortBy('hot')" id="sort-hot" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #252850;background:transparent;color:#555;font-family:monospace;cursor:pointer">🔥</button>
  </div>
  <div id="markets-list"><div class="empty">TAP START TO LOAD MARKETS</div></div>
</div>

<!-- ORDERS -->
<div id="panel-orders" class="panel">
  <div id="orders-list"><div class="empty">NO ORDERS YET</div></div>
</div>

<!-- SETTINGS -->
<div id="panel-settings" class="panel">
  <div class="row">
    <div><div style="font-size:11px;color:#ccc">Profit Target</div><div style="font-size:9px;color:#555">pull profits above this</div></div>
    <div class="seg">
      <button class="sb" onclick="setSetting('pullTarget',50,this)">$50</button>
      <button class="sb ab" onclick="setSetting('pullTarget',78,this)">$78</button>
      <button class="sb" onclick="setSetting('pullTarget',100,this)">$100</button>
      <button class="sb" onclick="setSetting('pullTarget',150,this)">$150</button>
    </div>
  </div>
  <div class="row">
    <div><div style="font-size:11px;color:#ccc">Reset To</div><div style="font-size:9px;color:#555">balance after pull</div></div>
    <div class="seg">
      <button class="sb ab" onclick="setSetting('resetTo',39,this)">$39</button>
      <button class="sb" onclick="setSetting('resetTo',25,this)">$25</button>
      <button class="sb" onclick="setSetting('resetTo',50,this)">$50</button>
    </div>
  </div>
  <div class="row">
    <div><div style="font-size:11px;color:#ccc">Min Odds</div><div style="font-size:9px;color:#555">skip trades below this</div></div>
    <div class="seg">
      <button class="sb" onclick="setSetting('minOdds',25,this)">25¢</button>
      <button class="sb ab" onclick="setSetting('minOdds',35,this)">35¢</button>
      <button class="sb" onclick="setSetting('minOdds',45,this)">45¢</button>
      <button class="sb" onclick="setSetting('minOdds',55,this)">55¢</button>
    </div>
  </div>
  <div class="row">
    <div><div style="font-size:11px;color:#ccc">Stop Loss</div><div style="font-size:9px;color:#555">exit at this % loss</div></div>
    <div class="seg">
      <button class="sb" onclick="setSetting('stopLoss',0.20,this)">20%</button>
      <button class="sb ar" onclick="setSetting('stopLoss',0.30,this)">30%</button>
      <button class="sb" onclick="setSetting('stopLoss',0.40,this)">40%</button>
      <button class="sb" onclick="setSetting('stopLoss',0.50,this)">50%</button>
    </div>
  </div>
  <div class="row" style="border:none">
    <div><div style="font-size:11px;color:#ccc">Trade Size</div><div style="font-size:9px;color:#555">adaptive % of balance</div></div>
    <div id="ts-disp" style="font-size:12px;font-weight:700;color:#00e5a0">2.0%</div>
  </div>
  <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
    <button class="btn btn-ghost" style="width:auto;padding:8px 12px;margin:0;font-size:11px" onclick="apiPost('/api/markets/refresh',{}).then(()=>flash('success','Markets refreshed'))">↺ Markets</button>
    <button class="btn btn-ghost" style="width:auto;padding:8px 12px;margin:0;font-size:11px" onclick="refreshAll()">↺ Full Refresh</button>
  </div>

  <!-- Adaptive model detail -->
  <div style="margin-top:14px;background:#0a0c16;border:1px solid #1e1e2e;border-radius:6px;padding:14px">
    <div style="font-size:10px;color:#888;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Adaptive Model</div>
    <div id="model-detail" style="font-size:10px;color:#888;line-height:1.8">Loading…</div>
  </div>

  <!-- Railway vars reminder -->
  <div style="margin-top:12px;background:#0a0c16;border:1px solid #4a9eff22;border-radius:6px;padding:14px">
    <div style="font-size:10px;color:#4a9eff;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Railway Variables Required</div>
    <div style="font-size:10px;color:#888;line-height:1.8">
      <b style="color:#ccc">KALSHI_KEY_ID</b> — from kalshi.com → Settings → API<br>
      <b style="color:#ccc">KALSHI_PRIVATE_KEY</b> — RSA private key (full PEM with headers)
    </div>
  </div>

  <!-- Error log -->
  <div style="margin-top:12px;background:#0a0c16;border:1px solid #ff445522;border-radius:6px;padding:14px">
    <div style="font-size:10px;color:#ff4455;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Error Log</div>
    <div id="error-log" style="font-size:9px;color:#888">None</div>
  </div>
</div>
</div>

<script>
// ── State ─────────────────────────────────────────────────────────────────────
let state = {
  running:false, balance:0, pnl:0, secured:0, slHits:0,
  markets:[], orderLog:[], errors:[],
  settings:{pullTarget:78,resetTo:39,minOdds:35,stopLoss:0.30},
  model:{maxOpen:10,copyPct:0.02,successRate:null,sessionWins:0,sessionLosses:0},
  config:{hasKeys:false}
};
let activeCategory='All';
const CATS=['All','Politics','Sports','Crypto','Economics'];
const CAT_KW={
  Politics:['election','president','congress','senate','trump','vote','govern','ukraine','iran','nato'],
  Sports:  ['nba','nfl','nhl','mlb','soccer','super bowl','world cup','championship','playoff','finals'],
  Crypto:  ['bitcoin','btc','eth','ethereum','crypto','interest rate','cpi','inflation'],
  Economics:['gdp','inflation','cpi','unemployment','fed','recession','earnings'],
};

// ── WebSocket ─────────────────────────────────────────────────────────────────
// Pure HTTP polling — no WebSocket needed
// Works on all Railway deployments
function connectWS(){
  // No-op — using HTTP polling instead
  setPill('ws-pill','● LIVE','pill-g');
}

function handle(msg){
  const{event:ev,data:d}=msg;
  if(ev==='init'){mergeState(d);renderAll();}
  else if(ev==='tick'){Object.assign(state,{balance:d.balance,pnl:d.pnl,secured:d.secured,slHits:d.slHits});updateStats();}
  else if(ev==='balance'){state.balance=d;updateStats();}
  else if(ev==='status'){state.status=d;$('status-bar').textContent='● '+d;}
  else if(ev==='order'){state.orderLog.unshift(d);renderOrders();updateStats();}
  else if(ev==='markets'){state.markets=d;renderMarkets();}
  else if(ev==='model_updated'){state.model=d;renderModel();}
  else if(ev==='optimizing'){$('model-bar').textContent='⏳ Optimizing model… running 500 simulations';}
  else if(ev==='profit_pull'){flash('success','💰 Profit pulled: $'+d.pulled+' · Secured: $'+d.total.toFixed(2));state.secured=d.total;updateStats();}
  else if(ev==='sl_hit'){flash('warn','SL hit: '+d.order.ticker+' · recovered $'+d.recovered);state.slHits=(state.slHits||0)+1;updateStats();}
  else if(ev==='error'){addError(d);flash('error',d.slice(0,60));}
  else if(ev==='settings'){state.settings=d;applySettings();}
}

function mergeState(d){
  if(!d)return;
  Object.assign(state,d);
  if(d.config)state.config=d.config;
  if(d.model)state.model=d.model;
  if(d.settings)state.settings=d.settings;
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderAll(){
  updateStats();renderMarkets();renderOrders();renderModel();applySettings();
  updateAgentBtn();
  if(!state.config?.hasKeys){
    $('no-keys-warn').style.display='block';
    $('status-bar').textContent='● Add KALSHI_KEY_ID and KALSHI_PRIVATE_KEY in Railway → Variables';
  }
  buildCatBar();
}

function updateStats(){
  const bal=state.balance||0,pt=state.settings?.pullTarget||78;
  const pct=Math.min(100,(bal/pt)*100);
  $('s-bal').textContent='$'+bal.toFixed(2);
  $('s-pnl').textContent=(state.pnl>=0?'+':'')+' $'+Math.abs(state.pnl||0).toFixed(2);
  $('s-pnl').style.color=(state.pnl||0)>=0?'#00e5a0':'#ff4455';
  $('s-ord').textContent=(state.orderLog||[]).filter(o=>o.status==='open').length;
  $('s-sl').textContent=state.slHits||0;
  $('s-sec').textContent='$'+(state.secured||0).toFixed(2);
  if((state.secured||0)>0)$('s-sec').style.color='#ffd700';
  $('prog').style.width=pct.toFixed(1)+'%';
  $('prog-txt').textContent='$'+bal.toFixed(2)+' / $'+pt.toFixed(2);
  $('s-target').textContent='$'+pt.toFixed(2);
  $('bal-pill').textContent='$'+bal.toFixed(2)+' USD';
  $('ts-disp').textContent=(((state.model?.copyPct)||0.02)*100).toFixed(1)+'% · $'+Math.max(0.01,+(bal*(state.model?.copyPct||0.02)).toFixed(2));
}

function buildCatBar(){
  const bar=$('cat-bar');if(!bar)return;
  bar.innerHTML=CATS.map(c=>'<button onclick="filterCat(\\''+c+'\\')"'
    +' style="padding:4px 10px;font-size:10px;border-radius:3px;font-family:monospace;cursor:pointer;white-space:nowrap;'
    +'border:1px solid '+(c===activeCategory?'#4a9eff88':'#252850')+';'
    +'background:'+(c===activeCategory?'#4a9eff18':'transparent')+';'
    +'color:'+(c===activeCategory?'#4a9eff':'#555')+'">'+c+'</button>').join('');
}

function filterCat(cat){activeCategory=cat;buildCatBar();renderMarkets();}

function renderMarkets(){
  const el=$('markets-list');if(!el)return;
  const allKW=Object.values(CAT_KW).flat();
  let filtered=activeCategory==='All'
    ?state.markets
    :state.markets.filter(m=>{
      if(m.category&&m.category.includes(activeCategory.toLowerCase()))return true;
      const t=(m.title||'').toLowerCase();
      return(CAT_KW[activeCategory]||[]).some(k=>t.includes(k));
    });

  $('mkt-count').textContent=filtered.length+' markets';
  $('bm').textContent=filtered.length;

  if(!filtered.length){el.innerHTML='<div class="empty">NO '+activeCategory.toUpperCase()+' MARKETS<br><br>Tap ↺ Markets in Settings</div>';return;}

  el.innerHTML=filtered.slice(0,80).map(m=>{
    const yO=m.yes_bid||50;
    const nO=m.no_bid||(100-yO);
    const yC=yO>=60?'#00e5a0':yO>=40?'#f5a623':'#ff4455';
    const nC=nO>=60?'#00e5a0':nO>=40?'#f5a623':'#ff4455';
    const q = (m.title||m.ticker||'').slice(0,80);
    const vol=m.volume_24h>0?'24h: '+m.volume_24h.toFixed(0)+' contracts':m.volume>0?'Vol: '+m.volume.toFixed(0):''; 
    const hot=yO>=65?'<span style="font-size:8px;background:#00e5a022;color:#00e5a0;border:1px solid #00e5a044;border-radius:3px;padding:1px 5px;margin-left:5px">HOT</span>':'';
    return '<div style="background:#0a0c16;border:1px solid #1a1a2a;border-radius:8px;padding:12px;margin-bottom:8px">'
      +'<div style="font-size:11px;color:#e0e8ff;font-weight:600;line-height:1.4;margin-bottom:4px">'+q+hot+'</div>'
      +'<div style="font-size:9px;color:#444870;margin-bottom:10px">'+vol+'</div>'
      +'<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'
      +'<button data-ticker="'+m.ticker+'" data-price="'+yO+'" onclick="trade(this.dataset.ticker,\\'yes\\',parseInt(this.dataset.price))"'
      +' style="padding:12px 6px;border-radius:6px;border:1px solid '+yC+'55;background:'+yC+'18;color:'+yC+';font-family:monospace;font-weight:700;cursor:pointer;-webkit-appearance:none">'
      +'<div style="font-size:11px;opacity:.7">YES</div>'
      +'<div style="font-size:18px;margin-top:2px">'+yO+'¢</div>'
      +'</button>'
      +'<button data-ticker="'+m.ticker+'" data-price="'+nO+'" onclick="trade(this.dataset.ticker,\\'no\\',parseInt(this.dataset.price))"'
      +' style="padding:12px 6px;border-radius:6px;border:1px solid '+nC+'55;background:'+nC+'18;color:'+nC+';font-family:monospace;font-weight:700;cursor:pointer;-webkit-appearance:none">'
      +'<div style="font-size:11px;opacity:.7">NO</div>'
      +'<div style="font-size:18px;margin-top:2px">'+nO+'¢</div>'
      +'</button>'
      +'</div></div>';
  }).join('');
}

function sortBy(by){
  ['vol','odds','hot'].forEach(s=>{
    const b=$('sort-'+s);if(!b)return;
    const on=(s==='vol'&&by==='volume')||(s===by);
    b.style.borderColor=on?'#4a9eff66':'#252850';
    b.style.background=on?'#4a9eff18':'transparent';
    b.style.color=on?'#4a9eff':'#555';
  });
  if(by==='volume')state.markets.sort((a,b)=>(b.volume||0)-(a.volume||0));
  else if(by==='odds')state.markets.sort((a,b)=>Math.abs((a.yes_bid||50)-50)-Math.abs((b.yes_bid||50)-50));
  else if(by==='hot')state.markets.sort((a,b)=>(b.volume||0)*Math.abs((b.yes_bid||50)-50)-(a.volume||0)*Math.abs((a.yes_bid||50)-50));
  renderMarkets();
}

function renderOrders(){
  const log=state.orderLog||[];
  $('bo').textContent=log.length;
  $('orders-list').innerHTML=log.length?log.slice(0,50).map(o=>{
    const cl=o.status==='stopped'?'#ff4455':o.side==='yes'?'#00e5a0':'#4a9eff';
    return '<div style="background:#0a0c16;border:1px solid #1a1a2a;border-radius:7px;padding:11px 13px;margin-bottom:7px">'
      +'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">'
      +'<span style="font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;background:'+cl+'22;color:'+cl+'">'
      +(o.status==='stopped'?'STOPPED':o.side.toUpperCase())+'</span>'
      +'<span style="font-size:13px;font-weight:700;color:#fff">$'+o.stake.toFixed(2)+'</span></div>'
      +'<div style="font-size:11px;color:#ccc">'+o.ticker+'</div>'
      +'<div style="font-size:9px;color:#444870;margin-top:3px">'+o.price+'¢ · '+o.count+' contracts · '+new Date(o.ts).toLocaleTimeString()+'</div>'
      +'</div>';
  }).join(''):'<div class="empty">NO ORDERS YET</div>';
}

function renderModel(){
  const m=state.model||{};
  const settled=(m.sessionWins||0)+(m.sessionLosses||0);
  const wr=settled>0?Math.round((m.sessionWins||0)/settled*100)+'%':'—';
  $('model-bar').textContent=m.optimizing?'⏳ Optimizing… running 500 simulations'
    :settled<5?'🧠 Needs 5 trades to calibrate · defaults active'
    :'🧠 '+(m.maxOpen||10)+' pos · '+((m.copyPct||0.02)*100).toFixed(1)+'% size · '+(m.successRate||'—')+'% success · win% '+wr;
  $('model-detail').innerHTML=
    '<div>Max positions: <b style="color:#fff">'+(m.maxOpen||10)+'</b></div>'
    +'<div>Trade size: <b style="color:#fff">'+((m.copyPct||0.02)*100).toFixed(1)+'%</b></div>'
    +'<div>Success rate: <b style="color:#00e5a0">'+(m.successRate||'—')+'%</b></div>'
    +'<div>Est. mins to target: <b style="color:#f5a623">'+(m.estMins||'—')+'</b></div>'
    +'<div>Session win rate: <b style="color:#fff">'+wr+'</b></div>'
    +'<div>Settled trades: <b style="color:#fff">'+settled+'</b></div>'
    +'<div style="color:#444870;font-size:9px;margin-top:4px">Re-optimizes every 10 settled trades</div>';
}

function addError(msg){
  const el=$('error-log');
  if(!el)return;
  el.innerHTML='<div style="color:#ff4455;margin-bottom:3px">'+new Date().toLocaleTimeString()+' '+msg+'</div>'+(el.innerHTML==='None'?'':el.innerHTML);
}

function applySettings(){
  const s=state.settings||{};
  [25,35,45,55].forEach(v=>{const b=document.querySelector('[onclick*="minOdds,'+v+'"]');if(b){b.classList.toggle('ab',s.minOdds===v);}});
  [0.20,0.30,0.40,0.50].forEach(v=>{const b=document.querySelector('[onclick*="stopLoss,'+v+'"]');if(b){b.classList.toggle('ar',s.stopLoss===v);}});
  [50,78,100,150].forEach(v=>{const b=document.querySelector('[onclick*="pullTarget,'+v+'"]');if(b){b.classList.toggle('ab',s.pullTarget===v);}});
}

function updateAgentBtn(){
  const r=state.running;const b=$('agent-btn');
  b.textContent=r?'⏹ STOP':'▶ START';
  b.className='btn '+(r?'btn-red':'btn-gold');
  b.style.cssText='width:auto;padding:6px 14px;margin:0;font-size:11px';
}

// ── Actions ───────────────────────────────────────────────────────────────────
async function toggleAgent(){
  const r=state.running;
  if(!r && !state.config?.hasKeys){
    flash('warn','Add API keys in Railway → Variables first — see warning above');
    $('no-keys-warn').style.display='block';
    return;
  }
  const res=await apiPost(r?'/api/agent/stop':'/api/agent/start',{});
  if(res.error){flash('error',res.error.slice(0,80));return;}
  state.running=!r;updateAgentBtn();
  flash(!r?'success':'warn',!r?'Agent started · trading 24/7':'Agent stopped');
}

async function trade(ticker,side,price){
  if(!state.running){flash('error','Start the agent first');return;}
  const res=await apiPost('/api/trade',{ticker,side,price});
  if(res.error)flash('error',res.error.slice(0,60));
  else flash('success',side.toUpperCase()+' '+ticker+' · $'+res.result?.order?.remaining_count||'?');
}

async function setSetting(key,val,btn){
  btn.closest('.seg').querySelectorAll('.sb').forEach(b=>b.classList.remove('ab','ar'));
  btn.classList.add(key==='stopLoss'?'ar':'ab');
  const res=await apiPost('/api/settings',{[key]:val});
  if(res.ok)state.settings[key]=val;
  updateStats();
}

async function loadMarketsPublic(){
  const res=await fetch('/api/markets/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  const d=await res.json().catch(()=>({}));
  if(d.count!==undefined){flash('success',d.count+' markets loaded');
    fetch('/api/state').then(r=>r.json()).then(d=>{mergeState(d);renderMarkets();});}
  else flash('warn','Markets need server running — check Railway deployment');
}

async function refreshAll(){
  const d=await fetch('/api/state').then(r=>r.json()).catch(()=>({}));
  mergeState(d);renderAll();flash('success','Refreshed');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function switchTab(n,b){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  b.classList.add('active');document.getElementById('panel-'+n).classList.add('active');
}
function $(id){return document.getElementById(id);}
function setPill(id,txt,cls){const e=$(id);e.textContent=txt;e.className='pill '+cls;}
function flash(t,m){
  const e=$('flash');e.className='flash f'+t[0];
  e.textContent=(t==='success'?'✓ ':t==='error'?'✗ ':'⚠ ')+m;
  e.style.display='block';setTimeout(()=>e.style.display='none',3500);
}
async function apiPost(url,body){
  try{const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return await r.json();}
  catch(e){return{error:e.message};}
}

// ── Init ──────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function(){
  setPill('ws-pill','● LIVE','pill-g');
  // Initial load
  fetch('/api/state').then(r=>r.json()).then(d=>{mergeState(d);renderAll();}).catch(()=>{});
  // Poll every 3 seconds for live updates
  setInterval(()=>{
    fetch('/api/state').then(r=>r.json()).then(d=>{
      mergeState(d);
      updateStats();
      renderOrders();
      renderModel();
      updateAgentBtn();
    }).catch(()=>{ setPill('ws-pill','○ OFFLINE','pill-gray'); });
  }, 3000);
});
</script>
</body>
</html>
`;

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.send(DASHBOARD_HTML);
});

// ─── Start ────────────────────────────────────────────────────────────────────
// Railway requires binding to 0.0.0.0
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Kalshi agent running on port ${PORT}`);
  console.log(`KALSHI_KEY_ID set: ${!!ENV.KALSHI_KEY_ID}`);
  console.log(`KALSHI_PRIVATE_KEY set: ${!!ENV.KALSHI_PRIVATE_KEY}`);
});
setInterval(agentTick, 15_000);

// Pre-load markets on boot
setTimeout(async () => {
  if (ENV.KALSHI_KEY_ID) {
    await loadBalance();
    await loadMarkets();
  }
}, 2000);
