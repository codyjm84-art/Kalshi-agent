// ─────────────────────────────────────────────────────────────────────────────
// Kalshi 24/7 Trading Agent Server
// Deploy on Railway.app — iPhone dashboard at your Railway URL
// ─────────────────────────────────────────────────────────────────────────────

import express from 'express';
import fetch   from 'node-fetch';
// ws module not used — HTTP polling only
import { createServer }    from 'http';
import crypto  from 'crypto';

const app    = express();
const server = createServer(app);
// WebSocket removed — dashboard uses HTTP polling
const PORT   = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// ─── Environment variables (set in Railway → Variables) ───────────────────────
const ENV = {
  KALSHI_KEY_ID:      process.env.KALSHI_KEY_ID      || '',
  KALSHI_PRIVATE_KEY: process.env.KALSHI_PRIVATE_KEY || '',
};

const KALSHI_BASE = 'https://trading-api.kalshi.com/trade-api/v2';

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
    // Public endpoint — no auth required
    const res  = await fetch(`${KALSHI_BASE}/markets?limit=200&status=open`);
    const data = await res.json();
    const allKW = state.settings.categories.flatMap(c => CAT_KW[c] || []);
    state.markets = (data.markets || []).filter(m => {
      const yes = m.yes_bid || m.last_price || 50;
      if (yes < state.settings.minOdds || yes > 100 - state.settings.minOdds) return false;
      const text = (m.title || m.ticker || '').toLowerCase();
      return allKW.some(k => text.includes(k));
    });
    broadcast('markets', state.markets.slice(0, 100));
    setStatus(`${state.markets.length} markets loaded`);
  } catch(e) {
    logError(e);
    setStatus('Markets load failed: ' + e.message.slice(0, 50));
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
app.get('/api/state', (req, res) => res.json({
  ...state,
  config: { hasKeys: !!(ENV.KALSHI_KEY_ID && ENV.KALSHI_PRIVATE_KEY) },
}));

app.post('/api/agent/start', async (req, res) => {
  if (!ENV.KALSHI_KEY_ID || !ENV.KALSHI_PRIVATE_KEY)
    return res.status(400).json({ error: 'Set KALSHI_KEY_ID and KALSHI_PRIVATE_KEY in Railway → Variables' });
  state.running = true;
  setStatus('Agent started');
  await loadMarkets();
  res.json({ ok: true });
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
app.get('/', (req, res) => res.sendFile('index.html', { root: 'public' }));

// ─── Start ────────────────────────────────────────────────────────────────────
server.listen(PORT, () => console.log(`Kalshi agent running on port ${PORT}`));
setInterval(agentTick, 15_000);

// Pre-load markets on boot
setTimeout(async () => {
  if (ENV.KALSHI_KEY_ID) {
    await loadBalance();
    await loadMarkets();
  }
}, 2000);
