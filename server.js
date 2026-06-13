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

app.use((req,res,next)=>{
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  if(req.method==='OPTIONS')return res.sendStatus(200);
  next();
});
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
  Politics:  ['election','president','congress','senate','trump','vote','govern','ukraine','russia','iran','nato','tariff','policy','bill','law','fed chair','supreme','cabinet'],
  Sports:    ['nba','nfl','nhl','mlb','mls','soccer','super bowl','world cup','championship','playoff','finals','league','series','cup','win','game','match','score','mvp','coach'],
  Crypto:    ['bitcoin','btc','eth','ethereum','crypto','solana','sol','xrp','doge','bnb','usdt','coinbase','binance','above','below','price','token','blockchain','defi','altcoin','halving'],
  Economics: ['gdp','inflation','cpi','unemployment','fed','recession','earnings','jobs','mortgage','housing','retail','deficit','tariff','trade'],
};

// Kalshi category values mapped to our tabs
const KALSHI_CATS = {
  Politics:  ['politics','political','election','economics'],
  Sports:    ['sports','sport'],
  Crypto:    ['crypto','cryptocurrency','finance'],
  Economics: ['economics','economy','finance','business'],
};

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  running:   false,
  status:    'Stopped',
  lastTick:  null,
  errors:    [],
  balance:   0,
  pnl:       0,   // session P&L — negative = loss
  secured:   0,
  slHits:    0,
  openOrders: [],
  orderLog:  [],
  markets:   [],
  marketsUpdated: null,
  followedTraders: [],
  autoTrade: false,          // master auto-trade switch
  signals:   [],             // detected trade signals
  autoLog:   [],             // auto-trade activity log
  priceHistory: {},          // ticker -> [price, price, ...] for momentum
  stoppedSet: [],            // persisted stopped tickers
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
    copyPct:      0.10,
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
  const ts = Date.now().toString();
  // Sign only the base path without query params — Kalshi requirement
  const basePath = path.split('?')[0];
  const msg = ts + method + '/trade-api/v2' + basePath;
  const key = crypto.createPrivateKey(ENV.KALSHI_PRIVATE_KEY);
  const sig = crypto.sign('sha256', Buffer.from(msg), {
    key,
    padding:    crypto.constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 32,
  });
  return { ts, sig: sig.toString('base64') };
}

// Rate limiter — minimum gap between Kalshi API requests
let lastKalshiRequest = 0;
const MIN_REQUEST_GAP = 500; // 500ms minimum between requests (max 2/sec)

async function kalFetch(method, path, body = null) {
  // Enforce rate limit gap
  const _now = Date.now();
  const _gap = _now - lastKalshiRequest;
  if (_gap < MIN_REQUEST_GAP) await new Promise(r => setTimeout(r, MIN_REQUEST_GAP - _gap));
  lastKalshiRequest = Date.now();
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
      // Paginate through ALL events — target 3000+ markets
      let allEvents = [];
      let cursor = '';
      for (let page = 0; page < 20; page++) {
        const url = '/events?limit=200&status=open&with_nested_markets=true' + (cursor ? '&cursor='+encodeURIComponent(cursor) : '');
        const evRes = await kalFetch('GET', url);
        const batch = evRes.events || [];
        allEvents = allEvents.concat(batch);
        if (!evRes.cursor || batch.length < 200) break;
        cursor = evRes.cursor;
      }
      for (const ev of allEvents) {
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
            close_time: ev.close_time || m.close_time || null,
            open_interest: parseFloat(m.open_interest_fp||0),
          });
        }
      }
      // Also fetch near-term markets (sports, daily crypto) separately
      // These don't appear well in the events API
      try {
        const nearRes = await kalFetch('GET', '/markets?limit=1000&status=open&min_close_ts='+Math.floor(Date.now()/1000)+'&max_close_ts='+Math.floor((Date.now()+90*86400000)/1000));
        const nearRaw = nearRes.markets || [];
        let added = 0;
        for (const m of nearRaw) {
          if (markets.find(x => x.ticker === m.ticker)) continue; // skip duplicates
          const yes = m.yes_bid_dollars ? Math.round(parseFloat(m.yes_bid_dollars)*100) : 50;
          if (yes < state.settings.minOdds || yes > 100 - state.settings.minOdds) continue;
          const title = m.yes_sub_title || m.title || m.ticker;
          markets.push({
            ticker:     m.ticker,
            title,
            yes_bid:    yes,
            no_bid:     100 - yes,
            volume:     parseFloat(m.volume_fp || 0),
            volume_24h: parseFloat(m.volume_24h_fp || 0),
            category:   (m.category || '').toLowerCase(),
            close_time: m.close_time || null,
            open_interest: parseFloat(m.open_interest_fp || 0),
          });
          added++;
        }
        if (added > 0) {
          const sample = markets.filter(m=>m.close_time).sort((a,b)=>new Date(a.close_time)-new Date(b.close_time)).slice(0,5);
          console.log('[Markets] added', added, 'near-term markets. Soonest:', sample.map(m=>m.ticker+'('+m.close_time?.slice(0,10)+')').join(', '));
        }

      // Fetch live daily series markets (MLB, NBA, BTC, etc.)
      // Kalshi series tickers — sports use game-specific formats
      const LIVE_SERIES = [
        'KXNHL',       // NHL hockey
        'KXBTCD',      // BTC daily price
        'KXETHD',      // ETH daily price
        'KXSOLD',      // SOL daily price
        'KXBNBD',      // BNB daily
        'KXNBASPREAD', // NBA game spreads
        'KXNBAML',     // NBA moneyline
        'KXMLBML',     // MLB moneyline
        'KXMLBSPREAD', // MLB spreads
        'KXNFLML',     // NFL moneyline
        'KXNFLSPREAD', // NFL spreads
        'KXSPX500',    // S&P 500
        'KXNDX',       // Nasdaq
        'KXHIGHNY',    // NYC temperature daily
      ];
      for (const series of LIVE_SERIES) {
        try {
          const sr = await kalFetch('GET', '/markets?limit=100&status=open&series_ticker='+series);
          const sMarkets = sr.markets || [];
          let seriesAdded = 0;
          for (const m of sMarkets) {
            if (markets.find(x => x.ticker === m.ticker)) continue;
            const yes = m.yes_bid_dollars ? Math.round(parseFloat(m.yes_bid_dollars)*100) : 50;
            if (yes < state.settings.minOdds || yes > 100 - state.settings.minOdds) continue;
            markets.push({
              ticker:     m.ticker,
              title:      m.yes_sub_title || m.title || m.ticker,
              yes_bid:    yes,
              no_bid:     100 - yes,
              volume:     parseFloat(m.volume_fp || 0),
              volume_24h: parseFloat(m.volume_24h_fp || 0),
              category:   series.includes('MLB')||series.includes('NBA')||series.includes('NFL')||series.includes('NHL') ? 'sports' : 'crypto',
              close_time: m.close_time || null,
              open_interest: parseFloat(m.open_interest_fp || 0),
            });
            seriesAdded++;
          }
          if (seriesAdded > 0) console.log('[Series]', series, 'added', seriesAdded, 'markets');
        } catch(e3) { /* series may not exist */ }
      }
      } catch(e2) { /* silent */ }

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
    state.marketsUpdated = new Date().toISOString();
    // Detect signals immediately after market load
    if (state.markets.length > 0) {
      const rawSigs_=detectSignals(state.markets);
      state.signals=rawSigs_.map(s=>({ticker:s.ticker,side:s.side,price:s.price,type:s.type,reason:s.reason,score:s.score,title:s.market?s.market.title:s.ticker}));
      broadcast('signals',state.signals);
    }
    broadcast('markets', state.markets.slice(0, 200));
    broadcast('markets_updated', state.marketsUpdated);
  } catch(e) {
    logError(e);
    setStatus('Markets failed: ' + e.message.slice(0, 50));
  }
}

// ─── Place order ──────────────────────────────────────────────────────────────
async function placeOrder(ticker, side, priceInCents) {
  if (!ENV.KALSHI_KEY_ID) throw new Error('KALSHI_KEY_ID not set in Railway Variables');
  const stake = Math.max(0.01, +(state.balance * state.model.copyPct).toFixed(2));
  const intCount = Math.max(1, Math.floor(stake * 100 / priceInCents));
  const yesPrice = side === 'yes' ? priceInCents : 100 - priceInCents;

  // Use fill_or_kill with high price to act as market order
  // This executes immediately at best available price
  const askPrice = Math.min(99, yesPrice + 3); // bid + buffer to cross spread

  const body = {
    ticker,
    action:          'buy',
    type:            'limit',
    time_in_force:   'fill_or_kill',  // execute immediately or cancel
    side,
    count:           intCount,
    yes_price:       askPrice,
    client_order_id: Date.now().toString(),
  };

  console.log('[Order] Placing:', JSON.stringify(body));
  let data;
  try {
    data = await kalFetch('POST', '/portfolio/orders', body);
  } catch(e) {
    if (e.message.includes('429') || e.message.includes('too_many')) {
      // Rate limited — wait 5 seconds and retry once
      console.log('[Order] Rate limited, waiting 5s...');
      await new Promise(r => setTimeout(r, 5000));
      data = await kalFetch('POST', '/portfolio/orders', body).catch(e2 => {
        console.error('[Order] Error after retry:', e2.message);
        throw e2;
      });
    } else if (e.message.includes('fill_or_kill') || e.message.includes('insufficient')) {
      console.log('[Order] FOK failed, retrying as regular limit');
      const fallback = {...body};
      delete fallback.time_in_force;
      data = await kalFetch('POST', '/portfolio/orders', fallback).catch(e2 => {
        console.error('[Order] Error:', e2.message);
        throw e2;
      });
    } else {
      console.error('[Order] Error:', e.message);
      throw e;
    }
  }

  state.balance -= stake;
  const market = state.markets.find(m => m.ticker === ticker);
  const entry = {
    id:     data.order?.order_id || ticker+'-'+Date.now(),
    ticker, side, stake,
    price:  priceInCents,
    count:  intCount,
    title:  market ? market.title : ticker,
    ts:     Date.now(),
    status: 'open',
    synced: false,
  };
  state.openOrders.push(entry);
  state.orderLog.unshift(entry);
  state.orderLog = state.orderLog.slice(0, 100);
  broadcast('order',   entry);
  broadcast('balance', state.balance);
  setStatus(`Order placed: ${side.toUpperCase()} ${ticker} · $${stake.toFixed(2)} · ${intCount} contracts`);
  console.log('[Kalshi] Order placed:', side.toUpperCase(), ticker, '$'+stake.toFixed(2), intCount, 'contracts');
  return data;
}


// ─── Stop loss monitor ────────────────────────────────────────────────────────
async function checkStopLosses() {
  state.positionValue = 0; // reset on each check
  for (const order of state.openOrders.filter(o => o.status === 'open')) {
    try {
      const data = await kalFetch('GET', `/markets/${order.ticker}`);
      const m    = data.market || {};
      // yes_bid_dollars is 0-1 float, yes_bid is integer cents — handle both
      const yesBidRaw = m.yes_bid_dollars !== undefined
        ? Math.round(parseFloat(m.yes_bid_dollars) * 100)
        : (m.yes_bid || order.price);
      const noBidRaw  = m.no_bid_dollars !== undefined
        ? Math.round(parseFloat(m.no_bid_dollars) * 100)
        : (m.no_bid || order.price);
      const cur = order.side === 'yes' ? yesBidRaw : noBidRaw;
      const slThreshold = order.price * (1 - state.settings.stopLoss);
      const posVal = +(cur / 100 * (order.count || 1)).toFixed(4);
      state.positionValue = +((state.positionValue || 0) + posVal).toFixed(4);
      console.log(`[SL Check] ${order.ticker} entry:${order.price}¢ cur:${cur}¢ val:$${posVal.toFixed(2)} threshold:${slThreshold.toFixed(1)}¢`);
      if (cur === 0) {
        order.status = 'stopped';
        stoppedTickers.add(order.ticker);
        state.stoppedSet=Array.from(stoppedTickers);
        state.openOrders = state.openOrders.filter(o => o.ticker !== order.ticker);
        console.log(`[SL] ${order.ticker} at 0¢ — settled, skipping`);
        continue;
      }
      if (cur <= slThreshold) {
        // Sell the position at current market price
        const sellCount = Math.max(1, Math.floor(order.count || 1));
        const sellPrice = Math.max(1, cur - 2); // slightly below bid to fill
        const sellBody = {
          ticker:          order.ticker,
          action:          'sell',
          type:            'limit',
          side:            order.side,
          count:           sellCount,
          yes_price:       order.side === 'yes' ? sellPrice : 100 - sellPrice,
          expiration_ts:   Math.floor(Date.now() / 1000) + 3600,
          client_order_id: 'sl-' + Date.now().toString(),
        };
        console.log(`[SL] Selling ${order.ticker} — count:${sellCount} price:${sellPrice}¢`);
        const sellResult = await kalFetch('POST', '/portfolio/orders', sellBody).catch(e => {
          console.error(`[SL] Sell failed for ${order.ticker}:`, e.message);
          return null;
        });
        if (sellResult) {
          console.log(`[SL] Sell placed for ${order.ticker}`);
        }
        order.status = 'stopped';
        stoppedTickers.add(order.ticker);
        state.stoppedSet=Array.from(stoppedTickers); // persist across restarts
        const recovered = +(sellCount * sellPrice / 100).toFixed(2);
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

// ─── Partial profit taking ────────────────────────────────────────────────────
// Rules:
//   Sell 1/2 at 75% profit
//   Sell 1/4 at 100% profit
//   Hold remainder to settlement
//   Minimum 4 contracts to apply rules (otherwise hold to settlement)

async function checkProfitTaking() {
  for (const order of state.openOrders.filter(o => o.status === 'open')) {
    try {
      const data = await kalFetch('GET', `/markets/${order.ticker}`);
      const mkt  = data.market || {};
      const cur  = order.side === 'yes' ? (mkt.yes_bid || order.price) : (mkt.no_bid || order.price);
      const entry = order.price; // cents
      const profit = ((cur - entry) / entry); // % gain

      // Need at least 4 contracts to apply partial rules
      if (!order.count || order.count < 4) continue;

      let sellCount = 0;
      let reason    = '';

      // Check 75% profit tier — sell half if not done yet
      if (profit >= 0.75 && !order.sold75) {
        sellCount = Math.floor(order.count / 2);
        reason    = '75% profit — selling half';
        order.sold75 = true;
      }
      // Check 100% profit tier — sell quarter if not done yet
      else if (profit >= 1.0 && !order.sold100) {
        sellCount = Math.floor(order.count / 4);
        reason    = '100% profit — selling quarter';
        order.sold100 = true;
      }

      if (sellCount < 1) continue;

      // Place sell order
      const sellPrice = Math.max(1, Math.min(99, cur - 2)); // slightly below bid to fill
      const sellBody = {
        ticker:          order.ticker,
        action:          'sell',
        type:            'limit',
        time_in_force:   'fill_or_kill',
        side:            order.side,
        count:           sellCount,
        yes_price:       order.side === 'yes' ? sellPrice : 100 - sellPrice,
        client_order_id: Date.now().toString(),
      };

      console.log(`[Profit] ${reason} on ${order.ticker} — selling ${sellCount} of ${order.count} @ ${cur}¢`);
      await kalFetch('POST', '/portfolio/orders', sellBody);

      // Update position count
      order.count -= sellCount;
      const proceeds = +(sellCount * cur / 100).toFixed(4);
      const cost     = +(sellCount * entry / 100).toFixed(4);
      const gain     = +(proceeds - cost).toFixed(4);
      state.pnl     += gain;
      state.balance += proceeds;

      broadcast('order', order);
      broadcast('balance', state.balance);
      setStatus(`💰 Partial profit: ${reason} on ${order.ticker} +$${gain.toFixed(2)}`);
      flash_server(`Partial profit: +$${gain.toFixed(2)} on ${order.ticker}`);
    } catch(e) { /* silent */ }
  }
}

function flash_server(msg) {
  broadcast('flash', { type: 'success', msg });
}

// ─── Monte Carlo optimizer ────────────────────────────────────────────────────
function runOptimizer() {
  const m = state.model;
  const settled = m.sessionWins + m.sessionLosses;
  if (settled < 3 || settled % 5 !== 0 || m.lastOptAt === settled || m.optimizing) return;

  m.optimizing = true;
  m.lastOptAt  = settled;
  broadcast('optimizing', true);

  const wr = m.sessionWins / settled;
  const ag = m.sessionWins > 0 ? m.totalGain / m.sessionWins : 0.92;

  const COMBOS = [];
  for (const maxOpen of [3, 5, 8, 10, 12, 15, 20])
    for (const copyPct of [0.05, 0.07, 0.08, 0.09, 0.10, 0.12, 0.15])
      COMBOS.push({ maxOpen, copyPct });

  let best = { maxOpen: 10, copyPct: 0.10, score: -Infinity, successRate: 0, estMins: 999 };

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


// ═══════════════════════════════════════════════════════════════════════════════
// RULES-BASED AUTO TRADING ENGINE
// Signals: volume spike, price momentum, smart money flow, value play
// ═══════════════════════════════════════════════════════════════════════════════

function detectSignals(markets) {
  const signals = [];
  const now = Date.now();

  // Compute avgVol excluding spread markets — they skew the baseline massively
  const vols   = markets.filter(m=>!m.ticker.includes('SPREAD')).map(m => m.volume_24h || 0).filter(v => v > 0);
  const avgVol = vols.length ? vols.reduce((a,b)=>a+b,0)/vols.length : 0;

  // Minimum absolute volume to avoid thinly traded manipulation
  const MIN_VOL_24H = 500;   // at least 500 contracts traded in 24h
  const MIN_TOTAL_VOL = 5000; // at least 5000 total contracts ever traded
  const SPIKE_MULTIPLIER = 3; // 3x average

  const now14 = Date.now();

  // Count for logging
  const within7  = markets.filter(m=>{if(!m.close_time)return false;const ct=new Date(m.close_time).getTime();return ct>now14&&ct<=now14+7*86400000;}).length;
  const within14 = markets.filter(m=>{if(!m.close_time)return false;const ct=new Date(m.close_time).getTime();return ct>now14&&ct<=now14+14*86400000;}).length;
  const within90 = markets.filter(m=>{if(!m.close_time)return false;const ct=new Date(m.close_time).getTime();return ct>now14&&ct<=now14+90*86400000;}).length;

  // SIGNAL FILTER: only non-sports markets closing within 7 days
  // Sports (KXNHL, KXNBA, KXMLB etc) are excluded — live games too noisy
  // Spreads already excluded from volume/value signals
  const EXCLUDED_PREFIXES = [
    // Sports only — crypto re-enabled (high volume, genuine directional signals)
    'KXNHL','KXNBA','KXMLB','KXNFL','KXNBASPREAD','KXMLBSPREAD','KXNFLSPREAD','KXNBAML','KXMLBML','KXNFLML',
  ];
  const isSportsTicker = t => EXCLUDED_PREFIXES.some(p => t.startsWith(p));

  const nearTermMarkets = markets.filter(m => {
    if (isSportsTicker(m.ticker)) return false; // exclude live sports
    if (!m.close_time) return false;
    const ct = new Date(m.close_time).getTime();
    return ct > now14 && ct <= now14 + 90 * 86400000; // closes within 90 days
  });

  console.log('[Signals] <90d non-sports:', nearTermMarkets.length, '| <14d:', within14, '| <90d:', within90);

  // Build full price history for all markets
  for (const m of markets) {
    const t=m.ticker;
    if(!state.priceHistory[t])state.priceHistory[t]=[];
    const h=state.priceHistory[t];
    h.push({yes:m.yes_bid||50,oi:m.open_interest||0,ts:now14});
    if(h.length>60)h.shift(); // 60 × 30s = 30min window
  }

  for (const m of nearTermMarkets) {
    const yes    = m.yes_bid || 50;
    const no     = m.no_bid  || 50;
    const vol24  = m.volume_24h || 0;
    const vol    = m.volume    || 0;
    const ticker = m.ticker;

    // Price history tracked above for all markets
    const hist = state.priceHistory[ticker] || [];
    // Skip thinly traded markets — easily manipulated
    if (vol < MIN_TOTAL_VOL) continue;
    if (vol24 < MIN_VOL_24H && vol24 > 0) continue;

    if (hist.length > 20) hist.shift(); // keep last 20 readings

    // ── Signal 1: DIRECTIONAL VOLUME SPIKE ──────────────────────────────────────
    // YES spike: high volume + price above 50 = buyers dominating
    // NO spike:  high volume + price below 50 = sellers dominating (NO buyers)
    const spikeRatio = vol24 / Math.max(avgVol, 1);
    // Skip spread markets for volume spikes — their volume is always high by design
    const isSpreadMkt = ticker.includes('SPREAD');
    if (!isSpreadMkt && vol24 > avgVol * SPIKE_MULTIPLIER && vol24 > MIN_VOL_24H) {

      // YES-SIDE spike: price >= 50 means YES buyers are driving volume
      if (yes >= 50 && yes >= state.settings.minOdds && yes <= 80) {
        signals.push({
          ticker, side: 'yes', price: yes,
          type:   'VOLUME_SPIKE',
          reason: `YES spike: ${vol24.toFixed(0)} vol (${spikeRatio.toFixed(1)}x avg) · price ${yes}¢ — buyer dominated`,
          score:  Math.min(100, Math.round(spikeRatio * 20)),
          market: m,
        });
      }

      // NO-SIDE spike: price < 50 means NO buyers pushing YES price down
      if (yes < 50 && no >= state.settings.minOdds && no <= 80) {
        signals.push({
          ticker, side: 'no', price: no,
          type:   'VOLUME_SPIKE',
          reason: `NO spike: ${vol24.toFixed(0)} vol (${spikeRatio.toFixed(1)}x avg) · YES at ${yes}¢ — seller dominated`,
          score:  Math.min(100, Math.round(spikeRatio * 20)),
          market: m,
        });
      }
    }

    // ── Signal 2: SHORT-WINDOW DIRECTIONAL PRESSURE ──────────────────────────────
    // Multi-window price velocity as proxy for directional volume
    // 30s ticks: 10=5min, 30=15min, 60=30min
    if (hist.length >= 10) {
      const win5  = hist.slice(-10).map(h => h.yes);
      const win15 = hist.length >= 30 ? hist.slice(-30).map(h => h.yes) : win5;
      const win30 = hist.length >= 60 ? hist.slice(-60).map(h => h.yes) : win15;
      const move5m  = win5[win5.length-1]   - win5[0];
      const move15m = win15[win15.length-1] - win15[0];
      const move30m = win30[win30.length-1] - win30[0];
      // Open interest direction — rising OI = net new buying
      const oiRecent = hist.slice(-10).map(h => h.oi||0);
      const oiChange = oiRecent[oiRecent.length-1] - oiRecent[0];

      // BUY pressure: price up across multiple windows + rising open interest
      if (move5m >= 3 && move15m >= 5 && oiChange >= 0 && yes >= state.settings.minOdds && yes <= 72) {
        signals.push({
          ticker, side: 'yes', price: yes,
          type:   'MOMENTUM_UP',
          reason: `BUY: +${move5m}¢/5m +${move15m}¢/15m +${move30m}¢/30m OI:${oiChange>=0?'+':''}${oiChange.toFixed(0)}${ticker.includes('SPREAD')?' [SPREAD]':''}`,
          score:  Math.min(100, (move5m*2 + move15m) * 5),
          market: m,
        });
      }
      // SELL pressure: price falling across windows
      if (move5m <= -3 && move15m <= -5 && no >= state.settings.minOdds && no <= 72) {
        signals.push({
          ticker, side: 'no', price: no,
          type:   'MOMENTUM_DOWN',
          reason: `SELL: ${move5m}¢/5m ${move15m}¢/15m ${move30m}¢/30m OI:${oiChange>=0?'+':''}${oiChange.toFixed(0)}`,
          score:  Math.min(100, (Math.abs(move5m)*2 + Math.abs(move15m)) * 5),
          market: m,
        });
      }
      // ACCELERATION: moving faster in last 5min than previous trend
      if (Math.abs(move5m) >= 4 && Math.abs(move5m) > Math.abs(move15m) * 0.4) {
        const dir = move5m > 0 ? 'yes' : 'no';
        const dp  = dir === 'yes' ? yes : no;
        if (dp >= state.settings.minOdds && dp <= 72) {
          signals.push({
            ticker, side: dir, price: dp,
            type:   'MOMENTUM_UP',
            reason: `ACCEL: ${move5m>0?'+':''}${move5m}¢/5m vs ${move15m>0?'+':''}${move15m}¢/15m`,
            score:  Math.min(100, Math.abs(move5m) * 10),
            market: m,
          });
        }
      }
    }

    // ── Signal 3: VALUE PLAY ──────────────────────────────────────────────────
    // YES price is 35-45¢ with strong volume — genuinely underpriced market
    // Exclude spread markets (naturally priced near 50¢ by design)
    const isSpread = ticker.includes('SPREAD') || ticker.includes('SPRد');
    if (!isSpread && yes >= 37 && yes <= 45 && vol24 > avgVol * 2.0 && vol24 > 1000 && vol > MIN_TOTAL_VOL) {
      signals.push({
        ticker, side: 'yes', price: yes,
        type:   'VALUE_PLAY',
        reason: `Underpriced YES at ${yes}¢ with above-avg volume ${vol24.toFixed(0)}`,
        score:  Math.round((45 - yes) * 3 + (vol24/Math.max(avgVol,1)) * 10),
        market: m,
      });
    }

    // ── Signal 4: SMART MONEY ─────────────────────────────────────────────────
    // Very high volume on a near-certain outcome (>70¢) — pros piling in
    if (yes >= 70 && yes <= 85 && vol24 > avgVol * 2) {
      signals.push({
        ticker, side: 'yes', price: yes,
        type:   'SMART_MONEY',
        reason: `High-conviction YES at ${yes}¢ with ${(vol24/Math.max(avgVol,1)).toFixed(1)}x avg volume`,
        score:  Math.round(yes * 0.8 + (vol24/Math.max(avgVol,1))*5),
        market: m,
      });
    }
  }

  // Boost scores for near-term markets
  const now_sig = Date.now();
  for (const s of signals) {
    const ct = s.market&&s.market.close_time ? new Date(s.market.close_time).getTime() : null;
    if (ct) {
      const d = (ct - now_sig) / 86400000;
      if (d < 7)        s.score = Math.round(s.score * 2.0);
      else if (d < 30)  s.score = Math.round(s.score * 1.5);
      else if (d < 90)  s.score = Math.round(s.score * 1.25);
      else if (d < 180) s.score = Math.round(s.score * 1.1);
    }
  }
  // Sort by score descending, dedupe by ticker
  const seen = new Set();
  const result = signals
    .sort((a,b) => b.score - a.score)
    .filter(s => { if(seen.has(s.ticker)) return false; seen.add(s.ticker); return true; })
    .slice(0, 20);

  // Debug: log signal detection stats
  const volsWithData = markets.filter(m=>(m.volume_24h||0)>0).length;
  console.log('[Signals] markets:'+markets.length+' avgVol:'+avgVol.toFixed(0)+' volsWithData:'+volsWithData+' signals:'+result.length+' histTickers:'+Object.keys(state.priceHistory).length);
  return result;
}

// Track recently failed tickers to avoid retry loops
const failedTickers = new Map(); // ticker -> timestamp
const stoppedTickers = new Set(); // tickers where stop loss already fired
let lastAutoTrade = 0; // timestamp of last auto-trade
const seenSignals = new Set(); // signals seen before auto-trade enabled — skip these

async function runAutoTrading(signals) {
  if (!state.autoTrade || !signals.length) return;
  if (state.balance < 0.50) { setStatus('Auto-trade: balance too low'); return; }

  const openCount = state.openOrders.filter(o => o.status === 'open').length;
  if (openCount >= state.model.maxOpen) return;

  // Clear failed tickers older than 5 minutes
  const now = Date.now();
  for (const [t, ts] of failedTickers) {
    if (now - ts > 300_000) failedTickers.delete(t);
  }
  // Rate limit auto-trades to once per 60 seconds
  if (now - lastAutoTrade < 60_000) return;

  // Take top signal that is NEW (not seen before auto-trade enabled)
  const openTickers = new Set(state.openOrders.map(o => o.ticker));
  const candidate   = signals.find(s =>
    !openTickers.has(s.ticker) &&
    !failedTickers.has(s.ticker) &&
    !seenSignals.has(s.ticker) &&  // only NEW signals
    s.score >= 40
  );
  if (!candidate) return;

  try {
    setStatus(`Auto-trade: ${candidate.type} on ${candidate.ticker} (score ${candidate.score})`);
    lastAutoTrade = Date.now();
    seenSignals.add(candidate.ticker); // don't trade this signal again
    await placeOrder(candidate.ticker, candidate.side, candidate.price).catch(e => {
      failedTickers.set(candidate.ticker, Date.now());
      throw e;
    });

    const logEntry = {
      ts:     Date.now(),
      type:   candidate.type,
      ticker: candidate.ticker,
      title:  candidate.market ? (candidate.market.title || candidate.ticker) : candidate.ticker,
      side:   candidate.side,
      price:  candidate.price,
      score:  candidate.score,
      reason: candidate.reason,
    };
    state.autoLog.unshift(logEntry);
    state.autoLog = state.autoLog.slice(0, 50);
    broadcast('auto_trade', logEntry);
    setStatus(`Auto-trade placed: ${candidate.side.toUpperCase()} ${candidate.ticker}`);
  } catch(e) {
    logError('Auto-trade failed: ' + e.message);
  }
}

// ─── Main agent tick (every 15 seconds) ──────────────────────────────────────
function dedupeOrders() {
  // Dedupe by TICKER — one entry per market
  const priority = {won:4, lost:4, settled:3, filled:2, open:1, pending:0};
  const seen = new Map();
  for (const o of state.orderLog) {
    const key = o.ticker; // use ticker not order_id as dedup key
    if (!seen.has(key)) {
      seen.set(key, o);
    } else {
      const existing = seen.get(key);
      const oPri = priority[o.status] || 0;
      const ePri = priority[existing.status] || 0;
      if (oPri > ePri) seen.set(key, o); // keep higher priority status
    }
  }
  state.orderLog = Array.from(seen.values()).sort((a,b)=>(b.ts||0)-(a.ts||0)).slice(0,100);
  // Dedupe openOrders by ticker
  const oseen = new Map();
  for (const o of state.openOrders) oseen.set(o.ticker, o);
  state.openOrders = Array.from(oseen.values());
}

async function syncKalshiPositions() {
  // Sync positions placed directly on Kalshi website
  try {

    // Cross-reference executed orders with active positions to find settled trades
    // Any executed order whose ticker is NOT in active market_positions = settled
    try {
      const execAll = await kalFetch('GET', '/portfolio/orders?limit=100&status=executed');
      const allExec = execAll.orders || [];
      const activePosRes = await kalFetch('GET', '/portfolio/positions');
      const activePos = Object.values(activePosRes.market_positions || {});
      const activeTickers = new Set(activePos.map(p => p.ticker));

      for (const o of allExec) {
        const ticker = o.ticker;
        if (!ticker) continue;
        if (o.action === 'sell') continue; // skip sell orders — track buys only
        if (stoppedTickers.has(ticker)) continue; // skip stopped positions
        const isActive = activeTickers.has(ticker);
        if (isActive) continue; // still open — skip

        // This order is settled — check if already recorded as won/lost
        const existing = state.orderLog.find(l => l.id === o.order_id);
        if (existing && (existing.status === 'won' || existing.status === 'lost')) continue;

        // Fetch settlement pnl from fills
        const side  = o.side || o.outcome_side || 'yes';
        const count = parseFloat(o.fill_count_fp || 1);
        const price = count > 0 && parseFloat(o.taker_fill_cost_dollars) > 0
          ? parseFloat(o.taker_fill_cost_dollars) / count  // actual avg fill price
          : parseFloat(o.yes_price_dollars || 0.5);
        const cost  = parseFloat(o.taker_fill_cost_dollars || count * price);
        const fees  = parseFloat(o.taker_fees_dollars || 0);

        // If settlement_payout_dollars available use it, else try payout from fills
        let pnl = null;
        let won = null;
        try {
          const mktRes = await kalFetch('GET', '/markets/'+ticker);
          const mkt = mktRes.market || {};
          if (mkt.result === 'yes' || mkt.result === 'no') {
            won = (side === mkt.result);
            pnl = won ? +(count * (1 - price) - fees).toFixed(4) : +(-cost).toFixed(4);
          }
        } catch(e2) {}

        const entry = {
          id:     o.order_id,
          ticker,
          side,
          stake:  +cost.toFixed(4),
          fees:   +fees.toFixed(4),
          price:  Math.round(price * 100),
          count:  +count.toFixed(2),
          pnl,
          result: won === true ? 'won' : won === false ? 'lost' : 'settled',
          ts:     new Date(o.created_time || Date.now()).getTime(),
          status: won === true ? 'won' : won === false ? 'lost' : 'settled',
          synced: true,
          title:  ticker,
        };

        // Update or insert in orderLog
        if (existing) {
          Object.assign(existing, entry);
        } else {
          state.orderLog.unshift(entry);
          state.orderLog = state.orderLog.slice(0, 100);
        }
        // Remove from openOrders
        state.openOrders = state.openOrders.filter(o2 => o2.ticker !== ticker);

        if (pnl !== null) {
          state.pnl = +(state.pnl + pnl).toFixed(4);
          if (pnl > 0) { state.model.sessionWins++; state.model.totalGain += pnl; }
          else { state.model.sessionLosses++; state.model.totalLoss += Math.abs(pnl); }
        }
        broadcast('order', entry);
        console.log('[Settled]', ticker, entry.status.toUpperCase(), pnl !== null ? '$'+pnl.toFixed(2) : '(pending result)');
        // Update dashboard P&L immediately
        broadcast('pnl_update', { pnl: state.pnl, balance: state.balance });
      }
    } catch(e) { logError('Settlement check: ' + e.message); }
    // Check settlement by fetching market result for each tracked order
    try {
      for (const entry of state.orderLog.filter(o => o.status === 'open' || o.status === 'filled')) {
        // Only check orders not in active positions
        if (activeTickers.has(entry.ticker)) continue;
        try {
          const mktRes = await kalFetch('GET', '/markets/' + entry.ticker);
          const mkt = mktRes.market || {};
          console.log('[Settlement check]', entry.ticker, 'status:', mkt.status, 'result:', mkt.result);
          if (mkt.status === 'finalized' || mkt.result) {
            const won = mkt.result === entry.side;
            const count = entry.count || 1;
            const price = (entry.price || 50) / 100;
            // Payout: win = count * $1, lose = $0
            const payout = won ? count * 1.0 : 0;
            const pnl = +(payout - entry.stake).toFixed(4);
            entry.status = won ? 'won' : 'lost';
            entry.pnl = pnl;
            entry.result = entry.status;
            state.openOrders = state.openOrders.filter(o => o.ticker !== entry.ticker);
            state.pnl = +(state.pnl + pnl).toFixed(4);
            if (won) state.model.sessionWins++;
            else state.model.sessionLosses++;
            broadcast('order', entry);
            broadcast('pnl_update', { pnl: state.pnl, balance: state.balance });
            console.log('[Settled]', entry.ticker, entry.status.toUpperCase(), '$'+pnl.toFixed(2));
          }
        } catch(e2) { /* market fetch failed — skip */ }
      }
    } catch(e) { /* silent */ }
    const data = await kalFetch('GET', '/portfolio/positions');
    // Log raw response keys to diagnose field names
    // market_positions is an object keyed by ticker — extract values
    const mp = Object.values(data.market_positions || {});
    const positions = mp; // use market_positions — has ticker + position_fp fields
    const posExposure = mp.reduce((s,p)=>s+parseFloat(p.market_exposure_dollars||0),0);
    state.positionValue = +posExposure.toFixed(2); // set directly from Kalshi
    console.log('[Positions] count:', mp.length, 'total_exposure: $'+posExposure.toFixed(2), 'cash: $'+(state.balance||0).toFixed(2), 'portfolio: $'+((state.balance||0)+posExposure).toFixed(2));
    // Detect settled positions: contracts=0, cost>0, exposure=0 = LOST
    for (const p of mp) {
      const contracts = parseFloat(p.position_fp || 0);
      const cost = parseFloat(p.total_traded_dollars || 0);
      const exposure = parseFloat(p.market_exposure_dollars || 0);
      const ticker = p.ticker;
      if (!ticker || contracts !== 0 || cost === 0 || exposure !== 0) continue;
      // This position settled at 0 = LOST
      const existing = state.orderLog.find(l => l.ticker === ticker);
      if (existing && (existing.status === 'won' || existing.status === 'lost')) continue;
      const pnl = -cost;
      if (existing) {
        existing.status = 'lost';
        existing.pnl = +pnl.toFixed(4);
        existing.result = 'lost';
      } else {
        const entry = {
          id: ticker+'-settled', ticker,
          side: 'yes', stake: +cost.toFixed(4),
          price: 50, count: 1, pnl: +pnl.toFixed(4),
          status: 'lost', result: 'lost', synced: true,
          ts: Date.now(),
        };
        state.orderLog.unshift(entry);
      }
      state.openOrders = state.openOrders.filter(o => o.ticker !== ticker);
      state.pnl = +(state.pnl + pnl).toFixed(4);
      state.model.sessionLosses++;
      stoppedTickers.add(ticker);
      state.stoppedSet = Array.from(stoppedTickers);
      broadcast('order', existing || state.orderLog[0]);
      console.log('[Auto-settled] LOST', ticker, '$'+pnl.toFixed(2));
    }
    for (const pos of positions) {
      const ticker = pos.ticker || pos.market_ticker;
      if (!ticker) continue;
      // position_fp is number of contracts (positive = YES, negative = NO)
      const contracts = parseFloat(pos.position_fp || 0);
      if (contracts === 0) continue;
      const alreadyTracked = state.openOrders.find(o => o.ticker === ticker);
      // Skip if already marked as settled/won/lost in orderLog or stop loss fired
      const isSettled = state.orderLog.find(l => l.ticker === ticker && (l.status==='won'||l.status==='lost'||l.status==='settled'||l.status==='stopped'));
      const isActiveMarket = state.markets.length===0 || state.markets.find(m=>m.ticker===ticker);
      if (!alreadyTracked && !isSettled && !stoppedTickers.has(ticker) && isActiveMarket) {
        const stake    = parseFloat(pos.total_traded_dollars || pos.market_exposure_dollars || 0);
        const count    = Math.abs(contracts);
        const price    = count > 0 ? Math.round((stake / count) * 100) : 50;
        const pnl      = parseFloat(pos.realized_pnl_dollars || 0);
        const entry = {
          id:     ticker + '-synced',
          marketValue: +parseFloat(pos.market_exposure_dollars||0).toFixed(4),
          unrealized:  +(parseFloat(pos.market_exposure_dollars||0)-stake).toFixed(4),
          ticker,
          side:   contracts > 0 ? 'yes' : 'no',
          stake:  +stake.toFixed(4),
          price:  Math.max(1, Math.min(99, price)),
          count:  +count.toFixed(2),
          pnl:    +pnl.toFixed(4),
          ts:     new Date(pos.last_updated_ts || Date.now()).getTime(),
          status: 'open',
          synced: true,
        };
        state.openOrders.push(entry);
        state.orderLog.unshift(entry);
        state.orderLog = state.orderLog.slice(0, 100);
        broadcast('order', entry);
        console.log('[Sync] Added position:', ticker, contracts > 0 ? 'YES' : 'NO', '$'+stake.toFixed(2));
      }
    }
    // Fetch executed (filled) orders — these are closed/completed trades
    const execRes = await kalFetch('GET', '/portfolio/orders?limit=100&status=executed');
    const execOrders = execRes.orders || [];


    for (const o of execOrders) {
      const ticker = o.ticker;
      if (!ticker) continue;
      // Skip if already tracked (including settled orders)
      const alreadyTracked = state.orderLog.find(l => l.id === o.order_id);
      if (alreadyTracked) continue;
      // Skip if already marked as won/lost/stopped
      const settledEntry = state.orderLog.find(l => l.ticker === ticker && (l.status==='won'||l.status==='lost'||l.status==='stopped'));
      const mktActive = state.markets.length===0 || state.markets.find(m=>m.ticker===ticker);
      if (settledEntry || stoppedTickers.has(ticker) || !mktActive) continue;

      const side    = o.side || o.outcome_side || 'yes';
      const count   = parseFloat(o.fill_count_fp || 1);
      const stake   = parseFloat(o.taker_fill_cost_dollars || 0);
      const price   = count > 0 && stake > 0 ? stake / count : parseFloat(o.yes_price_dollars || 0.5);
      const fees    = parseFloat(o.taker_fees_dollars || 0);

      // Check if market is still active
      const market    = state.markets.find(m => m.ticker === ticker);
      const isActive  = !!market;
      // If not in active markets — may be settled. Check via position sync.
      const posEntry  = state.openOrders.find(p => p.ticker === ticker);
      const isOpen    = isActive || !!posEntry;

      const entry = {
        id:     o.order_id,
        ticker,
        side,
        stake:  +stake.toFixed(4),
        fees:   +fees.toFixed(4),
        price:  Math.round(price * 100),
        count:  +count.toFixed(2),
        pnl:    null,  // filled when market settles
        result: isOpen ? 'open' : 'pending',
        ts:     new Date(o.created_time || Date.now()).getTime(),
        status: isOpen ? 'open' : 'pending',
        synced: true,
        title:  market ? market.title : ticker,
      };
      state.orderLog.unshift(entry);
      // Also add to openOrders if not already tracked
      // Avoid duplicates — check by order_id
      if (!state.openOrders.find(p => p.id === entry.id || p.ticker === ticker)) {
        state.openOrders.push({...entry});
      }
      // Only add to log if not already there
      if (!state.orderLog.find(l => l.id === entry.id)) {
        state.orderLog = state.orderLog.slice(0, 99);
      }
      broadcast('order', entry);
      console.log('[Order synced]', ticker, side.toUpperCase(), '$'+stake.toFixed(2));
    }
    const fillList = [];
    for (const f of fillList) {
      const ticker = f.ticker || f.market_ticker;
      const alreadyTracked = state.orderLog.find(o => o.id === f.fill_id || o.id === f.order_id);
      if (!alreadyTracked && ticker) {
        const entry = {
          id:     f.fill_id || f.order_id || ticker+'-'+Date.now(),
          ticker,
          side:   f.side || 'yes',
          stake:  parseFloat(f.count || 1) * parseFloat(f.yes_price || 50) / 100,
          price:  parseFloat(f.yes_price || 50),
          count:  parseFloat(f.count || 1),
          ts:     new Date(f.created_time || Date.now()).getTime(),
          status: 'filled',
          synced: true,
        };
        state.orderLog.unshift(entry);
        state.orderLog = state.orderLog.slice(0, 100);
        broadcast('order', entry);
      }
    }
  } catch(e) { /* silent — positions sync is best-effort */ }

  // Update positionValue from Kalshi's market_exposure_dollars
  // Broadcast updated position value (already set from posExposure above)
  if(state.positionValue>0){
    broadcast('pnl_update',{pnl:state.pnl,balance:state.balance,positionValue:state.positionValue});
    console.log('[Portfolio] position value: $'+state.positionValue.toFixed(2)+' cash: $'+state.balance.toFixed(2)+' total: $'+(state.balance+state.positionValue).toFixed(2));
  }

  // Clean duplicates after every sync
  dedupeOrders();
  broadcast('orders_sync', state.orderLog);
}

async function agentTick() {
  if (!state.running) return;
  state.lastTick = new Date().toISOString();
  try {
    await loadBalance();
    checkProfitPull();
    await checkStopLosses();
    await syncKalshiPositions(); // sync externally placed orders (includes settlement check)
    await checkProfitTaking();     // partial profit taking
    runOptimizer();

    // Detect signals and run auto-trading
    if (state.markets.length > 0) {
      const rawSigs_=detectSignals(state.markets);
      state.signals=rawSigs_.map(s=>({ticker:s.ticker,side:s.side,price:s.price,type:s.type,reason:s.reason,score:s.score,title:s.market?s.market.title:s.ticker}));
      broadcast('signals',state.signals);
      await runAutoTrading(state.signals);
    }

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

app.get('/api/signals', (req, res) => res.json({ signals: state.signals, autoLog: state.autoLog }));

app.get('/api/state', (req, res) => {
  dedupeOrders(); // always return clean deduplicated orders
  // Don't include full markets array in state - too large, causes timeouts
  // Dashboard fetches markets separately via /api/markets
  const { markets, priceHistory, ...stateWithoutMarkets } = state;
  res.json({
    ...stateWithoutMarkets,
    markets: [], // markets served separately via /api/markets to avoid timeout
    config:  { hasKeys: !!(ENV.KALSHI_KEY_ID && ENV.KALSHI_PRIVATE_KEY) },
    signals: state.signals || [],
  positionValue: +(state.positionValue||0).toFixed(2),
    autoLog: state.autoLog || [],
    autoTrade: state.autoTrade,
  });
});

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
  (state.stoppedSet||[]).forEach(t=>stoppedTickers.add(t)); // restore stopped tickers
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
  const { minOdds, stopLoss, pullTarget, resetTo, autoCopy, autoTrade, categories } = req.body;
  if (autoTrade !== undefined) {
    if (autoTrade && !state.autoTrade) {
      // Auto-trade just turned ON — mark all current signals as already seen
      seenSignals.clear();
      (state.signals || []).forEach(s => seenSignals.add(s.ticker));
      console.log('[AutoTrade] Enabled — skipping', seenSignals.size, 'existing signals');
    }
    state.autoTrade = autoTrade;
  }
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

app.get('/api/signals-data',(req,res)=>res.json({signals:state.signals||[],autoLog:state.autoLog||[],autoTrade:state.autoTrade}));
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
  <div class="stat"><div class="sl">Portfolio</div><div class="sv" id="s-port" style="color:#00e5a0">$0.00</div></div>
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
  <button class="tab" onclick="switchTab('signals',this)">Signals<span class="badge" id="bsig">0</span></button>
  <button class="tab" onclick="switchTab('orders',this)">Orders<span class="badge" id="bo">0</span></button>
  <button class="tab" onclick="switchTab('history',this)">History<span class="badge" id="bh">0</span></button>
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
  <div style="margin-bottom:8px">
    <input id="mkt-search" class="inp" style="margin-bottom:0" placeholder="🔍 Search markets…"
      oninput="searchMarkets(this.value)" autocomplete="off" autocorrect="off" autocapitalize="off"/>
  </div>
  <div style="display:flex;gap:4px;margin-bottom:8px;align-items:center">
    <div style="font-size:9px;color:#444870;flex:1" id="mkt-count"></div>
    <button onclick="sortBy('settlement')" id="sort-set" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #4a9eff66;background:#4a9eff18;color:#4a9eff;font-family:monospace;cursor:pointer">⏱ Soon</button>
    <button onclick="sortBy('volume')" id="sort-vol" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #252850;background:transparent;color:#555;font-family:monospace;cursor:pointer">↓ Vol</button>
    <button onclick="sortBy('odds')" id="sort-odds" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #252850;background:transparent;color:#555;font-family:monospace;cursor:pointer">50/50</button>
    <button onclick="sortBy('hot')" id="sort-hot" style="padding:3px 8px;font-size:9px;border-radius:3px;border:1px solid #252850;background:transparent;color:#555;font-family:monospace;cursor:pointer">🔥</button>
  </div>
  <div id="markets-list"><div class="empty">TAP START TO LOAD MARKETS</div></div>
</div>

<!-- ORDERS -->
<div id="panel-signals" class="panel">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
    <div style="font-size:10px;color:#444870;letter-spacing:1px;text-transform:uppercase">Auto-Trading Signals</div>
    <div style="display:flex;gap:6px;align-items:center">
      <span style="font-size:10px;color:#666">Auto-trade</span>
      <button class="tog" id="auto-tog" onclick="toggleAutoTrade()" style="background:#252850"><div class="tok" style="left:2px"></div></button>
    </div>
  </div>
  <div id="auto-log-section" style="margin-bottom:12px;display:none">
    <div style="font-size:9px;color:#00e5a0;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Recent Auto-Trades</div>
    <div id="auto-log-list"></div>
  </div>
  <div id="sig-debug" style="background:#090e0a;border:1px solid #00e5a033;border-radius:6px;padding:10px 12px;margin-bottom:10px;font-size:10px;color:#00e5a0;line-height:1.8">
    Signals in state: <b id="dbg-count">0</b><br>
    Last poll: <span id="dbg-time">never</span><br>
    Auto-trade: <span id="dbg-auto">off</span>
  </div>
  <div style="font-size:9px;color:#444870;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px">Live Signals</div>
  <div id="signals-list"><div class="empty">START agent to detect signals</div></div>
</div>
<div id="panel-orders" class="panel">
  <div id="orders-list"><div class="empty">NO OPEN ORDERS</div></div>
</div>

<!-- HISTORY -->
<div id="panel-history" class="panel">
  <div id="history-list"><div class="empty">NO SETTLED ORDERS YET</div></div>
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
let marketPage = 1;
const PAGE_SIZE = 50;
let searchQuery = '';

let state = {
  running:false, balance:0, pnl:0, secured:0, slHits:0, positionValue:0,
  markets:[], orderLog:[], errors:[],
  signals:[], autoLog:[], autoTrade:false,
  config:{hasKeys:false}
};
let activeCategory='All';
const CATS=['All','Live','<180d','Politics','Sports','Crypto','Economics'];
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
  else if(ev==='markets_updated'){
    const t=new Date(d);
    $('status-bar').textContent='● Markets updated: '+t.toLocaleTimeString();
  }
  else if(ev==='model_updated'){state.model=d;renderModel();}
  else if(ev==='optimizing'){$('model-bar').textContent='⏳ Optimizing model… running 500 simulations';}
  else if(ev==='profit_pull'){flash('success','💰 Profit pulled: $'+d.pulled+' · Secured: $'+d.total.toFixed(2));state.secured=d.total;updateStats();}
  else if(ev==='sl_hit'){flash('warn','SL hit: '+d.order.ticker+' · recovered $'+d.recovered);state.slHits=(state.slHits||0)+1;updateStats();}
  else if(ev==='error'){addError(d);flash('error',d.slice(0,60));}
  else if(ev==='signals'){state.signals=d;renderSignals();}
  else if(ev==='auto_trade'){if(!state.autoLog)state.autoLog=[];state.autoLog.unshift(d);flash('success','🤖 Auto: '+d.side.toUpperCase()+' '+d.ticker);renderSignals();}
  else if(ev==='orders_sync'){state.orderLog=d;$('bo').textContent=d.length;renderOrders();}
  else if(ev==='flash'){flash(d.type,d.msg);}
  else if(ev==='pnl_update'){state.pnl=d.pnl;state.balance=d.balance;updateStats();}
  else if(ev==='settings'){state.settings=d;applySettings();}
}

function mergeState(d){
  if(!d)return;
  // Don't overwrite markets if response has empty array — markets loaded separately
  const prevMarkets = state.markets;
  Object.assign(state,d);
  if(!d.markets||d.markets.length===0) state.markets = prevMarkets;
  if(d.config)state.config=d.config;
  if(d.model)state.model=d.model;
  if(d.marketsUpdated)state.marketsUpdated=d.marketsUpdated;
  if(d.signals!==undefined)state.signals=d.signals;
  if(d.autoLog)state.autoLog=d.autoLog;
  if(d.autoTrade!==undefined)state.autoTrade=d.autoTrade;
  if(d.positionValue!==undefined)state.positionValue=d.positionValue;
  if(d.portfolioValue!==undefined)state.portfolioValue=d.portfolioValue;
  if(d.pnl!==undefined){state.pnl=d.pnl;updateStats();}
  if(d.settings)state.settings=d.settings;
}

// ── Render ────────────────────────────────────────────────────────────────────
function renderAll(){
  updateStats();renderMarkets();renderOrders();renderModel();applySettings();
  updateAgentBtn();
  renderSignals();
  const at=$('auto-tog');
  if(at){const k=at.querySelector('.tok');at.style.background=state.autoTrade?'#00e5a0':'#252850';if(k)k.style.left=state.autoTrade?'19px':'2px';}
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
  const portVal=(state.balance||0)+(state.positionValue||0);
  const portEl=$('s-port');if(portEl)portEl.textContent='$'+portVal.toFixed(2);
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

function filterCat(cat){marketPage=1;searchQuery='';const s=$('mkt-search');if(s)s.value='';activeCategory=cat;buildCatBar();renderMarkets();}

function renderMarkets(){
  const el=$('markets-list');if(!el)return;
  const now=Date.now(); // needed for settlement countdown
  // Category keyword maps — must match server CAT_KW
  const DASH_KW={
    Politics:  ['election','president','congress','senate','trump','vote','govern','ukraine','russia','iran','nato','tariff','policy','bill','law','supreme','cabinet'],
    Sports:    ['nba','nfl','nhl','mlb','mls','soccer','super bowl','world cup','championship','playoff','finals','league','series','cup','win','game','match','score','mvp'],
    Crypto:    ['bitcoin','btc','eth','ethereum','crypto','solana','sol','xrp','doge','bnb','coinbase','binance','above','below','price','token','blockchain','defi','altcoin','halving'],
    Economics: ['gdp','inflation','cpi','unemployment','fed','recession','earnings','jobs','mortgage','housing','retail','deficit','trade'],
  };
  const DASH_CATS={
    Politics:  ['politics','political','election'],
    Sports:    ['sports','sport'],
    Crypto:    ['crypto','cryptocurrency'],
    Economics: ['economics','economy','finance','business'],
  };
  let filtered;
  if(activeCategory==='All'){
    filtered=state.markets;
  } else if(activeCategory==='Live'){
    filtered=state.markets.filter(m=>{
      if(!m.close_time)return false;
      const ms=new Date(m.close_time).getTime()-now;
      return ms>0&&ms<86400000;
    });
  } else if(activeCategory==='<180d'){
    filtered=state.markets.filter(m=>{
      if(!m.close_time)return false;
      const ms=new Date(m.close_time).getTime()-now;
      return ms>0&&ms<180*86400000;
    });
  } else {
    filtered=state.markets.filter(m=>{
      const mc=(m.category||'').toLowerCase();
      const kalshiCats=DASH_CATS[activeCategory]||[];
      if(mc&&kalshiCats.some(c=>mc===c))return true;
      const t=(m.title||'').toLowerCase();
      return(DASH_KW[activeCategory]||[]).some(k=>t.includes(k));
    });
  }

  const updStr=state.marketsUpdated?new Date(state.marketsUpdated).toLocaleTimeString():'never';
  const mktEl=$('mkt-count');
  if(mktEl){
    mktEl.innerHTML=filtered.length+' markets · <span style="color:#00e5a0">⟳ '+updStr+'</span>';
    // Flash green briefly to show update
    mktEl.style.opacity='0.4';
    setTimeout(()=>mktEl.style.opacity='1',200);
  }
  $('bm').textContent=filtered.length;

  if(!filtered.length){el.innerHTML='<div class="empty">NO '+activeCategory.toUpperCase()+' MARKETS<br><br>Tap ↺ Markets in Settings</div>';return;}

  // Apply search filter
  if(searchQuery){
    const q=searchQuery.toLowerCase();
    filtered=filtered.filter(m=>(m.title||m.ticker||'').toLowerCase().includes(q));
  }

  const total=filtered.length;
  const pageFiltered=filtered.slice(0,marketPage*PAGE_SIZE);
  const countEl=$('mkt-count');
  if(countEl)countEl.textContent=pageFiltered.length+' of '+total+' markets'+(searchQuery?' (filtered)':'');
  $('bm').textContent=total;

  // Simple bulletproof card render
  const ts = Date.now();
  let html = '';
  for (const m of pageFiltered) {
    const yes = m.yes_bid || 50;
    const no  = m.no_bid  || (100 - yes);
    const yC  = yes>=60?'#00e5a0':yes>=40?'#f5a623':'#ff4455';
    const nC  = no>=60?'#00e5a0':no>=40?'#f5a623':'#ff4455';
    const title = (m.title||m.ticker||'Unknown').slice(0,75);
    let settle = '';
    if (m.close_time) {
      const ms = new Date(m.close_time).getTime() - ts;
      if (ms > 0) {
        const h = Math.floor(ms/3600000);
        const d = Math.floor(h/24);
        settle = d>0 ? ' · '+d+'d' : h>0 ? ' · '+h+'h' : ' · <1h';
      }
    }
    const vol = m.volume_24h>0 ? '24h: '+Math.round(m.volume_24h) : m.volume>0 ? 'Vol: '+Math.round(m.volume) : '';
    html += '<div style="background:#0a0c16;border:1px solid #1a1a2a;border-radius:8px;padding:12px;margin-bottom:8px">'
      + '<div style="font-size:11px;color:#e0e8ff;font-weight:600;margin-bottom:4px">'+title+'</div>'
      + '<div style="font-size:9px;color:#444870;margin-bottom:10px">'+vol+settle+'</div>'
      + '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'
      + '<button data-ticker="'+m.ticker+'" data-price="'+yes+'" data-side="yes" onclick="trade(this.dataset.ticker,this.dataset.side,parseInt(this.dataset.price))" style="padding:10px;border-radius:5px;border:1px solid '+yC+'55;background:'+yC+'18;color:'+yC+';font-family:monospace;font-weight:700;font-size:13px;cursor:pointer;-webkit-appearance:none">YES<br>'+yes+'¢</button>'
      + '<button data-ticker="'+m.ticker+'" data-price="'+no+'" data-side="no" onclick="trade(this.dataset.ticker,this.dataset.side,parseInt(this.dataset.price))" style="padding:10px;border-radius:5px;border:1px solid '+nC+'55;background:'+nC+'18;color:'+nC+';font-family:monospace;font-weight:700;font-size:13px;cursor:pointer;-webkit-appearance:none">NO<br>'+no+'¢</button>'
      + '</div></div>';
  }
  el.innerHTML = html || '<div class="empty">No markets found</div>';

  // Load more button
  const remaining=filtered.length-marketPage*PAGE_SIZE;
  if(remaining>0){
    el.innerHTML+='<button onclick="loadMoreMarkets()" style="width:100%;padding:12px;margin-top:8px;border-radius:6px;border:1px solid #4a9eff44;background:#4a9eff11;color:#4a9eff;font-family:monospace;font-size:12px;cursor:pointer;-webkit-appearance:none">Load '+Math.min(PAGE_SIZE,remaining)+' more ('+remaining+' remaining)</button>';
  }
}

function searchMarkets(q){
  searchQuery=q;
  marketPage=1;
  renderMarkets();
}

function loadMoreMarkets(){
  marketPage++;
  renderMarkets();
  // Scroll to bottom of markets list
  const el=$('markets-list');
  if(el)el.lastElementChild?.scrollIntoView({behavior:'smooth'});
}

function sortBy(by){
  ['vol','odds','hot','set'].forEach(s=>{
    const b=$('sort-'+s);if(!b)return;
    const on=(s==='vol'&&by==='volume')||(s==='set'&&by==='settlement')||(s===by);
    b.style.borderColor=on?'#4a9eff66':'#252850';
    b.style.background=on?'#4a9eff18':'transparent';
    b.style.color=on?'#4a9eff':'#555';
  });
  const now2=Date.now();
  const FF=new Date('2099-01-01').getTime();
  if(by==='settlement'){
    // Sort by soonest closing — markets with no close_time go last
    // Filter out already-past markets first
    state.markets.sort((a,b)=>{
      const ta=a.close_time?new Date(a.close_time).getTime():FF;
      const tb=b.close_time?new Date(b.close_time).getTime():FF;
      // Push past markets to end
      const aValid=ta>now2?ta:FF+1;
      const bValid=tb>now2?tb:FF+1;
      return aValid-bValid;
    });
  }
  else if(by==='volume')state.markets.sort((a,b)=>(b.volume_24h||b.volume||0)-(a.volume_24h||a.volume||0));
  else if(by==='odds')state.markets.sort((a,b)=>Math.abs((a.yes_bid||50)-50)-Math.abs((b.yes_bid||50)-50));
  else if(by==='hot')state.markets.sort((a,b)=>(b.volume_24h||b.volume||0)*Math.abs((b.yes_bid||50)-50)-(a.volume_24h||a.volume||0)*Math.abs((a.yes_bid||50)-50));
  marketPage=1; // reset to page 1 after sort
  renderMarkets();
}

function renderOrders(){
  const log = state.orderLog || [];
  const open     = log.filter(o => o.status === 'open' || o.status === 'filled');
  const settled  = log.filter(o => o.status === 'won' || o.status === 'lost' || o.status === 'stopped' || o.status === 'settled');

  // Update badges
  $('bo').textContent = open.length;
  const bh = $('bh'); if(bh) bh.textContent = settled.length;

  // Shared card builder
  function makeCard(o) {
    const isWon   = o.status === 'won';
    const isLost  = o.status === 'lost' || o.status === 'stopped';
    const isOpen  = o.status === 'open' || o.status === 'filled';
    const mkt     = state.markets.find(m => m.ticker === o.ticker);
    const title   = o.title || (mkt ? mkt.title : o.ticker) || o.ticker;
    const bc      = isWon ? '#00e5a033' : isLost ? '#ff445533' : '#1a1a2a';
    const tc      = isWon ? '#00e5a0'   : isLost ? '#ff4455'   : '#4a9eff';
    const label   = isWon ? '✓ WON' : isLost ? '✗ LOST' : o.side.toUpperCase();
    const pnlStr  = o.pnl != null ? (o.pnl >= 0 ? '+$' : '-$') + Math.abs(o.pnl).toFixed(2) : '';
    // Unrealized P&L for open positions
    let unrealStr = '';
    if (isOpen && mkt) {
      const cp = o.side === 'yes' ? (mkt.yes_bid||o.price) : (mkt.no_bid||o.price);
      const up = +((cp/100*(o.count||1)) - (o.price/100*(o.count||1))).toFixed(2);
      unrealStr = '<div style="font-size:10px;margin-top:3px;color:'+(up>=0?'#00e5a0':'#ff4455')+'">'+(up>=0?'+':'')+up.toFixed(2)+'¢ unrealized · now: '+cp+'¢</div>';
    }
    return '<div style="background:'+bc+';border:1px solid '+(isWon?'#00e5a033':isLost?'#ff445533':'#252850')+';border-radius:8px;padding:12px;margin-bottom:8px">'
      + '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">'
      + '<span style="font-size:11px;font-weight:700;color:'+tc+'">'+label+'</span>'
      + '<span style="font-size:11px;font-weight:700;color:'+tc+'">'+o.price+'¢'+(pnlStr?' · '+pnlStr:'')+'</span>'
      + '</div>'
      + '<div style="font-size:11px;color:#e0e8ff;font-weight:600;margin-bottom:3px">'+title.slice(0,60)+'</div>'
      + '<div style="font-size:9px;color:#444870">'+o.ticker+'</div>'
      + '<div style="font-size:9px;color:#444870;margin-top:2px">'+Number(o.count||0).toFixed(2)+' contracts · '+new Date(o.ts).toLocaleDateString()+(o.synced?' · synced':'')+'</div>'
      + unrealStr
      + '</div>';
  }

  // Open orders panel
  const ol = $('orders-list');
  if(ol) ol.innerHTML = open.length ? open.map(makeCard).join('') : '<div class="empty">NO OPEN ORDERS</div>';

  // History panel
  const hl = $('history-list');
  if(hl) hl.innerHTML = settled.length ? settled.map(makeCard).join('') : '<div class="empty">NO SETTLED ORDERS YET</div>';
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

async function toggleAutoTrade(){
  const v=!state.autoTrade;
  const r=await apiPost('/api/settings',{autoTrade:v});
  if(r.ok){state.autoTrade=v;const t=$('auto-tog'),k=t.querySelector('.tok');t.style.background=v?'#00e5a0':'#252850';k.style.left=v?'19px':'2px';flash(v?'success':'warn',v?'Auto-trading ON':'Auto-trading OFF');}
}
function renderSignals(){
  const el=$('signals-list');if(!el)return;
  const sigs=state.signals||[];
  const b=$('bsig');if(b)b.textContent=sigs.length;
  // Update debug panel
  const dc=$('dbg-count'),dt=$('dbg-time'),da=$('dbg-auto');
  if(dc)dc.textContent=sigs.length;
  if(dt)dt.textContent=new Date().toLocaleTimeString();
  if(da)da.textContent=state.autoTrade?'ON':'off';
  const IC={VOLUME_SPIKE:'📊',MOMENTUM_UP:'📈',MOMENTUM_DOWN:'📉',VALUE_PLAY:'💎',SMART_MONEY:'🐋'};
  const LB={VOLUME_SPIKE:'Volume Spike',MOMENTUM_UP:'Momentum ↑',MOMENTUM_DOWN:'Momentum ↓',VALUE_PLAY:'Value Play',SMART_MONEY:'Smart Money'};
  const CL={VOLUME_SPIKE:'#4a9eff',MOMENTUM_UP:'#00e5a0',MOMENTUM_DOWN:'#00e5a0',VALUE_PLAY:'#f5a623',SMART_MONEY:'#ffd700'};
  if(!sigs.length){el.innerHTML='<div class="empty">NO SIGNALS YET<br><br><small style="color:#333">Needs a few minutes of price history</small></div>';return;}
  el.innerHTML=sigs.map(s=>{
    const c=CL[s.type]||'#888';
    return '<div style="background:#0a0c16;border:1px solid #1a1a2a;border-left:3px solid '+c+';border-radius:7px;padding:12px;margin-bottom:8px">'
      +'<div style="display:flex;justify-content:space-between;margin-bottom:5px"><span style="font-size:10px;font-weight:700;color:'+c+'">'+(IC[s.type]||'')+ ' '+(LB[s.type]||s.type)+'</span>'
      +'<span style="font-size:11px;font-weight:700;color:'+(s.score>=70?'#ffd700':s.score>=50?'#00e5a0':'#f5a623')+'">'+s.score+' pts</span></div>'
      +'<div style="font-size:11px;color:#e0e8ff;font-weight:600;margin-bottom:3px">'+(s.title||s.ticker).slice(0,65)+'</div>'
      +'<div style="font-size:9px;color:#888;margin-bottom:8px">'+s.reason+'</div>'
      +'<button data-t="'+s.ticker+'" data-s="'+s.side+'" data-p="'+s.price+'" onclick="trade(this.dataset.t,this.dataset.s,parseInt(this.dataset.p))"'
      +' style="width:100%;padding:9px;border-radius:5px;border:1px solid '+c+'55;background:'+c+'18;color:'+c+';font-family:monospace;font-weight:700;cursor:pointer;font-size:12px">'
      +s.side.toUpperCase()+' '+s.price+'¢ — '+s.ticker+'</button></div>';
  }).join('');
  const al=state.autoLog||[],ls=$('auto-log-section'),ll=$('auto-log-list');
  if(al.length&&ls){ls.style.display='block';if(ll)ll.innerHTML=al.slice(0,5).map(l=>'<div style="background:#060e08;border:1px solid #00e5a022;border-radius:5px;padding:8px 12px;margin-bottom:5px;font-size:10px"><b style="color:#00e5a0">'+l.side.toUpperCase()+' '+l.price+'¢</b> <span style="font-size:9px;color:#4a9eff">'+l.type+'</span><div style="color:#e0e8ff;font-size:10px;margin-top:2px;font-weight:600">'+(l.title||l.ticker)+'</div><div style="color:#444870;font-size:9px">'+l.ticker+'</div><div style="color:#555;font-size:9px;margin-top:2px">'+l.reason.slice(0,70)+'</div></div>').join('');}
}
async function trade(ticker,side,price){
  if(!ticker){flash('error','Invalid market');return;}
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
  let failCount=0;

  function poll(){
    fetch('/api/state')
      .then(r=>{
        if(!r.ok)throw new Error('HTTP '+r.status);
        return r.json();
      })
      .then(d=>{
        failCount=0;
        setPill('ws-pill','● LIVE','pill-g');
        mergeState(d);
        updateStats();
        renderOrders();
        renderModel();
        renderSignals();
        updateAgentBtn();
        // Show last update time in status bar
        const ts=new Date().toLocaleTimeString();
        $('status-bar').textContent='● Updated: '+ts+(d.running?' · Agent running':' · Agent stopped');
        // Markets are fetched separately — re-render if we have them
        if(state.markets&&state.markets.length){
          renderMarkets();
        }
        // Re-render orders with fresh deduplicated data
        if(d.orderLog){
          state.orderLog=d.orderLog;
          renderOrders();
          $('bo').textContent=d.orderLog.length;
        }
        // Always update and render signals
        if(d.signals!==undefined){
          state.signals=d.signals;
          state.autoLog=d.autoLog||state.autoLog||[];
          if(d.autoTrade!==undefined)state.autoTrade=d.autoTrade;
  if(d.positionValue!==undefined)state.positionValue=d.positionValue;
  if(d.portfolioValue!==undefined)state.portfolioValue=d.portfolioValue;
  if(d.pnl!==undefined){state.pnl=d.pnl;updateStats();}
          renderSignals();
          // Recalculate position value from live market prices
          if(state.markets&&state.markets.length&&state.openOrders&&state.openOrders.length){
            let pv=0;
            for(const o of state.openOrders.filter(x=>x.status==='open')){
              const mkt=state.markets.find(m=>m.ticker===o.ticker);
              if(mkt){const cp=o.side==='yes'?(mkt.yes_bid||o.price):(mkt.no_bid||o.price);pv+=cp/100*(o.count||1);}
            }
            state.positionValue=+pv.toFixed(2);
            const pe=$('s-port');if(pe)pe.textContent='$'+((state.balance||0)+pv).toFixed(2);
          }
        }
      })
      .catch(()=>{
        failCount++;
        if(failCount>=3){
          setPill('ws-pill','○ OFFLINE','pill-gray');
          // Don't show error — data from init load is still valid
        }
        // After many fails just silently retry — data loaded on init is still valid
        if(failCount>=5){
          failCount=3; // reset counter, keep retrying silently
        }
      });
  }

  // Initial load with retry
  function initialLoad(attempt){
    fetch('/api/state').then(r=>r.json()).then(d=>{
      mergeState(d);
      renderAll();
      setPill('ws-pill','● LIVE','pill-g');
      // Fetch full markets list separately
      fetch('/api/markets').then(r=>{
        if(!r.ok)throw new Error('HTTP '+r.status);
        return r.json();
      }).then(mkts=>{
        if(mkts&&mkts.length){
          state.markets=mkts;
          renderMarkets();
          $('bm').textContent=mkts.length;
          $('status-bar').textContent='● '+mkts.length+' markets loaded · '+new Date().toLocaleTimeString();
        }
      }).catch(e=>{
        // Retry once after 3 seconds
        setTimeout(()=>{
          fetch('/api/markets').then(r=>r.json()).then(mkts=>{
            if(mkts&&mkts.length){
              state.markets=mkts;
              renderMarkets();
              $('bm').textContent=mkts.length;
            }
          }).catch(()=>{});
        },3000);
      });
    }).catch(()=>{
      if(attempt<5) setTimeout(()=>initialLoad(attempt+1), 2000);
    });
  }
  initialLoad(1);

  // Poll every 3 seconds — self-healing
  setInterval(poll, 10000);

  // Also handle page visibility — re-poll immediately when user returns to tab
  document.addEventListener('visibilitychange',()=>{
    if(document.visibilityState==='visible'){
      failCount=0;
      poll();
    }
  });

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
setInterval(agentTick, 30_000);
// Refresh market prices every 90 seconds
setInterval(async () => {
  if (state.running) await loadMarkets();
}, 90_000);
// Clear seen signals every hour so markets can fire again on new conditions
setInterval(() => {
  const before = seenSignals.size;
  seenSignals.clear();
  if (before > 0) console.log('[AutoTrade] Cleared', before, 'seen signals — fresh evaluation');
}, 3600_000);

// Pre-load markets on boot
setTimeout(async () => {
  if (ENV.KALSHI_KEY_ID) {
    await loadBalance();
    await loadMarkets();
  }
}, 2000);
