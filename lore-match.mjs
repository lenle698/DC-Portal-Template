// Lore Match: AI product recommendation from a customer photo (Gemini Vision).
// Admin config lives in Firestore (appConfigs/loreMatch) and is edited from the portal
// sidebar module "lorematch". The public endpoint is called by the Shopify section.
//
//   GET  /api/lore-match/config            admin: settings + catalog (key is never returned)
//   PUT  /api/lore-match/config            admin: save settings (+ optional new Gemini key)
//   PUT  /api/lore-match/catalog           admin: replace design catalog
//   POST /api/lore-match/test              admin: run a photo through the live config
//   GET  /api/lore-match/stats             admin: last 30 days of usage
//   GET  /api/public/lore-match/health     public
//   POST /api/public/lore-match/analyze    public (origin allowlist + per-IP rate limit)

import { readFileSync } from 'node:fs';

const DEFAULT_DESIGNS = JSON.parse(readFileSync(new URL('./lore-match-catalog.json', import.meta.url), 'utf8')).designs;

export const OUTFIT_VIBES = {
  street: ['street', 'hype', 'car-culture', 'west-coast', 'money'],
  dark: ['dark', 'gothic', 'grim', 'playful-dark', 'minimal-color'],
  vintage: ['vintage', 'tattoo', 'americana', 'surreal'],
  sporty: ['sport', 'bold', 'aggressive', 'fire', 'power'],
  soft: ['romantic', 'angelic', 'playful', 'family'],
  earthy: ['earthy', 'grim', 'vintage'],
  minimal: ['minimal-color', 'message', 'dark'],
};

export const DEFAULT_SETTINGS = {
  enabled: true,
  model: 'gemini-3.8-flash',
  picks: 3,
  weights: { shoe: 0.6, outfit: 0.15, pair: 0.15, vibe: 0.1 },
  familyPenalty: 0.08,
  allowedOrigins: ['https://lorekicks.com', 'https://www.lorekicks.com', 'https://ijuzac-3e.myshopify.com'],
  rateLimitPerMinute: 8,
  extraPrompt: '',
};

const DOC_PATH = ['appConfigs', 'loreMatch'];
const STATS_COLLECTION = 'loreMatchStats';
const MAX_BODY = 3_500_000;
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];

// ---------------------------------------------------------------- color math
export function hexToRgb(hex) {
  const h = String(hex || '').replace('#', '').trim();
  const full = h.length === 3 ? h.split('').map(c => c + c).join('') : h;
  if (!/^[0-9a-fA-F]{6}$/.test(full)) return null;
  const n = parseInt(full, 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}
function rgbToLab([r, g, b]) {
  const lin = c => { c /= 255; return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
  const R = lin(r), G = lin(g), B = lin(b);
  const x = (R * 0.4124 + G * 0.3576 + B * 0.1805) / 0.95047;
  const y = R * 0.2126 + G * 0.7152 + B * 0.0722;
  const z = (R * 0.0193 + G * 0.1192 + B * 0.9505) / 1.08883;
  const f = t => (t > 0.008856 ? Math.cbrt(t) : 7.787 * t + 16 / 116);
  return [116 * f(y) - 16, 500 * (f(x) - f(y)), 200 * (f(y) - f(z))];
}
const labCache = new Map();
function lab(hex) {
  if (!labCache.has(hex)) { const rgb = hexToRgb(hex); labCache.set(hex, rgb ? rgbToLab(rgb) : null); }
  return labCache.get(hex);
}
export function deltaE(a, b) { const A = lab(a), B = lab(b); return A && B ? Math.hypot(A[0] - B[0], A[1] - B[1], A[2] - B[2]) : 100; }
const chroma = hex => { const l = lab(hex); return l ? Math.hypot(l[1], l[2]) : 0; };
const sim = (a, b) => Math.max(0, 1 - deltaE(a, b) / 50);

function paletteScore(colors, palette) {
  let total = 0, wsum = 0, best = null;
  for (const c of colors || []) {
    if (!c || !hexToRgb(c.hex)) continue;
    const neutral = chroma(c.hex) < 15;
    const w = (Number(c.weight) || 0.5) * (neutral ? 0.35 : 1);
    let top = 0;
    for (const p of palette || []) top = Math.max(top, sim(c.hex, p));
    total += w * top; wsum += w;
    if (!neutral && (!best || w * top > best.score)) best = { score: w * top, name: c.name, sim: top };
  }
  return { score: wsum ? total / wsum : 0, best };
}

const MODEL_WORDS = /\b(air\s+)?(jordan|aj|nike|dunk|low|high|mid|og|retro|sb|travis\s+scott|converse|chuck)\b|\b\d{1,2}s?\b/g;
const norm = s => String(s || '').toLowerCase().replace(/['’]/g, '').replace(/[^a-z0-9 &]/g, ' ');
const colorwayKey = p => norm(p).replace(MODEL_WORDS, ' ').replace(/\s+/g, ' ').trim();
function pairHit(shoeText, pairs) {
  const text = norm(shoeText);
  if (!text.trim()) return null;
  for (const p of pairs || []) { const key = colorwayKey(p); if (key.length >= 3 && text.includes(key)) return p; }
  return null;
}

// ---------------------------------------------------------------- matcher
export function recommend(analysis, designs, settings = DEFAULT_SETTINGS) {
  const rawW = { ...DEFAULT_SETTINGS.weights, ...(settings.weights || {}) };
  const wSum = Object.values(rawW).reduce((a, b) => a + (Number(b) || 0), 0) || 1;
  const W = Object.fromEntries(Object.entries(rawW).map(([k, v]) => [k, (Number(v) || 0) / wSum])); // normalized so scores stay 0..100
  const penalty = Number(settings.familyPenalty ?? DEFAULT_SETTINGS.familyPenalty);
  const k = Math.max(1, Math.min(6, Number(settings.picks) || 3));
  const shoes = analysis?.shoes || [];
  const shoeColors = shoes.flatMap(s => s.colors || []);
  const outfitColors = analysis?.outfit_colors || [];
  const shoeText = shoes.map(s => `${s.model_guess || ''} ${s.colorway_guess || ''}`).join(' ');
  const vibes = new Set((analysis?.vibes || []).flatMap(v => OUTFIT_VIBES[v] || []));
  const active = (designs || []).filter(d => d && d.active !== false);

  const scored = active.map(d => {
    const shoe = paletteScore(shoeColors, d.palette);
    const outfit = paletteScore(outfitColors, d.palette);
    const pair = pairHit(shoeText, d.pairs_with);
    const vibeOverlap = (d.vibe || []).filter(v => vibes.has(v)).length;
    const vibeScore = (d.vibe || []).length ? Math.min(1, vibeOverlap / 2) : 0;
    const shoeW = shoeColors.length ? W.shoe : 0;
    const outfitW = shoeColors.length ? W.outfit : W.outfit + W.shoe;
    const score = shoeW * shoe.score + outfitW * outfit.score + (pair ? W.pair : 0) + W.vibe * vibeScore + (Number(d.boost) || 0);
    return { d, score, shoe, outfit, pair, vibeOverlap };
  });

  const picks = [], pool = [...scored];
  while (picks.length < k && pool.length) {
    pool.forEach(s => { s.adj = s.score - picks.filter(p => p.d.family === s.d.family).length * penalty; });
    pool.sort((a, b) => b.adj - a.adj);
    picks.push(pool.shift());
  }
  return picks.map(p => ({ id: p.d.id, handle: p.d.handle || p.d.id, title: p.d.title, family: p.d.family, score: Math.round(p.score * 100), reason: reasonFor(p) }));
}

function reasonFor(p) {
  if (p.pair) return `Built for your ${p.pair}. The palette lines up with the colorway.`;
  const b = p.shoe.best || p.outfit.best;
  if (b && b.sim > 0.55) return `The ${b.name || 'accent'} on ${p.shoe.best ? 'your kicks' : 'your fit'} is pulled straight into ${p.d.title}.`;
  if (p.vibeOverlap) return `Same energy as your fit. ${p.d.title} keeps the story going.`;
  return 'A clean contrast piece that lets your kicks do the talking.';
}

// ---------------------------------------------------------------- Gemini
const BASE_PROMPT = `You are the style reader for LOREKICKS, a streetwear brand that makes graphic tees designed to match sneakers.
Look at the photo and describe ONLY the footwear and clothing.
Never describe or comment on the person's face, body, age, gender, ethnicity or identity.
Rules:
- shoes: one entry per distinct pair visible (usually 0 or 1). model_guess is the sneaker model if recognizable (e.g. "Air Jordan 1 High"), else a short description. colorway_guess is the popular colorway nickname if you are reasonably confident (e.g. "Chicago", "Bred", "Panda", "UNC", "Royal", "Midnight Navy", "Valentine's Day", "Medium Olive"), else "".
- colors: up to 4 main colors of that pair with approximate hex and weight (share of visible area, weights sum to about 1).
- outfit_colors: up to 4 main colors of the clothing (not skin, not background).
- vibes: 1 to 3 values from the allowed list that best describe the outfit.
- has_sneakers: true only if footwear is clearly visible.
- If the image contains no clothing or footwear, return has_sneakers false and empty arrays.`;

const COLOR = { type: 'OBJECT', properties: { name: { type: 'STRING' }, hex: { type: 'STRING' }, weight: { type: 'NUMBER' } }, required: ['name', 'hex', 'weight'] };
const RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    has_sneakers: { type: 'BOOLEAN' },
    shoes: { type: 'ARRAY', items: { type: 'OBJECT', properties: { model_guess: { type: 'STRING' }, colorway_guess: { type: 'STRING' }, confidence: { type: 'NUMBER' }, colors: { type: 'ARRAY', items: COLOR } }, required: ['model_guess', 'colorway_guess', 'colors'] } },
    outfit_colors: { type: 'ARRAY', items: COLOR },
    vibes: { type: 'ARRAY', items: { type: 'STRING', enum: Object.keys(OUTFIT_VIBES) } },
  },
  required: ['has_sneakers', 'shoes', 'outfit_colors', 'vibes'],
};

export async function analyzePhoto({ apiKey, model, base64, mimeType, extraPrompt = '', fetchImpl = fetch }) {
  if (!apiKey) throw Object.assign(new Error('Gemini API key is not configured'), { code: 'no_key' });
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const prompt = extraPrompt ? `${BASE_PROMPT}\nAdditional brand notes: ${String(extraPrompt).slice(0, 1500)}` : BASE_PROMPT;
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': apiKey },
    body: JSON.stringify({
      contents: [{ role: 'user', parts: [{ inline_data: { mime_type: mimeType, data: base64 } }, { text: prompt }] }],
      generationConfig: { temperature: 0.2, responseMimeType: 'application/json', responseSchema: RESPONSE_SCHEMA },
    }),
    signal: AbortSignal.timeout(25000),
  });
  if (!res.ok) throw new Error(`Gemini ${res.status}: ${(await res.text().catch(() => '')).slice(0, 300)}`);
  const data = await res.json();
  const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('') || '';
  try { return JSON.parse(text); } catch { const m = text.match(/\{[\s\S]*\}/); if (m) return JSON.parse(m[0]); throw new Error('Gemini returned no JSON'); }
}

// ---------------------------------------------------------------- config storage
let cache = null;
export function invalidateLoreMatchCache() { cache = null; }

async function loadConfig(firestore) {
  if (cache && Date.now() - cache.at < 60000) return cache.value;
  const snap = await firestore.collection(DOC_PATH[0]).doc(DOC_PATH[1]).get().catch(() => null);
  const raw = snap?.exists ? snap.data() : {};
  const value = {
    settings: { ...DEFAULT_SETTINGS, ...(raw.settings || {}), weights: { ...DEFAULT_SETTINGS.weights, ...(raw.settings?.weights || {}) } },
    designs: Array.isArray(raw.designs) && raw.designs.length ? raw.designs : DEFAULT_DESIGNS,
    geminiKeySealed: raw.geminiKeySealed || '',
    keyHint: raw.keyHint || '',
    updatedAt: raw.updatedAt?.toDate ? raw.updatedAt.toDate().toISOString() : raw.updatedAt || null,
    updatedBy: raw.updatedBy || null,
    catalogIsDefault: !(Array.isArray(raw.designs) && raw.designs.length),
  };
  cache = { at: Date.now(), value };
  return value;
}

const clampNum = (v, min, max, dflt) => { const n = Number(v); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : dflt; };
const str = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const slug = v => str(v, 80).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');

function cleanSettings(input = {}) {
  const w = input.weights || {};
  const origins = (Array.isArray(input.allowedOrigins) ? input.allowedOrigins : String(input.allowedOrigins || '').split(/[\s,]+/))
    .map(o => str(o, 200).replace(/\/+$/, '')).filter(o => /^https?:\/\/[a-z0-9.-]+(:\d+)?$/i.test(o)).slice(0, 20);
  return {
    enabled: input.enabled !== false,
    model: /^[a-z0-9.\-]{3,60}$/i.test(str(input.model, 60)) ? str(input.model, 60) : DEFAULT_SETTINGS.model,
    picks: Math.round(clampNum(input.picks, 1, 6, 3)),
    weights: { shoe: clampNum(w.shoe, 0, 1, 0.6), outfit: clampNum(w.outfit, 0, 1, 0.15), pair: clampNum(w.pair, 0, 1, 0.15), vibe: clampNum(w.vibe, 0, 1, 0.1) },
    familyPenalty: clampNum(input.familyPenalty, 0, 0.5, 0.08),
    allowedOrigins: origins,
    rateLimitPerMinute: Math.round(clampNum(input.rateLimitPerMinute, 1, 120, 8)),
    extraPrompt: str(input.extraPrompt, 1500),
  };
}

function cleanDesigns(list) {
  if (!Array.isArray(list)) throw Object.assign(new Error('designs must be an array'), { statusCode: 400 });
  if (list.length > 500) throw Object.assign(new Error('Tối đa 500 mẫu'), { statusCode: 400 });
  const seen = new Set();
  return list.map((d, i) => {
    const id = slug(d.id || d.handle || d.title) || `design-${i + 1}`;
    if (seen.has(id)) throw Object.assign(new Error(`Trùng id mẫu: ${id}`), { statusCode: 400 });
    seen.add(id);
    const palette = (Array.isArray(d.palette) ? d.palette : []).map(h => str(h, 7).toUpperCase()).filter(h => /^#[0-9A-F]{6}$/.test(h)).slice(0, 6);
    if (!palette.length) throw Object.assign(new Error(`Mẫu "${d.title || id}" cần ít nhất 1 màu hex`), { statusCode: 400 });
    const tags = v => (Array.isArray(v) ? v : String(v || '').split(',')).map(x => str(x, 60)).filter(Boolean).slice(0, 12);
    return {
      id, handle: slug(d.handle) || id, title: str(d.title, 80) || id, family: slug(d.family) || 'other', palette,
      vibe: tags(d.vibe).map(x => x.toLowerCase()), pairs_with: tags(d.pairs_with), active: d.active !== false,
      boost: clampNum(d.boost, -0.3, 0.3, 0), image: /^https:\/\//.test(str(d.image, 500)) ? str(d.image, 500) : '',
    };
  });
}

function publicConfig(cfg) {
  return { settings: cfg.settings, designs: cfg.designs, hasKey: Boolean(cfg.geminiKeySealed || process.env.GEMINI_API_KEY), keySource: cfg.geminiKeySealed ? 'portal' : (process.env.GEMINI_API_KEY ? 'env' : 'none'), keyHint: cfg.keyHint, updatedAt: cfg.updatedAt, updatedBy: cfg.updatedBy, catalogIsDefault: cfg.catalogIsDefault, vibeOptions: Object.keys(OUTFIT_VIBES), designVibeOptions: [...new Set(Object.values(OUTFIT_VIBES).flat())].sort() };
}

// ---------------------------------------------------------------- helpers
async function readBody(request) {
  const chunks = []; let size = 0;
  for await (const chunk of request) { size += chunk.length; if (size > MAX_BODY) throw Object.assign(new Error('Ảnh quá lớn'), { statusCode: 413 }); chunks.push(chunk); }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}
function parseImage(body) {
  const raw = String(body?.image || '');
  const m = raw.match(/^data:([^;]+);base64,/);
  const mime = (m ? m[1] : body?.mime) || 'image/jpeg';
  const base64 = raw.replace(/^data:[^;]+;base64,/, '');
  if (!base64) throw Object.assign(new Error('missing_image'), { statusCode: 400 });
  if (!ALLOWED_MIME.includes(mime)) throw Object.assign(new Error('unsupported_type'), { statusCode: 415 });
  return { base64, mime };
}
const rateHits = new Map();
function rateOk(ip, limit) {
  const now = Date.now(), list = (rateHits.get(ip) || []).filter(t => now - t < 60000);
  if (list.length >= limit) { rateHits.set(ip, list); return false; }
  list.push(now); rateHits.set(ip, list);
  if (rateHits.size > 5000) for (const [k, v] of rateHits) if (!v.some(t => now - t < 60000)) rateHits.delete(k);
  return true;
}
const today = () => new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 10); // Asia/Saigon day

function recordStat(firestore, FieldValue, fields, topPick = null) {
  if (!FieldValue) return;
  const inc = Object.fromEntries(Object.entries(fields).map(([k, v]) => [k, FieldValue.increment(v)]));
  if (topPick) inc.topPicks = { [topPick]: FieldValue.increment(1) };
  firestore.collection(STATS_COLLECTION).doc(today()).set({ ...inc, date: today() }, { merge: true }).catch(() => {});
}

function summarize(analysis) {
  const shoe = analysis?.shoes?.[0];
  return {
    shoe: shoe ? [shoe.model_guess, shoe.colorway_guess].filter(Boolean).join(' · ') : null,
    shoe_colors: (shoe?.colors || []).map(c => c.hex),
    outfit_colors: (analysis?.outfit_colors || []).map(c => c.hex),
    vibes: analysis?.vibes || [],
  };
}

async function runMatch(cfg, ctx, image) {
  const apiKey = (cfg.geminiKeySealed && ctx.openSecret(cfg.geminiKeySealed)) || process.env.GEMINI_API_KEY || '';
  const analysis = await analyzePhoto({ apiKey, model: cfg.settings.model, base64: image.base64, mimeType: image.mime, extraPrompt: cfg.settings.extraPrompt, fetchImpl: ctx.fetchImpl || fetch });
  const hasAnything = (analysis.shoes?.length || 0) + (analysis.outfit_colors?.length || 0) > 0;
  return { analysis, hasAnything, picks: hasAnything ? recommend(analysis, cfg.designs, cfg.settings) : [] };
}

// ---------------------------------------------------------------- router
/**
 * Returns true when the request was handled.
 * ctx: { firestore, FieldValue, json, requireLogin, userAccess, sealSecret, openSecret, fetchImpl? }
 */
export async function handleLoreMatch(request, response, requestUrl, ctx) {
  const path = requestUrl.pathname;
  if (!path.startsWith('/api/lore-match') && !path.startsWith('/api/public/lore-match')) return false;
  const { firestore, FieldValue, json } = ctx;

  // ---------- public ----------
  if (path.startsWith('/api/public/lore-match')) {
    const origin = String(request.headers.origin || '');
    const cfg = await loadConfig(firestore);
    const allowed = cfg.settings.allowedOrigins || [];
    const originOk = !origin || !allowed.length || allowed.includes(origin);
    response.setHeader('Access-Control-Allow-Origin', originOk && origin ? origin : (allowed[0] || '*'));
    response.setHeader('Vary', 'Origin');
    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    response.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (request.method === 'OPTIONS') { response.writeHead(204, { 'Access-Control-Max-Age': '86400' }); response.end(); return true; }

    if (request.method === 'GET' && path === '/api/public/lore-match/health') {
      json(response, 200, { ok: true, enabled: cfg.settings.enabled, designs: cfg.designs.filter(d => d.active !== false).length }); return true;
    }
    if (request.method !== 'POST' || path !== '/api/public/lore-match/analyze') { json(response, 404, { error: 'not_found' }); return true; }
    if (!originOk) { json(response, 403, { error: 'origin_not_allowed' }); return true; }
    if (!cfg.settings.enabled) { json(response, 503, { error: 'disabled', message: 'Lore Match is taking a break. Check back soon.' }); return true; }
    const ip = String(request.headers['x-forwarded-for'] || request.socket?.remoteAddress || 'anon').split(',')[0].trim();
    if (!rateOk(ip, cfg.settings.rateLimitPerMinute)) { json(response, 429, { error: 'rate_limited', message: 'Too many tries. Give it a minute.' }); return true; }

    let image;
    try { image = parseImage(await readBody(request)); }
    catch (e) { json(response, e.statusCode || 400, { error: e.message === 'missing_image' ? 'missing_image' : 'bad_request', message: 'Upload a JPG or PNG photo.' }); return true; }

    try {
      const { analysis, hasAnything, picks } = await runMatch(cfg, ctx, image);
      if (!hasAnything) { recordStat(firestore, FieldValue, { requests: 1, noKicks: 1 }); json(response, 200, { has_sneakers: false, picks: [], message: 'No kicks or fit found. Try a photo that shows your shoes.' }); return true; }
      recordStat(firestore, FieldValue, { requests: 1, matched: 1, ...(analysis.has_sneakers ? { withShoes: 1 } : {}) }, picks[0]?.id || null);
      json(response, 200, { has_sneakers: !!analysis.has_sneakers, detected: summarize(analysis), picks });
    } catch (e) {
      console.error('lore-match analyze failed:', e?.message);
      recordStat(firestore, FieldValue, { requests: 1, errors: 1 });
      json(response, 502, { error: 'vision_failed', message: "We couldn't read that photo. Try another one." });
    }
    return true;
  }

  // ---------- admin ----------
  const loginId = ctx.requireLogin(request, response);
  if (!loginId) return true;
  const access = await ctx.userAccess(loginId);
  const canManage = access.special || access.level === 'admin' || (access.modules || []).includes('lorematch');
  if (!canManage) { json(response, 403, { error: 'Bạn chưa có quyền module AI gợi ý sản phẩm' }); return true; }

  try {
    if (request.method === 'GET' && path === '/api/lore-match/config') {
      json(response, 200, publicConfig(await loadConfig(firestore))); return true;
    }
    if (request.method === 'PUT' && path === '/api/lore-match/config') {
      const body = await readBody(request);
      const update = { settings: cleanSettings(body.settings || {}), updatedAt: new Date(), updatedBy: loginId };
      if (typeof body.geminiKey === 'string' && body.geminiKey.trim()) {
        const key = body.geminiKey.trim();
        if (key.length < 20 || key.length > 200) { json(response, 400, { error: 'API key không hợp lệ' }); return true; }
        update.geminiKeySealed = ctx.sealSecret(key);
        update.keyHint = `…${key.slice(-4)}`;
      }
      if (body.clearKey === true) { update.geminiKeySealed = ''; update.keyHint = ''; }
      await firestore.collection(DOC_PATH[0]).doc(DOC_PATH[1]).set(update, { merge: true });
      invalidateLoreMatchCache();
      json(response, 200, publicConfig(await loadConfig(firestore))); return true;
    }
    if (request.method === 'PUT' && path === '/api/lore-match/catalog') {
      const body = await readBody(request);
      const designs = body.reset === true ? [] : cleanDesigns(body.designs);
      await firestore.collection(DOC_PATH[0]).doc(DOC_PATH[1]).set({ designs, updatedAt: new Date(), updatedBy: loginId }, { merge: true });
      invalidateLoreMatchCache();
      json(response, 200, publicConfig(await loadConfig(firestore))); return true;
    }
    if (request.method === 'POST' && path === '/api/lore-match/test') {
      const body = await readBody(request);
      const image = parseImage(body);
      const cfg = await loadConfig(firestore);
      const draft = body.settings ? { ...cfg, settings: { ...cfg.settings, ...cleanSettings({ ...cfg.settings, ...body.settings }) } } : cfg;
      const started = Date.now();
      const { analysis, picks } = await runMatch(draft, ctx, image);
      const all = recommend(analysis, draft.designs, { ...draft.settings, picks: 6, familyPenalty: 0 });
      json(response, 200, { ms: Date.now() - started, analysis, detected: summarize(analysis), picks, ranking: all }); return true;
    }
    if (request.method === 'GET' && path === '/api/lore-match/stats') {
      const snap = await firestore.collection(STATS_COLLECTION).orderBy('date', 'desc').limit(30).get().catch(() => ({ docs: [] }));
      json(response, 200, { days: snap.docs.map(d => ({ date: d.id, ...d.data() })) }); return true;
    }
    json(response, 404, { error: 'not_found' }); return true;
  } catch (e) {
    const status = e.statusCode || (e.code === 'no_key' ? 400 : 500);
    if (status >= 500) console.error('lore-match admin error:', e?.message);
    json(response, status, { error: e.code === 'no_key' ? 'Chưa cấu hình Gemini API key' : (e.message || 'Lỗi không xác định') });
    return true;
  }
}
