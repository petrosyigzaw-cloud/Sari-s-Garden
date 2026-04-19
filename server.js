'use strict';
const express      = require('express');
const Parser       = require('rss-parser');
const bcrypt       = require('bcryptjs');
const cookieParser = require('cookie-parser');
const crypto       = require('crypto');
const path         = require('path');
const fs           = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.json());

const PM_KEY  = process.env.PUBMED_API_KEY ? `&api_key=${process.env.PUBMED_API_KEY}` : '';
const PM_BASE = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/';
const HEADERS = { 'User-Agent': 'SarisGarden/1.0 (medical research platform)' };

// Refresh intervals
const RSS_INTERVAL    = 30 * 60 * 1000;   // 30 minutes
const PUBMED_INTERVAL =  2 * 60 * 60 * 1000; // 2 hours

// ─── Push notifications via ntfy.sh ──────────────────────────────────────────
// Set NTFY_TOPIC env var in Render to a unique string, e.g. "saris-garden-abc123"
// Then subscribe to that topic in the ntfy app (ntfy.sh) to receive alerts.
const NTFY_TOPIC = process.env.NTFY_TOPIC || null;

async function notify(title, body, priority = 'default') {
  if (!NTFY_TOPIC) return;
  try {
    await fetch(`https://ntfy.sh/${NTFY_TOPIC}`, {
      method:  'POST',
      headers: { 'Title': title, 'Priority': priority, 'Tags': 'stethoscope' },
      body
    });
  } catch (e) {
    console.error('[notify] Failed:', e.message);
  }
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
const AUTH_FILE = path.join(__dirname, 'data', 'auth.json');
const sessions  = new Map();

function getPasswordHash() {
  if (fs.existsSync(AUTH_FILE)) {
    try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8')).hash; } catch {}
  }
  return process.env.SARI_PASSWORD_HASH || null;
}

function savePasswordHash(hash) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  fs.writeFileSync(AUTH_FILE, JSON.stringify({ hash }), 'utf8');
}

async function initAuth() {
  if (!getPasswordHash() && process.env.SARI_INITIAL_PASSWORD) {
    console.log('[auth] Hashing initial password…');
    const hash = await bcrypt.hash(process.env.SARI_INITIAL_PASSWORD, 12);
    savePasswordHash(hash);
    console.log('[auth] Done.');
  }
}

function requireAuth(req, res, next) {
  const token = req.cookies?.sg_session;
  if (token && sessions.has(token)) {
    const s = sessions.get(token);
    if (s.expires > Date.now()) return next();
    sessions.delete(token);
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not authenticated' });
  res.redirect('/login');
}

// ─── Auth routes ──────────────────────────────────────────────────────────────
app.get('/login', (_, res) => res.sendFile(path.join(__dirname, 'login.html')));

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required.' });

  const expectedUsername = (process.env.SARI_USERNAME || 'Saron').toLowerCase();
  if (username.trim().toLowerCase() !== expectedUsername) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }

  const hash = getPasswordHash();
  if (!hash) return res.status(500).json({ error: 'No password configured. Set SARI_INITIAL_PASSWORD in Render.' });

  const valid = await bcrypt.compare(password, hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect username or password.' });

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expires: Date.now() + 7 * 24 * 60 * 60 * 1000 });
  res.cookie('sg_session', token, {
    httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax', secure: process.env.NODE_ENV === 'production'
  });
  res.json({ ok: true });
});

app.post('/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6)
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });

  const hash = getPasswordHash();
  if (hash) {
    const valid = await bcrypt.compare(currentPassword, hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  const newHash = await bcrypt.hash(newPassword, 12);
  savePasswordHash(newHash);
  console.log('[auth] Password changed.');
  res.json({ ok: true });
});

app.get('/auth/logout', (req, res) => {
  const token = req.cookies?.sg_session;
  if (token) sessions.delete(token);
  res.clearCookie('sg_session');
  res.redirect('/login');
});

// ─── Protected routes ─────────────────────────────────────────────────────────
app.get('/',             requireAuth, (_, res) => {
  res.setHeader('Cache-Control','no-store');
  res.sendFile(path.join(__dirname, 'saris-garden.html'));
});
app.get('/api/news',     requireAuth, (_, res) => res.json(cache.news));
app.get('/api/journals', requireAuth, (_, res) => res.json(cache.journals));
app.get('/api/status',   requireAuth, (_, res) => res.json({
  lastNewsFetch:    cache.lastNewsFetch    ? new Date(cache.lastNewsFetch).toISOString()    : null,
  lastJournalFetch: cache.lastJournalFetch ? new Date(cache.lastJournalFetch).toISOString() : null,
  newsCount:        cache.news.length,
  journalCount:     cache.journals.length,
  sourceHealth:     cache.sourceHealth,
}));

// ─── Cache & failure tracking ─────────────────────────────────────────────────
let cache = {
  news: [], journals: [],
  lastNewsFetch: null, lastJournalFetch: null,
  sourceHealth: {}   // sourceName → { ok: bool, lastError: str, failCount: int }
};

// How many consecutive failures before we fire a notification
const FAIL_THRESHOLD = 2;

function recordSuccess(source) {
  cache.sourceHealth[source] = { ok: true, lastError: null, failCount: 0 };
}

function recordFailure(source, message) {
  const prev = cache.sourceHealth[source] || { failCount: 0 };
  const failCount = (prev.failCount || 0) + 1;
  cache.sourceHealth[source] = { ok: false, lastError: message, failCount };
  return failCount;
}

// ─── RSS fetching ─────────────────────────────────────────────────────────────
const rss = new Parser({
  headers: HEADERS, timeout: 12000,
  customFields: { item: [
    ['media:content','mediaContent'],
    ['media:thumbnail','mediaThumbnail'],
    ['content:encoded','contentEncoded'],
    ['content','contentFull']
  ]}
});

function stripHtml(html=''){
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi,'')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi,'')
    .replace(/<[^>]+>/g,' ')
    // Decode all HTML entities
    .replace(/&#x([0-9A-Fa-f]+);/g,(_,h)=>{ try{return String.fromCharCode(parseInt(h,16));}catch{return ' ';} })
    .replace(/&#(\d+);/g,(_,d)=>{ try{return String.fromCharCode(parseInt(d,10));}catch{return ' ';} })
    .replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&lt;/g,'<')
    .replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'")
    .replace(/\s{2,}/g,' ').trim();
}

// Remove newsletter promo sentences before sending to client
const PROMO_RE = /sign up|subscribe|newsletter|stay on top|click here|read more|want to stay|in your inbox|biotech today|our coverage|to get our|follow us|advertising|sponsored/i;
function cleanFeedText(text){
  const sentences = (text||'').split(/(?<=[.!?])\s+/);
  return sentences.filter(s=>!PROMO_RE.test(s)).join(' ').trim();
}

function detectTag(text = '') {
  const t = text.toLowerCase();
  if (/cancer|oncol|tumor|tumour|chemotherapy|immunotherapy|car[-\s]?t|leukemia|lymphoma/.test(t)) return 'Oncology';
  if (/cardiac|cardio|heart failure|coronary|myocardial|atrial fibrillation|hypertension|sglt2|statin/.test(t)) return 'Cardiology';
  if (/nutrition|diet\b|vitamin|mineral|supplement|obesity|bmi|metabolic syndrome|plant.based/.test(t)) return 'Nutrition';
  if (/antimicrobial|antibiotic|resistance|sepsis|\bhiv\b|\btb\b|tuberculosis|malaria|\bcovid\b|mpox|cholera/.test(t)) return 'Infectious Disease';
  if (/alzheimer|parkinson|dementia|cognitive|seizure|epilepsy|multiple sclerosis|migraine|neurolog/.test(t)) return 'Neurology';
  if (/diabet|insulin|thyroid|endocrin|glucose|hba1c|glp.1|semaglutide|tirzepatide/.test(t)) return 'Endocrinology';
  if (/\bwomen\b|maternal|pregnancy|obstetric|gynecol|menopause|fertility|cervical|endometriosis/.test(t)) return "Women's Health";
  if (/ethiopia|tropical medicine|neglected tropical|leishmaniasis|schistosomiasis/.test(t)) return 'Tropical & Global Health';
  if (/public health|epidemi|surveillance|vaccination|immunization|ncd|non-communicable/.test(t)) return 'Public Health';
  return 'General Medicine';
}

const RSS_SOURCES = [
  { url: 'https://www.statnews.com/feed/',                             source: 'STAT News',       siteUrl: 'https://www.statnews.com',          max: 7 },
  { url: 'https://www.who.int/rss-feeds/news-english.xml',            source: 'WHO',             siteUrl: 'https://www.who.int',               max: 5 },
  { url: 'https://africacdc.org/feed/',                                source: 'Africa CDC',      siteUrl: 'https://africacdc.org',             max: 4 },
  { url: 'https://www.cochranelibrary.com/feed/cochrane-reviews-new', source: 'Cochrane Library', siteUrl: 'https://www.cochranelibrary.com',   max: 4 },
  { url: 'https://www.medscape.com/cx/rss/medpulse.xml',              source: 'Medscape',        siteUrl: 'https://www.medscape.com',          max: 5 },
  { url: 'https://ephi.gov.et/feed/',                                  source: 'EPHI',            siteUrl: 'https://ephi.gov.et',               max: 3 },
];

async function refreshNews() {
  console.log(`\n[${new Date().toISOString()}] Refreshing RSS feeds…`);
  const articles = [];
  const newFailures = [];

  for (const src of RSS_SOURCES) {
    try {
      const feed = await Promise.race([
        rss.parseURL(src.url),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout after 13s')), 13000))
      ]);
      (feed.items || []).slice(0, src.max).forEach(item => {
        if (!item.title || !item.link) return;
        const text = (item.title || '') + ' ' + (item.contentSnippet || '');
        // Prefer full content for richer drafts; fall back to snippet
        const fullText = cleanFeedText(stripHtml(item.contentEncoded || item.contentFull || ''));
        const snippet  = item.contentSnippet ? item.contentSnippet.trim() : '';
        articles.push({
          title:    item.title.trim(),
          site:     src.source,
          sourceUrl:item.link,
          tag:      detectTag(text),
          summary:  snippet.slice(0, 300),
          fullText: fullText.slice(0, 900),
          pubDate:  item.isoDate || item.pubDate || new Date().toISOString(),
          img:      item.enclosure?.url || item.mediaContent?.$.url || null,
          draft:    null
        });
      });
      recordSuccess(src.source);
      console.log(`  ✓ ${src.source}`);
    } catch (e) {
      const count = recordFailure(src.source, e.message);
      console.warn(`  ✗ ${src.source} (fail #${count}): ${e.message}`);
      if (count >= FAIL_THRESHOLD) newFailures.push(`${src.source}: ${e.message}`);
    }
  }

  if (articles.length) { cache.news = articles; cache.lastNewsFetch = Date.now(); }
  console.log(`[RSS] done — ${articles.length} articles`);

  if (newFailures.length) {
    await notify(
      '⚠️ Sari\'s Garden — Feed Failures',
      `${newFailures.length} source(s) failing:\n\n${newFailures.join('\n')}`,
      'high'
    );
  }

  // Alert if ALL sources failed
  const allFailed = RSS_SOURCES.every(s => !(cache.sourceHealth[s.source]?.ok));
  if (allFailed) {
    await notify(
      '🚨 Sari\'s Garden — All RSS Feeds Down',
      'Every RSS source is failing. News content is not updating. Check server logs.',
      'urgent'
    );
  }
}

// ─── PubMed fetching ──────────────────────────────────────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));

async function pmSearch(query, max = 5) {
  const url = `${PM_BASE}esearch.fcgi?db=pubmed&term=${encodeURIComponent(query)}&retmax=${max}&sort=date&retmode=json${PM_KEY}`;
  const r = await fetch(url, { headers: HEADERS });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).esearchresult?.idlist || [];
}

async function pmSummary(ids) {
  if (!ids.length) return {};
  const url = `${PM_BASE}esummary.fcgi?db=pubmed&id=${ids.join(',')}&retmode=json${PM_KEY}`;
  const r = await fetch(url, { headers: HEADERS });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return (await r.json()).result || {};
}

const JOURNAL_QUERIES = [
  { cat: 'Nutrition',               q: '(nutrition[MeSH] OR dietary interventions) AND (clinical trial[pt] OR systematic review[pt]) AND "last 1 year"[edat]' },
  { cat: 'Oncology',                q: '(neoplasms[MeSH]) AND (immunotherapy OR targeted therapy OR CAR-T) AND "last 1 year"[edat]' },
  { cat: 'Cardiology',              q: '(cardiovascular diseases[MeSH]) AND (clinical trial[pt] OR meta-analysis[pt]) AND "last 1 year"[edat]' },
  { cat: 'General Medicine',        q: '(NEJM[Journal] OR JAMA[Journal] OR BMJ[Journal]) AND (clinical trial[pt]) AND "last 6 months"[edat]' },
  { cat: 'Public Health',           q: '(public health[MeSH]) AND (systematic review[pt] OR meta-analysis[pt]) AND "last 1 year"[edat]' },
  { cat: 'Infectious Disease',      q: '(communicable diseases[MeSH]) AND (antimicrobial resistance OR vaccine) AND "last 1 year"[edat]' },
  { cat: 'Neurology',               q: '(nervous system diseases[MeSH]) AND (clinical trial[pt]) AND "last 1 year"[edat]' },
  { cat: 'Endocrinology',           q: '(diabetes mellitus[MeSH] OR obesity[MeSH]) AND (clinical trial[pt]) AND "last 1 year"[edat]' },
  { cat: "Women's Health",          q: '(womens health[MeSH] OR maternal health[MeSH]) AND (clinical trial[pt]) AND "last 1 year"[edat]' },
  { cat: 'Tropical & Global Health',q: '(tropical medicine[MeSH] OR global health[MeSH]) AND "last 1 year"[edat]' },
  { cat: 'Ethiopian Medicine',      q: 'Ethiopia[Affiliation] AND (health OR medicine OR disease) AND "last 2 years"[edat]' },
];

async function refreshJournals() {
  console.log(`\n[${new Date().toISOString()}] Refreshing PubMed journals…`);
  const journals = [];
  const newFailures = [];
  let successCount = 0;

  for (const { cat, q } of JOURNAL_QUERIES) {
    try {
      const ids = await pmSearch(q, 4);
      if (ids.length) {
        const results = await pmSummary(ids);
        ids.forEach(id => {
          const doc = results[id];
          if (!doc || !doc.title) return;
          journals.push({
            pmid:    id,
            title:   doc.title.replace(/<[^>]+>/g, '').trim(),
            author:  doc.authors?.[0]?.name ? doc.authors[0].name + (doc.authors.length > 1 ? ', et al.' : '') : 'et al.',
            journal: doc.fulljournalname || doc.source || '',
            jUrl:    `https://pubmed.ncbi.nlm.nih.gov/${id}/`,
            year:    (doc.pubdate || '').slice(0, 4) || new Date().getFullYear().toString(),
            cat
          });
        });
      }
      recordSuccess(`PubMed:${cat}`);
      successCount++;
      await delay(350);
    } catch (e) {
      const count = recordFailure(`PubMed:${cat}`, e.message);
      console.warn(`  ✗ PubMed (${cat}) fail #${count}: ${e.message}`);
      if (count >= FAIL_THRESHOLD) newFailures.push(`PubMed (${cat}): ${e.message}`);
      await delay(500);
    }
  }

  if (journals.length) { cache.journals = journals; cache.lastJournalFetch = Date.now(); }
  console.log(`[PubMed] done — ${journals.length} articles across ${successCount} categories`);

  if (newFailures.length) {
    await notify(
      '⚠️ Sari\'s Garden — PubMed Failures',
      `${newFailures.length} PubMed categor${newFailures.length > 1 ? 'ies' : 'y'} failing:\n\n${newFailures.join('\n')}`,
      'high'
    );
  }
}

// ─── Scheduler ────────────────────────────────────────────────────────────────
async function startScheduler() {
  // Run both immediately on startup
  await refreshNews();
  await refreshJournals();

  // RSS: every 30 minutes
  setInterval(refreshNews, RSS_INTERVAL);

  // PubMed: every 2 hours
  setInterval(refreshJournals, PUBMED_INTERVAL);

  // Send a startup notification so you know the server came online
  await notify(
    '🌷 Sari\'s Garden is online',
    `Server started. Crawling ${RSS_SOURCES.length} RSS sources every 30 min + PubMed every 2 hours.`,
    'low'
  );
}

// ─── Start ────────────────────────────────────────────────────────────────────
initAuth().then(() => {
  app.listen(PORT, () => {
    console.log(`Sari's Garden on :${PORT}`);
    startScheduler();
  });
});
