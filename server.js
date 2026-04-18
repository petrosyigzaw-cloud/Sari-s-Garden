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

// Optional PubMed API key (env var) — raises rate limit from 3 to 10 req/sec
const PM_KEY  = process.env.PUBMED_API_KEY ? `&api_key=${process.env.PUBMED_API_KEY}` : '';
const PM_BASE = 'https://eutils.ncbi.nlm.nih.gov/entrez/eutils/';
const HEADERS = { 'User-Agent': 'SarisGarden/1.0 (medical research platform)' };

// ─── Auth ─────────────────────────────────────────────────────────────────────
const AUTH_FILE = path.join(__dirname, 'data', 'auth.json');
const sessions  = new Map(); // token → { expires }

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

// On startup: if SARI_INITIAL_PASSWORD is set and no hash exists yet, hash and save it automatically
async function initAuth() {
  if (!getPasswordHash() && process.env.SARI_INITIAL_PASSWORD) {
    console.log('[auth] Hashing initial password from SARI_INITIAL_PASSWORD env var…');
    const hash = await bcrypt.hash(process.env.SARI_INITIAL_PASSWORD, 12);
    savePasswordHash(hash);
    console.log('[auth] Initial password hashed and saved.');
  }
}

function requireAuth(req, res, next) {
  const token = req.cookies?.sg_session;
  if (token && sessions.has(token)) {
    const s = sessions.get(token);
    if (s.expires > Date.now()) return next();
    sessions.delete(token);
  }
  // API routes → 401 JSON, page routes → redirect
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
  if (!hash) {
    return res.status(500).json({ error: 'No password configured. Set SARI_INITIAL_PASSWORD in Render environment.' });
  }

  const valid = await bcrypt.compare(password, hash);
  if (!valid) return res.status(401).json({ error: 'Incorrect username or password.' });

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { expires: Date.now() + 7 * 24 * 60 * 60 * 1000 }); // 7 days

  res.cookie('sg_session', token, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  });
  res.json({ ok: true });
});

app.post('/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters.' });
  }

  const hash = getPasswordHash();
  if (hash) {
    const valid = await bcrypt.compare(currentPassword, hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  const newHash = await bcrypt.hash(newPassword, 12);
  savePasswordHash(newHash);

  // Also log the hash so it can be set as SARI_PASSWORD_HASH env var if needed after a redeploy
  console.log('[auth] Password changed. If redeployed, set this in Render env vars:');
  console.log(`[auth] SARI_PASSWORD_HASH=${newHash}`);

  res.json({ ok: true });
});

app.get('/auth/logout', (req, res) => {
  const token = req.cookies?.sg_session;
  if (token) sessions.delete(token);
  res.clearCookie('sg_session');
  res.redirect('/login');
});

// ─── Protected app & API routes ───────────────────────────────────────────────
app.get('/',             requireAuth, (_, res) => res.sendFile(path.join(__dirname, 'saris-garden.html')));
app.get('/api/news',     requireAuth, (_, res) => res.json(cache.news));
app.get('/api/journals', requireAuth, (_, res) => res.json(cache.journals));
app.get('/api/status',   requireAuth, (_, res) => res.json({
  lastFetch:    cache.lastFetch,
  lastFetchAgo: cache.lastFetch ? Math.round((Date.now() - cache.lastFetch) / 60000) + ' min ago' : null,
  newsCount:    cache.news.length,
  journalCount: cache.journals.length,
}));

// ─── In-memory cache ──────────────────────────────────────────────────────────
let cache = { news: [], journals: [], lastFetch: null };
const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 hours

const rss = new Parser({
  headers: HEADERS,
  timeout: 12000,
  customFields: { item: [['media:content','mediaContent'],['media:thumbnail','mediaThumbnail']] }
});

// ─── Topic detection ──────────────────────────────────────────────────────────
function detectTag(text = '') {
  const t = text.toLowerCase();
  if (/cancer|oncol|tumor|tumour|chemotherapy|immunotherapy|car[-\s]?t|leukemia|lymphoma|carcinoma/.test(t)) return 'Oncology';
  if (/cardiac|cardio|heart failure|coronary|myocardial|atrial fibrillation|hypertension|sglt2|statin|arrhythmia/.test(t)) return 'Cardiology';
  if (/nutrition|diet\b|vitamin|mineral|supplement|obesity|bmi|metabolic syndrome|plant.based|malnutrition/.test(t)) return 'Nutrition';
  if (/antimicrobial|antibiotic|resistance|sepsis|\bhiv\b|\btb\b|tuberculosis|malaria|\bcovid\b|influenza|mpox|cholera/.test(t)) return 'Infectious Disease';
  if (/alzheimer|parkinson|dementia|cognitive|seizure|epilepsy|multiple sclerosis|migraine|neurolog/.test(t)) return 'Neurology';
  if (/diabet|insulin|thyroid|endocrin|glucose|hba1c|glp.1|semaglutide|tirzepatide|adrenal/.test(t)) return 'Endocrinology';
  if (/\bwomen\b|maternal|pregnancy|obstetric|gynecol|menopause|fertility|cervical|endometriosis/.test(t)) return "Women's Health";
  if (/ethiopia|tropical medicine|neglected tropical|leishmaniasis|schistosomiasis/.test(t)) return 'Tropical & Global Health';
  if (/public health|epidemi|surveillance|vaccination|immunization|ncd|non-communicable/.test(t)) return 'Public Health';
  return 'General Medicine';
}

// ─── RSS sources ──────────────────────────────────────────────────────────────
const RSS_SOURCES = [
  { url: 'https://www.statnews.com/feed/',                             source: 'STAT News',       siteUrl: 'https://www.statnews.com',          max: 7 },
  { url: 'https://www.who.int/rss-feeds/news-english.xml',            source: 'WHO',             siteUrl: 'https://www.who.int',               max: 5 },
  { url: 'https://africacdc.org/feed/',                                source: 'Africa CDC',      siteUrl: 'https://africacdc.org',             max: 4 },
  { url: 'https://www.cochranelibrary.com/feed/cochrane-reviews-new', source: 'Cochrane Library',siteUrl: 'https://www.cochranelibrary.com',    max: 4 },
  { url: 'https://www.medscape.com/cx/rss/medpulse.xml',              source: 'Medscape',        siteUrl: 'https://www.medscape.com',          max: 5 },
  { url: 'https://ephi.gov.et/feed/',                                  source: 'EPHI',            siteUrl: 'https://ephi.gov.et',               max: 3 },
];

async function fetchFeeds() {
  const articles = [];
  for (const src of RSS_SOURCES) {
    try {
      const feed = await Promise.race([
        rss.parseURL(src.url),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 13000))
      ]);
      (feed.items || []).slice(0, src.max).forEach(item => {
        if (!item.title || !item.link) return;
        const text = (item.title || '') + ' ' + (item.contentSnippet || item.summary || '');
        articles.push({
          title:     item.title.trim(),
          site:      src.source,
          sourceUrl: item.link,
          tag:       detectTag(text),
          summary:   item.contentSnippet ? item.contentSnippet.slice(0, 260).trim() : '',
          pubDate:   item.isoDate || item.pubDate || new Date().toISOString(),
          img:       item.enclosure?.url || item.mediaContent?.$.url || item.mediaThumbnail?.$.url || null,
          draft:     null
        });
      });
      console.log(`  ✓ ${src.source}`);
    } catch (e) {
      console.warn(`  ✗ ${src.source}: ${e.message}`);
    }
  }
  return articles;
}

// ─── PubMed ───────────────────────────────────────────────────────────────────
const delay = ms => new Promise(r => setTimeout(r, ms));

async function pmSearch(query, max = 5) {
  const url = `${PM_BASE}esearch.fcgi?db=pubmed&term=${encodeURIComponent(query)}&retmax=${max}&sort=date&retmode=json${PM_KEY}`;
  const r = await fetch(url, { headers: HEADERS });
  if (!r.ok) throw new Error(`esearch HTTP ${r.status}`);
  return (await r.json()).esearchresult?.idlist || [];
}

async function pmSummary(ids) {
  if (!ids.length) return {};
  const url = `${PM_BASE}esummary.fcgi?db=pubmed&id=${ids.join(',')}&retmode=json${PM_KEY}`;
  const r = await fetch(url, { headers: HEADERS });
  if (!r.ok) throw new Error(`esummary HTTP ${r.status}`);
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

async function fetchJournals() {
  const journals = [];
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
      console.log(`  ✓ PubMed (${cat}): ${ids.length}`);
      await delay(350);
    } catch (e) {
      console.warn(`  ✗ PubMed (${cat}): ${e.message}`);
      await delay(500);
    }
  }
  return journals;
}

async function refresh() {
  console.log(`\n[${new Date().toISOString()}] Refreshing content cache…`);
  try {
    const [news, journals] = await Promise.all([fetchFeeds(), fetchJournals()]);
    if (news.length)     cache.news     = news;
    if (journals.length) cache.journals = journals;
    cache.lastFetch = Date.now();
    console.log(`[cache] ${cache.news.length} news · ${cache.journals.length} journals`);
  } catch (e) {
    console.error('[cache] refresh failed:', e);
  }
}

initAuth().then(() => {
  refresh();
  setInterval(refresh, CACHE_TTL);
  app.listen(PORT, () => console.log(`Sari's Garden on :${PORT}`));
});
