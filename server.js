const express = require('express');
const app = express();

app.use(express.json({
  limit: '1mb',
  strict: false // allow non-object JSON bodies through so we can classify them as invalid ourselves
}));

const VALID_TYPES = new Set(['dns', 'ct_log', 'registry', 'archive', 'scan']);
const MS_PER_DAY = 24 * 60 * 60 * 1000;

function invalidResult() {
  return { verdict: 'invalid', confidence: 'low', corroboratingSources: [] };
}

function unverifiedResult() {
  return { verdict: 'unverified', confidence: 'low', corroboratingSources: [] };
}

function isPlainObject(v) {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function parseDateMs(s) {
  if (typeof s !== 'string') return null;
  const ms = Date.parse(s);
  return Number.isNaN(ms) ? null : ms;
}

function isValidSource(src) {
  if (!isPlainObject(src)) return false;
  const { id, origin, value, observedAt, type } = src;
  if (typeof id !== 'string') return false;
  if (typeof origin !== 'string') return false;
  if (typeof value !== 'string') return false;
  if (typeof observedAt !== 'string') return false;
  if (!VALID_TYPES.has(type)) return false;
  return true;
}

function corroborate(body) {
  // --- Rule 1: structural / top-level validation -------------------------
  if (!isPlainObject(body)) return invalidResult();

  const { claim, asOf, stalenessDays, sources } = body;

  if (!isPlainObject(claim)) return invalidResult();
  if (typeof claim.value !== 'string') return invalidResult();

  const asOfMs = parseDateMs(asOf);
  if (asOfMs === null) return invalidResult();

  if (typeof stalenessDays !== 'number' || Number.isNaN(stalenessDays)) {
    return invalidResult();
  }

  if (!Array.isArray(sources)) return invalidResult();

  // --- Filter to valid sources only --------------------------------------
  const validSources = sources.filter(isValidSource);

  // --- Compute freshness ---------------------------------------------------
  const withFreshness = validSources.map((src) => {
    const observedMs = parseDateMs(src.observedAt);
    let fresh = false;
    if (observedMs !== null) {
      const ageDays = (asOfMs - observedMs) / MS_PER_DAY;
      fresh = ageDays <= stalenessDays;
    }
    return { ...src, __fresh: fresh };
  });

  // --- Rule 2: contradicted -------------------------------------------------
  const contradicting = withFreshness.filter(
    (s) => s.__fresh && s.authoritative === true && s.value !== claim.value
  );

  if (contradicting.length > 0) {
    const ids = contradicting.map((s) => s.id).sort();
    return { verdict: 'contradicted', confidence: 'low', corroboratingSources: ids };
  }

  // --- Rule 3: supported ------------------------------------------------
  const agreeing = withFreshness.filter((s) => s.__fresh && s.value === claim.value);

  // reduce to one representative per origin: smallest id lexicographically
  const bestByOrigin = new Map(); // origin -> source
  for (const s of agreeing) {
    const current = bestByOrigin.get(s.origin);
    if (!current || s.id < current.id) {
      bestByOrigin.set(s.origin, s);
    }
  }

  const representatives = [...bestByOrigin.values()];

  if (representatives.length >= 2) {
    const distinctTypes = new Set(representatives.map((s) => s.type));
    const confidence = distinctTypes.size >= 2 ? 'high' : 'medium';
    const ids = representatives.map((s) => s.id).sort();
    return { verdict: 'supported', confidence, corroboratingSources: ids };
  }

  // --- Rule 4: unverified -------------------------------------------------
  return unverifiedResult();
}

app.post('/corroborate', (req, res) => {
  try {
    const result = corroborate(req.body);
    res.status(200).json(result);
  } catch (err) {
    // Any unexpected parsing/runtime failure is treated as an invalid claim,
    // never a 5xx that leaks internals.
    res.status(200).json(invalidResult());
  }
});

// Malformed JSON bodies land here via express.json()'s error handling.
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(200).json(invalidResult());
  }
  return res.status(200).json(invalidResult());
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`corroboration-service listening on port ${PORT}`);
});
