/**
 * Worker: edutraceug-academic-worker
 * Base URL: https://edutraceug-academic-worker.anubisdigital114-9df.workers.dev
 */

import * as XLSX from 'xlsx';

const DEFAULT_PROJECT_ID = 'edutrace-ug';

// ---------------------------------------------------------------- errors
class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

// ---------------------------------------------------------------- CORS / JSON
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Max-Age': '86400',
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...CORS_HEADERS },
  });
}

function binary(body, contentType, extraHeaders = {}) {
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': contentType, 'Cache-Control': 'no-store', ...CORS_HEADERS, ...extraHeaders },
  });
}

async function safeJson(request) {
  try {
    const body = await request.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('not object');
    return body;
  } catch {
    throw new HttpError(400, 'Invalid JSON body');
  }
}

// ---------------------------------------------------------------- helpers
function str(v) { return v === null || v === undefined ? '' : String(v); }
function enc(v) { return encodeURIComponent(v); }
function strOrEmpty(v) { return v === undefined || v === null ? '' : String(v).trim(); }

function generateId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let s = '';
  for (const b of bytes) s += chars[b % chars.length];
  return s;
}

function naturalSort(a, b) {
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

const EMOJI_RE = /[\u{1F000}-\u{1FAFF}\u{1F1E6}-\u{1F1FF}\u{2600}-\u{27BF}\u{2B00}-\u{2BFF}\u{FE0F}\u{200D}\u{20E3}\u{1F3FB}-\u{1F3FF}]/gu;

function cleanText(input, maxLen, label) {
  if (typeof input !== 'string') throw new HttpError(400, `${label} must be text`);
  const t = input.trim().replace(EMOJI_RE, '');
  if (!t) throw new HttpError(400, `${label} is required`);
  if (t.length > maxLen) throw new HttpError(400, `${label} is too long (max ${maxLen})`);
  return t;
}

// ---------------------------------------------------------------- class normalization
function normalizeClass(raw) {
  const s = strOrEmpty(raw);
  if (!s) return '';
  const compact = s.replace(/[.\-_]/g, '').replace(/\s+/g, ' ').trim();
  const noSpace = compact.replace(/\s+/g, '');
  const lower = noSpace.toLowerCase();

  const prefixMatch = lower.match(/^(senior|form|s|f)?([1-6])$/);
  if (prefixMatch) {
    const n = Number(prefixMatch[2]);
    return `Senior ${n}`;
  }
  const digitsMatch = lower.match(/(\d+)$/);
  if (digitsMatch) {
    const n = Number(digitsMatch[1]);
    if (n >= 1 && n <= 6) {
      const head = lower.slice(0, lower.length - digitsMatch[1].length);
      if (/^(senior|form|s|f)?$/.test(head)) {
        return `Senior ${n}`;
      }
    }
  }
  return s;
}

function normalizeStream(raw) {
  const s = strOrEmpty(raw);
  if (!s) return '';
  return s
    .replace(/\s+/g, ' ')
    .split(' ')
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(' ');
}

function classLevel(className) {
  const m = normalizeClass(className).match(/^Senior ([1-6])$/);
  if (!m) return null;
  const n = Number(m[1]);
  if (n <= 4) return 'olevel';
  return 'alevel';
}

// ---------------------------------------------------------------- service account
let _saCache = { raw: null, parsed: null };

function getServiceAccount(env) {
  const raw = env['ACCOUNT-SERVICE-FIREBASE'] || env['ACCOUNT_SERVICE_FIREBASE'];
  if (!raw) throw new HttpError(500, 'Server misconfigured: ACCOUNT-SERVICE-FIREBASE');
  if (_saCache.raw === raw && _saCache.parsed) return _saCache.parsed;
  const parsed = typeof raw === 'object' ? raw : JSON.parse(raw);
  _saCache = { raw, parsed };
  return parsed;
}

function getProjectId(env) {
  return getServiceAccount(env).project_id || DEFAULT_PROJECT_ID;
}

// ---------------------------------------------------------------- Firebase ID token
let jwksCache = { keys: null, expiry: 0 };

async function getJwks() {
  const now = Date.now();
  if (jwksCache.keys && now < jwksCache.expiry) return jwksCache.keys;
  const res = await fetch(
    'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'
  );
  if (!res.ok) throw new HttpError(502, 'JWKS fetch failed');
  const data = await res.json();
  jwksCache = { keys: data.keys, expiry: now + 3600_000 };
  return data.keys;
}

function b64urlToBytes(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToString(str) {
  return new TextDecoder().decode(b64urlToBytes(str));
}

function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function verifyIdToken(token, projectId) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new HttpError(401, 'Malformed token');
  const [headerB64, payloadB64, sigB64] = parts;

  let header, payload;
  try {
    header = JSON.parse(b64urlToString(headerB64));
    payload = JSON.parse(b64urlToString(payloadB64));
  } catch {
    throw new HttpError(401, 'Malformed token');
  }

  const keys = await getJwks();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new HttpError(401, 'Unknown signing key');

  const { alg, ...cleanJwk } = jwk;
  const key = await crypto.subtle.importKey(
    'jwk',
    cleanJwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    b64urlToBytes(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );
  if (!ok) throw new HttpError(401, 'Invalid token signature');

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new HttpError(401, 'Token expired');
  if (payload.iat > now + 60) throw new HttpError(401, 'Token issued in future');
  if (payload.aud !== projectId) throw new HttpError(401, 'Invalid audience');
  if (payload.iss !== `https://securetoken.google.com/${projectId}`) {
    throw new HttpError(401, 'Invalid issuer');
  }
  if (!payload.sub) throw new HttpError(401, 'Missing subject');
  return payload;
}

async function requireUser(request, env, schoolId, allowedRoles) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) throw new HttpError(401, 'Missing Bearer token');
  const payload = await verifyIdToken(m[1], getProjectId(env));
  if (!allowedRoles.includes(payload.role)) throw new HttpError(403, 'Not allowed for your role');
  if (String(payload.schoolId) !== String(schoolId)) {
    throw new HttpError(403, 'Not a member of this school');
  }
  return payload;
}

// ---------------------------------------------------------------- Firestore
let saTokenCache = new Map();

function pemToArrayBuffer(pem) {
  const b64 = pem
    .replace(/\\n/g, '\n')
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/[\r\n\s]/g, '');
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

async function importPrivateKey(pem) {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToArrayBuffer(pem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function getFirestoreToken(env) {
  const sa = getServiceAccount(env);
  const cached = saTokenCache.get(sa.client_email);
  if (cached && cached.expiry > Date.now() + 60_000) return cached.token;

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim = {
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/datastore',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };
  const headerB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const claimB64 = b64urlEncode(new TextEncoder().encode(JSON.stringify(claim)));
  const toSign = `${headerB64}.${claimB64}`;
  const key = await importPrivateKey(sa.private_key);
  const sigBuf = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(toSign)
  );
  const jwt = `${toSign}.${b64urlEncode(new Uint8Array(sigBuf))}`;

  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) throw new HttpError(502, 'Firestore auth failed: ' + (await res.text()));
  const data = await res.json();
  saTokenCache.set(sa.client_email, {
    token: data.access_token,
    expiry: Date.now() + 3500_000,
  });
  return data.access_token;
}

function toFsValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === 'string') return { stringValue: v };
  if (typeof v === 'boolean') return { booleanValue: v };
  if (typeof v === 'number') {
    return Number.isInteger(v) ? { integerValue: String(v) } : { doubleValue: v };
  }
  if (Array.isArray(v)) return { arrayValue: { values: v.map(toFsValue) } };
  if (typeof v === 'object') {
    const fields = {};
    for (const [k, val] of Object.entries(v)) fields[k] = toFsValue(val);
    return { mapValue: { fields } };
  }
  throw new HttpError(500, 'Cannot serialize value');
}

function fromFsValue(v) {
  if (!v) return null;
  if ('stringValue' in v) return v.stringValue;
  if ('integerValue' in v) return parseInt(v.integerValue, 10);
  if ('doubleValue' in v) return v.doubleValue;
  if ('booleanValue' in v) return v.booleanValue;
  if ('nullValue' in v) return null;
  if ('timestampValue' in v) return v.timestampValue;
  if ('arrayValue' in v) return (v.arrayValue.values || []).map(fromFsValue);
  if ('mapValue' in v) {
    const out = {};
    for (const [k, val] of Object.entries(v.mapValue.fields || {})) {
      out[k] = fromFsValue(val);
    }
    return out;
  }
  return null;
}

function fromFsDoc(doc) {
  const out = {};
  for (const [k, v] of Object.entries(doc.fields || {})) out[k] = fromFsValue(v);
  return out;
}

function fsBase(env) {
  return `https://firestore.googleapis.com/v1/projects/${getProjectId(env)}/databases/(default)/documents`;
}

function docName(env, segments) {
  return `projects/${getProjectId(env)}/databases/(default)/documents/${segments.map(enc).join('/')}`;
}

async function fsGet(env, docPath) {
  const token = await getFirestoreToken(env);
  const res = await fetch(`${fsBase(env)}/${docPath}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new HttpError(502, 'Firestore read failed');
  return fromFsDoc(await res.json());
}

async function fsPatch(env, docPath, data) {
  const token = await getFirestoreToken(env);
  const keys = Object.keys(data);
  const mask = keys.map((f) => `updateMask.fieldPaths=${enc(f)}`).join('&');
  const body = { fields: {} };
  for (const k of keys) body.fields[k] = toFsValue(data[k]);
  const res = await fetch(`${fsBase(env)}/${docPath}?${mask}`, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new HttpError(502, 'Firestore write failed: ' + (await res.text()));
  return fromFsDoc(await res.json());
}

async function fsCreate(env, collectionPath, data, docId) {
  const token = await getFirestoreToken(env);
  const qs = docId ? `?documentId=${enc(docId)}` : '';
  const body = { fields: {} };
  for (const [k, v] of Object.entries(data)) body.fields[k] = toFsValue(v);
  const res = await fetch(`${fsBase(env)}/${collectionPath}${qs}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (res.status === 409) throw new HttpError(409, 'Document already exists');
  if (!res.ok) throw new HttpError(502, 'Firestore create failed: ' + (await res.text()));
  const created = await res.json();
  return { id: created.name.split('/').pop(), data: fromFsDoc(created) };
}

async function fsQuery(env, parentPath, structuredQuery) {
  const token = await getFirestoreToken(env);
  const url = parentPath ? `${fsBase(env)}/${parentPath}:runQuery` : `${fsBase(env)}:runQuery`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ structuredQuery }),
  });
  if (!res.ok) throw new HttpError(502, 'Firestore query failed: ' + (await res.text()));
  const rows = await res.json();
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    if (r.document) out.push({ id: r.document.name.split('/').pop(), data: fromFsDoc(r.document) });
  }
  return out;
}

async function firestoreCommit(env, writes) {
  const token = await getFirestoreToken(env);
  const res = await fetch(`${fsBase(env)}:commit`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ writes }),
  });
  if (!res.ok) throw new HttpError(502, 'Firestore commit failed: ' + (await res.text()));
  return res.json();
}

async function commitAll(env, writes) {
  const CHUNK = 400;
  for (let i = 0; i < writes.length; i += CHUNK) {
    await firestoreCommit(env, writes.slice(i, i + CHUNK));
  }
}

function fsEq(field, value) {
  let v;
  if (typeof value === 'string') v = { stringValue: value };
  else if (typeof value === 'boolean') v = { booleanValue: value };
  else if (typeof value === 'number') {
    v = Number.isInteger(value) ? { integerValue: String(value) } : { doubleValue: value };
  } else v = { stringValue: String(value) };
  return { fieldFilter: { field: { fieldPath: field }, op: 'EQUAL', value: v } };
}

// ---------------------------------------------------------------- audit
async function logChange(env, schoolId, entry) {
  try {
    await fsCreate(env, `schools/${enc(schoolId)}/auditLog`, {
      ...entry,
      at: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Audit log write failed:', err && err.message);
  }
}

// ---------------------------------------------------------------- seed data
const COMPULSORY_SUBJECTS = [
  'English',
  'Mathematics',
  'Physics',
  'Chemistry',
  'Biology',
  'History',
  'Geography',
];

const OPTIONAL_SUBJECTS = [
  'ICT',
  'IRE',
  'CRE',
  'Entrepreneurship',
  'Literature',
  'Kiswahili',
  'Luganda',
  'Agriculture',
  'Physical Education',
  'Art',
  'Music',
  'Divinity',
  'Economics',
  'Foods and Nutrition',
  'Clothing and Textiles',
  'Technical Drawing',
  'Woodwork',
  'Metalwork',
  'Building Construction',
];

const DEFAULT_COMBINATIONS = [
  { code: 'PCM', name: 'Physics, Chemistry, Mathematics', subjects: ['Physics', 'Chemistry', 'Mathematics'] },
  { code: 'PCB', name: 'Physics, Chemistry, Biology', subjects: ['Physics', 'Chemistry', 'Biology'] },
  { code: 'BCM', name: 'Biology, Chemistry, Mathematics', subjects: ['Biology', 'Chemistry', 'Mathematics'] },
  { code: 'HEG', name: 'History, Economics, Geography', subjects: ['History', 'Economics', 'Geography'] },
  { code: 'MEG', name: 'Mathematics, Economics, Geography', subjects: ['Mathematics', 'Economics', 'Geography'] },
  { code: 'HEL', name: 'History, Economics, Literature', subjects: ['History', 'Economics', 'Literature'] },
  { code: 'HED', name: 'History, Economics, Divinity', subjects: ['History', 'Economics', 'Divinity'] },
  { code: 'PEM', name: 'Physics, Economics, Mathematics', subjects: ['Physics', 'Economics', 'Mathematics'] },
  { code: 'EGD', name: 'Economics, Geography, Divinity', subjects: ['Economics', 'Geography', 'Divinity'] },
  { code: 'ICT', name: 'Computer Science, Economics, Mathematics', subjects: ['ICT', 'Economics', 'Mathematics'] },
  { code: 'AGR', name: 'Agriculture, Biology, Chemistry', subjects: ['Agriculture', 'Biology', 'Chemistry'] },
  { code: 'CDF', name: 'Computer Science, Divinity, Literature', subjects: ['ICT', 'Divinity', 'Literature'] },
];

// ---------------------------------------------------------------- seed marker
async function ensureSeeded(env, schoolId) {
  const marker = await fsGet(env, `schools/${enc(schoolId)}/settings/academicSeeded`);
  if (marker && marker.seeded === true) return;

  const now = new Date().toISOString();

  for (const name of COMPULSORY_SUBJECTS) {
    const id = await stableSubjectId(name);
    try {
      await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(id)}`, {
        id,
        name,
        level: 'both',
        compulsory: true,
        order: COMPULSORY_SUBJECTS.indexOf(name) * 10 + 10,
        seed: true,
        archived: false,
        createdAt: now,
        updatedAt: now,
      });
    } catch (err) {
      console.error('Subject seed failed:', name, err && err.message);
    }
  }
  for (const name of OPTIONAL_SUBJECTS) {
    const id = await stableSubjectId(name);
    try {
      await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(id)}`, {
        id,
        name,
        level: 'both',
        compulsory: false,
        order: 1000 + OPTIONAL_SUBJECTS.indexOf(name) * 10,
        seed: true,
        archived: false,
        createdAt: now,
        updatedAt: now,
      });
    } catch (err) {
      console.error('Subject seed failed:', name, err && err.message);
    }
  }

  for (const combo of DEFAULT_COMBINATIONS) {
    const id = await stableComboId(combo.code);
    try {
      await fsPatch(env, `schools/${enc(schoolId)}/combinations/${enc(id)}`, {
        id,
        code: combo.code,
        name: combo.name,
        subjects: combo.subjects,
        seed: true,
        archived: false,
        createdAt: now,
        updatedAt: now,
      });
    } catch (err) {
      console.error('Combination seed failed:', combo.code, err && err.message);
    }
  }

  try {
    await fsPatch(env, `schools/${enc(schoolId)}/settings/academicSeeded`, {
      seeded: true,
      seededAt: now,
    });
  } catch (err) {
    console.error('Seed marker failed:', err && err.message);
  }
}

async function stableSubjectId(name) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`subject|${name}`));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 20);
}

async function stableComboId(code) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`combo|${code}`));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 20);
}

// ---------------------------------------------------------------- data loaders
async function listSubjects(env, schoolId, { includeArchived = false } = {}) {
  await ensureSeeded(env, schoolId);
  const rows = await fsQuery(env, `schools/${enc(schoolId)}`, {
    from: [{ collectionId: 'subjects' }],
    limit: 500,
  });
  const all = rows.map((r) => ({
    id: r.id,
    name: r.data.name || '',
    level: r.data.level || 'both',
    compulsory: r.data.compulsory === true,
    order: typeof r.data.order === 'number' ? r.data.order : 999,
    seed: r.data.seed === true,
    archived: r.data.archived === true,
  }));
  const filtered = includeArchived ? all : all.filter((s) => !s.archived);
  filtered.sort((a, b) => a.order - b.order || naturalSort(a.name, b.name));
  return filtered;
}

async function listCombinations(env, schoolId, { includeArchived = false } = {}) {
  await ensureSeeded(env, schoolId);
  const rows = await fsQuery(env, `schools/${enc(schoolId)}`, {
    from: [{ collectionId: 'combinations' }],
    limit: 500,
  });
  const all = rows.map((r) => ({
    id: r.id,
    code: r.data.code || '',
    name: r.data.name || '',
    subjects: Array.isArray(r.data.subjects) ? r.data.subjects : [],
    seed: r.data.seed === true,
    archived: r.data.archived === true,
  }));
  const filtered = includeArchived ? all : all.filter((c) => !c.archived);
  filtered.sort((a, b) => naturalSort(a.code, b.code));
  return filtered;
}

async function listStudents(env, schoolId, { className, stream } = {}) {
  const filters = [fsEq('recordType', 'student')];
  if (className) filters.push(fsEq('class', className));
  if (stream) filters.push(fsEq('stream', stream));
  const rows = await fsQuery(env, `schools/${enc(schoolId)}`, {
    from: [{ collectionId: 'roster' }],
    where: filters.length === 1 ? filters[0] : { compositeFilter: { op: 'AND', filters } },
    limit: 20000,
  });
  return rows.map((r) => ({
    id: r.id,
    firstName: r.data.firstName || '',
    lastName: r.data.lastName || '',
    class: normalizeClass(r.data.class || ''),
    classRaw: r.data.class || '',
    stream: r.data.stream || '',
    gender: r.data.gender || '',
    studentId: r.data.studentId || '',
    subjects: Array.isArray(r.data.subjects) ? r.data.subjects : [],
    combination: r.data.combination || null,
  }));
}

async function getSubjectById(env, schoolId, subjectId) {
  const doc = await fsGet(env, `schools/${enc(schoolId)}/subjects/${enc(subjectId)}`);
  if (!doc) throw new HttpError(404, 'Subject not found');
  return {
    id: subjectId,
    name: doc.name || '',
    level: doc.level || 'both',
    compulsory: doc.compulsory === true,
    order: typeof doc.order === 'number' ? doc.order : 999,
    seed: doc.seed === true,
    archived: doc.archived === true,
  };
}

async function getCombinationById(env, schoolId, comboId) {
  const doc = await fsGet(env, `schools/${enc(schoolId)}/combinations/${enc(comboId)}`);
  if (!doc) throw new HttpError(404, 'Combination not found');
  return {
    id: comboId,
    code: doc.code || '',
    name: doc.name || '',
    subjects: Array.isArray(doc.subjects) ? doc.subjects : [],
    seed: doc.seed === true,
    archived: doc.archived === true,
  };
}

// ---------------------------------------------------------------- handlers: subjects
async function handleListSubjects(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ['schoolAdmin', 'teacher']);
  const includeArchived = url.searchParams.get('includeArchived') === 'true';
  const subjects = await listSubjects(env, schoolId, { includeArchived });
  return { subjects };
}

async function handleCreateSubject(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  await ensureSeeded(env, schoolId);
  const body = await safeJson(request);

  const name = cleanText(body.name, 60, 'name');
  const level = ['olevel', 'alevel', 'both'].includes(body.level) ? body.level : 'both';
  const compulsory = body.compulsory === true;
  const order = Number.isFinite(Number(body.order)) ? Number(body.order) : 5000;

  const existing = await listSubjects(env, schoolId, { includeArchived: true });
  if (existing.some((s) => s.name.toLowerCase() === name.toLowerCase())) {
    throw new HttpError(409, `A subject named "${name}" already exists`);
  }

  const id = generateId();
  const now = new Date().toISOString();
  await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(id)}`, {
    id,
    name,
    level,
    compulsory,
    order,
    seed: false,
    archived: false,
    createdBy: String(user.sub),
    createdAt: now,
    updatedAt: now,
  });

  await logChange(env, schoolId, {
    action: 'subject.create',
    by: String(user.sub),
    target: id,
    after: { name, level, compulsory, order },
  });

  return { id, name, level, compulsory, order, seed: false, archived: false };
}

async function handleUpdateSubject(request, env, schoolId, subjectId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const existing = await getSubjectById(env, schoolId, subjectId);
  const body = await safeJson(request);

  const update = {};
  if ('name' in body) {
    const name = cleanText(body.name, 60, 'name');
    const all = await listSubjects(env, schoolId, { includeArchived: true });
    if (all.some((s) => s.id !== subjectId && s.name.toLowerCase() === name.toLowerCase())) {
      throw new HttpError(409, `A subject named "${name}" already exists`);
    }
    update.name = name;
  }
  if ('level' in body) {
    if (!['olevel', 'alevel', 'both'].includes(body.level)) {
      throw new HttpError(400, 'level must be olevel, alevel, or both');
    }
    update.level = body.level;
  }
  if ('compulsory' in body) {
    if (typeof body.compulsory !== 'boolean') {
      throw new HttpError(400, 'compulsory must be boolean');
    }
    update.compulsory = body.compulsory;
  }
  if ('order' in body) {
    const n = Number(body.order);
    if (!Number.isFinite(n)) throw new HttpError(400, 'order must be a number');
    update.order = n;
  }
  if (!Object.keys(update).length) throw new HttpError(400, 'Nothing to update');

  update.updatedAt = new Date().toISOString();
  update.updatedBy = String(user.sub);

  await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(subjectId)}`, update);
  await logChange(env, schoolId, {
    action: 'subject.update',
    by: String(user.sub),
    target: subjectId,
    before: existing,
    after: update,
  });
  return { ...existing, ...update };
}

async function handleDeleteSubject(request, env, schoolId, subjectId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const existing = await getSubjectById(env, schoolId, subjectId);

  await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(subjectId)}`, {
    archived: true,
    archivedAt: new Date().toISOString(),
    archivedBy: String(user.sub),
  });
  await logChange(env, schoolId, {
    action: 'subject.archive',
    by: String(user.sub),
    target: subjectId,
    before: existing,
  });
  return { status: 'archived', id: subjectId };
}

async function handleSeedSubjects(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const now = new Date().toISOString();
  let added = 0;

  const existing = await listSubjects(env, schoolId, { includeArchived: true });
  const existingNames = new Set(existing.map((s) => s.name.toLowerCase()));

  for (const name of COMPULSORY_SUBJECTS) {
    if (existingNames.has(name.toLowerCase())) continue;
    const id = await stableSubjectId(name);
    await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(id)}`, {
      id,
      name,
      level: 'both',
      compulsory: true,
      order: COMPULSORY_SUBJECTS.indexOf(name) * 10 + 10,
      seed: true,
      archived: false,
      createdAt: now,
      updatedAt: now,
    });
    existingNames.add(name.toLowerCase());
    added += 1;
  }
  for (const name of OPTIONAL_SUBJECTS) {
    if (existingNames.has(name.toLowerCase())) continue;
    const id = await stableSubjectId(name);
    await fsPatch(env, `schools/${enc(schoolId)}/subjects/${enc(id)}`, {
      id,
      name,
      level: 'both',
      compulsory: false,
      order: 1000 + OPTIONAL_SUBJECTS.indexOf(name) * 10,
      seed: true,
      archived: false,
      createdAt: now,
      updatedAt: now,
    });
    existingNames.add(name.toLowerCase());
    added += 1;
  }

  await logChange(env, schoolId, {
    action: 'subjects.seed',
    by: String(user.sub),
    count: added,
  });
  return { status: 'ok', added };
}

// ---------------------------------------------------------------- handlers: combinations
async function handleListCombinations(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ['schoolAdmin', 'teacher']);
  const includeArchived = url.searchParams.get('includeArchived') === 'true';
  const combinations = await listCombinations(env, schoolId, { includeArchived });
  return { combinations };
}

async function handleCreateCombination(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  await ensureSeeded(env, schoolId);
  const body = await safeJson(request);

  const code = cleanText(body.code, 10, 'code').toUpperCase();
  const name = cleanText(body.name, 120, 'name');
  if (!Array.isArray(body.subjects) || body.subjects.length === 0) {
    throw new HttpError(400, 'subjects must be a non-empty array');
  }
  const subjects = body.subjects.map((s) => cleanText(s, 60, 'subject'));

  const existing = await listCombinations(env, schoolId, { includeArchived: true });
  if (existing.some((c) => c.code.toUpperCase() === code)) {
    throw new HttpError(409, `A combination with code "${code}" already exists`);
  }

  const id = generateId();
  const now = new Date().toISOString();
  await fsPatch(env, `schools/${enc(schoolId)}/combinations/${enc(id)}`, {
    id,
    code,
    name,
    subjects,
    seed: false,
    archived: false,
    createdBy: String(user.sub),
    createdAt: now,
    updatedAt: now,
  });

  await logChange(env, schoolId, {
    action: 'combination.create',
    by: String(user.sub),
    target: id,
    after: { code, name, subjects },
  });
  return { id, code, name, subjects, seed: false, archived: false };
}

async function handleUpdateCombination(request, env, schoolId, comboId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const existing = await getCombinationById(env, schoolId, comboId);
  const body = await safeJson(request);

  const update = {};
  if ('code' in body) {
    const code = cleanText(body.code, 10, 'code').toUpperCase();
    const all = await listCombinations(env, schoolId, { includeArchived: true });
    if (all.some((c) => c.id !== comboId && c.code.toUpperCase() === code)) {
      throw new HttpError(409, `A combination with code "${code}" already exists`);
    }
    update.code = code;
  }
  if ('name' in body) update.name = cleanText(body.name, 120, 'name');
  if ('subjects' in body) {
    if (!Array.isArray(body.subjects) || body.subjects.length === 0) {
      throw new HttpError(400, 'subjects must be a non-empty array');
    }
    update.subjects = body.subjects.map((s) => cleanText(s, 60, 'subject'));
  }
  if (!Object.keys(update).length) throw new HttpError(400, 'Nothing to update');

  update.updatedAt = new Date().toISOString();
  update.updatedBy = String(user.sub);

  await fsPatch(env, `schools/${enc(schoolId)}/combinations/${enc(comboId)}`, update);
  await logChange(env, schoolId, {
    action: 'combination.update',
    by: String(user.sub),
    target: comboId,
    before: existing,
    after: update,
  });
  return { ...existing, ...update };
}

async function handleDeleteCombination(request, env, schoolId, comboId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const existing = await getCombinationById(env, schoolId, comboId);

  await fsPatch(env, `schools/${enc(schoolId)}/combinations/${enc(comboId)}`, {
    archived: true,
    archivedAt: new Date().toISOString(),
    archivedBy: String(user.sub),
  });
  await logChange(env, schoolId, {
    action: 'combination.archive',
    by: String(user.sub),
    target: comboId,
    before: existing,
  });
  return { status: 'archived', id: comboId };
}

async function handleSeedCombinations(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const now = new Date().toISOString();
  const existing = await listCombinations(env, schoolId, { includeArchived: true });
  const existingCodes = new Set(existing.map((c) => c.code.toUpperCase()));
  let added = 0;

  for (const combo of DEFAULT_COMBINATIONS) {
    if (existingCodes.has(combo.code)) continue;
    const id = await stableComboId(combo.code);
    await fsPatch(env, `schools/${enc(schoolId)}/combinations/${enc(id)}`, {
      id,
      code: combo.code,
      name: combo.name,
      subjects: combo.subjects,
      seed: true,
      archived: false,
      createdAt: now,
      updatedAt: now,
    });
    existingCodes.add(combo.code);
    added += 1;
  }

  await logChange(env, schoolId, {
    action: 'combinations.seed',
    by: String(user.sub),
    count: added,
  });
  return { status: 'ok', added };
}

// ---------------------------------------------------------------- handlers: students
async function handleListStudents(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ['schoolAdmin', 'teacher']);
  const className = url.searchParams.get('class')
    ? normalizeClass(url.searchParams.get('class'))
    : '';
  const stream = url.searchParams.get('stream') ? normalizeStream(url.searchParams.get('stream')) : '';
  const students = await listStudents(env, schoolId, { className, stream });
  return { students, count: students.length };
}

async function handleGetStudent(request, env, schoolId, rosterId) {
  await requireUser(request, env, schoolId, ['schoolAdmin', 'teacher']);
  const doc = await fsGet(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`);
  if (!doc) throw new HttpError(404, 'Student not found');
  if (doc.recordType && doc.recordType !== 'student') {
    throw new HttpError(400, 'Not a student record');
  }
  return {
    id: rosterId,
    firstName: doc.firstName || '',
    lastName: doc.lastName || '',
    class: normalizeClass(doc.class || ''),
    classRaw: doc.class || '',
    stream: doc.stream || '',
    gender: doc.gender || '',
    studentId: doc.studentId || '',
    subjects: Array.isArray(doc.subjects) ? doc.subjects : [],
    combination: doc.combination || null,
  };
}

async function handleSetStudentSubjects(request, env, schoolId, rosterId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const body = await safeJson(request);
  if (!Array.isArray(body.subjects)) throw new HttpError(400, 'subjects must be an array');
  const subjects = body.subjects.map((s) => cleanText(s, 60, 'subject'));

  const doc = await fsGet(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`);
  if (!doc) throw new HttpError(404, 'Student not found');
  if (doc.recordType && doc.recordType !== 'student') {
    throw new HttpError(400, 'Not a student record');
  }

  const now = new Date().toISOString();
  await fsPatch(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`, {
    subjects,
    academicUpdatedAt: now,
    academicUpdatedBy: String(user.sub),
  });

  await logChange(env, schoolId, {
    action: 'student.subjects.set',
    by: String(user.sub),
    target: rosterId,
    before: Array.isArray(doc.subjects) ? doc.subjects : [],
    after: subjects,
  });

  return { status: 'ok', rosterId, subjects };
}

async function handleSetStudentCombination(request, env, schoolId, rosterId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const body = await safeJson(request);
  const code = cleanText(body.combinationCode, 10, 'combinationCode').toUpperCase();

  const combos = await listCombinations(env, schoolId);
  const combo = combos.find((c) => c.code.toUpperCase() === code);
  if (!combo) throw new HttpError(404, `Combination "${code}" not found`);

  const doc = await fsGet(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`);
  if (!doc) throw new HttpError(404, 'Student not found');
  if (doc.recordType && doc.recordType !== 'student') {
    throw new HttpError(400, 'Not a student record');
  }

  const now = new Date().toISOString();
  await fsPatch(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`, {
    subjects: combo.subjects,
    combination: combo.code,
    academicUpdatedAt: now,
    academicUpdatedBy: String(user.sub),
  });

  await logChange(env, schoolId, {
    action: 'student.combination.set',
    by: String(user.sub),
    target: rosterId,
    after: { combination: combo.code, subjects: combo.subjects },
  });

  return { status: 'ok', rosterId, combination: combo.code, subjects: combo.subjects };
}

async function handleDeleteStudentCombination(request, env, schoolId, rosterId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const doc = await fsGet(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`);
  if (!doc) throw new HttpError(404, 'Student not found');

  const now = new Date().toISOString();
  await fsPatch(env, `schools/${enc(schoolId)}/roster/${enc(rosterId)}`, {
    combination: null,
    academicUpdatedAt: now,
    academicUpdatedBy: String(user.sub),
  });
  await logChange(env, schoolId, {
    action: 'student.combination.remove',
    by: String(user.sub),
    target: rosterId,
  });
  return { status: 'ok' };
}

async function handleBulkStudents(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const body = await safeJson(request);

  if (!Array.isArray(body.rosterIds) || body.rosterIds.length === 0) {
    throw new HttpError(400, 'rosterIds must be a non-empty array');
  }
  if (body.rosterIds.length > 2000) {
    throw new HttpError(400, 'Too many students in one call (max 2000)');
  }

  let subjects = null;
  let combinationCode = null;

  if (Array.isArray(body.subjects) && body.subjects.length > 0) {
    subjects = body.subjects.map((s) => cleanText(s, 60, 'subject'));
  }
  if (body.combinationCode) {
    combinationCode = cleanText(body.combinationCode, 10, 'combinationCode').toUpperCase();
    const combos = await listCombinations(env, schoolId);
    const combo = combos.find((c) => c.code.toUpperCase() === combinationCode);
    if (!combo) throw new HttpError(404, `Combination "${combinationCode}" not found`);
    subjects = combo.subjects;
  }
  if (!subjects) throw new HttpError(400, 'Provide either subjects or combinationCode');

  const now = new Date().toISOString();
  const writes = [];
  for (const rid of body.rosterIds) {
    const data = {
      subjects,
      academicUpdatedAt: now,
      academicUpdatedBy: String(user.sub),
    };
    if (combinationCode) data.combination = combinationCode;
    writes.push({
      update: {
        name: docName(env, ['schools', schoolId, 'roster', rid]),
        fields: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, toFsValue(v)])),
      },
      updateMask: { fieldPaths: Object.keys(data) },
    });
  }
  await commitAll(env, writes);
  await logChange(env, schoolId, {
    action: 'students.bulk.assign',
    by: String(user.sub),
    count: writes.length,
    subjects: combinationCode ? `combo:${combinationCode}` : subjects.join(', '),
  });

  return { status: 'ok', count: writes.length, subjects, combination: combinationCode };
}

// ---------------------------------------------------------------- handlers: template + upload
async function handleDownloadTemplate(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ['schoolAdmin', 'teacher']);
  const className = url.searchParams.get('class')
    ? normalizeClass(url.searchParams.get('class'))
    : '';
  if (!className) throw new HttpError(400, 'class is required');
  const stream = url.searchParams.get('stream') ? normalizeStream(url.searchParams.get('stream')) : '';
  const mode = url.searchParams.get('mode') || 'subjects';

  const [students, subjects] = await Promise.all([
    listStudents(env, schoolId, { className, stream }),
    listSubjects(env, schoolId),
  ]);
  if (!students.length) throw new HttpError(400, 'No students in that class/stream');

  const level = classLevel(className);
  let headers, rows;

  if (mode === 'combinations' && level === 'alevel') {
    headers = ['rosterId', 'First Name', 'Last Name', 'Class', 'Stream', 'Combination'];
    rows = students.map((s) => [
      s.id, s.firstName, s.lastName, s.class, s.stream, s.combination || '',
    ]);
  } else {
    const applicable = level === 'olevel'
      ? subjects.filter((s) => s.compulsory)
      : subjects;
    headers = ['rosterId', 'First Name', 'Last Name', 'Class', 'Stream', ...applicable.map((s) => s.name)];
    rows = students.map((s) => {
      const row = [s.id, s.firstName, s.lastName, s.class, s.stream];
      for (const sub of applicable) {
        row.push(s.subjects.includes(sub.name) ? '✓' : '');
      }
      return row;
    });
  }

  const ws = XLSX.utils.aoa_to_sheet([headers, ...rows]);
  const wb = XLSX.utils.book_new();
  XLSX.utils.book_append_sheet(wb, ws, 'Academic');
  const buf = XLSX.write(wb, { type: 'array', bookType: 'xlsx' });

  const filename = `academic_${className}${stream ? '_' + stream : ''}_${mode}.xlsx`.replace(/[^\w.\-]+/g, '_');
  return binary(buf, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', {
    'Content-Disposition': `attachment; filename="${filename}"`,
  });
}

function cellStr(values, idx) {
  if (idx === undefined || idx === null || idx < 0) return '';
  const raw = values[idx];
  if (raw === undefined || raw === null) return '';
  return String(raw).replace(/\s+/g, ' ').trim();
}

function normalizeHeader(v) {
  return String(v ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

async function handleUpload(request, env, schoolId) {
  await requireUser(request, env, schoolId, ['schoolAdmin']);

  let form;
  try {
    form = await request.formData();
  } catch (err) {
    throw new HttpError(400, `Could not parse multipart body: ${err.message}`);
  }

  const file = form.get('file');
  if (!file || typeof file === 'string' || typeof file.arrayBuffer !== 'function') {
    throw new HttpError(400, '"file" is required');
  }
  const className = normalizeClass(str(form.get('class')));
  if (!className) throw new HttpError(400, 'class is required');
  const stream = form.get('stream') ? normalizeStream(str(form.get('stream'))) : '';
  const mode = str(form.get('mode') || 'subjects');

  const [students, subjects, combinations] = await Promise.all([
    listStudents(env, schoolId, { className, stream }),
    listSubjects(env, schoolId),
    listCombinations(env, schoolId),
  ]);
  const byId = new Map(students.map((s) => [s.id, s]));
  const subjectNames = new Set(subjects.map((s) => s.name));
  const comboByCode = new Map(combinations.map((c) => [c.code.toUpperCase(), c]));

  const bytes = await file.arrayBuffer();
  let wb;
  try {
    wb = XLSX.read(new Uint8Array(bytes), { type: 'array' });
  } catch (err) {
    throw new HttpError(400, `Could not read the spreadsheet: ${err.message}`);
  }
  if (!wb.SheetNames || wb.SheetNames.length === 0) {
    throw new HttpError(400, 'Workbook has no sheets');
  }
  const sheet = wb.Sheets[wb.SheetNames[0]];
  const matrix = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: '', blankrows: false, raw: false });
  if (matrix.length < 2) throw new HttpError(400, 'Sheet has no data rows');

  const headerRow = matrix[0].map((h) => String(h ?? '').trim());
  const headerMap = {};
  headerRow.forEach((h, i) => {
    const k = normalizeHeader(h);
    if (k) headerMap[k] = i;
  });

  const rosterIdCol = headerMap['rosterid'];
  if (rosterIdCol === undefined) throw new HttpError(400, 'Missing rosterId column');

  const rows = [];
  const errors = [];
  const duplicates = new Set();

  for (let i = 1; i < matrix.length; i += 1) {
    const raw = matrix[i] || [];
    if (!raw.some((v) => String(v ?? '').trim() !== '')) continue;
    const rid = cellStr(raw, rosterIdCol);
    if (!rid) {
      errors.push({ excelRow: i + 1, error: 'Missing rosterId' });
      continue;
    }
    if (!byId.has(rid)) {
      errors.push({ excelRow: i + 1, rosterId: rid, error: 'Student not in class' });
      continue;
    }
    if (duplicates.has(rid)) {
      errors.push({ excelRow: i + 1, rosterId: rid, error: 'Duplicate row' });
      continue;
    }
    duplicates.add(rid);

    if (mode === 'combinations') {
      const codeCol = headerMap['combination'];
      if (codeCol === undefined) {
        errors.push({ excelRow: i + 1, error: 'Missing Combination column' });
        continue;
      }
      const code = cellStr(raw, codeCol).toUpperCase();
      if (!code) continue;
      const combo = comboByCode.get(code);
      if (!combo) {
        errors.push({ excelRow: i + 1, rosterId: rid, error: `Unknown combination "${code}"` });
        continue;
      }
      rows.push({ rosterId: rid, subjects: combo.subjects, combination: combo.code });
    } else {
      const picked = [];
      for (const [k, idx] of Object.entries(headerMap)) {
        if (['rosterid', 'firstname', 'lastname', 'class', 'stream'].includes(k)) continue;
        const originalHeader = headerRow[idx];
        if (!subjectNames.has(originalHeader)) continue;
        const v = cellStr(raw, idx).toLowerCase();
        if (v === '' || v === '0' || v === 'no' || v === 'n' || v === 'false') continue;
        picked.push(originalHeader);
      }
      if (!picked.length) continue;
      rows.push({ rosterId: rid, subjects: picked });
    }
  }

  return {
    status: 'validated',
    mode,
    class: className,
    stream,
    totalRows: rows.length,
    errors,
    preview: rows.slice(0, 50),
    _full: rows,
  };
}

async function handleUploadConfirm(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const body = await safeJson(request);

  if (!Array.isArray(body.rows) || body.rows.length === 0) {
    throw new HttpError(400, 'rows is required');
  }
  if (body.rows.length > 2000) throw new HttpError(400, 'Too many rows (max 2000)');

  const now = new Date().toISOString();
  const writes = [];

  for (const row of body.rows) {
    const rid = cleanText(row.rosterId, 40, 'rosterId');
    if (!Array.isArray(row.subjects) || row.subjects.length === 0) continue;
    const subjects = row.subjects.map((s) => cleanText(s, 60, 'subject'));
    const data = {
      subjects,
      academicUpdatedAt: now,
      academicUpdatedBy: String(user.sub),
    };
    if (row.combination) data.combination = cleanText(row.combination, 10, 'combination');

    writes.push({
      update: {
        name: docName(env, ['schools', schoolId, 'roster', rid]),
        fields: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, toFsValue(v)])),
      },
      updateMask: { fieldPaths: Object.keys(data) },
    });
  }

  await commitAll(env, writes);
  await logChange(env, schoolId, {
    action: 'academic.upload.confirm',
    by: String(user.sub),
    count: writes.length,
  });

  return { status: 'ok', written: writes.length };
}

// ---------------------------------------------------------------- handlers: O-Level bulk & coverage
async function handleApplyOLevel(request, env, schoolId) {
  const user = await requireUser(request, env, schoolId, ['schoolAdmin']);
  const body = await safeJson(request);
  const className = normalizeClass(body.class);
  if (!className) throw new HttpError(400, 'class is required');
  if (classLevel(className) !== 'olevel') {
    throw new HttpError(400, 'This class is not O-Level');
  }

  const subjects = await listSubjects(env, schoolId);
  const compulsory = subjects.filter((s) => s.compulsory).map((s) => s.name);
  if (!compulsory.length) throw new HttpError(400, 'No compulsory subjects configured');

  const students = await listStudents(env, schoolId, { className });
  if (!students.length) throw new HttpError(400, 'No students in that class');

  const now = new Date().toISOString();
  const writes = students.map((s) => {
    const merged = Array.from(new Set([...(s.subjects || []), ...compulsory]));
    const data = {
      subjects: merged,
      academicUpdatedAt: now,
      academicUpdatedBy: String(user.sub),
    };
    return {
      update: {
        name: docName(env, ['schools', schoolId, 'roster', s.id]),
        fields: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, toFsValue(v)])),
      },
      updateMask: { fieldPaths: Object.keys(data) },
    };
  });

  await commitAll(env, writes);
  await logChange(env, schoolId, {
    action: 'olevel.compulsory.apply',
    by: String(user.sub),
    class: className,
    count: writes.length,
  });

  return { status: 'ok', class: className, updatedStudents: writes.length, compulsorySubjects: compulsory };
}

async function handleOLevelCoverage(request, env, schoolId, url) {
  await requireUser(request, env, schoolId, ['schoolAdmin', 'teacher']);
  const className = url.searchParams.get('class') ? normalizeClass(url.searchParams.get('class')) : '';
  if (!className) throw new HttpError(400, 'class is required');

  const [subjects, students] = await Promise.all([
    listSubjects(env, schoolId),
    listStudents(env, schoolId, { className }),
  ]);

  const compulsory = subjects.filter((s) => s.compulsory).map((s) => s.name);
  let completeCount = 0;
  const missingCoverage = [];

  for (const s of students) {
    const assigned = new Set(s.subjects || []);
    const missing = compulsory.filter((c) => !assigned.has(c));
    if (missing.length === 0) {
      completeCount += 1;
    } else {
      missingCoverage.push({
        rosterId: s.id,
        firstName: s.firstName,
        lastName: s.lastName,
        missing,
      });
    }
  }

  return {
    class: className,
    totalStudents: students.length,
    completeCount,
    incompleteCount: missingCoverage.length,
    compulsorySubjects: compulsory,
    missingCoverage,
  };
}

// ---------------------------------------------------------------- WORKER ENTRY POINT & ROUTER
export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === 'GET' && path === '/health') {
        return json({ status: 'ok', worker: 'edutraceug-academic-worker' });
      }

      const match = path.match(/^\/schools\/([^\/]+)\/(.+)$/);
      if (!match) throw new HttpError(404, 'Route not found');

      const schoolId = decodeURIComponent(match[1]);
      const subPath = match[2];
      const method = request.method;

      // Routes: Subjects
      if (method === 'GET' && subPath === 'subjects') return json(await handleListSubjects(request, env, schoolId, url));
      if (method === 'POST' && subPath === 'subjects') return json(await handleCreateSubject(request, env, schoolId));
      if (method === 'POST' && subPath === 'subjects/seed-defaults') return json(await handleSeedSubjects(request, env, schoolId));
      if (method === 'GET' && subPath === 'subjects/template') return await handleDownloadTemplate(request, env, schoolId, url);
      if (method === 'POST' && subPath === 'subjects/upload') return json(await handleUpload(request, env, schoolId));
      if (method === 'POST' && subPath === 'subjects/upload/confirm') return json(await handleUploadConfirm(request, env, schoolId));

      let m = subPath.match(/^subjects\/([^\/]+)$/);
      if (m) {
        const subjectId = decodeURIComponent(m[1]);
        if (method === 'PATCH') return json(await handleUpdateSubject(request, env, schoolId, subjectId));
        if (method === 'DELETE') return json(await handleDeleteSubject(request, env, schoolId, subjectId));
      }

      // Routes: Combinations
      if (method === 'GET' && subPath === 'combinations') return json(await handleListCombinations(request, env, schoolId, url));
      if (method === 'POST' && subPath === 'combinations') return json(await handleCreateCombination(request, env, schoolId));
      if (method === 'POST' && subPath === 'combinations/seed-defaults') return json(await handleSeedCombinations(request, env, schoolId));

      m = subPath.match(/^combinations\/([^\/]+)$/);
      if (m) {
        const comboId = decodeURIComponent(m[1]);
        if (method === 'PATCH') return json(await handleUpdateCombination(request, env, schoolId, comboId));
        if (method === 'DELETE') return json(await handleDeleteCombination(request, env, schoolId, comboId));
      }

      // Routes: Students
      if (method === 'GET' && subPath === 'students') return json(await handleListStudents(request, env, schoolId, url));
      if (method === 'POST' && subPath === 'students/bulk') return json(await handleBulkStudents(request, env, schoolId));

      m = subPath.match(/^students\/([^\/]+)$/);
      if (m && method === 'GET') return json(await handleGetStudent(request, env, schoolId, decodeURIComponent(m[1])));

      m = subPath.match(/^students\/([^\/]+)\/subjects$/);
      if (m && method === 'PUT') return json(await handleSetStudentSubjects(request, env, schoolId, decodeURIComponent(m[1])));

      m = subPath.match(/^students\/([^\/]+)\/combination$/);
      if (m) {
        const rosterId = decodeURIComponent(m[1]);
        if (method === 'PUT') return json(await handleSetStudentCombination(request, env, schoolId, rosterId));
        if (method === 'DELETE') return json(await handleDeleteStudentCombination(request, env, schoolId, rosterId));
      }

      // Routes: O-Level
      if (method === 'POST' && subPath === 'olevel/apply') return json(await handleApplyOLevel(request, env, schoolId));
      if (method === 'GET' && subPath === 'olevel/coverage') return json(await handleOLevelCoverage(request, env, schoolId, url));

      throw new HttpError(404, 'Endpoint not found');
    } catch (err) {
      if (err instanceof HttpError) {
        return json({ error: err.message, ...err.extra }, err.status);
      }
      console.error('Unhandled Server Error:', err);
      return json({ error: 'Internal server error', message: err.message }, 500);
    }
  },
};
