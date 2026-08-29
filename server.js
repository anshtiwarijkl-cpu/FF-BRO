import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import { MongoClient } from 'mongodb';
import mysql from 'mysql2/promise';
import { createClient } from 'redis';
import admin from 'firebase-admin';
import QRCode from 'qrcode';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', Number(process.env.TRUST_PROXY || 1));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

const PORT = Number(process.env.PORT || 3000);
const SESSION_TTL_MS = Number(process.env.SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const LOGIN_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const HEALTH_TIMEOUT_MS = Number(process.env.HEALTH_TIMEOUT_MS || 5000);
const COOKIE_NAME = 'scannerapi_sid';
const PROD = process.env.NODE_ENV === 'production';

function required(name) {
  const value = process.env[name];
  return value && value.trim() ? value.trim() : null;
}

function safeError(error) {
  return {
    name: error?.name || 'Error',
    code: error?.code ?? null,
    message: error?.message || String(error)
  };
}

async function withTimeout(promise, ms = HEALTH_TIMEOUT_MS) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Operation timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function safeEqualString(a, b) {
  const ab = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

function now() {
  return Date.now();
}

function setSessionCookie(res, token) {
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    'HttpOnly',
    'Path=/',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    'SameSite=Lax'
  ];
  if (PROD) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res) {
  const parts = [
    `${COOKIE_NAME}=`,
    'HttpOnly',
    'Path=/',
    'Max-Age=0',
    'SameSite=Lax'
  ];
  if (PROD) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  for (const piece of header.split(';')) {
    const [k, ...rest] = piece.trim().split('=');
    if (k) cookies[k] = decodeURIComponent(rest.join('='));
  }
  return cookies;
}

function clientIp(req) {
  return req.ip || req.socket?.remoteAddress || '';
}

function normalizeIp(ip) {
  if (!ip) return '';
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}

function ipv4ToInt(ip) {
  const parts = normalizeIp(ip).split('.');
  if (parts.length !== 4) return null;
  const nums = parts.map(Number);
  if (nums.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((nums[0] << 24) >>> 0) + ((nums[1] << 16) >>> 0) + ((nums[2] << 8) >>> 0) + nums[3]) >>> 0;
}

function ipMatchesRule(ip, rule) {
  ip = normalizeIp(ip.trim());
  rule = normalizeIp(rule.trim());
  if (!ip || !rule) return false;
  if (rule === '*') return true;
  if (ip === rule) return true;

  const [network, bitsText] = rule.split('/');
  if (!bitsText || !network || ipv4ToInt(ip) === null || ipv4ToInt(network) === null) return false;
  const bits = Number(bitsText);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(network) & mask);
}

function allowedIpList(settings) {
  return String(settings?.allowed_ips || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
}

let firebaseDb = null;
function initFirebase() {
  const projectId = required('FIREBASE_PROJECT_ID');
  const clientEmail = required('FIREBASE_CLIENT_EMAIL');
  const privateKey = process.env.FIREBASE_PRIVATE_KEY;
  const databaseURL = required('FIREBASE_DATABASE_URL');

  if (!projectId || !clientEmail || !privateKey || !databaseURL) {
    return { configured: false, reason: 'Firebase Admin credentials are not fully configured' };
  }

  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId,
        clientEmail,
        privateKey: privateKey.replace(/\\n/g, '\n')
      }),
      databaseURL
    });
  }
  firebaseDb = admin.database();
  return { configured: true };
}

function fb(pathName = '') {
  const init = initFirebase();
  if (!init.configured) throw new Error(init.reason);
  return firebaseDb.ref(pathName);
}

async function getSettings() {
  const snap = await withTimeout(fb('settings').once('value'));
  return snap.val() || {};
}

async function addActivity(message, meta = {}) {
  try {
    const id = randomToken(12);
    await fb(`activity/${id}`).set({
      id,
      message,
      meta,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Activity log failed:', safeError(error));
  }
}

async function ensureSecuritySettings() {
  const settings = await getSettings();
  return {
    two_fa_enabled: Boolean(settings.two_fa_enabled),
    ip_verification_enabled: Boolean(settings.ip_verification_enabled),
    allowed_ips: String(settings.allowed_ips || '')
  };
}

async function isIpAllowed(req) {
  const settings = await getSettings();
  if (!settings.ip_verification_enabled) return { allowed: true, enabled: false };
  const rules = allowedIpList(settings);
  if (rules.length === 0) return { allowed: false, enabled: true, reason: 'IP verification is enabled but no allowed IPs are configured' };
  const ip = clientIp(req);
  return {
    allowed: rules.some(rule => ipMatchesRule(ip, rule)),
    enabled: true,
    ip,
    rules
  };
}

async function getSessionByRequest(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  const tokenHash = sha256(token);
  const snap = await fb(`admin_auth/sessions/${tokenHash}`).once('value');
  const session = snap.val();
  if (!session) return null;

  const currentVersionSnap = await fb('admin_auth/session_version').once('value');
  const currentVersion = Number(currentVersionSnap.val() || 0);
  if (Number(session.version || 0) !== currentVersion) return null;
  if (Number(session.expiresAt || 0) <= now()) return null;
  if (session.revokedAt) return null;

  return { token, tokenHash, ...session };
}

async function requireAdmin(req, res, next) {
  try {
    const session = await getSessionByRequest(req);
    if (!session) return res.status(401).json({ ok: false, error: 'AUTH_REQUIRED' });
    const ip = await isIpAllowed(req);
    if (!ip.allowed) return res.status(403).json({ ok: false, error: 'IP_NOT_ALLOWED', ip: ip.ip });
    req.adminSession = session;
    next();
  } catch (error) {
    console.error(error);
    res.status(503).json({ ok: false, error: 'AUTH_CHECK_UNAVAILABLE', details: safeError(error) });
  }
}

async function requireAdminIp(req, res, next) {
  try {
    const result = await isIpAllowed(req);
    if (!result.allowed) {
      return res.status(403).json({ ok: false, error: 'IP_NOT_ALLOWED', ip: result.ip });
    }
    next();
  } catch {
    res.status(503).json({ ok: false, error: 'IP_CHECK_UNAVAILABLE' });
  }
}

async function readAdminCredential(username) {
  const expectedUsername = required('ADMIN_USERNAME');
  const plainPassword = process.env.ADMIN_PASSWORD ?? '';
  const hash = required('ADMIN_PASSWORD_HASH');

  if (!expectedUsername || !safeEqualString(username, expectedUsername)) return { ok: false };
  return { ok: true, plainPassword, hash };
}

async function verifyPassword(password, credential) {
  if (credential.hash) {
    // Supported format: scrypt$N$r$p$salt$derivedHex
    const parts = credential.hash.split('$');
    if (parts.length === 6 && parts[0] === 'scrypt') {
      const [, nRaw, rRaw, pRaw, saltB64, derivedHex] = parts;
      try {
        const n = Number(nRaw);
        const r = Number(rRaw);
        const p = Number(pRaw);
        const derived = await new Promise((resolve, reject) => {
          crypto.scrypt(password, Buffer.from(saltB64, 'base64'), 32, { N: n, r, p, maxmem: 128 * 1024 * 1024 }, (err, key) => {
            if (err) reject(err); else resolve(key.toString('hex'));
          });
        });
        return safeEqualString(derived, derivedHex);
      } catch {
        return false;
      }
    }
    return false;
  }
  return safeEqualString(password, credential.plainPassword);
}

function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(input).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function totpCode(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 1000 / 30);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', base32Decode(secret)).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(binary % 1_000_000).padStart(6, '0');
}

function verifyTotp(secret, code, window = 1) {
  const normalized = String(code || '').replace(/\D/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const t = Date.now();
  for (let delta = -window; delta <= window; delta += 1) {
    if (safeEqualString(totpCode(secret, t + delta * 30_000), normalized)) return true;
  }
  return false;
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function makeOtpauth(secret, username) {
  const issuer = encodeURIComponent(process.env.TOTP_ISSUER || 'ScannerAPI');
  const label = encodeURIComponent(`${process.env.TOTP_ISSUER || 'ScannerAPI'}:${username}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
}

async function hashBackupCode(code) {
  const salt = crypto.randomBytes(16);
  const derived = await new Promise((resolve, reject) => {
    crypto.scrypt(String(code), salt, 32, (err, key) => err ? reject(err) : resolve(key));
  });
  return { salt: salt.toString('base64'), hash: derived.toString('base64') };
}

async function verifyBackupCode(code, records) {
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    try {
      const derived = await new Promise((resolve, reject) => {
        crypto.scrypt(String(code), Buffer.from(rec.salt, 'base64'), 32, (err, key) => err ? reject(err) : resolve(key));
      });
      if (safeEqualString(derived.toString('base64'), rec.hash)) return i;
    } catch {}
  }
  return -1;
}

async function createSession(username, req) {
  const token = randomToken(32);
  const tokenHash = sha256(token);
  const versionSnap = await fb('admin_auth/session_version').once('value');
  const version = Number(versionSnap.val() || 0);
  const session = {
    username,
    createdAt: now(),
    expiresAt: now() + SESSION_TTL_MS,
    version,
    ip: clientIp(req),
    userAgent: req.get('user-agent') || ''
  };
  await fb(`admin_auth/sessions/${tokenHash}`).set(session);
  setSessionCookie(req.res, token);
  return session;
}

async function revokeCurrentSession(req) {
  const session = req.adminSession;
  if (!session) return;
  await fb(`admin_auth/sessions/${session.tokenHash}/revokedAt`).set(now());
}

async function incrementSessionVersion() {
  const ref = fb('admin_auth/session_version');
  const snap = await ref.once('value');
  const next = Number(snap.val() || 0) + 1;
  await ref.set(next);
  return next;
}

async function createLoginChallenge(username, req) {
  const token = randomToken(32);
  const hash = sha256(token);
  await fb(`admin_auth/login_challenges/${hash}`).set({
    username,
    ip: clientIp(req),
    createdAt: now(),
    expiresAt: now() + LOGIN_CHALLENGE_TTL_MS
  });
  return token;
}

async function consumeLoginChallenge(token) {
  const hash = sha256(token);
  const ref = fb(`admin_auth/login_challenges/${hash}`);
  const snap = await ref.once('value');
  const data = snap.val();
  if (!data || Number(data.expiresAt) <= now()) {
    try { await ref.remove(); } catch {}
    return null;
  }
  await ref.remove();
  return data;
}

const loginBuckets = new Map();
function loginRateLimited(ip) {
  const key = normalizeIp(ip);
  const windowMs = 15 * 60 * 1000;
  const max = 10;
  const item = loginBuckets.get(key) || { count: 0, resetAt: now() + windowMs };
  if (item.resetAt <= now()) {
    item.count = 0;
    item.resetAt = now() + windowMs;
  }
  item.count += 1;
  loginBuckets.set(key, item);
  return item.count > max;
}

let mongoClient = null;
let mysqlPool = null;
let redisClient = null;

async function ensureMongo() {
  const uri = required('MONGODB_URI');
  if (!uri) throw new Error('MONGODB_URI missing');
  if (!mongoClient) mongoClient = new MongoClient(uri, { serverSelectionTimeoutMS: HEALTH_TIMEOUT_MS, connectTimeoutMS: HEALTH_TIMEOUT_MS, maxPoolSize: 10 });
  await withTimeout(mongoClient.connect());
  return mongoClient;
}

async function ensureMysql() {
  const host = required('MYSQL_HOST');
  const user = required('MYSQL_USER');
  const db = required('MYSQL_DATABASE');
  if (!host || !user || !db) throw new Error('MySQL configuration incomplete');
  if (!mysqlPool) {
    mysqlPool = mysql.createPool({
      host,
      port: Number(process.env.MYSQL_PORT || 3306),
      user,
      password: process.env.MYSQL_PASSWORD || '',
      database: db,
      connectionLimit: 10,
      waitForConnections: true,
      connectTimeout: HEALTH_TIMEOUT_MS,
      ssl: process.env.MYSQL_SSL === 'true' ? {} : undefined
    });
  }
  return mysqlPool;
}

async function ensureRedis() {
  const url = required('REDIS_URL');
  if (!url) throw new Error('REDIS_URL missing');
  if (!redisClient) {
    redisClient = createClient({ url, socket: { connectTimeout: HEALTH_TIMEOUT_MS } });
    redisClient.on('error', () => {});
    await withTimeout(redisClient.connect());
  }
  return redisClient;
}

async function checkMongo() {
  const start = performance.now();
  try {
    const client = await ensureMongo();
    const dbName = required('MONGODB_DB');
    await withTimeout(client.db(dbName).command({ ping: 1 }));
    return { status: 'CONNECTED', latency_ms: Math.round(performance.now() - start), error: null };
  } catch (error) {
    try { await mongoClient?.close(); } catch {}
    mongoClient = null;
    return { status: 'DISCONNECTED', latency_ms: Math.round(performance.now() - start), error: safeError(error) };
  }
}

async function checkMysql() {
  const start = performance.now();
  try {
    const pool = await ensureMysql();
    const [rows] = await withTimeout(pool.query('SELECT VERSION() AS version, NOW() AS server_time'));
    return { status: 'CONNECTED', latency_ms: Math.round(performance.now() - start), version: rows?.[0]?.version || null, error: null };
  } catch (error) {
    try { await mysqlPool?.end(); } catch {}
    mysqlPool = null;
    return { status: 'DISCONNECTED', latency_ms: Math.round(performance.now() - start), error: safeError(error) };
  }
}

async function checkRedis() {
  const start = performance.now();
  try {
    const client = await ensureRedis();
    const pong = await withTimeout(client.ping());
    return { status: 'CONNECTED', latency_ms: Math.round(performance.now() - start), response: pong, error: null };
  } catch (error) {
    try { await redisClient?.quit(); } catch { try { redisClient?.disconnect(); } catch {} }
    redisClient = null;
    return { status: 'DISCONNECTED', latency_ms: Math.round(performance.now() - start), error: safeError(error) };
  }
}

async function checkFirebase() {
  const start = performance.now();
  try {
    await withTimeout(fb('__scannerapi_healthcheck').once('value'));
    return { status: 'CONNECTED', latency_ms: Math.round(performance.now() - start), error: null };
  } catch (error) {
    return { status: 'DISCONNECTED', latency_ms: Math.round(performance.now() - start), error: safeError(error) };
  }
}

async function healthSnapshot() {
  const [firebase, mongodb, mysqlDb, redis] = await Promise.all([
    checkFirebase(), checkMongo(), checkMysql(), checkRedis()
  ]);
  const services = { firebase, mongodb, mysql: mysqlDb, redis };
  const connected = Object.values(services).filter(v => v.status === 'CONNECTED').length;
  return { ok: connected === 4, checked_at: new Date().toISOString(), summary: `${connected}/4 connected`, services };
}

function requireDeleteConfirmation(body, expected) {
  return body?.confirm === expected;
}

async function deleteAllDatabases() {
  const result = { firebase: null, mongodb: null, mysql: null, redis: null, ok: true };
  try { await fb('/').set({}); result.firebase = { status: 'DELETED' }; }
  catch (e) { result.firebase = { status: 'ERROR', error: safeError(e) }; result.ok = false; }

  try { const c = await ensureMongo(); const db = c.db(required('MONGODB_DB')); await db.dropDatabase(); result.mongodb = { status: 'DELETED' }; }
  catch (e) { result.mongodb = { status: 'ERROR', error: safeError(e) }; result.ok = false; }

  try {
    const host = required('MYSQL_HOST'); const user = required('MYSQL_USER'); const database = required('MYSQL_DATABASE');
    const conn = await mysql.createConnection({ host, port: Number(process.env.MYSQL_PORT || 3306), user, password: process.env.MYSQL_PASSWORD || '', connectTimeout: HEALTH_TIMEOUT_MS, ssl: process.env.MYSQL_SSL === 'true' ? {} : undefined });
    const safeDb = database.replaceAll('`', '``');
    await conn.query(`DROP DATABASE IF EXISTS \`${safeDb}\``);
    await conn.query(`CREATE DATABASE \`${safeDb}\``);
    await conn.end();
    result.mysql = { status: 'DELETED_AND_RECREATED' };
  } catch (e) { result.mysql = { status: 'ERROR', error: safeError(e) }; result.ok = false; }

  try { const r = await ensureRedis(); await r.flushDb(); result.redis = { status: 'FLUSHED' }; }
  catch (e) { result.redis = { status: 'ERROR', error: safeError(e) }; result.ok = false; }
  return result;
}

async function clearTarget(target) {
  if (target === 'activity') {
    await fb('activity').set({});
    return { firebase: 'activity cleared' };
  }
  if (target === 'logs') {
    await fb('logs').set({});
    return { firebase: 'logs cleared' };
  }
  if (target === 'failed_logins') {
    await fb('failed_logins').set({});
    return { firebase: 'failed_logins cleared' };
  }
  if (target === 'activity-all') {
    const out = {};
    try { await fb('activity').set({}); out.firebase = 'activity cleared'; } catch (e) { out.firebase = safeError(e); }
    try { await fb('logs').set({}); out.firebase_logs = 'logs cleared'; } catch (e) { out.firebase_logs = safeError(e); }
    try { const c = await ensureMongo(); const db = c.db(required('MONGODB_DB')); const names = ['activity_logs','logs']; for (const n of names) { try { await db.collection(n).deleteMany({}); } catch {} } out.mongodb = 'known activity/log collections cleared'; } catch (e) { out.mongodb = safeError(e); }
    try { const pool = await ensureMysql(); for (const table of ['activity_logs','logs']) { try { await pool.query(`DELETE FROM \`${table}\``); } catch {} } out.mysql = 'known activity/log tables cleared'; } catch (e) { out.mysql = safeError(e); }
    try { const r = await ensureRedis(); const prefix = process.env.REDIS_ACTIVITY_PREFIX || 'scannerapi:activity:'; let cursor = 0; let deleted = 0; do { const scan = await r.scan(cursor, { MATCH: `${prefix}*`, COUNT: 200 }); cursor = Number(scan.cursor); if (scan.keys.length) deleted += await r.del(scan.keys); } while (cursor !== 0); out.redis = `deleted ${deleted} activity keys`; } catch (e) { out.redis = safeError(e); }
    return out;
  }
  throw new Error('Unknown clear target');
}

// ---------------------------------------------------------------------------
// AUTH
// ---------------------------------------------------------------------------
app.post('/api/admin/login', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const password = String(req.body?.password || '');
  if (!username || !password) return res.status(400).json({ ok: false, error: 'USERNAME_PASSWORD_REQUIRED' });
  if (loginRateLimited(clientIp(req))) return res.status(429).json({ ok: false, error: 'TOO_MANY_LOGIN_ATTEMPTS' });

  try {
    const credential = await readAdminCredential(username);
    if (!credential.ok || !(await verifyPassword(password, credential))) {
      await addActivity('Admin login failed', { ip: clientIp(req), username });
      try { await fb(`failed_logins/${randomToken(10)}`).set({ username, ip: clientIp(req), timestamp: new Date().toISOString(), action: 'login_failed' }); } catch {}
      return res.status(401).json({ ok: false, error: 'INVALID_CREDENTIALS' });
    }

    const security = await ensureSecuritySettings();
    if (security.two_fa_enabled) {
      const challengeToken = await createLoginChallenge(username, req);
      return res.json({ ok: true, requires_2fa: true, challenge_token: challengeToken });
    }

    const ip = await isIpAllowed(req);
    if (!ip.allowed) return res.status(403).json({ ok: false, error: 'IP_NOT_ALLOWED' });

    await createSession(username, req);
    await addActivity('Admin logged in', { ip: clientIp(req), username });
    return res.json({ ok: true, requires_2fa: false, username, redirect: '/dashboard.html' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ ok: false, error: 'LOGIN_SERVER_ERROR', details: safeError(error) });
  }
});

app.post('/api/admin/login/2fa', async (req, res) => {
  const challenge = String(req.body?.challenge_token || '');
  const code = String(req.body?.code || '').trim();
  const backupCode = String(req.body?.backup_code || '').trim();
  if (!challenge || (!code && !backupCode)) return res.status(400).json({ ok: false, error: 'OTP_REQUIRED' });

  try {
    const challengeData = await consumeLoginChallenge(challenge);
    if (!challengeData) return res.status(401).json({ ok: false, error: 'CHALLENGE_EXPIRED' });

    const settings = await getSettings();
    let verified = false;
    if (code && settings.two_fa_secret) verified = verifyTotp(settings.two_fa_secret, code);

    if (!verified && backupCode && Array.isArray(settings.backup_codes)) {
      const idx = await verifyBackupCode(backupCode, settings.backup_codes);
      if (idx >= 0) {
        const remaining = settings.backup_codes.slice();
        remaining.splice(idx, 1);
        await fb('settings/backup_codes').set(remaining);
        verified = true;
      }
    }

    if (!verified) {
      await addActivity('2FA verification failed', { username: challengeData.username, ip: clientIp(req) });
      return res.status(401).json({ ok: false, error: 'INVALID_2FA' });
    }

    const ip = await isIpAllowed(req);
    if (!ip.allowed) return res.status(403).json({ ok: false, error: 'IP_NOT_ALLOWED' });

    await createSession(challengeData.username, req);
    await addActivity('Admin completed 2FA login', { username: challengeData.username, ip: clientIp(req) });
    return res.json({ ok: true, username: challengeData.username, redirect: '/dashboard.html' });
  } catch (error) {
    res.status(500).json({ ok: false, error: '2FA_SERVER_ERROR', details: safeError(error) });
  }
});

app.get('/api/admin/me', requireAdmin, async (req, res) => {
  const security = await ensureSecuritySettings();
  res.json({ ok: true, username: req.adminSession.username, ip: clientIp(req), security });
});

app.post('/api/admin/logout', requireAdmin, async (req, res) => {
  try {
    await revokeCurrentSession(req);
    clearSessionCookie(res);
    await addActivity('Admin logged out', { username: req.adminSession.username });
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'LOGOUT_FAILED' });
  }
});

app.post('/api/admin/sessions/terminate-all', requireAdmin, async (req, res) => {
  await incrementSessionVersion();
  await addActivity('All admin sessions terminated', { by: req.adminSession.username });
  clearSessionCookie(res);
  res.json({ ok: true });
});

app.get('/api/admin/security/status', requireAdmin, async (req, res) => {
  const settings = await getSettings();
  res.json({
    ok: true,
    two_fa_enabled: Boolean(settings.two_fa_enabled),
    ip_verification_enabled: Boolean(settings.ip_verification_enabled),
    allowed_ips: String(settings.allowed_ips || ''),
    backup_codes_remaining: Array.isArray(settings.backup_codes) ? settings.backup_codes.length : 0
  });
});

app.post('/api/admin/ip-settings', requireAdmin, async (req, res) => {
  const enabled = Boolean(req.body?.enabled);
  const allowedIPs = String(req.body?.allowed_ips || '').trim();
  await fb('settings').update({ ip_verification_enabled: enabled, allowed_ips: allowedIPs, last_updated: new Date().toISOString() });
  await addActivity('IP verification settings changed', { enabled, allowed_ips: allowedIPs });
  res.json({ ok: true });
});

app.post('/api/admin/2fa/setup', requireAdmin, async (req, res) => {
  const security = await getSettings();
  if (security.two_fa_enabled) return res.status(400).json({ ok: false, error: '2FA_ALREADY_ENABLED' });
  const secret = generateTotpSecret();
  const uri = makeOtpauth(secret, req.adminSession.username);
  const qrDataUrl = await QRCode.toDataURL(uri, { width: 220, margin: 1 });
  const setupToken = randomToken(24);
  await fb(`admin_auth/2fa_setup/${sha256(setupToken)}`).set({ username: req.adminSession.username, secret, expiresAt: now() + 10 * 60 * 1000 });
  res.json({ ok: true, setup_token: setupToken, secret, otpauth_uri: uri, qr_data_url: qrDataUrl });
});

app.post('/api/admin/2fa/enable', requireAdmin, async (req, res) => {
  const setupToken = String(req.body?.setup_token || '');
  const code = String(req.body?.code || '');
  if (!setupToken || !code) return res.status(400).json({ ok: false, error: 'SETUP_TOKEN_AND_CODE_REQUIRED' });
  const ref = fb(`admin_auth/2fa_setup/${sha256(setupToken)}`);
  const snap = await ref.once('value');
  const data = snap.val();
  if (!data || Number(data.expiresAt) <= now()) return res.status(400).json({ ok: false, error: 'SETUP_EXPIRED' });
  if (!verifyTotp(data.secret, code)) return res.status(400).json({ ok: false, error: 'INVALID_TOTP' });

  const codes = [];
  const plainCodes = [];
  for (let i = 0; i < 10; i++) {
    const codeValue = crypto.randomBytes(6).toString('hex');
    plainCodes.push(codeValue);
    codes.push(await hashBackupCode(codeValue));
  }
  await fb('settings').update({ two_fa_enabled: true, two_fa_secret: data.secret, backup_codes: codes, last_updated: new Date().toISOString() });
  await ref.remove();
  await addActivity('2FA enabled', { username: req.adminSession.username });
  res.json({ ok: true, backup_codes: plainCodes });
});

app.post('/api/admin/2fa/disable', requireAdmin, async (req, res) => {
  const code = String(req.body?.code || '');
  const settings = await getSettings();
  if (!settings.two_fa_secret || !verifyTotp(settings.two_fa_secret, code)) return res.status(401).json({ ok: false, error: 'INVALID_TOTP' });
  await fb('settings').update({ two_fa_enabled: false, two_fa_secret: null, backup_codes: [], last_updated: new Date().toISOString() });
  await addActivity('2FA disabled', { username: req.adminSession.username });
  res.json({ ok: true });
});

app.post('/api/admin/2fa/regenerate-backup', requireAdmin, async (req, res) => {
  const code = String(req.body?.code || '');
  const settings = await getSettings();
  if (!settings.two_fa_secret || !verifyTotp(settings.two_fa_secret, code)) return res.status(401).json({ ok: false, error: 'INVALID_TOTP' });
  const plainCodes = [];
  const records = [];
  for (let i = 0; i < 10; i++) {
    const value = crypto.randomBytes(6).toString('hex');
    plainCodes.push(value);
    records.push(await hashBackupCode(value));
  }
  await fb('settings/backup_codes').set(records);
  await addActivity('Backup codes regenerated', { username: req.adminSession.username });
  res.json({ ok: true, backup_codes: plainCodes });
});

// ---------------------------------------------------------------------------
// API KEY SECURITY / RATE LIMITING
// ---------------------------------------------------------------------------
async function getUserById(userId) {
  const snap = await fb(`users/${userId}`).once('value');
  return snap.val();
}

async function verifyApiKey(apiKey) {
  if (!apiKey) return null;
  const snap = await fb('users').once('value');
  const users = snap.val() || {};
  for (const [id, user] of Object.entries(users)) {
    if (user?.api_key && safeEqualString(user.api_key, apiKey) && user.active !== false) return { id, ...user };
  }
  return null;
}

const memRate = new Map();
async function rateLimitByApiKey(apiKey, plan) {
  const settings = await getSettings();
  const max = plan === 'premium' ? Number(settings.premium_per_min || 50) : plan === 'owner' ? Number(settings.owner_per_min || 1000) : Number(settings.free_per_min || 10);
  const windowSec = 60;

  try {
    const redis = await ensureRedis();
    const key = `scannerapi:rate:${sha256(apiKey)}:${Math.floor(now() / 1000 / windowSec)}`;
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, windowSec + 2);
    return { allowed: count <= max, count, limit: max, source: 'redis' };
  } catch (error) {
    if (PROD) return { allowed: false, count: 0, limit: max, source: 'unavailable', error: safeError(error) };
    const key = sha256(apiKey);
    const item = memRate.get(key) || { count: 0, resetAt: now() + windowSec * 1000 };
    if (item.resetAt <= now()) { item.count = 0; item.resetAt = now() + windowSec * 1000; }
    item.count += 1;
    memRate.set(key, item);
    return { allowed: item.count <= max, count: item.count, limit: max, source: 'memory-fallback-dev' };
  }
}

app.post('/api/admin/api-key/rotate', requireAdmin, async (req, res) => {
  const userId = String(req.body?.user_id || '');
  const currentKey = String(req.body?.current_key || '');
  const requested = String(req.body?.new_key || '').trim();
  if (!userId || !currentKey) return res.status(400).json({ ok: false, error: 'USER_AND_CURRENT_KEY_REQUIRED' });
  const user = await getUserById(userId);
  if (!user) return res.status(404).json({ ok: false, error: 'USER_NOT_FOUND' });
  if (!safeEqualString(currentKey, user.api_key || '')) return res.status(401).json({ ok: false, error: 'CURRENT_KEY_INVALID' });
  const newKey = requested || `sk_${randomToken(24)}`;
  await fb(`users/${userId}/api_key`).set(newKey);
  await addActivity('API key rotated', { username: user.username, by: req.adminSession.username });
  res.json({ ok: true, api_key: newKey });
});

app.post('/api/scanner/verify-key', async (req, res) => {
  const apiKey = String(req.get('x-api-key') || req.body?.api_key || '').trim();
  const user = await verifyApiKey(apiKey);
  if (!user) return res.status(401).json({ ok: false, error: 'INVALID_API_KEY' });
  const rl = await rateLimitByApiKey(apiKey, user.plan || 'free');
  if (!rl.allowed) {
    const status = rl.source === 'unavailable' ? 503 : 429;
    return res.status(status).json({ ok: false, error: rl.source === 'unavailable' ? 'RATE_LIMIT_BACKEND_UNAVAILABLE' : 'RATE_LIMIT_EXCEEDED', limit: rl.limit, count: rl.count, rate_limit_source: rl.source });
  }
  res.json({ ok: true, user: { id: user.id, username: user.username, plan: user.plan || 'free' }, rate_limit: rl });
});

// ---------------------------------------------------------------------------
// ACTIVITY / CLEANUP
// ---------------------------------------------------------------------------
app.get('/api/admin/activity', requireAdmin, async (req, res) => {
  const snap = await fb('activity').once('value');
  const data = snap.val() || {};
  res.json({ ok: true, activity: Object.values(data).reverse().slice(0, 100) });
});

app.post('/api/admin/activity', requireAdmin, async (req, res) => {
  const message = String(req.body?.message || '').trim();
  if (!message) return res.status(400).json({ ok: false, error: 'MESSAGE_REQUIRED' });
  await addActivity(message, { by: req.adminSession.username, ip: clientIp(req) });
  res.json({ ok: true });
});

app.post('/api/admin/clear-data', requireAdmin, async (req, res) => {
  const target = String(req.body?.target || '');
  const allowed = ['activity', 'logs', 'failed_logins', 'activity-all'];
  if (!allowed.includes(target)) return res.status(400).json({ ok: false, error: 'INVALID_TARGET' });
  try {
    const result = await clearTarget(target);
    await addActivity(`Cleared ${target}`, { by: req.adminSession.username });
    res.json({ ok: true, result });
  } catch (error) {
    res.status(500).json({ ok: false, error: 'CLEAR_FAILED', details: safeError(error) });
  }
});

// ---------------------------------------------------------------------------
// DATABASE HEALTH / DESTRUCTIVE ADMIN ACTIONS
// ---------------------------------------------------------------------------
app.get('/api/health', async (req, res) => {
  const result = await healthSnapshot();
  res.status(result.ok ? 200 : 503).json(result);
});

app.get('/api/health/stream', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  let closed = false;
  req.on('close', () => { closed = true; });
  const send = async () => {
    if (closed) return;
    try { res.write(`data: ${JSON.stringify(await healthSnapshot())}\n\n`); }
    catch (e) { res.write(`data: ${JSON.stringify({ ok: false, error: safeError(e) })}\n\n`); }
  };
  await send();
  const interval = setInterval(send, Number(process.env.HEALTH_INTERVAL_MS || 5000));
  req.on('close', () => clearInterval(interval));
});

app.post('/api/admin/databases/delete-all', requireAdmin, async (req, res) => {
  if (!requireDeleteConfirmation(req.body, 'DELETE ALL DATABASE DATA')) return res.status(400).json({ ok: false, error: 'CONFIRMATION_REQUIRED' });
  const result = await deleteAllDatabases();
  clearSessionCookie(res);
  res.status(result.ok ? 200 : 207).json(result);
});

app.post('/api/admin/databases/:db/clear', requireAdmin, async (req, res) => {
  const db = req.params.db;
  const expected = `DELETE ALL ${db.toUpperCase()} DATA`;
  if (!requireDeleteConfirmation(req.body, expected)) return res.status(400).json({ ok: false, error: 'CONFIRMATION_REQUIRED' });
  try {
    let result;
    if (db === 'mongodb') {
      const c = await ensureMongo();
      await c.db(required('MONGODB_DB')).dropDatabase();
      result = { status: 'DELETED' };
    } else if (db === 'mysql') {
      const database = required('MYSQL_DATABASE');
      const conn = await mysql.createConnection({ host: required('MYSQL_HOST'), port: Number(process.env.MYSQL_PORT || 3306), user: required('MYSQL_USER'), password: process.env.MYSQL_PASSWORD || '', connectTimeout: HEALTH_TIMEOUT_MS, ssl: process.env.MYSQL_SSL === 'true' ? {} : undefined });
      const safeDb = database.replaceAll('`', '``');
      await conn.query(`DROP DATABASE IF EXISTS \`${safeDb}\``);
      await conn.query(`CREATE DATABASE \`${safeDb}\``);
      await conn.end();
      result = { status: 'DELETED_AND_RECREATED' };
    } else if (db === 'redis') {
      const r = await ensureRedis();
      await r.flushDb();
      result = { status: 'FLUSHED' };
    } else if (db === 'firebase') {
      await fb('/').set({});
      result = { status: 'DELETED' };
    } else throw new Error('Unsupported database');
    await addActivity(`${db} cleared`, { by: req.adminSession.username });
    res.json({ ok: true, ...result });
  } catch (error) {
    res.status(500).json({ ok: false, error: safeError(error) });
  }
});

// ---------------------------------------------------------------------------
// STATIC FILES
// ---------------------------------------------------------------------------
app.get('/dashboard.html', async (req, res) => {
  try {
    const session = await getSessionByRequest(req);
    if (!session) return res.redirect('/login.html');
    const ip = await isIpAllowed(req);
    if (!ip.allowed) return res.redirect('/404.html');
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  } catch {
    res.redirect('/login.html');
  }
});
app.get('/dashboard', (req, res) => res.redirect('/dashboard.html'));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.get('/', (_req, res) => res.redirect('/login.html'));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ ok: false, error: 'INTERNAL_SERVER_ERROR', details: safeError(err) });
});

if (!process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`ScannerAPI secure server: http://localhost:${PORT}`);
  });
}

export default app;

async function shutdown() {
  try { await mongoClient?.close(); } catch {}
  try { await mysqlPool?.end(); } catch {}
  try { await redisClient?.quit(); } catch {}
  try { if (admin.apps.length) await admin.app().delete(); } catch {}
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
