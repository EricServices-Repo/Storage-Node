'use strict';

const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const { pipeline } = require('stream/promises');
const express = require('express');

const UI_PORT = parseInt(process.env.UI_PORT || '80', 10);
const API_PORT = parseInt(process.env.API_PORT || process.env.PORT || '3901', 10);
const DATA_ROOT = path.resolve(process.env.DATA_ROOT || '/data');
const SECRET = (process.env.STORAGE_API_SECRET || '').trim();
const MAX_BODY_BYTES = Math.min(
  parseInt(process.env.MAX_PUT_BYTES || String(64 * 1024 * 1024 * 1024), 10) || 64 * 1024 * 1024 * 1024,
  256 * 1024 * 1024 * 1024
);

const STATE_DIR = path.join(DATA_ROOT, '.file-uploader-node');
const STATE_FILE = path.join(STATE_DIR, 'node_state.json');
const DEFAULT_NODE_STATUS = normalizeNodeStatus(process.env.STORAGE_NODE_STATUS || 'active');
const TRANSFER_CONFIRM_PHRASE = 'TRANSFER_NODE';
const MAX_TRANSFER_OBJECTS = parseInt(process.env.MAX_TRANSFER_OBJECTS || '200000', 10) || 200000;

const UI_COOKIE = 'storage_ui';
const UI_SESSION_MS = 7 * 24 * 60 * 60 * 1000;

const transferJobs = new Map();
let transferRunLock = false;

let netSamplePrev = { t: 0, rx: 0, tx: 0 };

function normalizeNodeStatus(s) {
  const v = String(s || '')
    .toLowerCase()
    .trim();
  if (v === 'disabled' || v === 'maintenance' || v === 'active') return v;
  return 'active';
}

async function readPersistedNodeStatus() {
  try {
    const raw = await fsp.readFile(STATE_FILE, 'utf8');
    const j = JSON.parse(raw);
    if (j && typeof j.status === 'string') return normalizeNodeStatus(j.status);
  } catch {
    /* no state file */
  }
  return null;
}

async function getEffectiveNodeStatus() {
  const persisted = await readPersistedNodeStatus();
  if (persisted) return persisted;
  return DEFAULT_NODE_STATUS;
}

async function writePersistedNodeStatus(status) {
  await fsp.mkdir(STATE_DIR, { recursive: true, mode: 0o700 });
  const body = JSON.stringify({
    status: normalizeNodeStatus(status),
    updatedAt: new Date().toISOString(),
  });
  await fsp.writeFile(STATE_FILE, body, { mode: 0o600 });
}

function delay(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function auth(req, res, next) {
  if (!SECRET) {
    res.status(503).type('text/plain').send('STORAGE_API_SECRET is not set');
    return;
  }
  const h = req.headers.authorization || '';
  const m = /^Bearer\s+(.+)$/i.exec(h);
  const tok = m ? m[1].trim() : '';
  if (tok !== SECRET) {
    res.status(401).type('text/plain').send('Unauthorized');
    return;
  }
  next();
}

function passwordMatches(given) {
  if (!SECRET) return false;
  const ha = crypto.createHash('sha256').update(String(given), 'utf8').digest();
  const hb = crypto.createHash('sha256').update(SECRET, 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb);
}

function signUiPayload(obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET + ':ui').update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function readUiSession(req) {
  if (!SECRET) return null;
  const raw = req.headers.cookie;
  if (!raw) return null;
  const m = new RegExp(`(?:^|;\\s*)${UI_COOKIE}=([^;]+)`).exec(raw);
  if (!m) return null;
  let val;
  try {
    val = decodeURIComponent(m[1]);
  } catch {
    return null;
  }
  const dot = val.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = val.slice(0, dot);
  const sig = val.slice(dot + 1);
  const exp = crypto.createHmac('sha256', SECRET + ':ui').update(payload).digest('base64url');
  let sigBuf;
  let expBuf;
  try {
    sigBuf = Buffer.from(sig, 'base64url');
    expBuf = Buffer.from(exp, 'base64url');
  } catch {
    return null;
  }
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!data || typeof data.exp !== 'number' || typeof data.csrf !== 'string') return null;
  if (Date.now() > data.exp) return null;
  return data;
}

function setUiSessionCookie(res, session) {
  const token = signUiPayload(session);
  const parts = [
    `${UI_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/ui',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(UI_SESSION_MS / 1000)}`,
  ];
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearUiSessionCookie(res) {
  res.setHeader('Set-Cookie', `${UI_COOKIE}=; Path=/ui; HttpOnly; SameSite=Strict; Max-Age=0`);
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function escapeJsString(s) {
  return JSON.stringify(String(s));
}

function parseUid(raw) {
  const n = parseInt(String(raw), 10);
  if (!Number.isFinite(n) || n < 1 || n > 0xffffffff) {
    return null;
  }
  return n;
}

function userRoot(uid) {
  return path.join(DATA_ROOT, 'users', String(uid));
}

function filesDir(uid) {
  return path.join(userRoot(uid), 'files');
}

function fshareDir(uid) {
  return path.join(userRoot(uid), 'fshare_zips');
}

function validStoredFile(name) {
  return /^[0-9a-f]{32}$/i.test(String(name));
}

function validStoredZip(name) {
  return /^[0-9a-f]{32}\.zip$/i.test(String(name));
}

async function diskStatsForPath(root) {
  try {
    const s = await fsp.statfs(root);
    const bsize = Number(s.bsize) || 4096;
    const blocks = Number(s.blocks) || 0;
    const bfree = Number(s.bfree) || 0;
    const total = blocks * bsize;
    const free = bfree * bsize;
    const files = Number(s.files);
    const ffree = Number(s.ffree);
    return {
      total,
      free,
      ok: true,
      inodesTotal: Number.isFinite(files) ? files : null,
      inodesFree: Number.isFinite(ffree) ? ffree : null,
    };
  } catch {
    return {
      total: 0,
      free: 0,
      ok: false,
      inodesTotal: null,
      inodesFree: null,
    };
  }
}

async function countUserDirs() {
  const usersPath = path.join(DATA_ROOT, 'users');
  try {
    const names = await fsp.readdir(usersPath, { withFileTypes: true });
    let n = 0;
    for (const d of names) {
      if (d.isDirectory() && /^\d+$/.test(d.name)) n += 1;
    }
    return n;
  } catch {
    return 0;
  }
}

async function readProcText(rel) {
  try {
    return await fsp.readFile(path.join('/proc', rel), 'utf8');
  } catch {
    return '';
  }
}

function parseCpuAgg(line) {
  const p = line.trim().split(/\s+/);
  if (p[0] !== 'cpu' || p.length < 5) return null;
  const nums = p.slice(1).map((x) => parseInt(x, 10));
  if (nums.some((n) => !Number.isFinite(n))) return null;
  const idle = nums[3] + (nums[4] || 0);
  const total = nums.reduce((a, b) => a + b, 0);
  return { idle, total };
}

function parseMeminfoKb(text) {
  const out = {};
  for (const line of text.split('\n')) {
    const m = /^(\w+):\s+(\d+)\s+kB\s*$/i.exec(line);
    if (m) out[m[1]] = parseInt(m[2], 10) * 1024;
  }
  return out;
}

function parseNetDev(text) {
  const lines = text.split('\n').slice(2);
  let rx = 0;
  let tx = 0;
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 10) continue;
    const ifname = parts[0].replace(/:$/, '');
    if (ifname === 'lo') continue;
    rx += parseInt(parts[1], 10) || 0;
    tx += parseInt(parts[9], 10) || 0;
  }
  return { rx, tx };
}

async function collectHostMetrics() {
  const memRaw = await readProcText('meminfo');
  const stat1 = await readProcText('stat');
  await delay(400);
  const stat2 = await readProcText('stat');
  const netRaw = await readProcText('net/dev');
  const loadavg = (await readProcText('loadavg')).trim().split(/\s+/).slice(0, 3);

  const mem = parseMeminfoKb(memRaw);
  const memTotal = mem.MemTotal || null;
  const memAvail = mem.MemAvailable || mem.MemFree || null;
  const memUsed = memTotal != null && memAvail != null ? Math.max(0, memTotal - memAvail) : null;

  const line1 = stat1.split('\n').find((l) => l.startsWith('cpu '));
  const line2 = stat2.split('\n').find((l) => l.startsWith('cpu '));
  const c1 = line1 ? parseCpuAgg(line1) : null;
  const c2 = line2 ? parseCpuAgg(line2) : null;
  let cpuPct = null;
  if (c1 && c2) {
    const didle = c2.idle - c1.idle;
    const dtotal = c2.total - c1.total;
    if (dtotal > 0) cpuPct = Math.min(100, Math.max(0, Math.round((100 * (dtotal - didle)) / dtotal)));
  }

  const net = parseNetDev(netRaw);
  const now = Date.now();
  let rxBps = null;
  let txBps = null;
  if (netSamplePrev.t > 0) {
    const dt = (now - netSamplePrev.t) / 1000;
    if (dt > 0.05) {
      rxBps = Math.max(0, (net.rx - netSamplePrev.rx) / dt);
      txBps = Math.max(0, (net.tx - netSamplePrev.tx) / dt);
    }
  }
  netSamplePrev = { t: now, rx: net.rx, tx: net.tx };

  return {
    cpu: { usagePct: cpuPct, load1: loadavg[0] || null, load5: loadavg[1] || null, load15: loadavg[2] || null },
    memory: {
      totalBytes: memTotal,
      availBytes: memAvail,
      usedBytes: memUsed,
      swapTotalBytes: mem.SwapTotal || null,
      swapFreeBytes: mem.SwapFree || null,
    },
    network: {
      rxBytesTotal: net.rx,
      txBytesTotal: net.tx,
      rxBytesPerSec: rxBps,
      txBytesPerSec: txBps,
    },
    procAvailable: Boolean(memRaw && stat1),
  };
}

function putHandler(absPath, req, res) {
  const len = parseInt(req.headers['content-length'] || '0', 10);
  if (!Number.isFinite(len) || len < 1 || len > MAX_BODY_BYTES) {
    res.status(400).type('text/plain').send('Invalid or missing Content-Length');
    return;
  }
  const dir = path.dirname(absPath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
  const tmp = absPath + '.part.' + process.pid + '.' + Date.now();
  const out = fs.createWriteStream(tmp, { flags: 'wx' });
  (async () => {
    try {
      await pipeline(req, out);
      const st = await fsp.stat(tmp);
      if (st.size !== len) {
        await fsp.unlink(tmp).catch(() => {});
        if (!res.headersSent) {
          res.status(400).type('text/plain').send('Size mismatch');
        }
        return;
      }
      await fsp.rename(tmp, absPath);
      if (!res.headersSent) {
        res.status(201).json({ ok: true, bytes: len });
      }
    } catch (e) {
      await fsp.unlink(tmp).catch(() => {});
      if (!res.headersSent) {
        res.status(500).type('text/plain').send(String(e && e.message));
      }
    }
  })();
}

async function* eachStoredBlob() {
  const usersPath = path.join(DATA_ROOT, 'users');
  let uidStrs = [];
  try {
    uidStrs = await fsp.readdir(usersPath);
  } catch {
    return;
  }
  for (const uidStr of uidStrs) {
    if (!/^\d+$/.test(uidStr)) continue;
    const uid = parseInt(uidStr, 10);
    if (!Number.isFinite(uid)) continue;
    const fd = filesDir(uid);
    let fnames = [];
    try {
      fnames = await fsp.readdir(fd);
    } catch {
      fnames = [];
    }
    for (const name of fnames) {
      const low = name.toLowerCase();
      if (!validStoredFile(low)) continue;
      const abs = path.join(fd, low);
      const st = await fsp.stat(abs).catch(() => null);
      if (!st || !st.isFile()) continue;
      yield { kind: 'file', uid, name: low, absPath: abs, size: st.size };
    }
    const zd = fshareDir(uid);
    let znames = [];
    try {
      znames = await fsp.readdir(zd);
    } catch {
      znames = [];
    }
    for (const name of znames) {
      const low = name.toLowerCase();
      if (!validStoredZip(low)) continue;
      const abs = path.join(zd, low);
      const st = await fsp.stat(abs).catch(() => null);
      if (!st || !st.isFile()) continue;
      yield { kind: 'fshare', uid, name: low, absPath: abs, size: st.size };
    }
  }
}

async function countBlobs() {
  let n = 0;
  for await (const _ of eachStoredBlob()) {
    n += 1;
    if (n > MAX_TRANSFER_OBJECTS) return { count: n, overLimit: true };
  }
  return { count: n, overLimit: false };
}

function sanitizeRemoteBase(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (!u.hostname) return null;
  return u.origin;
}

function pushLog(job, line) {
  job.logs.push(`${new Date().toISOString()}  ${line}`);
  if (job.logs.length > 300) job.logs.splice(0, job.logs.length - 300);
}

async function putBlobToRemote(remoteBase, remoteSecret, blob) {
  const rel = blob.kind === 'file' ? `files/${blob.name}` : `fshare-zips/${blob.name}`;
  const putUrl = `${remoteBase}/v1/users/${blob.uid}/${rel}`;
  const st = await fsp.stat(blob.absPath);
  const stream = fs.createReadStream(blob.absPath);
  const init = {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${remoteSecret}`,
      'Content-Length': String(st.size),
    },
    body: stream,
    duplex: 'half',
  };
  let res;
  try {
    res = await fetch(putUrl, init);
  } catch (e) {
    throw new Error(`fetch PUT ${rel}: ${e && e.message}`);
  }
  if (!res.ok) {
    const t = await res.text().catch(() => '');
    throw new Error(`PUT ${rel}: HTTP ${res.status} ${t.slice(0, 200)}`);
  }
}

async function prepareRemoteUser(remoteBase, remoteSecret, uid) {
  const prepUrl = `${remoteBase}/v1/users/${uid}/prepare`;
  const res = await fetch(prepUrl, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${remoteSecret}`,
      'Content-Length': '0',
    },
  }).catch((e) => {
    throw new Error(`prepare ${uid}: ${e && e.message}`);
  });
  if (!res.ok) {
    const t = await res.text().catch(() => '');
    throw new Error(`prepare ${uid}: HTTP ${res.status} ${t.slice(0, 200)}`);
  }
}

async function runTransferJob(job, remoteBase, remoteSecret, deleteLocal) {
  job.state = 'running';
  pushLog(job, 'Counting objects…');
  const { count, overLimit } = await countBlobs();
  if (overLimit) {
    throw new Error(`More than ${MAX_TRANSFER_OBJECTS} objects; refusing. Raise MAX_TRANSFER_OBJECTS or use an external tool.`);
  }
  job.total = count;
  pushLog(job, `Found ${count} object(s) to transfer.`);

  const preparedUsers = new Set();
  let done = 0;
  let bytesDone = 0;

  for await (const blob of eachStoredBlob()) {
    if (!preparedUsers.has(blob.uid)) {
      pushLog(job, `POST /v1/users/${blob.uid}/prepare on target…`);
      await prepareRemoteUser(remoteBase, remoteSecret, blob.uid);
      preparedUsers.add(blob.uid);
    }
    pushLog(job, `PUT ${blob.kind}/${blob.name} (user ${blob.uid}, ${formatBytes(blob.size)})…`);
    await putBlobToRemote(remoteBase, remoteSecret, blob);
    done += 1;
    bytesDone += blob.size;
    job.done = done;
    job.bytesDone = bytesDone;

    if (deleteLocal) {
      await fsp.unlink(blob.absPath).catch(() => {});
    }
  }

  if (deleteLocal && count > 0) {
    pushLog(job, 'Removing empty local user directories…');
    await pruneEmptyUserTrees();
  }

  job.state = 'completed';
  pushLog(job, deleteLocal ? 'Transfer finished; local blobs removed where successful.' : 'Transfer finished (local data kept).');
}

async function pruneEmptyUserTrees() {
  const usersPath = path.join(DATA_ROOT, 'users');
  let uidStrs = [];
  try {
    uidStrs = await fsp.readdir(usersPath);
  } catch {
    return;
  }
  for (const uidStr of uidStrs) {
    if (!/^\d+$/.test(uidStr)) continue;
    const uid = parseInt(uidStr, 10);
    const ur = userRoot(uid);
    for (const sub of ['files', 'fshare_zips']) {
      const p = path.join(ur, sub);
      try {
        const left = await fsp.readdir(p);
        if (left.length === 0) await fsp.rmdir(p);
      } catch {
        /* ignore */
      }
    }
    try {
      const left = await fsp.readdir(ur);
      if (left.length === 0) await fsp.rmdir(ur);
    } catch {
      /* ignore */
    }
  }
}

const uiApp = express();
uiApp.disable('x-powered-by');
uiApp.use(express.urlencoded({ extended: false, limit: '256kb' }));

uiApp.get('/', (_req, res) => {
  res.redirect(302, '/ui/');
});

uiApp.get('/ui/login', (req, res) => {
  if (!SECRET) {
    res
      .status(503)
      .type('html')
      .send(
        uiPage(
          'Setup required',
          '<p class="err">Set <code>STORAGE_API_SECRET</code> in the container environment, then restart.</p>',
          false
        )
      );
    return;
  }
  if (readUiSession(req)) {
    res.redirect(302, '/ui/');
    return;
  }
  const err = req.query.err === '1' ? '<p class="err">Incorrect secret.</p>' : '';
  res.type('html').send(
    uiPage(
      'Storage node — sign in',
      `${err}<form method="post" action="/ui/login"><label>Management password</label><p class="hint">Use the same value as <code>STORAGE_API_SECRET</code> (Bearer token for the API).</p><input type="password" name="password" autocomplete="current-password" required autofocus /><button type="submit">Sign in</button></form>`,
      false
    )
  );
});

uiApp.post('/ui/login', (req, res) => {
  if (!SECRET) {
    res.status(503).type('text/plain').send('STORAGE_API_SECRET is not set');
    return;
  }
  const pwd = String(req.body && req.body.password ? req.body.password : '');
  if (!passwordMatches(pwd)) {
    res.redirect(302, '/ui/login?err=1');
    return;
  }
  const csrf = crypto.randomBytes(16).toString('hex');
  setUiSessionCookie(res, { exp: Date.now() + UI_SESSION_MS, csrf });
  res.redirect(302, '/ui/');
});

uiApp.post('/ui/logout', (req, res) => {
  clearUiSessionCookie(res);
  res.redirect(302, '/ui/login');
});

function requireUi(req, res, next) {
  if (!SECRET) {
    res.status(503).type('text/plain').send('STORAGE_API_SECRET is not set');
    return;
  }
  const sess = readUiSession(req);
  if (!sess) {
    res.redirect(302, '/ui/login');
    return;
  }
  req.uiSession = sess;
  next();
}

uiApp.get('/ui/api/metrics', requireUi, async (_req, res) => {
  const [host, disk] = await Promise.all([collectHostMetrics(), diskStatsForPath(DATA_ROOT)]);
  res.json({
    ok: true,
    host,
    storage: {
      dataRoot: DATA_ROOT,
      totalBytes: disk.ok ? disk.total : null,
      freeBytes: disk.ok ? disk.free : null,
      usedBytes: disk.ok && disk.total > 0 ? disk.total - disk.free : null,
      inodesTotal: disk.inodesTotal,
      inodesFree: disk.inodesFree,
      ok: disk.ok,
    },
    nodeStatus: await getEffectiveNodeStatus(),
  });
});

uiApp.get('/ui/api/transfer/:id', requireUi, (req, res) => {
  const job = transferJobs.get(String(req.params.id || ''));
  if (!job) {
    res.status(404).json({ ok: false, error: 'not_found' });
    return;
  }
  res.json({
    ok: true,
    job: {
      id: job.id,
      state: job.state,
      total: job.total,
      done: job.done,
      bytesDone: job.bytesDone,
      logs: job.logs,
      error: job.error,
      startedAt: job.startedAt,
    },
  });
});

uiApp.post('/ui/status', requireUi, async (req, res) => {
  const csrf = String(req.body && req.body.csrf ? req.body.csrf : '');
  if (!csrf || csrf !== req.uiSession.csrf) {
    res.status(403).type('text/plain').send('Invalid CSRF');
    return;
  }
  const st = normalizeNodeStatus(req.body && req.body.status);
  try {
    await writePersistedNodeStatus(st);
    res.redirect(302, '/ui/?msg=statussaved');
  } catch (e) {
    res.status(500).type('html').send(uiShell('Error', `<p class="err">${escapeHtml(String(e && e.message))}</p>`, true));
  }
});

uiApp.post('/ui/transfer-start', requireUi, async (req, res) => {
  const csrf = String(req.body && req.body.csrf ? req.body.csrf : '');
  if (!csrf || csrf !== req.uiSession.csrf) {
    res.status(403).type('text/plain').send('Invalid CSRF');
    return;
  }
  if (transferRunLock) {
    res.redirect(302, '/ui/?msg=transferbusy');
    return;
  }
  const confirm = String(req.body && req.body.confirm ? req.body.confirm : '').trim();
  if (confirm !== TRANSFER_CONFIRM_PHRASE) {
    res.redirect(302, '/ui/?msg=badconfirm');
    return;
  }
  const remoteBase = sanitizeRemoteBase(req.body && req.body.remote_base);
  if (!remoteBase) {
    res.redirect(302, '/ui/?msg=badurl');
    return;
  }
  const remoteSecret = String(req.body && req.body.remote_secret ? req.body.remote_secret : '').trim() || SECRET;
  const deleteLocal = String(req.body && req.body.delete_local ? req.body.delete_local : '') === '1';

  const jobId = crypto.randomBytes(10).toString('hex');
  const job = {
    id: jobId,
    state: 'queued',
    startedAt: new Date().toISOString(),
    logs: [],
    done: 0,
    total: 0,
    bytesDone: 0,
    error: null,
  };
  transferJobs.set(jobId, job);
  transferRunLock = true;
  pushLog(job, `Target: ${remoteBase}  delete_local=${deleteLocal}`);

  (async () => {
    try {
      await runTransferJob(job, remoteBase, remoteSecret, deleteLocal);
    } catch (e) {
      job.state = 'failed';
      job.error = String(e && e.message);
      pushLog(job, `FAILED: ${job.error}`);
    } finally {
      transferRunLock = false;
    }
  })();

  res.redirect(302, `/ui/?transfer=${encodeURIComponent(jobId)}`);
});

uiApp.get('/ui/', requireUi, async (req, res) => {
  const [disk, userCount, nodeStatus] = await Promise.all([
    diskStatsForPath(DATA_ROOT),
    countUserDirs(),
    getEffectiveNodeStatus(),
  ]);
  const totalStr = disk.ok ? formatBytes(disk.total) : '—';
  const freeStr = disk.ok ? formatBytes(disk.free) : '—';
  const usedStr = disk.ok && disk.total > 0 ? formatBytes(disk.total - disk.free) : '—';
  const pct =
    disk.ok && disk.total > 0 ? Math.round(((disk.total - disk.free) / disk.total) * 100) : null;
  const bar =
    pct != null
      ? `<div class="bar"><span style="width:${Math.min(100, pct)}%"></span></div><p class="muted">${pct}% used (volume)</p>`
      : '';

  const statusBadge = statusPillHtml(nodeStatus);
  const msg =
    req.query.msg === 'prepared'
      ? '<p class="ok">User directories prepared.</p>'
      : req.query.msg === 'baduid'
        ? '<p class="err">Invalid user id.</p>'
        : req.query.msg === 'statussaved'
          ? '<p class="ok">Storage status saved.</p>'
          : req.query.msg === 'badconfirm'
            ? `<p class="err">Type <code>${escapeHtml(TRANSFER_CONFIRM_PHRASE)}</code> exactly to confirm transfer.</p>`
            : req.query.msg === 'badurl'
              ? '<p class="err">Invalid target API base URL (use <code>http://</code> or <code>https://</code>, no trailing path).</p>'
              : req.query.msg === 'transferbusy'
                ? '<p class="err">Another transfer is already running.</p>'
                : '';

  const inodeRow =
    disk.ok && disk.inodesTotal != null && disk.inodesFree != null
      ? `<tr><th>Inodes (filesystem)</th><td>${escapeHtml(String(disk.inodesTotal - disk.inodesFree))} used / ${escapeHtml(String(disk.inodesTotal))} total (${escapeHtml(String(disk.inodesFree))} free)</td></tr>`
      : '';

  const transferId = String(req.query.transfer || '').trim();
  const transferPanel =
    transferId && transferJobs.has(transferId)
      ? `<section class="transfer-live"><h2>Transfer progress</h2><pre id="transfer-log" class="log"></pre><p class="hint"><a href="/ui/">Clear from URL</a> when finished (job stays in memory until restart).</p></section>
        <script>(function(){var id=${escapeJsString(transferId)};function poll(){fetch('/ui/api/transfer/'+encodeURIComponent(id)).then(function(r){return r.json()}).then(function(j){if(!j||!j.ok)return;var b=j.job;var el=document.getElementById('transfer-log');if(el)el.textContent=(b.logs||[]).join('\\n');}).catch(function(){});}poll();setInterval(poll,1500);})();</script>`
      : '';

  const body = `
    ${msg}
    <div class="grid-2">
    <section><h2>Storage status</h2>
    <p>Current: ${statusBadge}</p>
    <p class="hint"><strong>Active</strong> — normal API. <strong>Maintenance</strong> — reads only (GET/HEAD); writes return 503. <strong>Disabled</strong> — all API traffic returns 503 (health fails).</p>
    <form method="post" action="/ui/status">
    <input type="hidden" name="csrf" value="${escapeHtml(req.uiSession.csrf)}" />
    <label for="status">Set status</label>
    <select name="status" id="status">
      <option value="active" ${nodeStatus === 'active' ? 'selected' : ''}>Active</option>
      <option value="maintenance" ${nodeStatus === 'maintenance' ? 'selected' : ''}>Maintenance</option>
      <option value="disabled" ${nodeStatus === 'disabled' ? 'selected' : ''}>Disabled</option>
    </select>
    <button type="submit">Save status</button>
    </form>
    <p class="hint">Persisted under <code>${escapeHtml(path.join(DATA_ROOT, '.file-uploader-node', 'node_state.json'))}</code> (overrides <code>STORAGE_NODE_STATUS</code> env until changed).</p>
    </section>
    <section><h2>Volume summary</h2>
    <p><strong>Data root</strong> <code>${escapeHtml(DATA_ROOT)}</code></p>
    <table class="kv"><tr><th>Total</th><td>${escapeHtml(totalStr)}</td></tr>
    <tr><th>Free</th><td>${escapeHtml(freeStr)}</td></tr>
    <tr><th>Used (approx.)</th><td>${escapeHtml(usedStr)}</td></tr>
    ${inodeRow}</table>
    ${bar}
    </section>
    </div>

    <section class="metrics"><h2>Live metrics</h2>
    <p class="hint">Host view (Linux <code>/proc</code> inside the container). Refreshes every few seconds.</p>
    <div class="grid-metrics" id="metrics-root">
      <div class="metric-card"><h3>CPU</h3><p class="metric-val" id="m-cpu">—</p><p class="muted" id="m-load">load —</p></div>
      <div class="metric-card"><h3>Memory</h3><p class="metric-val" id="m-ram">—</p><p class="muted" id="m-swap">swap —</p></div>
      <div class="metric-card"><h3>Network</h3><p class="metric-val" id="m-net">—</p><p class="muted" id="m-net-tot">totals —</p></div>
      <div class="metric-card"><h3>Storage (${escapeHtml(DATA_ROOT)})</h3><p class="metric-val" id="m-disk">—</p><p class="muted" id="m-inode">inodes —</p></div>
    </div>
    </section>

    <section><h2>Users on this node</h2><p>Numeric user directories under <code>users/</code>: <strong>${userCount}</strong></p></section>

    <section><h2>Prepare user</h2><p class="hint">Creates <code>files/</code> and <code>fshare_zips/</code> for a numeric app user id (same as <code>POST /v1/users/:uid/prepare</code> on port ${escapeHtml(String(API_PORT))}).</p>
    <form method="post" action="/ui/prepare">
    <input type="hidden" name="csrf" value="${escapeHtml(req.uiSession.csrf)}" />
    <label>User id</label><input name="uid" type="number" min="1" max="4294967295" required />
    <button type="submit">Prepare</button></form></section>

    <section class="danger-zone"><h2>Node transfer</h2>
    <p class="hint">Copies every stored blob on <strong>this</strong> node to another storage node via its HTTP API, then optionally deletes local copies. Set this node to <strong>Maintenance</strong> first so the app stops writing here. Target must expose the same <code>/v1/*</code> API and accept your Bearer secret.</p>
    <p class="err">Destructive: verify target URL and secret. Large pools can take a long time; cap is ${escapeHtml(String(MAX_TRANSFER_OBJECTS))} objects.</p>
    <form method="post" action="/ui/transfer-start">
    <input type="hidden" name="csrf" value="${escapeHtml(req.uiSession.csrf)}" />
    <label>Target API base URL</label>
    <input name="remote_base" type="url" placeholder="https://new-storage.example.com:3901" required />
    <label>Target Bearer secret</label>
    <input name="remote_secret" type="password" autocomplete="off" placeholder="Leave blank to use STORAGE_API_SECRET" />
    <label class="row"><input type="checkbox" name="delete_local" value="1" /> Delete each local file after a successful PUT (then prune empty dirs)</label>
    <label>Type <code>${escapeHtml(TRANSFER_CONFIRM_PHRASE)}</code> to confirm</label>
    <input name="confirm" type="text" autocomplete="off" required />
    <button type="submit" class="btn-danger">Start transfer</button>
    </form></section>

    <section><h2>API</h2><p class="muted">Clients use <strong>port ${escapeHtml(String(API_PORT))}</strong> with <code>Authorization: Bearer …</code> on <code>/v1/*</code>. Example: <code>GET http://&lt;host&gt;:${escapeHtml(String(API_PORT))}/v1/health</code> returns JSON including <code>node_status</code>.</p></section>
    ${transferPanel}
    <script>(function(){
      function fmtBytes(n){if(n==null||!isFinite(n))return '—';var u=['B','KB','MB','GB','TB'];var i=0;while(n>=1024&&i<u.length-1){n/=1024;i++;}return (i===0?n.toFixed(0):n.toFixed(1))+' '+u[i];}
      function fmtRate(n){if(n==null||!isFinite(n))return '—';return fmtBytes(n)+'/s';}
      function tick(){
        fetch('/ui/api/metrics').then(function(r){return r.json()}).then(function(j){
          if(!j||!j.ok)return;
          var h=j.host||{};
          var s=j.storage||{};
          var cpu=h.cpu||{};
          document.getElementById('m-cpu').textContent = (cpu.usagePct!=null)?(cpu.usagePct+'% busy (sampled)'):'—';
          document.getElementById('m-load').textContent = 'load '+(cpu.load1||'—')+' / '+(cpu.load5||'—')+' / '+(cpu.load15||'—');
          var mem=h.memory||{};
          var ramTxt='—';
          if(mem.totalBytes&&mem.usedBytes!=null)ramTxt=fmtBytes(mem.usedBytes)+' / '+fmtBytes(mem.totalBytes)+' used';
          document.getElementById('m-ram').textContent=ramTxt;
          var swp='swap —';
          if(mem.swapTotalBytes&&mem.swapFreeBytes!=null)swp='swap '+fmtBytes(mem.swapTotalBytes-mem.swapFreeBytes)+' / '+fmtBytes(mem.swapTotalBytes)+' used';
          document.getElementById('m-swap').textContent=swp;
          var net=h.network||{};
          var netLine='—';
          if(net.rxBytesPerSec!=null&&net.txBytesPerSec!=null)netLine=fmtRate(net.rxBytesPerSec)+' RX · '+fmtRate(net.txBytesPerSec)+' TX';
          document.getElementById('m-net').textContent=netLine;
          document.getElementById('m-net-tot').textContent='totals RX '+fmtBytes(net.rxBytesTotal)+' · TX '+fmtBytes(net.txBytesTotal);
          var dtxt='—';
          if(s.ok&&s.totalBytes!=null&&s.usedBytes!=null)dtxt=fmtBytes(s.usedBytes)+' / '+fmtBytes(s.totalBytes)+' used';
          document.getElementById('m-disk').textContent=dtxt;
          var id='—';
          if(s.inodesTotal!=null&&s.inodesFree!=null)id=(s.inodesTotal-s.inodesFree)+' / '+s.inodesTotal+' used ('+s.inodesFree+' free)';
          document.getElementById('m-inode').textContent='inodes '+id;
        }).catch(function(){});
      }
      tick();setInterval(tick,4000);
    })();</script>`;

  res.type('html').send(uiShell('Storage node', body, true));
});

uiApp.post('/ui/prepare', requireUi, async (req, res) => {
  const csrf = String(req.body && req.body.csrf ? req.body.csrf : '');
  if (!csrf || csrf !== req.uiSession.csrf) {
    res.status(403).type('text/plain').send('Invalid CSRF');
    return;
  }
  const uid = parseUid(req.body && req.body.uid);
  if (!uid) {
    res.redirect(302, '/ui/?msg=baduid');
    return;
  }
  try {
    await fsp.mkdir(filesDir(uid), { recursive: true, mode: 0o755 });
    await fsp.mkdir(fshareDir(uid), { recursive: true, mode: 0o755 });
    res.redirect(302, '/ui/?msg=prepared');
  } catch (e) {
    res.status(500).type('html').send(uiShell('Error', `<p class="err">${escapeHtml(String(e && e.message))}</p>`, true));
  }
});

async function apiStorageModeGuard(req, res, next) {
  try {
    const mode = await getEffectiveNodeStatus();
    req.nodeStatus = mode;
    if (mode === 'disabled') {
      res
        .status(503)
        .type('json')
        .send(JSON.stringify({ ok: false, error: 'disabled', message: 'Storage node is disabled' }));
      return;
    }
    if (mode === 'maintenance') {
      const m = req.method;
      if (m === 'POST' || m === 'PUT' || m === 'DELETE') {
        res
          .status(503)
          .type('json')
          .send(JSON.stringify({ ok: false, error: 'maintenance', message: 'Storage node is in maintenance (read-only)' }));
        return;
      }
    }
    next();
  } catch (e) {
    res.status(500).type('text/plain').send(String(e && e.message));
  }
}

const apiApp = express();
apiApp.disable('x-powered-by');
apiApp.use('/v1', apiStorageModeGuard);

apiApp.get('/v1/health', auth, async (_req, res) => {
  const st = await getEffectiveNodeStatus();
  res.json({ ok: true, data_root: DATA_ROOT, node_status: st });
});

apiApp.post('/v1/users/:uid/prepare', auth, async (req, res) => {
  const uid = parseUid(req.params.uid);
  if (!uid) {
    res.status(400).type('text/plain').send('Bad user id');
    return;
  }
  try {
    await fsp.mkdir(filesDir(uid), { recursive: true, mode: 0o755 });
    await fsp.mkdir(fshareDir(uid), { recursive: true, mode: 0o755 });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).type('text/plain').send(String(e && e.message));
  }
});

apiApp.put('/v1/users/:uid/files/:name', auth, (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredFile(name)) {
    res.status(400).type('text/plain').send('Bad path');
    return;
  }
  putHandler(path.join(filesDir(uid), name.toLowerCase()), req, res);
});

apiApp.put('/v1/users/:uid/fshare-zips/:name', auth, (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredZip(name)) {
    res.status(400).type('text/plain').send('Bad path');
    return;
  }
  putHandler(path.join(fshareDir(uid), name.toLowerCase()), req, res);
});

async function sendFile(absPath, req, res, downloadName) {
  try {
    const st = await fsp.stat(absPath);
    if (!st.isFile()) {
      res.status(404).type('text/plain').send('Not found');
      return;
    }
    res.setHeader('Content-Length', String(st.size));
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (downloadName) {
      const ascii = String(downloadName).replace(/[^\x20-\x7E]+/g, '_').slice(0, 180) || 'download';
      res.setHeader('Content-Disposition', 'attachment; filename="' + ascii + '"');
    }
    fs.createReadStream(absPath).pipe(res);
  } catch {
    res.status(404).type('text/plain').send('Not found');
  }
}

apiApp.get('/v1/users/:uid/files/:name', auth, (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredFile(name)) {
    res.status(400).type('text/plain').send('Bad path');
    return;
  }
  res.setHeader('Content-Type', 'application/octet-stream');
  sendFile(path.join(filesDir(uid), name.toLowerCase()), req, res, null);
});

apiApp.get('/v1/users/:uid/fshare-zips/:name', auth, (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredZip(name)) {
    res.status(400).type('text/plain').send('Bad path');
    return;
  }
  res.setHeader('Content-Type', 'application/zip');
  sendFile(path.join(fshareDir(uid), name.toLowerCase()), req, res, name.toLowerCase());
});

async function headBlob(absPath, res) {
  try {
    const st = await fsp.stat(absPath);
    if (!st.isFile()) {
      res.status(404).end();
      return;
    }
    res.setHeader('Content-Length', String(st.size));
    res.status(200).end();
  } catch {
    res.status(404).end();
  }
}

apiApp.head('/v1/users/:uid/files/:name', auth, async (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredFile(name)) {
    res.status(400).end();
    return;
  }
  await headBlob(path.join(filesDir(uid), name.toLowerCase()), res);
});

apiApp.head('/v1/users/:uid/fshare-zips/:name', auth, async (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredZip(name)) {
    res.status(400).end();
    return;
  }
  await headBlob(path.join(fshareDir(uid), name.toLowerCase()), res);
});

apiApp.delete('/v1/users/:uid/files/:name', auth, async (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredFile(name)) {
    res.status(400).json({ ok: false });
    return;
  }
  try {
    await fsp.unlink(path.join(filesDir(uid), name.toLowerCase()));
    res.json({ ok: true });
  } catch {
    res.json({ ok: true });
  }
});

apiApp.delete('/v1/users/:uid/fshare-zips/:name', auth, async (req, res) => {
  const uid = parseUid(req.params.uid);
  const name = String(req.params.name || '');
  if (!uid || !validStoredZip(name)) {
    res.status(400).json({ ok: false });
    return;
  }
  try {
    await fsp.unlink(path.join(fshareDir(uid), name.toLowerCase()));
    res.json({ ok: true });
  } catch {
    res.json({ ok: true });
  }
});

uiApp.use('/v1', (_req, res) => {
  res
    .status(404)
    .type('text/plain')
    .send(`Storage API is on port ${API_PORT} only (use /v1/* there, not on the UI port).`);
});

uiApp.use((_req, res) => {
  res.status(404).type('text/plain').send('Not found');
});

apiApp.use((_req, res) => {
  res.status(404).type('text/plain').send('Not found');
});

function formatBytes(n) {
  if (n == null || !Number.isFinite(n)) return '—';
  if (n < 1024) return `${Math.round(n)} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = -1;
  do {
    v /= 1024;
    i += 1;
  } while (v >= 1024 && i < u.length - 1);
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function statusPillHtml(status) {
  const cls = status === 'active' ? 'pill ok' : status === 'maintenance' ? 'pill warn' : 'pill bad';
  return `<span class="${cls}">${escapeHtml(status)}</span>`;
}

function uiPage(title, innerHtml, navLogout) {
  return uiShell(title, innerHtml, navLogout);
}

function uiShell(title, innerHtml, navLogout) {
  const nav = navLogout
    ? '<nav><span>File-Uploader storage node</span><form method="post" action="/ui/logout" style="display:inline"><button type="submit" class="linkbtn">Sign out</button></form></nav>'
    : '<nav><span>File-Uploader storage node</span></nav>';
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>${escapeHtml(title)}</title><style>
:root{--bg:#0f1419;--card:#1a222d;--text:#e7ecf1;--muted:#8b9bab;--accent:#3d8fd1;--err:#e06c75;--ok:#98c379;--warn:#e5c07b;}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
nav{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;background:var(--card);border-bottom:1px solid #2a3542}
main{max-width:960px;margin:0 auto;padding:28px 20px 48px}
h1{font-size:1.35rem;margin:0 0 8px}h2{font-size:1rem;margin:0 0 12px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.04em}
section{background:var(--card);border-radius:10px;padding:18px 20px;margin-bottom:16px;border:1px solid #2a3542}
section.metrics h2{margin-bottom:8px}
.grid-2{display:grid;grid-template-columns:1fr;gap:16px}
@media(min-width:720px){.grid-2{grid-template-columns:1fr 1fr}}
.grid-metrics{display:grid;grid-template-columns:1fr;gap:12px}
@media(min-width:640px){.grid-metrics{grid-template-columns:repeat(2,1fr)}}
@media(min-width:900px){.grid-metrics{grid-template-columns:repeat(4,1fr)}}
.metric-card{background:#121920;border-radius:8px;padding:12px 14px;border:1px solid #2a3542}
.metric-card h3{margin:0 0 6px;font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.metric-val{font-size:1.15rem;font-weight:600;margin:0}
label{display:block;margin:10px 0 6px;font-size:.9rem;color:var(--muted)}
label.row{display:flex;align-items:center;gap:10px;margin-top:12px}
input[type=password],input[type=number],input[type=url],input[type=text],select{width:100%;padding:10px 12px;border-radius:8px;border:1px solid #3d4a5c;background:#121920;color:var(--text);font-size:1rem}
button{padding:10px 18px;border-radius:8px;border:none;background:var(--accent);color:#fff;font-weight:600;cursor:pointer;margin-top:14px;font-size:.95rem}
.btn-danger{background:var(--err)}
.linkbtn{background:transparent;color:var(--muted);margin:0;padding:6px 10px;font-weight:500}
.hint{font-size:.85rem;color:var(--muted);margin:8px 0 0;line-height:1.45}.err{color:var(--err)}.ok{color:var(--ok)}
table.kv{width:100%;border-collapse:collapse}table.kv th{text-align:left;color:var(--muted);font-weight:500;padding:6px 8px 6px 0;width:42%}table.kv td{padding:6px 0}
.bar{height:8px;background:#2a3542;border-radius:4px;overflow:hidden;margin-top:10px}.bar span{display:block;height:100%;background:var(--accent);border-radius:4px}
code{font-size:.88em;background:#121920;padding:2px 6px;border-radius:4px}
.pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:.85rem;font-weight:600;text-transform:capitalize}
.pill.ok{background:#1e3d2a;color:var(--ok)}.pill.warn{background:#3d3420;color:var(--warn)}.pill.bad{background:#3d2028;color:var(--err)}
.danger-zone{border-color:#5c2d35}
pre.log{background:#121920;border:1px solid #2a3542;border-radius:8px;padding:12px;font-size:11px;line-height:1.4;max-height:280px;overflow:auto;white-space:pre-wrap}
</style></head><body>${nav}<main><h1>${escapeHtml(title)}</h1>${innerHtml}</main></body></html>`;
}

uiApp.listen(UI_PORT, '0.0.0.0', () => {
  // eslint-disable-next-line no-console
  console.log('storage-node UI listening on %s (management)', UI_PORT);
});

apiApp.listen(API_PORT, '0.0.0.0', () => {
  // eslint-disable-next-line no-console
  console.log('storage-node API listening on %s DATA_ROOT=%s', API_PORT, DATA_ROOT);
});
