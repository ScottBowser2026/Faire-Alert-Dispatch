const {onCall, onRequest, HttpsError} = require('firebase-functions/v2/https');
const {onSchedule} = require('firebase-functions/v2/scheduler');
const {defineSecret} = require('firebase-functions/params');
const admin = require('firebase-admin');
const twilio = require('twilio');
const crypto = require('crypto');

const TWILIO_SID   = defineSecret('TWILIO_SID');
const TWILIO_TOKEN = defineSecret('TWILIO_TOKEN');

admin.initializeApp({
  databaseURL: 'https://faire-alert-system.firebaseio.com',
});
const db = admin.database();

const REGION = 'us-central1';

// ---------- helpers ----------

// Twilio requires E.164. Accepts 7175550188, 717-555-0188, (717) 555-0188, +17175550188
function toE164(raw) {
  if (!raw) return null;
  const s = String(raw).trim();
  if (s.startsWith('+')) {
    const d = s.slice(1).replace(/[^\d]/g, '');
    return d.length >= 10 ? '+' + d : null;
  }
  const d = s.replace(/[^\d]/g, '');
  if (d.length === 10) return '+1' + d;
  if (d.length === 11 && d.startsWith('1')) return '+' + d;
  return null;
}

function client() {
  return twilio(TWILIO_SID.value(), TWILIO_TOKEN.value());
}

// ---------- PIN hashing ----------
// A 4-digit PIN has only 10,000 possibilities, so the hash alone is not a
// strong barrier — the SMS second factor is what actually protects the
// account. Hashing prevents casual exposure of every PIN at once.
function hashPin(pin, salt) {
  return crypto.pbkdf2Sync(String(pin), salt, 100000, 32, 'sha256').toString('hex');
}

function makePinRecord(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  return {salt, hash: hashPin(pin, salt)};
}

function checkPin(pin, record) {
  if (!record || !record.salt || !record.hash) return false;
  const candidate = hashPin(pin, record.salt);
  const a = Buffer.from(candidate, 'hex');
  const b = Buffer.from(record.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Strips the PIN record before anything goes back to the browser.
function publicUser(id, u) {
  return {
    id,
    firstName: u.firstName || '',
    lastName: u.lastName || '',
    phone: u.phone || '',
    email: u.email || '',
    role: u.role,
    site: u.site,
    mustChangePin: !!u.mustChangePin,
  };
}

async function siteMeta(site) {
  const snap = await db.ref(`sites/${site}/meta`).once('value');
  return snap.val() || {};
}

// Every send goes through here so nothing can dispatch from an unverified number
// or a site that hasn't been marked live.
async function requireSendableSite(site) {
  const meta = await siteMeta(site);
  if ((meta.status || 'pending') !== 'live') {
    throw new HttpsError('failed-precondition', `${site} is not live. Mark it live in the Sites tab once its number is verified.`);
  }
  const from = toE164(meta.tollFree);
  if (!from) {
    throw new HttpsError('failed-precondition', `${site} has no valid toll-free number configured.`);
  }
  return {meta, from};
}

async function getUser(userId) {
  const snap = await db.ref(`users/${userId}`).once('value');
  const u = snap.val();
  if (!u) throw new HttpsError('not-found', 'Account not found.');
  return u;
}

function fullName(u) {
  return `${u.firstName || ''} ${u.lastName || ''}`.trim();
}

async function logActivity(type, site, actor, detail, meta) {
  await db.ref('activityLog').push({
    ts: Date.now(),
    type, site: site || '—', actor: actor || 'system',
    detail, meta: meta || null,
  });
}

// Send one message per recipient. Twilio has no true bulk endpoint on the
// Messages API, so failures are collected per-number rather than aborting the batch.
async function sendMany(from, numbers, body) {
  const c = client();
  const results = {sent: 0, failed: 0, errors: []};
  await Promise.all(numbers.map(async (to) => {
    try {
      await c.messages.create({from, to, body});
      results.sent++;
    } catch (e) {
      results.failed++;
      if (results.errors.length < 10) results.errors.push({to, msg: e.message});
    }
  }));
  return results;
}

// ---------- 1. sendAlert ----------
exports.sendAlert = onCall(
  {region: REGION, secrets: [TWILIO_SID, TWILIO_TOKEN]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');

    const {userId, pin, site, listIds, message, alertName, category, isDrill} = req.data || {};
    if (!userId || !site || !Array.isArray(listIds) || !listIds.length || !message) {
      throw new HttpsError('invalid-argument', 'Missing required fields.');
    }

    const user = await getUser(userId);

    // Re-verify the sender's PIN at the moment of dispatch. This is what stops
    // someone using an unattended session that is already signed in.
    const pinOk = (user.pinHash && user.pinSalt)
      ? checkPin(pin, {hash: user.pinHash, salt: user.pinSalt})
      : (user.pin && String(user.pin) === String(pin));
    if (!pinOk) {
      throw new HttpsError('permission-denied', 'Incorrect PIN. Re-enter your PIN to send.');
    }
    if (user.role !== 'superadmin' && user.role !== 'admin') {
      throw new HttpsError('permission-denied', 'Your account cannot send alerts.');
    }
    if (user.role === 'admin' && user.site !== site) {
      throw new HttpsError('permission-denied', 'You can only send alerts for your own site.');
    }

    const {from} = await requireSendableSite(site);

    // Build recipient set, skipping opted-out numbers and de-duplicating
    // anyone who appears on more than one list.
    const [recSnap, optSnap] = await Promise.all([
      db.ref(`sites/${site}/recipients`).once('value'),
      db.ref(`sites/${site}/optOuts`).once('value'),
    ]);
    const recipients = recSnap.val() || {};
    const optOuts = optSnap.val() || {};
    const optedOut = new Set(
      Object.values(optOuts).map((o) => toE164(o.phone)).filter(Boolean)
    );

    const numbers = new Set();
    listIds.forEach((lid) => {
      const members = (recipients[lid] && recipients[lid].members) || {};
      Object.values(members).forEach((m) => {
        if (m.active === false) return;   // inactive recipients are skipped
        const e = toE164(m.phone);
        if (e && !optedOut.has(e)) numbers.add(e);
      });
    });

    if (numbers.size === 0) {
      throw new HttpsError('failed-precondition', 'No valid recipients on the selected lists.');
    }

    // Every message carries the site's header so recipients know at a glance
    // which property it came from.
    const meta = await siteMeta(site);
    const header = (meta.alertHeader || `${site} OPERATIONS ALERT`).toUpperCase();
    const fullMessage = `${header}\n${message}`;

    const results = await sendMany(from, Array.from(numbers), fullMessage);

    await logActivity(
      isDrill ? 'drill_sent' : 'alert_sent',
      site,
      fullName(user),
      `${alertName} → ${listIds.join(', ')}`,
      {recipients: results.sent, failed: results.failed, category: category || null, message}
    );

    return results;
  }
);

// ---------- 2. sendVerificationCode ----------
// Used for both login 2FA and the Active Shooter authorization code.
// The code is stored server-side; the client never receives it.
exports.sendVerificationCode = onCall(
  {region: REGION, secrets: [TWILIO_SID, TWILIO_TOKEN]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {userId, purpose} = req.data || {};
    if (!userId) throw new HttpsError('invalid-argument', 'Missing userId.');

    const user = await getUser(userId);
    const to = toE164(user.phone);
    if (!to) throw new HttpsError('failed-precondition', 'No valid phone number on this account.');

    // Send from the user's own site, or PARF for cross-site Superusers.
    const site = user.site === 'ALL' ? 'PARF' : user.site;
    const {from} = await requireSendableSite(site);

    const code = String(Math.floor(100000 + Math.random() * 900000));
    const label = purpose === 'authorize' ? 'authorization' : 'login';
    const body = `Faire Operations ${label} code: ${code}. Expires in 5 minutes. If you did not request this, contact your Superuser.`;

    await client().messages.create({from, to, body});

    await db.ref(`verificationCodes/${userId}`).set({
      code,
      purpose: purpose || 'login',
      expires: Date.now() + 5 * 60 * 1000,
      attempts: 0,
    });

    return {sent: true, maskedTo: to.slice(-4)};
  }
);

// ---------- 3. verifyCode ----------
exports.verifyCode = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {userId, code} = req.data || {};
  if (!userId || !code) throw new HttpsError('invalid-argument', 'Missing userId or code.');

  const ref = db.ref(`verificationCodes/${userId}`);
  const rec = (await ref.once('value')).val();
  if (!rec) throw new HttpsError('not-found', 'No code was requested. Start over.');
  if (Date.now() > rec.expires) {
    await ref.remove();
    throw new HttpsError('deadline-exceeded', 'That code expired. Request a new one.');
  }
  if ((rec.attempts || 0) >= 5) {
    await ref.remove();
    throw new HttpsError('resource-exhausted', 'Too many attempts. Request a new code.');
  }
  if (String(code) !== rec.code) {
    await ref.update({attempts: (rec.attempts || 0) + 1});
    throw new HttpsError('permission-denied', 'That code does not match.');
  }

  await ref.remove();
  const user = await getUser(userId);

  if (rec.purpose === 'login') {
    // Notify Superusers of the sign-in, excluding the person signing in.
    const usersSnap = await db.ref('users').once('value');
    const all = usersSnap.val() || {};
    const supers = Object.entries(all)
      .filter(([id, u]) => u.role === 'superadmin' && id !== userId)
      .map(([, u]) => toE164(u.phone))
      .filter(Boolean);

    if (supers.length) {
      try {
        const site = user.site === 'ALL' ? 'PARF' : user.site;
        const meta = await siteMeta(site);
        const from = toE164(meta.tollFree);
        if (from && (meta.status || 'pending') === 'live') {
          const when = new Date().toLocaleString('en-US', {timeZone: 'America/New_York'});
          const body = `Faire Operations login: ${fullName(user)} (${user.role === 'superadmin' ? 'Superuser' : 'Operations Manager'}) signed in at ${when}.`;
          await sendMany(from, supers, body);
        }
      } catch (e) {
        console.warn('Login notification failed:', e.message);
      }
    }

    await logActivity('login', user.site, fullName(user), `${fullName(user)} signed in`);
  }

  return {verified: true};
});

// ---------- 4. resetPin ----------
// Rate limiting lives here, not in the browser, so it cannot be bypassed.
exports.resetPin = onCall(
  {region: REGION, secrets: [TWILIO_SID, TWILIO_TOKEN]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {phone, lastName} = req.data || {};
    const digits = String(phone || '').replace(/[^\d]/g, '');
    if (digits.length < 10 || !lastName) {
      throw new HttpsError('invalid-argument', 'Enter both your phone number and last name.');
    }

    const WINDOW = 60 * 60 * 1000;
    const MAX = 3;
    const COOLDOWN = 60 * 1000;

    const key = digits.slice(-10);
    const rlRef = db.ref(`rateLimits/pinReset/${key}`);
    const hist = ((await rlRef.once('value')).val() || {}).attempts || [];
    const now = Date.now();
    const recent = hist.filter((t) => now - t < WINDOW);

    if (recent.length >= MAX) {
      throw new HttpsError('resource-exhausted', 'Too many reset requests. Try again later or contact your Operations Manager.');
    }
    if (recent.length && now - Math.max(...recent) < COOLDOWN) {
      throw new HttpsError('resource-exhausted', 'Please wait a minute before requesting another PIN.');
    }
    await rlRef.set({attempts: [...recent, now]});

    const usersSnap = await db.ref('users').once('value');
    const all = usersSnap.val() || {};
    const hit = Object.entries(all).find(([, u]) =>
      String(u.phone || '').replace(/[^\d]/g, '').slice(-10) === key &&
      String(u.lastName || '').toLowerCase() === String(lastName).toLowerCase()
    );

    // Deliberately vague: the same response whether or not an account matched,
    // so this cannot be used to probe which numbers are registered.
    const vague = {sent: true};
    if (!hit) return vague;

    const [userId, user] = hit;
    const to = toE164(user.phone);
    if (!to) return vague;

    const site = user.site === 'ALL' ? 'PARF' : user.site;
    const meta = await siteMeta(site);
    const from = toE164(meta.tollFree);
    if (!from || (meta.status || 'pending') !== 'live') return vague;

    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    const rec = makePinRecord(newPin);
    await db.ref(`users/${userId}`).update({pinHash: rec.hash, pinSalt: rec.salt, pin: null, mustChangePin: true});
    await client().messages.create({
      from, to,
      body: `Faire Operations: your new PIN is ${newPin}. Keep it private. If you did not request this, contact your Superuser.`,
    });

    await logActivity('user_changed', user.site, 'system', `PIN reset requested for ${fullName(user)}`);
    return vague;
  }
);

// ---------- 5. smsWebhook ----------
// Twilio posts inbound messages here. Handles STOP, START, and HELP.
// Point each number's "A message comes in" webhook at this URL.
exports.smsWebhook = onRequest({region: REGION}, async (req, res) => {
  const from = toE164(req.body.From);
  const to = toE164(req.body.To);
  const bodyText = String(req.body.Body || '').trim().toUpperCase();

  const reply = (msg) => {
    res.set('Content-Type', 'text/xml');
    res.send(msg
      ? `<Response><Message>${msg}</Message></Response>`
      : '<Response></Response>');
  };

  if (!from || !to) return reply('');

  // Match the inbound number back to a site
  const sitesSnap = await db.ref('sites').once('value');
  const sites = sitesSnap.val() || {};
  let site = null;
  Object.entries(sites).forEach(([code, s]) => {
    if (s.meta && toE164(s.meta.tollFree) === to) site = code;
  });
  if (!site) return reply('');

  const STOP_WORDS = ['STOP', 'STOPALL', 'CANCEL', 'END', 'QUIT', 'UNSUBSCRIBE'];
  const START_WORDS = ['START', 'JOIN', 'SUBSCRIBE', 'YES', 'UNSTOP'];

  if (STOP_WORDS.includes(bodyText)) {
    const existing = (await db.ref(`sites/${site}/optOuts`).once('value')).val() || {};
    const already = Object.values(existing).some((o) => toE164(o.phone) === from);
    if (!already) {
      await db.ref(`sites/${site}/optOuts`).push({
        name: '(via STOP reply)',
        phone: from,
        date: new Date().toLocaleDateString('en-US'),
      });
      await logActivity('optout', site, 'system', `${from} opted out via STOP`);
    }
    // Twilio's Advanced Opt-Out sends its own confirmation; stay silent here
    // to avoid the recipient receiving two messages.
    return reply('');
  }

  if (START_WORDS.includes(bodyText)) {
    const existing = (await db.ref(`sites/${site}/optOuts`).once('value')).val() || {};
    const match = Object.entries(existing).find(([, o]) => toE164(o.phone) === from);
    if (match) {
      await db.ref(`sites/${site}/optOuts/${match[0]}`).remove();
      await logActivity('optout', site, 'system', `${from} resubscribed via START`);
    }
    return reply('');
  }

  if (bodyText === 'HELP' || bodyText === 'INFO') {
    const meta = (sites[site] && sites[site].meta) || {};
    return reply(`${meta.name || site} Alerts: For help, contact 717-665-7021. Reply STOP to unsubscribe.`);
  }

  return reply('');
});

// ---------- 6. migratePins ----------
// One-time conversion of plaintext PINs to salted hashes. Safe to run more
// than once — accounts already migrated are skipped.
exports.migratePins = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');

  const snap = await db.ref('users').once('value');
  const all = snap.val() || {};
  const updates = {};
  let migrated = 0, skipped = 0;

  Object.entries(all).forEach(([id, u]) => {
    if (u.pinHash && u.pinSalt) { skipped++; return; }
    if (!u.pin) { skipped++; return; }
    const rec = makePinRecord(u.pin);
    updates[`users/${id}/pinHash`] = rec.hash;
    updates[`users/${id}/pinSalt`] = rec.salt;
    updates[`users/${id}/pin`] = null;   // remove the plaintext
    migrated++;
  });

  if (Object.keys(updates).length) await db.ref().update(updates);
  return {migrated, skipped};
});

// ---------- 7. login ----------
// The browser no longer reads the user table. It sends a PIN; this returns
// only the matching user's own record, with the PIN material stripped.
exports.login = onCall(
  {region: REGION, secrets: [TWILIO_SID, TWILIO_TOKEN]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {pin} = req.data || {};
    if (!/^\d{4}$/.test(String(pin || ''))) {
      throw new HttpsError('invalid-argument', 'Enter a 4-digit PIN.');
    }

    // Throttle by anonymous auth uid so a single client cannot grind through
    // all 10,000 combinations.
    const uid = req.auth.uid;
    const rlRef = db.ref(`rateLimits/login/${uid}`);
    const rl = (await rlRef.once('value')).val() || {};
    const now = Date.now();
    const recent = (rl.attempts || []).filter((t) => now - t < 15 * 60 * 1000);
    if (recent.length >= 10) {
      throw new HttpsError('resource-exhausted', 'Too many attempts. Wait 15 minutes and try again.');
    }

    const snap = await db.ref('users').once('value');
    const all = snap.val() || {};
    let found = null;
    Object.entries(all).forEach(([id, u]) => {
      if (found) return;
      if (u.pinHash && u.pinSalt) {
        if (checkPin(pin, {hash: u.pinHash, salt: u.pinSalt})) found = [id, u];
      } else if (u.pin && String(u.pin) === String(pin)) {
        found = [id, u];   // pre-migration fallback
      }
    });

    if (!found) {
      await rlRef.set({attempts: [...recent, now]});
      throw new HttpsError('permission-denied', 'PIN not recognized.');
    }
    await rlRef.remove();

    const [userId, user] = found;

    // Send the second-factor code immediately, same call.
    const to = toE164(user.phone);
    if (!to) throw new HttpsError('failed-precondition', 'No valid phone number on this account.');
    const site = user.site === 'ALL' ? 'PARF' : user.site;
    const {from} = await requireSendableSite(site);

    const code = String(Math.floor(100000 + Math.random() * 900000));
    await client().messages.create({
      from, to,
      body: `Faire Operations login code: ${code}. Expires in 5 minutes. If you did not request this, contact your Superuser.`,
    });
    await db.ref(`verificationCodes/${userId}`).set({
      code, purpose: 'login', expires: Date.now() + 5 * 60 * 1000, attempts: 0,
    });

    return {userId, maskedPhone: to.slice(-4), mustChangePin: !!user.mustChangePin};
  }
);

// ---------- 8. getAppData ----------
// Everything the app needs after a verified login, assembled server-side so
// the client never needs read access to the users table.
exports.getAppData = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {userId} = req.data || {};
  if (!userId) throw new HttpsError('invalid-argument', 'Missing userId.');

  const me = await getUser(userId);
  const snap = await db.ref('/').once('value');
  const d = snap.val() || {};

  const allUsers = Object.entries(d.users || {}).map(([id, u]) => publicUser(id, u));
  // Operations Managers only see accounts at their own site.
  const visibleUsers = me.role === 'superadmin'
    ? allUsers
    : allUsers.filter((u) => u.site === me.site);

  const log = Object.entries(d.activityLog || {})
    .map(([id, e]) => Object.assign({lid: id}, e))
    .sort((a, b) => (b.ts || 0) - (a.ts || 0))
    .slice(0, 300);

  return {
    me: publicUser(userId, me),
    users: visibleUsers,
    sites: d.sites || {},
    activityLog: me.role === 'superadmin' ? log : log.filter((e) => e.site === me.site),
    reportSettings: d.reportSettings || {},
    attendanceReport: d.attendanceReport || {},
  };
});

// ---------- 9. saveUserAccount ----------
// Account writes go through here so PINs are hashed before storage and
// permissions are enforced server-side.
exports.saveUserAccount = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId, action, target} = req.data || {};
  const actor = await getUser(actorId);
  if (actor.role !== 'superadmin' && actor.role !== 'admin') {
    throw new HttpsError('permission-denied', 'Not authorized.');
  }

  const usersSnap = await db.ref('users').once('value');
  const all = usersSnap.val() || {};
  const superCount = Object.values(all).filter((u) => u.role === 'superadmin').length;

  if (action === 'create') {
    if (target.role === 'superadmin' && actor.role !== 'superadmin') {
      throw new HttpsError('permission-denied', 'Only a Superuser can create a Superuser.');
    }
    if (actor.role === 'admin' && target.site !== actor.site) {
      throw new HttpsError('permission-denied', 'You can only add accounts at your own site.');
    }
    if (!/^\d{4}$/.test(String(target.pin || ''))) {
      throw new HttpsError('invalid-argument', 'PIN must be exactly 4 digits.');
    }
    // Reject a duplicate PIN — two accounts sharing one would make logins ambiguous.
    const dup = Object.values(all).some((u) =>
      (u.pinHash && u.pinSalt && checkPin(target.pin, {hash: u.pinHash, salt: u.pinSalt})) ||
      (u.pin && String(u.pin) === String(target.pin))
    );
    if (dup) throw new HttpsError('already-exists', 'That PIN is already in use.');

    const rec = makePinRecord(target.pin);
    const id = 'u' + Date.now();
    await db.ref(`users/${id}`).set({
      firstName: target.firstName, lastName: target.lastName,
      phone: target.phone, email: target.email || '',
      role: target.role, site: target.role === 'superadmin' ? 'ALL' : target.site,
      pinHash: rec.hash, pinSalt: rec.salt,
      mustChangePin: true,
    });
    await logActivity('user_changed', target.site, fullName(actor),
      `Created account ${target.firstName} ${target.lastName}`);
    // Put the new staff member on their site's Managers recipient list.
    try {
      const s = target.role === 'superadmin' ? null : target.site;
      if (s) await syncManagersForSite(s);
      else for (const code of ['PARF','SRF','KRF','GARF']) await syncManagersForSite(code);
    } catch (e) { console.warn('manager sync failed:', e.message); }
    return {id};
  }

  if (action === 'update') {
    const existing = all[target.id];
    if (!existing) throw new HttpsError('not-found', 'Account not found.');
    if (actor.role === 'admin' && existing.site !== actor.site) {
      throw new HttpsError('permission-denied', 'You can only edit accounts at your own site.');
    }
    if (existing.role === 'superadmin' && target.role && target.role !== 'superadmin' && superCount <= 1) {
      throw new HttpsError('failed-precondition', 'Assign another Superuser before changing this one.');
    }

    const upd = {};
    ['firstName', 'lastName', 'phone', 'email', 'role', 'site'].forEach((k) => {
      if (target[k] !== undefined) upd[k] = target[k];
    });
    if (upd.role === 'superadmin') upd.site = 'ALL';
    if (target.pin) {
      if (!/^\d{4}$/.test(String(target.pin))) {
        throw new HttpsError('invalid-argument', 'PIN must be exactly 4 digits.');
      }
      const rec = makePinRecord(target.pin);
      upd.pinHash = rec.hash;
      upd.pinSalt = rec.salt;
      upd.pin = null;
    }
    await db.ref(`users/${target.id}`).update(upd);
    await logActivity('user_changed', existing.site, fullName(actor),
      `Updated account ${fullName(existing)}`);
    return {ok: true};
  }

  if (action === 'delete') {
    const existing = all[target.id];
    if (!existing) throw new HttpsError('not-found', 'Account not found.');
    if (actor.role === 'admin' && existing.site !== actor.site) {
      throw new HttpsError('permission-denied', 'You can only remove accounts at your own site.');
    }
    if (existing.role === 'superadmin' && superCount <= 1) {
      throw new HttpsError('failed-precondition', 'Assign another Superuser before deleting this one.');
    }
    await db.ref(`users/${target.id}`).remove();
    await logActivity('user_changed', existing.site, fullName(actor),
      `Deleted account ${fullName(existing)}`);
    return {ok: true};
  }

  throw new HttpsError('invalid-argument', 'Unknown action.');
});

// ---------- 10. adminResetPin ----------
exports.adminResetPin = onCall(
  {region: REGION, secrets: [TWILIO_SID, TWILIO_TOKEN]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {actorId, targetId} = req.data || {};
    const actor = await getUser(actorId);
    if (actor.role !== 'superadmin' && actor.role !== 'admin') {
      throw new HttpsError('permission-denied', 'Not authorized.');
    }
    const target = await getUser(targetId);
    if (actor.role === 'admin' && target.site !== actor.site) {
      throw new HttpsError('permission-denied', 'You can only reset PINs at your own site.');
    }

    const to = toE164(target.phone);
    if (!to) throw new HttpsError('failed-precondition', 'No valid phone number on that account.');
    const site = target.site === 'ALL' ? 'PARF' : target.site;
    const {from} = await requireSendableSite(site);

    const newPin = String(Math.floor(1000 + Math.random() * 9000));
    const rec = makePinRecord(newPin);
    await db.ref(`users/${targetId}`).update({pinHash: rec.hash, pinSalt: rec.salt, pin: null, mustChangePin: true});
    await client().messages.create({
      from, to,
      body: `Faire Operations: your new PIN is ${newPin}. Keep it private.`,
    });
    await logActivity('user_changed', target.site, fullName(actor), `PIN reset for ${fullName(target)}`);
    return {ok: true, maskedPhone: to.slice(-4)};
  }
);

// ---------- 11. syncManagersToList ----------
// Puts every Operations Manager and Superuser onto their site's Managers
// recipient list. Additive only — anyone added by hand stays, and an entry
// marked inactive is left inactive rather than being switched back on.
async function syncManagersForSite(site) {
  const [usersSnap, listSnap] = await Promise.all([
    db.ref('users').once('value'),
    db.ref(`sites/${site}/recipients/managers`).once('value'),
  ]);
  const users = usersSnap.val() || {};
  const list = listSnap.val() || {};
  const members = list.members || {};

  const existing = new Set(
    Object.values(members).map((m) => toE164(m.phone)).filter(Boolean)
  );

  const staff = Object.values(users).filter((u) =>
    (u.role === 'superadmin' || (u.role === 'admin' && u.site === site))
  );

  const updates = {};
  let added = 0;
  staff.forEach((u) => {
    const e = toE164(u.phone);
    if (!e || existing.has(e)) return;
    const key = 'auto_' + Date.now() + '_' + added;
    updates[key] = {
      name: `${u.firstName || ''} ${u.lastName || ''}`.trim() || '(staff)',
      phone: u.phone,
      active: true,
      fromAccount: true,
    };
    added++;
  });

  if (added) {
    await db.ref(`sites/${site}/recipients/managers/members`).update(updates);
    if (!list.name) {
      await db.ref(`sites/${site}/recipients/managers/name`).set('Managers');
    }
  }
  return added;
}

exports.syncManagers = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId, site} = req.data || {};
  const actor = await getUser(actorId);
  if (actor.role !== 'superadmin' && actor.role !== 'admin') {
    throw new HttpsError('permission-denied', 'Not authorized.');
  }

  const targets = actor.role === 'superadmin'
    ? (site ? [site] : ['PARF', 'SRF', 'KRF', 'GARF'])
    : [actor.site];

  const results = {};
  for (const s of targets) {
    results[s] = await syncManagersForSite(s);
  }
  const total = Object.values(results).reduce((a, b) => a + b, 0);
  if (total) {
    await logActivity('list_changed', targets.join(', '), fullName(actor),
      `Synced ${total} staff account(s) onto Managers list(s)`);
  }
  return {results, total};
});

// ---------- 12. changePin ----------
// Self-service PIN change. The PIN is not just a login credential here — it is
// re-entered to dispatch an alert, so an easily guessed one is a real risk on
// a session someone left open.
const WEAK_PINS = new Set([
  '0000','1111','2222','3333','4444','5555','6666','7777','8888','9999',
  '1234','2345','3456','4567','5678','6789','7890',
  '4321','5432','6543','7654','8765','9876','0987',
  '1212','2121','1313','6969','2580','0852','1004','2000','1122','1313',
]);

function pinProblem(pin) {
  if (!/^\d{4}$/.test(String(pin))) return 'PIN must be exactly 4 digits.';
  if (WEAK_PINS.has(String(pin))) return 'That PIN is too easy to guess. Choose another.';
  const d = String(pin);
  if (d[0] === d[1] && d[1] === d[2] && d[2] === d[3]) return 'That PIN is too easy to guess. Choose another.';
  // Reject a birth year, which is the other common pick.
  const asNum = parseInt(d, 10);
  if (asNum >= 1940 && asNum <= 2026) return 'Avoid using a year. Choose another PIN.';
  return null;
}

exports.changePin = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {userId, currentPin, newPin} = req.data || {};
  if (!userId) throw new HttpsError('invalid-argument', 'Missing userId.');

  const user = await getUser(userId);

  // Someone changing a PIN they were just issued has already proven identity
  // through the SMS code, so the current PIN is not demanded again.
  if (!user.mustChangePin) {
    const ok = (user.pinHash && user.pinSalt)
      ? checkPin(currentPin, {hash: user.pinHash, salt: user.pinSalt})
      : (user.pin && String(user.pin) === String(currentPin));
    if (!ok) throw new HttpsError('permission-denied', 'Current PIN is incorrect.');
  }

  const problem = pinProblem(newPin);
  if (problem) throw new HttpsError('invalid-argument', problem);

  if (String(newPin) === String(currentPin)) {
    throw new HttpsError('invalid-argument', 'New PIN must be different from the current one.');
  }

  // A PIN already in use would make logins ambiguous, since login matches on PIN alone.
  const allSnap = await db.ref('users').once('value');
  const all = allSnap.val() || {};
  const taken = Object.entries(all).some(([id, u]) => {
    if (id === userId) return false;
    if (u.pinHash && u.pinSalt) return checkPin(newPin, {hash: u.pinHash, salt: u.pinSalt});
    return u.pin && String(u.pin) === String(newPin);
  });
  if (taken) throw new HttpsError('already-exists', 'That PIN is already in use. Choose another.');

  const rec = makePinRecord(newPin);
  await db.ref(`users/${userId}`).update({
    pinHash: rec.hash,
    pinSalt: rec.salt,
    pin: null,
    mustChangePin: null,
  });

  await logActivity('user_changed', user.site, fullName(user), `${fullName(user)} changed their own PIN`);
  return {ok: true};
});

// ---------- 13. Recipient list review reminders ----------
// Emailed to each site's Operations Managers, Thursday and Friday mornings.
// Superusers are not included — this is a site-level housekeeping task.

const EMAILJS_PRIVATE = defineSecret('EMAILJS_PRIVATE');

const EMAILJS_SERVICE  = 'service_inri5q5';
const EMAILJS_TEMPLATE = 'template_56axz1i';
const EMAILJS_PUBLIC   = 'sB7w0MyBj_u6ayu_0';

async function sendEmail(toEmail, toName, subject, message) {
  const res = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      service_id: EMAILJS_SERVICE,
      template_id: EMAILJS_TEMPLATE,
      user_id: EMAILJS_PUBLIC,
      accessToken: EMAILJS_PRIVATE.value(),
      template_params: {
        to_email: toEmail,
        name: toName,
        email: toEmail,
        subject,
        message,
        time: new Date().toLocaleString('en-US', {timeZone: 'America/New_York'}),
      },
    }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`EmailJS ${res.status}: ${body}`);
  }
  return true;
}

// Report sends are recorded so a failing address is visible rather than silent.
async function recordReportSend(kind, site, recipients, results, subject, body) {
  const failed = results.filter((r) => !r.ok);
  await db.ref('reportHistory').push({
    ts: Date.now(),
    kind,
    site: site || 'ALL',
    total: recipients.length,
    sent: results.filter((r) => r.ok).length,
    failed: failed.length,
    failures: failed.map((f) => ({to: f.to, error: (f.error || '').slice(0, 200)})),
    subject: subject || '',
    body: (body || '').slice(0, 4000),
  });
  // Trim to 30 days so the table stays readable.
  const cutoff = Date.now() - 30 * 86400000;
  const old = await db.ref('reportHistory').orderByChild('ts').endAt(cutoff).once('value');
  const updates = {};
  Object.keys(old.val() || {}).forEach((k) => { updates[k] = null; });
  if (Object.keys(updates).length) await db.ref('reportHistory').update(updates);
}

// Sends to a list, collecting per-address outcomes rather than aborting on failure.
async function sendEmailBatch(recipients, nameFor, subject, message) {
  const results = [];
  for (const to of recipients) {
    try {
      await sendEmail(to, nameFor, subject, message);
      results.push({to, ok: true});
    } catch (e) {
      results.push({to, ok: false, error: e.message});
    }
  }
  return results;
}

const STALE_DAYS = 7;

async function buildReviewReminder(site) {
  const [recSnap, metaSnap] = await Promise.all([
    db.ref(`sites/${site}/recipients`).once('value'),
    db.ref(`sites/${site}/meta`).once('value'),
  ]);
  const rec = recSnap.val() || {};
  const meta = metaSnap.val() || {};
  const now = Date.now();

  const lines = [];
  const stale = [];
  Object.values(rec).forEach((r) => {
    const members = Object.values(r.members || {});
    const active = members.filter((m) => m.active !== false).length;
    const days = r.lastReviewed ? Math.floor((now - r.lastReviewed) / 86400000) : null;
    const isStale = days === null || days >= STALE_DAYS;
    if (isStale) stale.push(r.name);
    lines.push(`  ${r.name}: ${active} active of ${members.length}` +
      (days === null ? '  — never reviewed' : `  — reviewed ${days} day(s) ago`) +
      (isStale ? '  ** REVIEW DUE **' : ''));
  });

  const siteName = meta.name || site;
  const subject = stale.length
    ? `${site} recipient list review due before this weekend`
    : `${site} recipient lists are current`;

  const message = [
    `${siteName} — recipient list review`,
    '',
    stale.length
      ? `The following list(s) have not been reviewed in ${STALE_DAYS} days: ${stale.join(', ')}.`
      : 'All lists have been reviewed recently. No action needed.',
    '',
    'Current lists:',
    ...lines,
    '',
    'Review and update at alerts.lancelotbiz.com before the weekend.',
    'Remove anyone no longer working, and mark seasonal staff inactive rather than deleting them.',
  ].join('\n');

  return {subject, message, staleCount: stale.length};
}

async function runReviewReminders(siteFilter) {
  const usersSnap = await db.ref('users').once('value');
  const users = usersSnap.val() || {};
  const sitesSnap = await db.ref('sites').once('value');
  const sites = sitesSnap.val() || {};

  const codes = siteFilter ? [siteFilter] : Object.keys(sites);
  const results = {};

  for (const site of codes) {
    // Operations Managers at this site only. Superusers are excluded by design.
    const managers = Object.values(users).filter((u) =>
      u.role === 'admin' && u.site === site && u.email
    );
    if (!managers.length) { results[site] = {sent: 0, reason: 'no managers with an email'}; continue; }

    const {subject, message} = await buildReviewReminder(site);
    const batch = await sendEmailBatch(managers.map((m) => m.email), `${site} Alerts`, subject, message);
    const sent = batch.filter((r) => r.ok).length;
    const errors = batch.filter((r) => !r.ok).map((r) => `${r.to}: ${r.error}`);
    await recordReportSend('review', site, managers.map((m) => m.email), batch, subject, message);
    results[site] = {sent, errors};
    if (sent) {
      await logActivity('list_changed', site, 'system',
        `Review reminder emailed to ${sent} Operations Manager(s)`);
    }
  }
  return results;
}

// Manual trigger from the Recipients tab
exports.sendReviewReminder = onCall(
  {region: REGION, secrets: [EMAILJS_PRIVATE]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {actorId, site} = req.data || {};
    const actor = await getUser(actorId);
    if (actor.role !== 'superadmin' && actor.role !== 'admin') {
      throw new HttpsError('permission-denied', 'Not authorized.');
    }
    const target = actor.role === 'superadmin' ? (site || null) : actor.site;
    return await runReviewReminders(target);
  }
);

// Scheduled: Thursday and Friday at 8:00 AM Eastern
exports.scheduledReviewReminder = onSchedule(
  {
    region: REGION,
    schedule: '0 8 * * 4,5',
    timeZone: 'America/New_York',
    secrets: [EMAILJS_PRIVATE],
  },
  async () => {
    const results = await runReviewReminders(null);
    console.log('Scheduled review reminders:', JSON.stringify(results));
  }
);

// ---------- 14. sendPatronCount ----------
// Attendance goes to a fixed audience — Security Personnel and Mt Hope Staff,
// plus the Teams channel. No recipient picker, so a count cannot accidentally
// be broadcast to vendors or performers.
const PATRON_LISTS = ['managers', 'security', 'mt-hope-staff'];
const TEAMS_EMAIL  = 'b1cf51b4.parenfaire.com@amer.teams.ms';

exports.sendPatronCount = onCall(
  {region: REGION, secrets: [TWILIO_SID, TWILIO_TOKEN, EMAILJS_PRIVATE]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {userId, pin, site, count} = req.data || {};

    const user = await getUser(userId);
    if (user.role !== 'superadmin' && user.role !== 'admin') {
      throw new HttpsError('permission-denied', 'Your account cannot send counts.');
    }
    if (user.role === 'admin' && user.site !== site) {
      throw new HttpsError('permission-denied', 'You can only send counts for your own site.');
    }

    const pinOk = (user.pinHash && user.pinSalt)
      ? checkPin(pin, {hash: user.pinHash, salt: user.pinSalt})
      : (user.pin && String(user.pin) === String(pin));
    if (!pinOk) throw new HttpsError('permission-denied', 'Incorrect PIN.');

    const num = parseInt(String(count).replace(/[^\d]/g, ''), 10);
    if (!Number.isFinite(num) || num < 0) {
      throw new HttpsError('invalid-argument', 'Enter a valid patron count.');
    }

    const {from} = await requireSendableSite(site);
    const meta = await siteMeta(site);
    const header = (meta.alertHeader || `${site} OPERATIONS ALERT`).toUpperCase();

    const when = new Date().toLocaleTimeString('en-US',
      {timeZone: 'America/New_York', hour: 'numeric', minute: '2-digit'});
    const body = `${header}\nPatron count as of ${when}: ${num.toLocaleString('en-US')}`;

    // Build the fixed recipient set
    const [recSnap, optSnap] = await Promise.all([
      db.ref(`sites/${site}/recipients`).once('value'),
      db.ref(`sites/${site}/optOuts`).once('value'),
    ]);
    const recipients = recSnap.val() || {};
    const optOuts = optSnap.val() || {};
    const optedOut = new Set(
      Object.values(optOuts).map((o) => toE164(o.phone)).filter(Boolean)
    );

    const numbers = new Set();
    PATRON_LISTS.forEach((lid) => {
      const members = (recipients[lid] && recipients[lid].members) || {};
      Object.values(members).forEach((m) => {
        if (m.active === false) return;
        const e = toE164(m.phone);
        if (e && !optedOut.has(e)) numbers.add(e);
      });
    });

    const results = numbers.size
      ? await sendMany(from, Array.from(numbers), body)
      : {sent: 0, failed: 0, errors: []};

    await db.ref(`sites/${site}/patronCounts`).push({
      ts: Date.now(),
      count: num,
      by: fullName(user),
    });

    await logActivity('patron_count', site, fullName(user),
      `Patron count ${num.toLocaleString('en-US')} sent`,
      {recipients: results.sent, count: num});

    return {sent: results.sent, failed: results.failed, count: num, when};
  }
);

// ---------- 15. Attendance report ----------
// One end-of-day summary instead of an email per count.

function pad(str, len, right) {
  const s = String(str);
  return right ? s.padEnd(len) : s.padStart(len);
}

async function buildAttendanceReport(site, dayKey) {
  const snap = await db.ref(`sites/${site}/patronCounts`).once('value');
  const all = Object.values(snap.val() || {});
  const metaSnap = await db.ref(`sites/${site}/meta`).once('value');
  const meta = metaSnap.val() || {};

  const forDay = all.filter((c) => {
    const d = new Date(c.ts);
    return d.toLocaleDateString('en-CA', {timeZone: 'America/New_York'}) === dayKey;
  }).sort((a, b) => a.ts - b.ts);

  if (!forDay.length) return null;

  const fmtT = (ts) => new Date(ts).toLocaleTimeString('en-US',
    {timeZone: 'America/New_York', hour: 'numeric', minute: '2-digit'});

  const peak = forDay.reduce((m, c) => (c.count > m.count ? c : m), forDay[0]);
  const final = forDay[forDay.length - 1];

  const dateLabel = new Date(forDay[0].ts).toLocaleDateString('en-US',
    {timeZone: 'America/New_York', weekday: 'long', month: 'long', day: 'numeric', year: 'numeric'});

  const lines = [];
  lines.push(`${site} ATTENDANCE \u2014 ${dateLabel}`);
  lines.push(meta.name || site);
  lines.push('');
  forDay.forEach((c) => {
    lines.push(`${pad(fmtT(c.ts), 9)}  ${pad(c.count.toLocaleString('en-US'), 7)}  ${c.by || ''}`);
  });
  lines.push('');
  lines.push(`Peak    ${peak.count.toLocaleString('en-US')} at ${fmtT(peak.ts)}`);
  lines.push(`Final   ${final.count.toLocaleString('en-US')}`);
  lines.push(`Counts  ${forDay.length}`);

  return {
    subject: `${site} attendance \u2014 ${dateLabel} \u2014 final ${final.count.toLocaleString('en-US')}`,
    message: lines.join('\n'),
    entries: forDay,
    final: final.count,
  };
}

async function runAttendanceReport(site, dayKey) {
  const rpt = await buildAttendanceReport(site, dayKey);
  if (!rpt) return {sent: 0, reason: 'no counts recorded'};

  const rsSnap = await db.ref('attendanceReport').once('value');
  const rs = rsSnap.val() || {};
  const recipients = rs.recipients ? Object.values(rs.recipients) : [];
  if (!recipients.length) return {sent: 0, reason: 'no recipients configured'};

  const batch = await sendEmailBatch(recipients, `${site} Attendance`, rpt.subject, rpt.message);
  const sent = batch.filter((r) => r.ok).length;
  const errors = batch.filter((r) => !r.ok).map((r) => `${r.to}: ${r.error}`);
  await recordReportSend('attendance', site, recipients, batch, rpt.subject, rpt.message);
  if (sent) {
    await logActivity('patron_count', site, 'system',
      `Attendance report emailed to ${sent} recipient(s)`);
  }
  return {sent, errors, final: rpt.final, count: rpt.entries.length};
}

exports.sendAttendanceReport = onCall(
  {region: REGION, secrets: [EMAILJS_PRIVATE]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {actorId, site, day} = req.data || {};
    const actor = await getUser(actorId);
    if (actor.role !== 'superadmin' && actor.role !== 'admin') {
      throw new HttpsError('permission-denied', 'Not authorized.');
    }
    const target = actor.role === 'superadmin' ? (site || 'PARF') : actor.site;
    const dayKey = day || new Date().toLocaleDateString('en-CA', {timeZone: 'America/New_York'});
    return await runAttendanceReport(target, dayKey);
  }
);

// 11:00 PM Eastern, every day. Silent on days with no counts.
exports.scheduledAttendanceReport = onSchedule(
  {
    region: REGION,
    schedule: '0 23 * * *',
    timeZone: 'America/New_York',
    secrets: [EMAILJS_PRIVATE],
  },
  async () => {
    const sitesSnap = await db.ref('sites').once('value');
    const sites = Object.keys(sitesSnap.val() || {});
    const dayKey = new Date().toLocaleDateString('en-CA', {timeZone: 'America/New_York'});
    const out = {};
    for (const site of sites) {
      out[site] = await runAttendanceReport(site, dayKey);
    }
    console.log('Scheduled attendance reports:', JSON.stringify(out));
  }
);

// Returns the day's counts so the client can build a CSV without extra reads.
exports.getAttendanceDay = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId, site, day} = req.data || {};
  const actor = await getUser(actorId);
  const target = actor.role === 'superadmin' ? (site || 'PARF') : actor.site;
  const dayKey = day || new Date().toLocaleDateString('en-CA', {timeZone: 'America/New_York'});
  const rpt = await buildAttendanceReport(target, dayKey);
  return rpt ? {entries: rpt.entries, final: rpt.final, site: target, day: dayKey}
             : {entries: [], site: target, day: dayKey};
});

// Recent counts with their record ids, so entries can be removed individually.
exports.getRecentCounts = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId, site} = req.data || {};
  const actor = await getUser(actorId);
  const target = actor.role === 'superadmin' ? (site || 'PARF') : actor.site;

  // Today only. Older counts stay in the database and in report history —
  // this just keeps the screen from carrying yesterday's numbers forward.
  const dayKey = new Date().toLocaleDateString('en-CA', {timeZone: 'America/New_York'});
  const snap = await db.ref(`sites/${target}/patronCounts`)
    .orderByChild('ts').limitToLast(60).once('value');
  const rows = Object.entries(snap.val() || {})
    .map(([id, c]) => Object.assign({id}, c))
    .filter((c) => new Date(c.ts).toLocaleDateString('en-CA', {timeZone: 'America/New_York'}) === dayKey)
    .sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return {counts: rows, day: dayKey};
});

// Recipient list for the attendance report, kept separate from the activity digest.
exports.setAttendanceRecipients = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId, recipients} = req.data || {};
  const actor = await getUser(actorId);
  if (actor.role !== 'superadmin') {
    throw new HttpsError('permission-denied', 'Only a Superuser can change report recipients.');
  }
  const obj = {};
  (recipients || []).forEach((e, i) => { obj['r' + i] = e; });
  await db.ref('attendanceReport/recipients').set(obj);
  return {ok: true};
});

// ---------- 16. Activity digest + report history ----------

exports.sendActivityReport = onCall(
  {region: REGION, secrets: [EMAILJS_PRIVATE]},
  async (req) => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
    const {actorId, subject, message, site} = req.data || {};
    const actor = await getUser(actorId);
    if (actor.role !== 'superadmin' && actor.role !== 'admin') {
      throw new HttpsError('permission-denied', 'Not authorized.');
    }

    const rsSnap = await db.ref('reportSettings/recipients').once('value');
    const recipients = Object.values(rsSnap.val() || {});
    if (!recipients.length) {
      throw new HttpsError('failed-precondition', 'No report recipients configured.');
    }

    const batch = await sendEmailBatch(recipients, 'Faire Operations', subject, message);
    const sent = batch.filter((r) => r.ok).length;
    await recordReportSend('activity', site || 'ALL', recipients, batch, subject, message);

    return {
      sent,
      failed: batch.length - sent,
      failures: batch.filter((r) => !r.ok).map((r) => ({to: r.to, error: r.error})),
    };
  }
);

exports.getReportHistory = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId} = req.data || {};
  const actor = await getUser(actorId);

  const snap = await db.ref('reportHistory').orderByChild('ts').limitToLast(120).once('value');
  let rows = Object.entries(snap.val() || {}).map(([id, r]) => Object.assign({id}, r));
  rows.sort((a, b) => (b.ts || 0) - (a.ts || 0));

  // Operations Managers only see their own site's reports.
  if (actor.role !== 'superadmin') {
    rows = rows.filter((r) => r.site === actor.site);
  }
  return {history: rows};
});

// ---------- 17. deletePatronCount ----------
// Removes a single count entry. Scoped deliberately narrow — there is no
// bulk delete, so a mistake costs one row rather than a day of records.
exports.deletePatronCount = onCall({region: REGION}, async (req) => {
  if (!req.auth) throw new HttpsError('unauthenticated', 'Sign in first.');
  const {actorId, site, entryId} = req.data || {};
  if (!site || !entryId) throw new HttpsError('invalid-argument', 'Missing site or entry.');

  const actor = await getUser(actorId);
  if (actor.role !== 'superadmin') {
    throw new HttpsError('permission-denied', 'Only a Superuser can remove a recorded count.');
  }

  const ref = db.ref(`sites/${site}/patronCounts/${entryId}`);
  const entry = (await ref.once('value')).val();
  if (!entry) throw new HttpsError('not-found', 'That entry no longer exists.');

  await ref.remove();
  await logActivity('patron_count', site, fullName(actor),
    `Removed patron count of ${Number(entry.count).toLocaleString('en-US')} recorded at ` +
    new Date(entry.ts).toLocaleTimeString('en-US', {timeZone: 'America/New_York', hour: 'numeric', minute: '2-digit'}));

  return {ok: true};
});
