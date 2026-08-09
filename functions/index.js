const {onCall, onRequest, HttpsError} = require('firebase-functions/v2/https');
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
