const {onCall, onRequest, HttpsError} = require('firebase-functions/v2/https');
const {defineSecret} = require('firebase-functions/params');
const admin = require('firebase-admin');
const twilio = require('twilio');

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

    const {userId, site, listIds, message, alertName, category, isDrill} = req.data || {};
    if (!userId || !site || !Array.isArray(listIds) || !listIds.length || !message) {
      throw new HttpsError('invalid-argument', 'Missing required fields.');
    }

    const user = await getUser(userId);
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
        const e = toE164(m.phone);
        if (e && !optedOut.has(e)) numbers.add(e);
      });
    });

    if (numbers.size === 0) {
      throw new HttpsError('failed-precondition', 'No valid recipients on the selected lists.');
    }

    const results = await sendMany(from, Array.from(numbers), message);

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
    await db.ref(`users/${userId}/pin`).set(newPin);
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
