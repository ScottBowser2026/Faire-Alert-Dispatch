# Faire Alert Dispatch

Multi-site operational alert dispatch system for Lancelot Entertainment Investment Co.

## Properties

| Code | Property | Status |
|---|---|---|
| PARF | Pennsylvania Renaissance Faire | Live |
| SRF | Scarborough Renaissance Faire | Pending toll-free verification |
| KRF | King Richard's Faire | Pending toll-free verification |
| GARF | Georgia Renaissance Faire | Pending toll-free verification |

## Roles

- **Superuser** — cross-site access, Sites tab, Reports config, Test tab
- **Operations Manager** — scoped to one site, can send alerts and manage that site's recipients

## Login

4-digit PIN followed by a 6-digit verification code sent to the user's own phone.
Active Shooter alerts additionally require double confirmation plus a one-time code.

## Alert categories

- **Gate Status** — Opening / Closing
- **Weather** — Event / Non-Show
- **Safety Alert** — Emergency / All Clear
- **Test** — Superuser only, includes Active Shooter Drill

## Stack

- Firebase Realtime Database (`faire-alert-system` instance)
- Firebase Anonymous Auth
- GitHub Pages hosting

## Deploying an update

Every deploy must bump the version in **two** places, or clients won't be
prompted to refresh:

1. `APP_VERSION` near the top of the `<script>` block in `index.html`
2. the `"version"` value in `version.json`

Use the same value in both (e.g. `2026.09.02.1`). Open tabs poll
`version.json` every 5 minutes and on refocus; on a mismatch they show a
"new version available" banner with a Reload button — no auto-refresh, so
no one gets kicked out mid-alert-send.

## Not yet connected

SMS sending, verification codes, PIN reset texts, and the emailed report are
simulated. Demo codes display on screen. These require Cloud Functions on the
Firebase Blaze plan, which holds the Twilio credentials — those cannot live in
client-side code.

## Data structure

```
users/{userId}
sites/{code}/meta            name, tollFree, status
sites/{code}/recipients/{listId}/members/{memberId}
sites/{code}/optOuts/{id}
activityLog/{id}
reportSettings
```
