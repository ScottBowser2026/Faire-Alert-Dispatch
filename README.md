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
