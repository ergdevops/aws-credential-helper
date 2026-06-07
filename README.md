# AWS Credential Helper

A Chrome extension that captures AWS temporary credentials from your Okta → AWS SAML sign-in and surfaces them in a popup, ready to paste into `~/.aws/credentials`, a Bash/Zsh shell, or PowerShell by [@ergdevops](https://github.com/ergdevops)

No credentials ever leave your browser. No backend, no telemetry, no remote scripts. See [PRIVACY.md](PRIVACY.md) for full details.

> **Chrome Web Store listing note:** This extension uses `webRequest` (read-only, non-blocking) to read the SAML assertion from the Okta→AWS sign-in POST. No request is modified or cancelled. It includes an optional support link to the developer.

---

## What it does

When you sign in to AWS via your Okta tile:

1. Okta POSTs a signed **SAMLResponse** to `https://signin.aws.amazon.com/saml`.
2. AWS consumes that assertion server-side and gives your browser a console-session cookie. The actual AWS access key, secret key, and session token **never reach the browser** — they live only inside AWS.
3. This extension watches that same POST, grabs a copy of the SAMLResponse, and calls **`sts:AssumeRoleWithSAML`** itself against `https://sts.amazonaws.com/` to mint a **parallel** set of temporary credentials (1-hour by default) for the same role.
4. Those credentials are stored in `chrome.storage.session` (RAM only; cleared when Chrome closes) and shown in the toolbar popup.

The popup formats credentials three ways and copies on click:

- `~/.aws/credentials` block (`[default]` profile)
- Bash / Zsh `export` lines
- PowerShell `$env:` lines

If your SAML assertion contains **multiple roles**, a role picker appears. You can assume roles **individually and simultaneously** — each assumed role gets its own credential card. Assume as many as you need in one session.

A **settings panel** (⚙ icon in the header) lets you configure:
- Session duration (1–12 hours)
- AWS China partition support
- Custom Okta domain (for non-standard Okta URLs)

No code editing required.

---

## Install

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked**
4. Pick this folder
5. Pin the extension to the toolbar so you can see the icon

That's it. No build step.

---

## Using it

1. Sign in to AWS via your Okta AWS tile as usual.
2. Click the key-icon in the Chrome toolbar.
3. The popup shows credential cards with account ID, role name, time remaining, and the three credential formats.
4. Click `⎘` next to any block (or any single value) to copy.

**Multi-role workflow:**
- If your SAML assertion contains multiple roles, a **role picker** appears at the top.
- Select a role and click **assume** — a credential card appears.
- The picker stays open. Select another role and assume again to add more cards.
- Already-assumed roles show a **✓** in the picker.
- Click **✕** on any card to remove just that role's credentials.
- Click **✕ clear all sessions** in the footer to wipe everything.

The secret access key and session token are masked by default (`wZ4G••••••••NjPL`). Click the `◐` icon next to a value to reveal it.

When credentials expire, the card border turns red. Sign in to AWS again to refresh.

Click the **⚙** icon in the header to open settings:
- **Session duration** — set credential lifetime from 1 to 12 hours (saved locally via `chrome.storage.local`).
- **AWS China partition** — toggle on to intercept sign-ins via `signin.amazonaws.cn` and call `sts.cn-north-1.amazonaws.com.cn`.
- **Custom Okta domain** — enter your organisation's Okta URL (e.g. `mycompany.okta.com`) if you use a vanity domain instead of the standard `.okta.com` suffix. The domain is added to the trusted initiator list at sign-in time — no code changes needed.

---

## How it works (technical)

### 1. Intercepting the SAML POST

`background.js` registers a `chrome.webRequest.onBeforeRequest` listener on `https://signin.aws.amazon.com/saml`. With the `["requestBody"]` extra-info option, Chrome decodes the form body and exposes `details.requestBody.formData.SAMLResponse`. This is a **non-blocking** read — the request continues to AWS exactly as normal.

### 2. Origin / context guards

Before processing, the listener requires:

- `details.method === "POST"`
- `details.tabId >= 0` (came from a real tab, not a background context)
- `details.type === "main_frame"` (top-level navigation, not a subframe)
- Either `details.initiator` ends in a trusted Okta suffix (`.okta.com` / `.oktapreview.com`), **or** `initiator` is `undefined` — many IdPs use a `no-referrer` policy on their auto-submit form, which strips the origin. In that case STS's own assertion-signature check is what keeps the path safe: only assertions signed by a configured IdP can mint credentials.

If you use a custom Okta domain, enter it in the ⚙ settings panel under **custom okta domain** (e.g. `mycompany.okta.com`). No code editing required.

### 3. Parsing the assertion

MV3 service workers do not have `DOMParser`. The extension spins up an **offscreen document** (`offscreen.html` / `offscreen.js`) via `chrome.offscreen.createDocument` solely to safely parse XML with the real DOM. It extracts the `https://aws.amazon.com/SAML/Attributes/Role` attribute, splits each `AttributeValue` on `,`, and validates both halves are well-formed ARNs:

- `arn:aws:iam::<acct>:saml-provider/<name>` (principal)
- `arn:aws:iam::<acct>:role/<name>` (role)

### 4. Assuming the role

`background.js` reads \`sessionHours\` from \`chrome.storage.local\` (set via the settings panel, default 1 h) and posts a form-encoded `AssumeRoleWithSAML` call to the appropriate STS endpoint — `https://sts.amazonaws.com/` for global or `https://sts.cn-north-1.amazonaws.com.cn/` for China:

```
Action=AssumeRoleWithSAML
Version=2011-06-15
PrincipalArn=arn:aws:iam::…:saml-provider/Okta
RoleArn=arn:aws:iam::…:role/Prod-admin-access
SAMLAssertion=<the same base64 SAMLResponse>
DurationSeconds=3600
```

This is an **unsigned** API call — the SAML assertion is the authentication material. STS returns XML with `AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`. The offscreen parser pulls those values out, the SW writes them to `chrome.storage.session.credentials`, and the popup reads them.

### 5. Credential encryption

Before writing to `chrome.storage.session`, credentials and pending SAML state are encrypted using **AES-GCM 256-bit** via the Web Crypto API:

1. A non-extractable AES-GCM key is generated at service worker startup using `crypto.subtle.generateKey` and held only in a module-level variable — it is never written to any storage.
2. A fresh random 12-byte IV is generated for every encryption operation.
3. The plain object is JSON-serialised, encrypted, and stored as `{ iv: [...], ciphertext: [...] }`.
4. The popup never reads storage directly — it sends a `getCredentials` message to the service worker, which decrypts and returns the plain object.
5. If the service worker is killed and restarted (key lost), stale encrypted blobs are detected, wiped, and the popup reverts to "waiting for sign-in".

### 6. Multi-role assertions

When your SAML assertion lists more than one role, the SW encrypts and stores the full list as `pending` (with a 5-minute TTL) and the popup shows a role picker. You can assume roles one at a time — each assumed role is added to an encrypted credentials map (`{ [roleArn]: credObject }`) in `chrome.storage.session`. The picker stays open so you can assume additional roles. The SW verifies the chosen `roleArn` is present in the stored assertion before calling STS — you can't pick an arbitrary ARN. Removing a single card sends a `clearRole` message to the SW, which deletes only that role from the map.

---

## Security model

| Concern | Mitigation |
|---|---|
| Credential exfiltration | Credentials are AES-GCM encrypted before being written to `chrome.storage.session`. The 256-bit key is generated at service worker startup and held only in memory — never stored. No remote endpoints other than the AWS sign-in and STS URLs. No analytics. |
| Cross-origin SAML forgery | Initiator allow-list + `main_frame` + `tabId >= 0` checks. Even if bypassed, STS rejects any assertion not signed by a configured IdP. |
| XSS in popup | All credential rendering uses `.textContent`, never `innerHTML`. CSP follows MV3 defaults — no inline scripts, no remote code. |
| XML injection / namespace tricks | Offscreen `DOMParser` with namespace-aware lookup (`getElementsByTagNameNS("*", …)`); ARN values validated against a strict regex. |
| Clipboard retention | After copy, the extension waits 60 s and overwrites the clipboard if it still contains the credential it wrote. |
| Stale credentials | Popup compares `Expiration` to `Date.now()` and surfaces "expired" status. |
| Long-lived storage | Session-scoped storage clears on browser close. Manual `✕ clear session` button wipes immediately. |

### Limitations

- Uses non-blocking `webRequest` to read SAML request bodies, which is permitted under MV3. However, Chrome Web Store review may scrutinize extensions that access authentication data such as SAML assertions — this extension is intended for unpacked / internal / enterprise-policy installs.
- Session duration is configurable from 1–12 hours via the ⚙ settings panel. The upper bound is set by your IAM role's `MaxSessionDuration`.
- AWS China partition (`signin.amazonaws.cn`) is supported — enable it via the settings panel toggle.

---

## File layout

```
manifest.json    MV3 manifest, permissions, icons
background.js    Service worker: intercept → assume → store; reads settings
offscreen.html   Hosts the DOMParser (SWs lack DOM)
offscreen.js     SAML / STS XML parsing
popup.html       Toolbar popup markup (includes settings panel)
popup.css        Dark theme (GitHub-dark base, amber accent)
popup.js         Renders credentials, settings panel (duration + China toggle)
icon*.png        16 / 32 / 48 / 128 px key icon
```

---

## Troubleshooting

**Popup says "waiting for SAML sign-in" after signing in.**
Open `chrome://extensions` → the extension's "service worker" link → Console tab. Sign in again. If you see nothing, the listener never fired — the SAML POST may be going to a different URL. If you see `rejected:` log lines, the initiator guard caught it; check `TRUSTED_INITIATOR_SUFFIXES` in `background.js`.

**Role picker didn't appear / only one role available.**
Check that more than one role is present in the `Role` attribute of the SAML response. If only one role is in the assertion, the SW assumes it automatically without showing the picker.

**"STS 403" or similar.**
The role's `MaxSessionDuration` may be shorter than the `DurationSeconds` requested. Lower `DurationSeconds` in `background.js`.

**Icon doesn't appear.**
Pin the extension to the toolbar via the puzzle-piece menu.

---

## Support

I build Android device trees, custom ROM support, and dev tools like AWS Credential Helper. Open source, no ads, no paywalls — just code. Support the work if it's been useful.

[**Support this project on Topmate ($5)**](https://topmate.io/ergdev/2144445)



---

## Credits


---

## License

[GNU GPL v3.0](LICENSE) — free to use, modify, and distribute, with the requirement that derivative works are also licensed under the GPL and their source code remains available. No warranty.

Copyright © 2026 Arghaya Mondal.
