# Privacy Policy — AWS Credential Helper

**Last updated:** June 2026

## What this extension does

AWS Credential Helper intercepts the SAML POST made by your browser during an Okta → AWS sign-in and uses the SAML assertion to call AWS STS and mint a set of temporary IAM credentials. Those credentials are displayed in the extension popup for you to copy. Supported Okta domains include `*.okta.com`, `*.oktapreview.com`, and `*.okta-emea.com`. A custom Okta domain may also be configured in settings.

## Data collected

This extension collects **no personal data**. The SAML assertion intercepted during sign-in is transiently held in service worker memory solely to call AWS STS — it is never written to disk, logged, or transmitted to any party other than `sts.amazonaws.com` (or `sts.cn-north-1.amazonaws.com.cn` for China). It is discarded immediately after credentials are minted.

| Data | Where it lives | When it's cleared |
|---|---|---|
| AWS temporary credentials (access key, secret key, session token) | `chrome.storage.session` (RAM only), AES-GCM encrypted — decryption key held only in service worker memory | On browser close, or when you click **✕ clear all sessions** |
| Extension settings (session duration, China partition toggle, custom Okta domain) | `chrome.storage.local` (local device only, never synced) | When you uninstall the extension |

## Data sharing

- **No data ever leaves your browser** other than the two AWS endpoints required for normal operation: `signin.aws.amazon.com` (or `signin.amazonaws.cn`) and `sts.amazonaws.com` (or `sts.cn-north-1.amazonaws.com.cn`).
- No analytics, telemetry, logging, or remote scripts of any kind.
- No third-party services are contacted.

## Permissions used

| Permission | Why |
|---|---|
| `webRequest` + host permissions for AWS sign-in URLs | To read the SAML assertion from the form POST (non-blocking; does not modify or cancel the request). When no HTTP referrer is present (common with identity-provider auto-submit forms), the POST is still processed because AWS STS independently validates the SAML cryptographic signature — a forged assertion cannot mint credentials. |
| `storage` | To persist settings locally and hold encrypted credentials in session storage |
| `offscreen` | To safely parse XML using the browser's DOM parser (MV3 service workers lack `DOMParser`) |
| `clipboardRead` (optional) | To verify clipboard contents before auto-clearing after 60 seconds, preventing stale credentials from persisting. Requested only when the user first copies a credential value — never on startup. |

## Topmate support link

The settings panel contains a hyperlink to the developer's Topmate support page (`topmate.io/ergdev/2144445`). Clicking it opens Topmate in a new browser tab. The extension transmits no data to Topmate; the link is purely navigational. Paying is entirely optional — the extension is free and GPL-licensed regardless.

## Contact

For questions or concerns: [@ergdevops](https://github.com/ergdevops) — support@ergdev.in
