// AWS Credential Helper — Copyright (C) 2026 Arghaya Mondal
// SPDX-License-Identifier: GPL-3.0-or-later
const SAML_ENDPOINT_GLOBAL = "https://signin.aws.amazon.com/saml";
const SAML_ENDPOINT_CHINA = "https://signin.amazonaws.cn/saml";
const STS_ENDPOINT_GLOBAL = "https://sts.amazonaws.com/";
const STS_ENDPOINT_CHINA = "https://sts.cn-north-1.amazonaws.com.cn/";
const OFFSCREEN_URL = "offscreen.html";
const TRUSTED_INITIATOR_SUFFIXES = [".okta.com", ".oktapreview.com"];
const PENDING_TTL_MS = 5 * 60_000;
// base64 encodes ~4/3 of source; cap the b64 string at 4/3 × 2 MB
const SAML_MAX_B64_CHARS = Math.ceil(2 * 1024 * 1024 * 4 / 3);
const ROLE_ARN_RE = /^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/; // H1 — validate roleArn

// ─── per-session AES-GCM key (memory only, never stored) ─────
let sessionKey = null;

async function getSessionKey() {
  if (sessionKey) return sessionKey;
  sessionKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
  return sessionKey;
}

async function encryptObject(obj) {
  const key = await getSessionKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(obj));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  return { iv: Array.from(iv), ciphertext: Array.from(new Uint8Array(ciphertext)) };
}

async function decryptObject(blob) {
  if (!sessionKey) return null;
  const iv = new Uint8Array(blob.iv);
  const ciphertext = new Uint8Array(blob.ciphertext);
  try {
    const decoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, sessionKey, ciphertext);
    return JSON.parse(new TextDecoder().decode(decoded));
  } catch {
    return null;
  }
}

// ─── credentials map helpers ─────────────────────────────────
async function getCredsMap() {
  const { credentialsMap } = await chrome.storage.session.get("credentialsMap");
  if (!credentialsMap) return {};
  const map = await decryptObject(credentialsMap);
  if (!map) {
    await chrome.storage.session.remove("credentialsMap");
    return {};
  }
  return map;
}

async function saveCredsMap(map) {
  const encrypted = await encryptObject(map);
  await chrome.storage.session.set({ credentialsMap: encrypted });
}

// ─── settings ────────────────────────────────────────────────
async function getSettings() {
  const { sessionHours = 1, chinaPartition = false, customOktaDomain = "" } = await chrome.storage.local.get(["sessionHours", "chinaPartition", "customOktaDomain"]);
  return { sessionHours, chinaPartition, customOktaDomain };
}

const OKTA_DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(okta\.com|oktapreview\.com|okta-emea\.com)$/;

async function getTrustedSuffixes() {
  const { customOktaDomain } = await getSettings();
  const suffixes = [...TRUSTED_INITIATOR_SUFFIXES];
  if (customOktaDomain && OKTA_DOMAIN_RE.test(customOktaDomain)) suffixes.push(customOktaDomain);
  return suffixes;
}

function isTrustedInitiator(initiator, trustedSuffixes) {
  if (!initiator) return false;
  try {
    const url = new URL(initiator);
    if (url.protocol !== "https:") return false;
    return trustedSuffixes.some((s) => url.hostname === s || url.hostname.endsWith("." + s));
  } catch {
    return false;
  }
}

async function isAcceptableSamlPost(details) {
  if (details.method !== "POST") return false;
  if (details.tabId < 0) return false;
  if (details.type !== "main_frame") return false;
  if (!details.requestBody?.formData) return false;
  const trustedSuffixes = await getTrustedSuffixes();
  // Trusted initiator → safe to auto-assume a single role.
  if (isTrustedInitiator(details.initiator, trustedSuffixes)) return { ok: true, trusted: true };
  // Missing initiator is common (no-referrer auto-submit forms) but is NOT
  // proof of user intent: a replayed/forged top-level POST looks identical.
  // Accept the capture but require explicit confirmation before calling STS,
  // so a silent assertion-replay cannot mint credentials.
  if (!details.initiator) return { ok: true, trusted: false };
  return { ok: false, trusted: false };
}

// ─── webRequest listener ──────────────────────────────────────
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    (async () => {
      try {
        const verdict = await isAcceptableSamlPost(details);
        if (!verdict.ok) return;
        const samlField = details.requestBody.formData.SAMLResponse;
        if (!samlField || !samlField[0]) return;
        // reject oversized assertions before decoding (cap on b64 chars)
        if (samlField[0].length > SAML_MAX_B64_CHARS) return;
        const china = details.url.startsWith(SAML_ENDPOINT_CHINA);
        handleSamlResponse(samlField[0], china, verdict.trusted).catch(() => {});
      } catch (_) {}
    })();
  },
  { urls: [SAML_ENDPOINT_GLOBAL, SAML_ENDPOINT_CHINA] },
  ["requestBody"]
);

// ─── offscreen helpers ────────────────────────────────────────
async function ensureOffscreen() {
  const url = chrome.runtime.getURL(OFFSCREEN_URL);
  if (chrome.runtime.getContexts) {
    const ctxs = await chrome.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"], documentUrls: [url] });
    if (ctxs.length) return;
  }
  try {
    await chrome.offscreen.createDocument({
      url: OFFSCREEN_URL,
      reasons: ["DOM_PARSER"],
      justification: "Parse SAML and STS XML responses safely with DOMParser.",
    });
  } catch (e) {
    if (!String(e).includes("Only a single offscreen")) throw e;
  }
}

async function offscreenSend(payload) {
  await ensureOffscreen();
  return await chrome.runtime.sendMessage({ target: "offscreen", ...payload });
}

// ─── SAML → STS flow ─────────────────────────────────────────
async function handleSamlResponse(samlB64, china = false, trusted = false) {
  const samlXml = atobUtf8(samlB64);
  const resp = await offscreenSend({ type: "parseSaml", xml: samlXml });
  if (!resp?.ok) throw new Error(resp?.error || "saml parse failed");
  const roles = resp.roles;
  if (!roles || roles.length === 0) throw new Error("No AWS roles in SAML assertion");

  // Only auto-assume when the capture came from a trusted initiator. An
  // untrusted/no-initiator capture always requires explicit confirmation,
  // even for a single role, so a silent replay cannot mint credentials.
  if (roles.length === 1 && trusted) {
    await assumeAndStore(roles[0], samlB64, china);
    return;
  }

  // Stash for the popup to confirm/pick. needsConfirm is true when the capture
  // was not from a trusted initiator (this also covers the single-role case).
  const encrypted = await encryptObject({
    samlAssertion: samlB64, roles, china,
    needsConfirm: !trusted, createdAt: Date.now(),
  });
  await chrome.storage.session.set({ pending: encrypted });
}

async function assumeAndStore(role, samlB64, china = false) {
  const creds = await assumeRoleWithSaml(role.principalArn, role.roleArn, samlB64, china);
  if (!creds.AccessKeyId || !creds.SecretAccessKey || !creds.SessionToken) {
    throw new Error("STS returned incomplete credentials");
  }
  const accountId = role.roleArn.split(":")[4];
  const roleName = role.roleArn.split("role/")[1] || role.roleArn;

  const map = await getCredsMap();
  map[role.roleArn] = {
    accountId,
    roleName,
    roleArn: role.roleArn,
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.SessionToken,
    expiration: creds.Expiration,
    capturedAt: new Date().toISOString(),
  };
  await saveCredsMap(map);
}

async function assumeRoleWithSaml(principalArn, roleArn, samlAssertion, china = false) {
  const { sessionHours } = await getSettings();
  const durationSeconds = String(Math.min(12, Math.max(1, sessionHours)) * 3600);
  const stsEndpoint = china ? STS_ENDPOINT_CHINA : STS_ENDPOINT_GLOBAL;
  const body = new URLSearchParams({
    Action: "AssumeRoleWithSAML",
    Version: "2011-06-15",
    PrincipalArn: principalArn,
    RoleArn: roleArn,
    SAMLAssertion: samlAssertion,
    DurationSeconds: durationSeconds,
  });
  const res = await fetch(stsEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!res.ok) throw new Error(`STS ${res.status}`);
  const text = await res.text();
  const resp = await offscreenSend({ type: "parseSts", xml: text });
  if (!resp?.ok) throw new Error(resp?.error || "sts parse failed");
  return resp.creds;
}

function atobUtf8(b64) {
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder("utf-8").decode(bytes);
}

// ─── message handlers ─────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return;
  if (msg?.target === "offscreen") return;

  if (msg?.type === "getCredentials") {
    (async () => {
      const { credentialsMap: rawCreds } = await chrome.storage.session.get("credentialsMap");
      const map = await getCredsMap();
      const sessionExpired = !!rawCreds && Object.keys(map).length === 0;
      const { pending } = await chrome.storage.session.get("pending");
      const pend = pending ? await decryptObject(pending) : null;
      if (pending && !pend) await chrome.storage.session.remove("pending");
      // L3 — evict expired pending in getCredentials, not just in selectRole
      if (pend && Date.now() - pend.createdAt > PENDING_TTL_MS) {
        await chrome.storage.session.remove("pending");
        sendResponse({ ok: true, credentialsMap: map, pending: null, sessionExpired });
        return;
      }
      // strip raw SAML assertion — popup only needs roles list + confirm flag
      const safePend = pend ? { roles: pend.roles, china: pend.china, needsConfirm: !!pend.needsConfirm, createdAt: pend.createdAt } : null;
      sendResponse({ ok: true, credentialsMap: map, pending: safePend, sessionExpired });
    })();
    return true;
  }

  if (msg?.type === "clearCredentials") {
    chrome.storage.session.remove(["credentialsMap", "pending"]).then(() => sendResponse({ ok: true }));
    return true;
  }

  if (msg?.type === "clearRole") {
    (async () => {
      // H1 — validate roleArn before using as object key
      if (!ROLE_ARN_RE.test(msg.roleArn)) return sendResponse({ ok: false, error: "invalid roleArn" });
      const map = await getCredsMap();
      delete map[msg.roleArn];
      if (Object.keys(map).length > 0) {
        await saveCredsMap(map);
      } else {
        await chrome.storage.session.remove("credentialsMap");
      }
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (msg?.type === "selectRole") {
    (async () => {
      const { pending } = await chrome.storage.session.get("pending");
      if (!pending) return sendResponse({ ok: false, error: "no pending selection" });
      const pend = await decryptObject(pending);
      if (!pend) {
        await chrome.storage.session.remove("pending");
        return sendResponse({ ok: false, error: "session expired; sign in again" });
      }
      if (Date.now() - pend.createdAt > PENDING_TTL_MS) {
        await chrome.storage.session.remove("pending");
        return sendResponse({ ok: false, error: "selection expired; sign in again" });
      }
      if (!ROLE_ARN_RE.test(msg.roleArn)) return sendResponse({ ok: false, error: "invalid roleArn" });
      const role = pend.roles.find((r) => r.roleArn === msg.roleArn);
      if (!role) return sendResponse({ ok: false, error: "role not in assertion" });
      try {
        await assumeAndStore(role, pend.samlAssertion, pend.china ?? false);
        // keep pending so the picker stays for additional roles
        sendResponse({ ok: true });
      } catch (e) {
        sendResponse({ ok: false, error: e.message || String(e) });
      }
    })();
    return true;
  }

  if (msg?.type === "settingsUpdated") {
    // M2 — ignore payload; re-read settings from storage on demand
    sendResponse({ ok: true });
    return true;
  }

  // catch-all — reject unknown message types rather than silently dropping
  sendResponse({ ok: false, error: "unknown message type" });
});
