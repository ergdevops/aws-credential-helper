// AWS Credential Helper — Copyright (C) 2026 Arghaya Mondal
// SPDX-License-Identifier: GPL-3.0-or-later
const $ = (id) => document.getElementById(id);
const CLIPBOARD_CLEAR_MS = 60_000;
const ROLE_ARN_RE = /^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/;

function untilTime(iso) {
  if (!iso) return "—";
  const diff = new Date(iso).getTime() - Date.now();
  if (diff <= 0) return "expired";
  const m = Math.floor(diff / 60000);
  if (m < 60) return `⏱ ${m}m`;
  const h = Math.floor(m / 60);
  return `⏱ ${h}h${String(m % 60).padStart(2, "0")}m`;
}

const fmtCredsFile = (c) =>
  `[default]\naws_access_key_id = ${c.accessKeyId}\naws_secret_access_key = ${c.secretAccessKey}\naws_session_token = ${c.sessionToken}\n`;
const fmtBash = (c) =>
  `export AWS_ACCESS_KEY_ID="${c.accessKeyId}"\nexport AWS_SECRET_ACCESS_KEY="${c.secretAccessKey}"\nexport AWS_SESSION_TOKEN="${c.sessionToken}"`;
const fmtPs = (c) =>
  `$env:AWS_ACCESS_KEY_ID="${c.accessKeyId}"\n$env:AWS_SECRET_ACCESS_KEY="${c.secretAccessKey}"\n$env:AWS_SESSION_TOKEN="${c.sessionToken}"`;

function mask(v) {
  if (!v) return "—";
  if (v.length <= 8) return "•".repeat(v.length);
  return v.slice(0, 4) + "•".repeat(Math.min(20, v.length - 8)) + v.slice(-4);
}

let clipboardReadGranted = false;
let clipboardBannerShown = false;

// A — defer banner to first copy action, not popup open
async function maybeShowClipboardBanner() {
  if (clipboardBannerShown) return;
  try {
    clipboardReadGranted = await chrome.permissions.contains({ permissions: ["clipboardRead"] });
  } catch (_) {}
  if (!clipboardReadGranted) {
    clipboardBannerShown = true;
    $("clipboard-banner").hidden = false;
  }
}

// #4 — consistent null guards on both banner buttons
const clipboardAllowBtn = $("clipboard-allow");
const clipboardDenyBtn = $("clipboard-deny");
if (clipboardAllowBtn) {
  clipboardAllowBtn.addEventListener("click", async () => {
    $("clipboard-banner").hidden = true;
    try {
      clipboardReadGranted = await chrome.permissions.request({ permissions: ["clipboardRead"] });
    } catch (_) {}
  });
}
if (clipboardDenyBtn) {
  clipboardDenyBtn.addEventListener("click", () => {
    $("clipboard-banner").hidden = true;
  });
}

async function copyText(text, btn) {
  if (!text) return;
  await maybeShowClipboardBanner();
  await navigator.clipboard.writeText(text);
  const orig = btn.textContent;
  btn.classList.add("copied");
  btn.textContent = "✓";
  setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 1200);
  setTimeout(async () => {
    try {
      if (!clipboardReadGranted) return;
      const cur = await navigator.clipboard.readText();
      if (cur === text) await navigator.clipboard.writeText("");
    } catch (_) {}
  }, CLIPBOARD_CLEAR_MS);
}

// ─── card builder ─────────────────────────────────────────────
function buildCard(c) {
  const expired = c.expiration && new Date(c.expiration).getTime() <= Date.now();
  const revealed = { sk: false, st: false };

  const card = document.createElement("section");
  card.className = "card" + (expired ? " card-expired" : "");
  card.dataset.roleArn = c.roleArn;

  // ── card header ──
  const head = document.createElement("div");
  head.className = "card-head";

  const roleSpan = document.createElement("span");
  roleSpan.className = "card-role";
  roleSpan.textContent = c.roleName;

  const accountSpan = document.createElement("span");
  accountSpan.className = "card-account";
  accountSpan.textContent = c.accountId;

  const expiresSpan = document.createElement("span");
  expiresSpan.className = "card-expires" + (expired ? " expired-text" : "");
  expiresSpan.textContent = untilTime(c.expiration);

  const removeBtn = document.createElement("button");
  removeBtn.className = "ic remove-btn";
  removeBtn.title = "remove this role";
  removeBtn.textContent = "✕";
  removeBtn.addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ type: "clearRole", roleArn: c.roleArn });
    card.remove();
    await refreshHeader();
    if (!$("cards-container").hasChildNodes()) {
      $("empty-block").hidden = false;
      $("footer").hidden = true;
    }
  });

  head.append(roleSpan, accountSpan, expiresSpan, removeBtn);

  // ── ~/.aws/credentials block ──
  const credsBlock = buildOutputBlock("~/.aws/credentials", fmtCredsFile(c));
  const credsKv = document.createElement("div");
  credsKv.className = "kv";
  const kvDefault = document.createElement("span");
  kvDefault.className = "kv-default";
  kvDefault.textContent = "[default]";
  credsKv.appendChild(kvDefault);

  const akRow = buildKvRow("aws_access_key_id", c.accessKeyId, false);
  const skRow = buildKvRow("aws_secret_access_key", mask(c.secretAccessKey), true);
  const stRow = buildKvRow("aws_session_token", mask(c.sessionToken), true);

  // wire reveal buttons
  skRow.revealBtn.addEventListener("click", () => {
    revealed.sk = !revealed.sk;
    skRow.revealBtn.textContent = revealed.sk ? "●" : "◐";
    skRow.valueSpan.textContent = revealed.sk ? c.secretAccessKey : mask(c.secretAccessKey);
    skRow.valueSpan.classList.toggle("hidden", !revealed.sk);
  });
  stRow.revealBtn.addEventListener("click", () => {
    revealed.st = !revealed.st;
    stRow.revealBtn.textContent = revealed.st ? "●" : "◐";
    stRow.valueSpan.textContent = revealed.st ? c.sessionToken : mask(c.sessionToken);
    stRow.valueSpan.classList.toggle("hidden", !revealed.st);
  });

  // wire copy-value buttons
  akRow.copyBtn.addEventListener("click", () => copyText(c.accessKeyId, akRow.copyBtn));
  skRow.copyBtn.addEventListener("click", () => copyText(c.secretAccessKey, skRow.copyBtn));
  stRow.copyBtn.addEventListener("click", () => copyText(c.sessionToken, stRow.copyBtn));

  // wire copy-block button
  credsBlock.copyBtn.addEventListener("click", () => copyText(fmtCredsFile(c), credsBlock.copyBtn));

  credsKv.append(...akRow.nodes, ...skRow.nodes, ...stRow.nodes);
  credsBlock.content.appendChild(credsKv);

  // ── bash block ──
  const bashBlock = buildOutputBlock("bash / zsh", fmtBash(c));
  bashBlock.copyBtn.addEventListener("click", () => copyText(fmtBash(c), bashBlock.copyBtn));
  const bashPre = document.createElement("pre");
  bashPre.className = "code";
  bashPre.textContent = fmtBash(c);
  bashBlock.content.appendChild(bashPre);

  // ── powershell block ──
  const psBlock = buildOutputBlock("powershell", fmtPs(c));
  psBlock.copyBtn.addEventListener("click", () => copyText(fmtPs(c), psBlock.copyBtn));
  const psPre = document.createElement("pre");
  psPre.className = "code";
  psPre.textContent = fmtPs(c);
  psBlock.content.appendChild(psPre);

  card.append(head, credsBlock.el, bashBlock.el, psBlock.el);
  return card;
}

function buildOutputBlock(labelText) {
  const el = document.createElement("div");
  el.className = "card-section";

  const head = document.createElement("div");
  head.className = "block-head";

  const label = document.createElement("span");
  label.className = "label";
  label.textContent = labelText;

  const copyBtn = document.createElement("button");
  copyBtn.className = "ic";
  copyBtn.title = "copy block";
  copyBtn.textContent = "⎘";

  head.append(label, copyBtn);

  const content = document.createElement("div");
  el.append(head, content);

  return { el, copyBtn, content };
}

function buildKvRow(key, displayValue, isSecret) {
  const kSpan = document.createElement("span");
  kSpan.className = "kv-k";
  kSpan.textContent = key;

  const eqSpan = document.createElement("span");
  eqSpan.className = "kv-eq";
  eqSpan.textContent = "=";

  const valueSpan = document.createElement("span");
  valueSpan.className = "kv-v" + (isSecret ? " secret hidden" : "");
  valueSpan.textContent = displayValue;

  const revealBtn = document.createElement("button");
  if (isSecret) {
    revealBtn.className = "ic reveal";
    revealBtn.textContent = "◐";
  } else {
    revealBtn.className = "kv-spacer";
  }

  const copyBtn = document.createElement("button");
  copyBtn.className = "ic";
  copyBtn.title = "copy value";
  copyBtn.textContent = "⎘";

  return { nodes: [kSpan, eqSpan, valueSpan, revealBtn, copyBtn], valueSpan, revealBtn, copyBtn };
}

// ─── header helpers ───────────────────────────────────────────
async function refreshHeader() {
  const resp = await chrome.runtime.sendMessage({ type: "getCredentials" });
  const map = resp?.credentialsMap ?? {};
  const entries = Object.values(map);
  if (entries.length === 0) {
    $("bar").classList.remove("active", "expired");
    $("cell-account").textContent = "—";
    $("cell-role").textContent = "no session";
    $("cell-expires").textContent = "—";
    return;
  }
  const anyExpired = entries.some(c => c.expiration && new Date(c.expiration).getTime() <= Date.now());
  const allExpired = entries.every(c => c.expiration && new Date(c.expiration).getTime() <= Date.now());
  $("bar").classList.toggle("active", !allExpired);
  $("bar").classList.toggle("expired", allExpired);
  if (entries.length === 1) {
    $("cell-account").textContent = entries[0].accountId;
    $("cell-role").textContent = entries[0].roleName;
    $("cell-expires").textContent = untilTime(entries[0].expiration);
  } else {
    $("cell-account").textContent = "—";
    $("cell-role").textContent = `${entries.length} roles active`;
    $("cell-expires").textContent = anyExpired ? "some expired" : "—";
  }
}

// ─── main load ────────────────────────────────────────────────
async function load() {
  const resp = await chrome.runtime.sendMessage({ type: "getCredentials" });
  const { credentialsMap = {}, pending, sessionExpired } = resp ?? {};
  if (sessionExpired) {
    const emptyMsg = $("empty-block").querySelector(".empty-msg");
    emptyMsg.replaceChildren();
    const msg = document.createElement("span");
    msg.className = "dim";
    msg.textContent = "Session expired — sign in again.";
    emptyMsg.appendChild(msg);
  }

  const container = $("cards-container");
  container.replaceChildren();

  const entries = Object.values(credentialsMap);

  if (entries.length > 0) {
    for (const c of entries) container.appendChild(buildCard(c));
    $("empty-block").hidden = true;
    $("footer").hidden = false;
  } else {
    $("empty-block").hidden = false;
    $("footer").hidden = true;
  }

  const allAssumed = pending?.roles?.length > 0 &&
    pending.roles.every(r => credentialsMap[r.roleArn]);
  // Show the confirm/picker UI for any pending capture that needs confirmation
  // (untrusted/no-initiator, incl. single role) or any multi-role capture.
  const needsConfirm = pending?.needsConfirm || (pending?.roles?.length > 1);
  if (pending?.roles?.length >= 1 && needsConfirm && !allAssumed) {
    renderPicker(pending, credentialsMap);
    $("picker-block").hidden = false;
    $("empty-block").hidden = true;
    if (entries.length > 0) $("footer").hidden = false;
  } else {
    $("picker-block").hidden = true;
  }

  await refreshHeader();
}

function renderPicker(pending, credentialsMap = {}) {
  const sel = $("role-select");
  sel.replaceChildren();
  for (const r of pending.roles) {
    if (!ROLE_ARN_RE.test(r.roleArn)) continue;
    const opt = document.createElement("option");
    opt.value = r.roleArn;
    const active = credentialsMap[r.roleArn] ? " ✓" : "";
    opt.textContent = r.roleArn + active;
    sel.appendChild(opt);
  }
}

// ─── event listeners ──────────────────────────────────────────
$("clear-btn").addEventListener("click", async () => {
  await chrome.runtime.sendMessage({ type: "clearCredentials" });
  await load();
});

$("role-go").addEventListener("click", async () => {
  const sel = $("role-select");
  const roleArn = sel.value.replace(/ ✓$/, "");
  if (!roleArn || !ROLE_ARN_RE.test(roleArn)) return;
  const errEl = $("picker-err");
  errEl.hidden = true;
  const btn = $("role-go");
  btn.disabled = true;
  btn.textContent = "assuming…";
  const resp = await chrome.runtime.sendMessage({ type: "selectRole", roleArn });
  btn.disabled = false;
  btn.textContent = "assume";
  if (!resp?.ok) {
    // M3 — cap error length to prevent layout break from long STS messages
    const err = (resp?.error || "failed to assume role").slice(0, 200);
    errEl.textContent = err;
    errEl.hidden = false;
    return;
  }
  await load();
});

// ─── settings ────────────────────────────────────────────────
async function loadSettings() {
  const { sessionHours = 1, chinaPartition = false, customOktaDomain = "" } = await chrome.storage.local.get(["sessionHours", "chinaPartition", "customOktaDomain"]);
  $("duration-input").value = sessionHours;
  $("china-toggle").checked = chinaPartition;
  $("okta-input").value = customOktaDomain;
}

$("settings-toggle").addEventListener("click", () => {
  const panel = $("settings-panel");
  const btn = $("settings-toggle");
  panel.hidden = !panel.hidden;
  btn.classList.toggle("active", !panel.hidden);
  if (!panel.hidden) {
    loadSettings();
    $("settings-saved").hidden = true;
  }
});

const OKTA_DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.(okta\.com|oktapreview\.com|okta-emea\.com)$/;

$("settings-save").addEventListener("click", async () => {
  const hours = Math.min(12, Math.max(1, parseInt($("duration-input").value, 10) || 1));
  const china = $("china-toggle").checked;
  const rawDomain = $("okta-input").value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  if (rawDomain && !OKTA_DOMAIN_RE.test(rawDomain)) {
    $("okta-input").style.outline = "1px solid var(--bad)";
    return;
  }
  $("okta-input").style.outline = "";
  $("duration-input").value = hours;
  $("okta-input").value = rawDomain;
  await chrome.storage.local.set({ sessionHours: hours, chinaPartition: china, customOktaDomain: rawDomain });
  // M2 — send no payload; background re-reads settings from storage on demand
  await chrome.runtime.sendMessage({ type: "settingsUpdated" });
  const saved = $("settings-saved");
  saved.hidden = false;
  setTimeout(() => { saved.hidden = true; }, 2000);
});

load();
