// AWS Credential Helper — Copyright (C) 2026 Arghaya Mondal
// SPDX-License-Identifier: GPL-3.0-or-later
const ROLE_ATTR = "https://aws.amazon.com/SAML/Attributes/Role";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // only accept messages from within this extension
  if (sender.id !== chrome.runtime.id) return;
  if (msg?.target !== "offscreen") return;

  try {
    if (msg.type === "parseSaml") {
      sendResponse({ ok: true, roles: parseSamlRoles(msg.xml) });
    } else if (msg.type === "parseSts") {
      sendResponse({ ok: true, creds: parseStsCreds(msg.xml) });
    } else {
      sendResponse({ ok: false, error: "unknown type" });
    }
  } catch (e) {
    sendResponse({ ok: false, error: e.message || String(e) });
  }
  return false;
});

function parseXml(xml) {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  const err = doc.querySelector("parsererror");
  if (err) throw new Error("XML parse error");
  return doc;
}

function parseSamlRoles(xml) {
  const doc = parseXml(xml);
  // Match Attribute by Name regardless of namespace prefix.
  const attrs = Array.from(doc.getElementsByTagNameNS("*", "Attribute"));
  const roleAttr = attrs.find((a) => a.getAttribute("Name") === ROLE_ATTR);
  if (!roleAttr) return [];
  const values = Array.from(roleAttr.getElementsByTagNameNS("*", "AttributeValue"));
  const MAX_ROLES = 100;
  return values
    .slice(0, MAX_ROLES)
    .map((el) => (el.textContent || "").trim())
    .map((v) => {
      const parts = v.split(",").map((s) => s.trim());
      // L1 — tightened regex: role/provider names are alphanumeric + /-_+=,.@
      const principalArn = parts.find((p) => /^arn:aws[a-z-]*:iam::\d{12}:saml-provider\/[\w+=,.@-]+$/.test(p));
      const roleArn = parts.find((p) => /^arn:aws[a-z-]*:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(p));
      return roleArn && principalArn ? { roleArn, principalArn } : null;
    })
    .filter(Boolean);
}

function parseStsCreds(xml) {
  const doc = parseXml(xml);
  const get = (tag) => {
    const el = doc.getElementsByTagNameNS("*", tag)[0];
    return el ? el.textContent : null;
  };
  return {
    AccessKeyId: get("AccessKeyId"),
    SecretAccessKey: get("SecretAccessKey"),
    SessionToken: get("SessionToken"),
    Expiration: get("Expiration"),
  };
}
