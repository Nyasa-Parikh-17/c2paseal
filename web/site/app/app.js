// C2paSeal web app. All checks run in the C2paSeal Go library: here as
// WebAssembly (c2paseal.wasm), or, when the page is served by
// `c2paseal serve` (which has no .wasm), in that local process through its
// HTTP API. Both return the same JSON (Go package internal/analysis); this
// script only displays it and never decides validity itself.
"use strict";

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

const yieldToPaint = () => new Promise((r) => setTimeout(r, 30));

function signedName(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(0, dot) + ".signed" + name.slice(dot) : name + ".signed";
}

const base64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function fetchText(path) {
  const r = await fetch(path);
  if (!r.ok) throw new Error(path + ": HTTP " + r.status);
  return r.text();
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error("could not load " + src));
    document.head.append(s);
  });
}

// --- Engines ---------------------------------------------------------------
// analyze(file, trust) and sign(file, trust) resolve to an Analysis:
// {file, size, format, manifest_store, read_error, statuses, validation_state,
//  trusted_test_root, signed?: {name, data (base64)}} or {error}.

const demo = {}; // TEST ONLY demo PKI, loaded on first use
async function demoFile(name) {
  if (!demo[name]) demo[name] = await fetchText("demo/" + name);
  return demo[name];
}

// userTrust is the trust list the user loaded ({name, pem, count}), or null.
// It is added to the anchors of every check, and kept in this browser.
let userTrust = null;
const TRUST_KEY = "c2paseal.trustlist";

// anchorsPEM is the PEM text of the trust anchors for a check: the demo root
// if its box is ticked, and the user's trust list.
async function anchorsPEM(trustDemo) {
  const parts = [];
  if (trustDemo) parts.push(await demoFile("demo-root.pem"));
  if (userTrust) parts.push(userTrust.pem);
  return parts.join("\n");
}

const countCerts = (pem) => (pem.match(/-----BEGIN CERTIFICATE-----/g) || []).length;

async function wasmEngine() {
  const resp = await fetch("c2paseal.wasm");
  if (!resp.ok) return null;
  await loadScript("wasm_exec.js");
  const go = new Go();
  let instance;
  try {
    ({ instance } = await WebAssembly.instantiateStreaming(resp.clone(), go.importObject));
  } catch (e) {
    // Some hosts send .wasm without application/wasm.
    ({ instance } = await WebAssembly.instantiate(await resp.arrayBuffer(), go.importObject));
  }
  go.run(instance); // defines globalThis.c2paseal and keeps running
  if (typeof globalThis.c2paseal !== "object") throw new Error("c2paseal.wasm did not start");
  const api = globalThis.c2paseal;
  const analyzeBytes = async (bytes, name, trust, manifestStore) =>
    JSON.parse(api.analyze(bytes, { name, trustAnchors: await anchorsPEM(trust), manifestStore }));
  return {
    mode: "wasm",
    // checkTrust returns an error message if pem is not a usable trust list.
    checkTrust(pem) {
      const r = JSON.parse(api.analyze(new Uint8Array(0), { name: "check", trustAnchors: pem }));
      return r.error ? r.error.replace(/^trustAnchors: /, "") : "";
    },
    where: "Everything runs in this browser tab (WebAssembly). Files are not uploaded. After the first visit the app also works offline.",
    async analyze(file, trust) {
      return analyzeBytes(new Uint8Array(await file.arrayBuffer()), file.name, trust);
    },
    async sign(file, trust) {
      const opts = { cert: await demoFile("demo-chain.pem"), key: await demoFile("demo.key"), title: file.name };
      const r = JSON.parse(api.sign(new Uint8Array(await file.arrayBuffer()), opts));
      if (r.error) return r;
      const name = signedName(file.name);
      const a = await analyzeBytes(base64ToBytes(r.data), name, trust);
      a.signed = { name, data: r.data };
      return a;
    },
    // recover reads the watermark from the decoded pixels, fetches the
    // manifest store for its ID and verifies the file against it.
    async recover(file, storeURL, trust) {
      const fileBytes = new Uint8Array(await file.arrayBuffer());
      let px;
      try {
        px = await pixels(file);
      } catch (e) {
        return { error: "This browser could not decode the image: " + e.message };
      }
      const wm = JSON.parse(api.extractWatermark(px.data, px.width, px.height));
      if (wm.error) return { noWatermark: true, file: file.name, detail: wm.error };
      const url = storeURL.replace(/\/+$/, "") + "/v1/manifests/" + wm.id;
      let r;
      try {
        r = await fetch(url);
      } catch (e) {
        return { error: "Could not reach the manifest store at " + storeURL + " (" + e.message + ")." };
      }
      if (r.status === 404) return { error: "The manifest store has no credentials for watermark " + wm.id + "." };
      if (!r.ok) return { error: "The manifest store answered " + r.status + "." };
      const store = new Uint8Array(await r.arrayBuffer());
      const a = await analyzeBytes(fileBytes, file.name, trust, store);
      a.recovered = { id: wm.id, confidence: wm.confidence, store: storeURL };
      return a;
    },
  };
}

// pixels decodes an image file in the browser and returns its RGBA bytes,
// without colour management, as the watermark was embedded.
async function pixels(file) {
  const bmp = await createImageBitmap(file, { colorSpaceConversion: "none", premultiplyAlpha: "none" });
  const canvas = document.createElement("canvas");
  canvas.width = bmp.width;
  canvas.height = bmp.height;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(bmp, 0, 0);
  const d = ctx.getImageData(0, 0, bmp.width, bmp.height);
  return { data: new Uint8Array(d.data.buffer), width: bmp.width, height: bmp.height };
}

function serverEngine() {
  const post = async (path, file, trust) => {
    const form = new FormData();
    form.append("file", file);
    if (trust) form.append("trust", "1");
    if (userTrust) form.append("anchors", userTrust.pem);
    try {
      const r = await fetch(path, { method: "POST", body: form });
      const ct = r.headers.get("Content-Type") || "";
      if (!ct.startsWith("application/json")) return { error: path + ": HTTP " + r.status };
      return await r.json();
    } catch (e) {
      return { error: String(e) };
    }
  };
  return {
    mode: "server",
    where: "Checks run in the c2paseal serve process on this computer (this page has no WebAssembly build).",
    analyze: (file, trust) => post("api/verify", file, trust),
    sign: (file, trust) => post("api/sign", file, trust),
  };
}

// --- Reading the results ----------------------------------------------------
// These choose words and colours only; the statuses and the validation state
// are the library's.

// noCredentials: the file has no C2PA manifest at all. The library reports
// that as Invalid with claim.missing, which is right for a validator but
// reads as "tampered" to a person; most images simply have none.
function noCredentials(a) {
  const st = a.statuses || [];
  return !a.manifest_store && st.length > 0 && st.every((s) => s.code === "claim.missing");
}

// untrusted: the signer's certificate does not chain to a trust anchor. The
// manifest itself is intact, so it is shown as a warning, not a failure.
const isUntrusted = (s) => s.code === "signingCredential.untrusted" && s.kind === "failure";

// Failures that mean the file or its manifest changed after signing.
const TAMPER_CODES = new Set(["assertion.dataHash.mismatch", "assertion.hashedURI.mismatch", "claimSignature.mismatch"]);

function activeManifest(a) {
  const store = a.manifest_store;
  return store && store.manifests ? store.manifests[store.active_manifest] : null;
}

function formatTime(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toISOString().replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
}

// signedBy is the spec's kind of wording: who signed, and that the content
// has not changed since then. Never "real" or "true".
function signedBy(m) {
  const sig = (m && m.signature) || {};
  const who = sig.common_name || sig.issuer || "an unnamed signer";
  const issuer = sig.issuer && sig.issuer !== who ? " (certificate issued by " + sig.issuer + ")" : "";
  const since = sig.time
    ? "unmodified since " + formatTime(sig.time) + ", the time in its time-stamp."
    : "unmodified since it was signed. It has no time-stamp, so when that was is not known.";
  return "Signed by " + who + issuer + ", " + since;
}

// recoveredBanner describes credentials found by watermark. The copy's
// bytes are not the signed file's, so the hard binding fails by design;
// what counts is that the signature validates and nothing else fails.
function recoveredBanner(a) {
  const m = activeManifest(a);
  const failures = (a.statuses || []).filter((s) => s.kind === "failure");
  const expected = new Set(["assertion.dataHash.mismatch", "assertion.bmffHash.mismatch", "signingCredential.untrusted"]);
  const validated = (a.statuses || []).some((s) => s.code === "claimSignature.validated");
  const other = failures.find((s) => !expected.has(s.code));
  if (!m || !validated || other) {
    return { cls: "invalid", title: "Recovered credentials not valid",
      text: "The manifest store returned credentials for watermark " + a.recovered.id + ", but they do not validate." +
        (other ? " First problem: " + (other.explanation || other.code) + "." : "") };
  }
  const sig = m.signature || {};
  const who = sig.common_name || sig.issuer || "an unnamed signer";
  const issuer = sig.issuer && sig.issuer !== who ? " (certificate issued by " + sig.issuer + ")" : "";
  const when = sig.time ? " at " + formatTime(sig.time) + " (time-stamp)" : "";
  const changed = failures.some((s) => s.code.endsWith("Hash.mismatch"))
    ? " This copy is not the signed file: its bytes changed since signing (re-encoded, resized or edited), so only its watermark links it to these credentials."
    : " This copy matches the signed file.";
  const trust = failures.some(isUntrusted) ? " The signer is not on your trust list." : "";
  return { cls: "recovered", title: "Credentials recovered",
    text: "Signed by " + who + issuer + when + "; the signature is valid." + changed + trust +
      " Watermark " + a.recovered.id + " (confidence " + a.recovered.confidence.toFixed(2) + ")." };
}

// banner returns {cls, title, text} for the status banner.
function banner(a) {
  if (a.recovered) return recoveredBanner(a);
  if (a.noWatermark) {
    return { cls: "none", title: "No watermark found",
      text: "This copy carries no C2paSeal watermark, or it was cropped or changed too much to read (see ROBUSTNESS.md)." };
  }
  if (noCredentials(a)) {
    return { cls: "none", title: "No Content Credentials",
      text: "This file has no C2PA manifest, so there is nothing to check. Most images have none; that alone is not a sign of tampering." };
  }
  const m = activeManifest(a);
  const failures = (a.statuses || []).filter((s) => s.kind === "failure");
  if (a.validation_state === "Invalid") {
    const tampered = failures.some((s) => s.scope === "active manifest" && TAMPER_CODES.has(s.code));
    const first = failures.find((s) => !isUntrusted(s));
    const why = first ? " First problem: " + (first.explanation || first.code) + "." : "";
    return tampered
      ? { cls: "invalid", title: "Changed since it was signed", text: "The file or its manifest no longer matches the signature." + why }
      : { cls: "invalid", title: "Content Credentials not valid", text: "The manifest could not be validated." + why };
  }
  if (failures.some(isUntrusted)) {
    return { cls: "untrusted", title: "Signer not on your trust list",
      text: signedBy(m) + " The certificate does not chain to a trust anchor you chose, so who the signer is has not been confirmed." };
  }
  return { cls: "valid", title: a.validation_state === "Trusted" ? "Valid, trusted signer" : "Valid", text: signedBy(m) };
}

// --- Provenance graph -------------------------------------------------------

// manifestLabel extracts the manifest label from an ingredient's link,
// e.g. "self#jumbf=/c2pa/urn:c2pa:…/…" → "urn:c2pa:…".
function manifestLabel(ingredient) {
  const ref = ingredient.activeManifest || ingredient.c2pa_manifest || ingredient.manifest;
  const url = ref && ref.url;
  const m = typeof url === "string" && url.match(/\/c2pa\/([^/]+)/);
  return m ? m[1] : null;
}

function ingredientsOf(m) {
  const out = [];
  for (const [k, v] of Object.entries((m && m.assertion_store) || {})) {
    if (k.startsWith("c2pa.ingredient") && v && typeof v === "object") out.push(v);
  }
  return out;
}

function manifestNode(store, label, m, extra, seen) {
  const li = el("li");
  const card = el("div", "node" + (label === store.active_manifest ? " current" : ""));
  if (extra.rel) card.append(el("span", "rel", extra.rel));
  const claim = m.claim || {};
  card.append(el("span", "title", extra.title || claim["dc:title"] || m.title || label));
  const sig = m.signature || {};
  const bits = [];
  if (label === store.active_manifest) bits.push("this file");
  if (sig.common_name) bits.push("signed by " + sig.common_name);
  if (sig.time) bits.push(formatTime(sig.time));
  bits.push(label);
  card.append(el("span", "meta", bits.join(" · ")));
  li.append(card);

  const ings = ingredientsOf(m);
  if (ings.length) {
    const ul = el("ul");
    for (const ing of ings) {
      const child = manifestLabel(ing);
      const cm = child && store.manifests[child];
      if (cm && !seen.has(child)) {
        seen.add(child);
        ul.append(manifestNode(store, child, cm, { rel: ing.relationship, title: ing["dc:title"] }, seen));
      } else {
        const leaf = el("li");
        const c = el("div", "node");
        if (ing.relationship) c.append(el("span", "rel", ing.relationship));
        c.append(el("span", "title", ing["dc:title"] || "untitled ingredient"));
        c.append(el("span", "meta", [ing["dc:format"], child ? "manifest " + child + " not in this file" : "no Content Credentials"].filter(Boolean).join(" · ")));
        leaf.append(c);
        ul.append(leaf);
      }
    }
    li.append(ul);
  }
  return li;
}

function provenanceGraph(store) {
  const m = store.manifests && store.manifests[store.active_manifest];
  if (!m) return null;
  const ul = el("ul", "graph");
  ul.append(manifestNode(store, store.active_manifest, m, {}, new Set([store.active_manifest])));
  return ul;
}

// --- Rendering ----------------------------------------------------------------

function render(target, a) {
  const panel = el("div", "panel");
  panel.dataset.file = a.file || "";
  if (a.error) {
    const b = el("div", "status error");
    b.append(el("h3", "", "Could not process the file"), el("p", "", a.error));
    panel.append(b);
    target.replaceChildren(panel);
    return;
  }
  panel.append(el("div", "meta", [a.file, a.format || "", a.size ? a.size + " bytes" : "", a.trustNote || "",
    a.recovered ? "from " + a.recovered.store : ""].filter(Boolean).join(" · ")));

  const b = banner(a);
  const box = el("div", "status " + b.cls);
  box.dataset.state = b.cls;
  box.append(el("h3", "", b.title), el("p", "", b.text));
  panel.append(box);

  if (a.signed) {
    const blob = new Blob([base64ToBytes(a.signed.data)], { type: "image/" + (a.format || "jpeg") });
    const link = el("a", "download", "Download " + a.signed.name);
    link.href = URL.createObjectURL(blob);
    link.download = a.signed.name;
    panel.append(link);
  }

  const store = a.manifest_store;
  if (store) {
    const g = provenanceGraph(store);
    if (g) {
      panel.append(el("h2", "", "Provenance"));
      const n = Object.keys(store.manifests || {}).length;
      panel.append(el("p", "meta", n === 1 && ingredientsOf(activeManifest(a)).length === 0
        ? "One manifest, with no ingredients: it records no earlier files."
        : n + " manifests in this file. Each card is a manifest; the files it was made from hang below it."));
      panel.append(g);
    }
  }

  const none = noCredentials(a);
  const det = el("details");
  det.append(el("summary", "", "Validation statuses (" + (a.statuses || []).length + ")"));
  const ul = el("ul", "statuses");
  for (const s of a.statuses || []) {
    const warn = isUntrusted(s);
    const li = el("li", none ? "neutral" : warn ? "warning" : s.kind);
    if (s.scope !== "active manifest") li.append(el("span", "scope", s.scope + " "));
    const kind = none ? "no manifest" : warn ? "warning" : s.kind;
    li.append(el("code", "", s.code), " ", el("span", "meta", "(" + kind + ")"));
    if (warn) li.append(el("span", "why label", "Signer not on your trust list."));
    if (s.explanation) li.append(el("span", "why", s.explanation));
    ul.append(li);
  }
  det.append(ul);
  if (!none && b.cls === "invalid") det.open = true;
  if ((a.statuses || []).length > 0) panel.append(det);

  if (store) {
    const raw = el("details");
    raw.append(el("summary", "", "Raw manifest store (JSON)"));
    raw.append(el("pre", "raw", JSON.stringify(store, null, 2)));
    panel.append(raw);
  } else if (a.read_error && !none) {
    panel.append(el("p", "meta", "No readable manifest store: " + a.read_error));
  }
  target.replaceChildren(panel);
}

// --- Wiring -------------------------------------------------------------------

let engine = null;
let idle = Promise.resolve();
let lastVerify = null; // the File on the Verify tab
let lastSign = null;   // the File signed on the Sign tab
let lastRecover = null; // the File on the Recover tab

function run(busyId, fn) {
  idle = (async () => {
    $(busyId).textContent = "Working…";
    await yieldToPaint();
    try {
      await fn();
    } finally {
      $(busyId).textContent = "";
    }
  })();
  return idle;
}

// noted adds to a result which trust anchors its check used, for display.
function noted(a, trustDemo) {
  if (a && !a.error) {
    a.trustNote = [trustDemo ? "demo root trusted" : "", userTrust ? "your trust list (" + userTrust.name + ")" : ""]
      .filter(Boolean).join(", ");
  }
  return a;
}

function verifyFile(file) {
  lastVerify = file;
  const trust = $("trust").checked;
  return run("busy-verify", async () => render($("result-verify"), noted(await engine.analyze(file, trust), trust)));
}

// signFile signs the File that getFile resolves to. The fetch for the
// sample is inside the operation, so whenIdle() covers it.
function signFile(getFile) {
  return run("busy-sign", async () => {
    const file = await getFile();
    lastSign = file;
    const trust = $("sign-trust").checked;
    const a = noted(await engine.sign(file, trust), trust);
    render($("result-sign"), a);
    if (a.signed) {
      // Signing the result again keeps the first manifest as its parent,
      // which shows in the provenance graph.
      const again = el("button", "again", "Sign the signed file again");
      again.addEventListener("click", () => signFile(() => new File([base64ToBytes(a.signed.data)], a.signed.name)));
      $("result-sign").querySelector(".panel").insertBefore(again, $("result-sign").querySelector(".panel h2, .panel details"));
    }
  });
}

function recoverFile(file) {
  lastRecover = file;
  const store = $("store-url").value.trim();
  return run("busy-recover", async () => {
    if (!/^https?:\/\//.test(store)) {
      render($("result-recover"), { error: "Enter the manifest store URL first (http:// or https://)." });
      return;
    }
    const trust = $("recover-trust").checked;
    render($("result-recover"), noted(await engine.recover(file, store, trust), trust));
  });
}

// The store URL is remembered in this browser (a convenience; nothing
// depends on it), and can be preset with ?store=<url>.
function initStoreURL() {
  const q = new URLSearchParams(location.search).get("store");
  let saved = "";
  try {
    saved = localStorage.getItem("c2paseal.store") || "";
  } catch (e) { /* storage unavailable */ }
  $("store-url").value = q || saved;
  $("store-url").addEventListener("change", () => {
    try {
      localStorage.setItem("c2paseal.store", $("store-url").value.trim());
    } catch (e) { /* storage unavailable */ }
  });
}

// --- Your trust list ----------------------------------------------------------

function showTrustList(message) {
  const loaded = !!userTrust;
  $("trustlist").classList.toggle("loaded", loaded);
  $("trustlist-state").textContent = loaded
    ? userTrust.name + ", " + userTrust.count + (userTrust.count === 1 ? " certificate" : " certificates") + (userTrust.remembered ? "" : " (this visit only)")
    : "none loaded";
  $("trustlist-clear").hidden = !loaded;
  $("trustlist-error").hidden = !message;
  $("trustlist-error").textContent = message || "";
}

// recheck runs the current results again, after the trust list changed.
function recheck() {
  if (lastVerify) verifyFile(lastVerify);
  if (lastRecover) recoverFile(lastRecover);
}

function initTrustList() {
  try {
    const saved = JSON.parse(localStorage.getItem(TRUST_KEY) || "null");
    if (saved && typeof saved.pem === "string" && countCerts(saved.pem) > 0) {
      userTrust = { name: String(saved.name || "trust list"), pem: saved.pem, count: countCerts(saved.pem), remembered: true };
    }
  } catch (e) { /* storage unavailable or unreadable */ }
  showTrustList();
  $("trustlist-file").addEventListener("change", async (e) => {
    const f = e.target.files[0];
    e.target.value = "";
    if (!f) return;
    const pem = await f.text();
    const count = countCerts(pem);
    const problem = count === 0 ? "No certificates in " + f.name + ": a trust list is PEM text with -----BEGIN CERTIFICATE----- blocks."
      : engine && engine.checkTrust ? engine.checkTrust(pem) : "";
    if (problem) {
      showTrustList(problem);
      return;
    }
    userTrust = { name: f.name, pem, count, remembered: false };
    try {
      localStorage.setItem(TRUST_KEY, JSON.stringify({ name: f.name, pem }));
      userTrust.remembered = true;
    } catch (err) { /* too large or storage unavailable: kept for this visit */ }
    showTrustList();
    recheck();
  });
  $("trustlist-clear").addEventListener("click", () => {
    userTrust = null;
    try {
      localStorage.removeItem(TRUST_KEY);
    } catch (e) { /* storage unavailable */ }
    showTrustList();
    recheck();
  });
}

async function sampleFile() {
  const r = await fetch("demo/sample.jpg");
  return new File([await r.blob()], "sample.jpg", { type: "image/jpeg" });
}

const TABS = ["verify", "sign", "recover"];

// selectTab shows a tab. The URL follows (#sign, #recover), so tabs can be
// linked to, as the site's top bar does.
function selectTab(name, updateURL = true) {
  if (!TABS.includes(name)) name = "verify";
  for (const t of TABS) {
    const on = t === name;
    $("tab-" + t).setAttribute("aria-selected", String(on));
    $("tab-" + t).tabIndex = on ? 0 : -1;
    $("pane-" + t).hidden = !on;
  }
  // The top bar marks "Sign" on the Sign tab, "Check an image" otherwise.
  const [current, other] = name === "sign" ? ["nav-sign", "nav-check"] : ["nav-check", "nav-sign"];
  $(current).setAttribute("aria-current", "page");
  $(other).removeAttribute("aria-current");
  if (updateURL) {
    history.replaceState(null, "", location.pathname + location.search + (name === "verify" ? "" : "#" + name));
  }
}

const tabFromHash = () => location.hash.replace(/^#/, "");

function wire() {
  $("tab-verify").addEventListener("click", () => selectTab("verify"));
  $("tab-sign").addEventListener("click", () => selectTab("sign"));
  $("tab-recover").addEventListener("click", () => selectTab("recover"));
  window.addEventListener("hashchange", () => selectTab(tabFromHash(), false));
  selectTab(tabFromHash(), false);
  initTrustList();
  document.querySelector(".tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const tabs = ["verify", "sign", "recover"];
    const cur = tabs.findIndex((t) => $("tab-" + t).getAttribute("aria-selected") === "true");
    const next = tabs[(cur + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    selectTab(next);
    $("tab-" + next).focus();
  });

  $("file").addEventListener("change", (e) => { if (e.target.files[0]) verifyFile(e.target.files[0]); });
  const drop = $("drop");
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    if (engine && e.dataTransfer.files[0]) verifyFile(e.dataTransfer.files[0]);
  });
  $("trust").addEventListener("change", () => { if (lastVerify) verifyFile(lastVerify); });

  $("sign-sample").addEventListener("click", () => signFile(sampleFile));
  $("sign-file").addEventListener("change", (e) => {
    const f = e.target.files[0];
    if (f) signFile(() => f);
  });
  $("recover-file").addEventListener("change", (e) => { if (e.target.files[0]) recoverFile(e.target.files[0]); });
  const rdrop = $("recover-drop");
  rdrop.addEventListener("dragover", (e) => { e.preventDefault(); rdrop.classList.add("over"); });
  rdrop.addEventListener("dragleave", () => rdrop.classList.remove("over"));
  rdrop.addEventListener("drop", (e) => {
    e.preventDefault();
    rdrop.classList.remove("over");
    if (engine && engine.recover && e.dataTransfer.files[0]) recoverFile(e.dataTransfer.files[0]);
  });
  $("recover-trust").addEventListener("change", () => { if (lastRecover) recoverFile(lastRecover); });
  initStoreURL();
  $("sign-trust").addEventListener("change", () => {
    const f = lastSign;
    if (f) signFile(() => f);
  });
}

async function start() {
  wire();
  try {
    engine = (await wasmEngine()) || serverEngine();
  } catch (e) {
    $("where").textContent = "The validator did not load: " + e.message;
    $("where").classList.add("error");
    throw e;
  }
  $("where").textContent = engine.where;
  for (const id of ["file", "sign-sample", "sign-file"]) $(id).disabled = false;
  if (engine.recover) {
    $("recover-file").disabled = false;
  } else {
    $("recover-note").hidden = false;
    $("recover-note").textContent = "Recovering credentials reads the watermark with the WebAssembly build, which this page does not have here. " +
      "Use the GitHub Pages site, or `sealstore recover` on the command line.";
  }
  if (engine.mode === "wasm" && "serviceWorker" in navigator) {
    // Caches the app, including c2paseal.wasm, for offline use.
    navigator.serviceWorker.register("sw.js").catch((e) => console.warn("service worker:", e));
  }
  return engine.mode;
}

// For tests and debugging: the engine mode once loaded, and a promise for
// the current operation.
window.c2pasealApp = {
  ready: start(),
  whenIdle: () => idle,
};
