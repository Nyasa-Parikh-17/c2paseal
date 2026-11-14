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
  const analyzeBytes = async (bytes, name, trust) =>
    JSON.parse(api.analyze(bytes, { name, trustAnchors: trust ? await demoFile("demo-root.pem") : "" }));
  return {
    mode: "wasm",
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
  };
}

function serverEngine() {
  const post = async (path, file, trust) => {
    const form = new FormData();
    form.append("file", file);
    if (trust) form.append("trust", "1");
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

// banner returns {cls, title, text} for the status banner.
function banner(a) {
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
  panel.append(el("div", "meta", [a.file, a.format || "unknown format", a.size + " bytes", a.trusted_test_root ? "demo root trusted" : ""].filter(Boolean).join(" · ")));

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
  panel.append(det);

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

function verifyFile(file) {
  lastVerify = file;
  return run("busy-verify", async () => render($("result-verify"), await engine.analyze(file, $("trust").checked)));
}

// signFile signs the File that getFile resolves to. The fetch for the
// sample is inside the operation, so whenIdle() covers it.
function signFile(getFile) {
  return run("busy-sign", async () => {
    const file = await getFile();
    lastSign = file;
    const a = await engine.sign(file, $("sign-trust").checked);
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

async function sampleFile() {
  const r = await fetch("demo/sample.jpg");
  return new File([await r.blob()], "sample.jpg", { type: "image/jpeg" });
}

function selectTab(name) {
  for (const t of ["verify", "sign"]) {
    const on = t === name;
    $("tab-" + t).setAttribute("aria-selected", String(on));
    $("tab-" + t).tabIndex = on ? 0 : -1;
    $("pane-" + t).hidden = !on;
  }
}

function wire() {
  $("tab-verify").addEventListener("click", () => selectTab("verify"));
  $("tab-sign").addEventListener("click", () => selectTab("sign"));
  document.querySelector(".tabs").addEventListener("keydown", (e) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    const next = $("tab-verify").getAttribute("aria-selected") === "true" ? "sign" : "verify";
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
