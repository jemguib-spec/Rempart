// api-explorer.js - console API de Rempart : chaque commande d'api-spec.js
// peut être exécutée depuis la page, avec la session de l'interface ou un
// jeton porteur. Le jeton n'est gardé qu'en mémoire (perdu au rechargement).

import { GROUPS, SCOPES } from "./api-spec.js";
import { $, $$, h, initTheme, initMenu, copy } from "./docs-common.js";

initTheme();
initMenu();

const auth = { mode: "session", token: "" };
const slug = (e) => "op-" + e.m.toLowerCase() + "-" + e.p.replace(/^\//, "").replace(/[{}]/g, "").replace(/[^a-z0-9]+/gi, "-").replace(/-$/, "");
const tokenAllowed = (scope) => scope !== "session" && scope !== "local";
const pretty = (v) => JSON.stringify(v, null, 2);
const sq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";

// ---- portées ----
const sb = $("#scopes tbody");
for (const [k, v] of Object.entries(SCOPES)) sb.append(h("tr", {}, h("td", {}, h("span.scope." + k, { text: v.label })), h("td", { text: v.text })));

// ---- table des matières et cartes ----
const toc = $("#toc"), ops = $("#ops");
const tocLinks = [];
for (const g of GROUPS) {
  const list = h("ul");
  for (const e of g.endpoints) {
    const a = h("a", { href: "#" + slug(e), title: e.sum }, h("span.m." + e.m, { text: e.m }), h("span.path", { text: e.p.replace(/^\/api/, "") || "/" }));
    a.dataset.search = [e.m, e.p, e.sum, g.title, e.scope].join(" ").toLowerCase();
    tocLinks.push(a);
    list.append(h("li", {}, a));
  }
  toc.append(h("div", { "data-group": g.id }, h("h3", { text: g.title }), list));

  const sec = h("section", { "data-group": g.id }, h("h2.group-head", { id: "g-" + g.id, text: g.title }), g.text ? h("p", { text: g.text }) : null);
  for (const e of g.endpoints) sec.append(card(e, g));
  ops.append(sec);
}

function card(e, g) {
  const d = h("details.op." + e.m, { id: slug(e) },
    h("summary", {}, h("span.m." + e.m, { text: e.m }), h("span.p", { text: e.p }), h("span.sum", { text: e.sum }), h("span.scope." + e.scope, { text: SCOPES[e.scope].label, title: SCOPES[e.scope].text })));
  d.dataset.search = [e.m, e.p, e.sum, e.text || "", g.title, e.scope].join(" ").toLowerCase();
  d.addEventListener("toggle", () => { if (d.open && !d.dataset.built) { d.append(buildBody(e)); d.dataset.built = "1"; } });
  return d;
}

function buildBody(e) {
  const body = h("div.body");
  if (e.text) body.append(h("p", { text: e.text }));
  if (!tokenAllowed(e.scope)) body.append(h("div.callout", {}, h("div", { text: e.scope === "local" ? "Réservé au compte administrateur local, dans une session de l'interface. Refusé à tout jeton." : "Réservé à une session de l'interface (rôle administrateur). Refusé à tout jeton : un jeton volé ne peut pas s'en servir." })));
  if (e.scope === "backup" || e.scope === "sync") body.append(h("div.callout.warn", {}, h("div", { text: "Portée explicite : un jeton « admin » ne suffit pas, il faut un jeton qui porte exactement cette portée." })));

  if (e.fields?.length) {
    body.append(h("div", {}, h("h4", { text: "Champs du corps" }), h("div.table-wrap", {}, h("table", {},
      h("thead", {}, h("tr", {}, h("th", { text: "Champ" }), h("th", { text: "Type" }), h("th", { text: "Description" }))),
      h("tbody", {}, e.fields.map(([f, t, x]) => h("tr", {}, h("td", {}, h("code", { text: f })), h("td", { text: t }), h("td", { text: x }))))))));
  }

  // paramètres de chemin et de requête
  const inputs = [];
  const params = [...(e.params || [])];
  for (const m of e.p.matchAll(/\{(\w+)\}/g)) if (!params.some((p) => p.n === m[1])) params.push({ n: m[1], in: "path", req: true });
  if (params.length) {
    const box = h("div.params");
    for (const p of params) {
      const id = slug(e) + "-" + p.n;
      const inp = h("input", { type: "text", id, value: p.ex ?? "", placeholder: p.in === "path" ? "obligatoire" : "facultatif", spellcheck: "false", autocomplete: "off" });
      inp.dataset.name = p.n; inp.dataset.in = p.in; if (p.req) inp.dataset.req = "1";
      inputs.push(inp);
      box.append(h("label", { for: id }, h("span", {}, p.n, p.req ? h("em", { text: " *" }) : null, h("small.muted", { text: p.in === "path" ? "  (chemin)" : "  (requête)" })), inp, p.d ? h("small", { text: p.d }) : null));
    }
    body.append(h("div", {}, h("h4", { text: "Paramètres" }), box));
  }

  let ta = null;
  if (e.body !== undefined) {
    ta = h("textarea", { spellcheck: "false", "aria-label": "Corps JSON de la requête", rows: String(Math.min(18, pretty(e.body).split("\n").length + 1)) });
    ta.value = pretty(e.body);
    ta.addEventListener("keydown", (ev) => { if (ev.key === "Tab") { ev.preventDefault(); ta.setRangeText("  ", ta.selectionStart, ta.selectionEnd, "end"); } });
    body.append(h("div", {}, h("h4", { text: "Corps (JSON)" }), ta));
  }

  if (e.resp !== undefined) {
    const ex = h("details.example", {}, h("summary.small.muted", { text: "Exemple de réponse" }), h("pre", {}, h("code", { text: pretty(e.resp) })));
    if (e.resp2) ex.append(h("p.small.muted", { text: "Variante (second facteur requis) :" }), h("pre", {}, h("code", { text: pretty(e.resp2) })));
    body.append(ex);
  }

  const curlPre = h("code");
  const curlBox = h("details.curl", {}, h("summary.small.muted", { text: "Commande curl équivalente" }), h("pre", {}, curlPre));
  const result = h("div");
  const run = h("button.btn.primary", { type: "button" }, e.nav ? "Ouvrir" : "Exécuter");
  const reset = h("button.btn", { type: "button", text: "Réinitialiser" });
  const cp = h("button.btn", { type: "button", text: "Copier curl" });
  body.append(h("div.actions", {}, run, ta ? reset : null, cp), curlBox, result);

  const build = () => {
    let path = e.p;
    const q = new URLSearchParams();
    for (const i of inputs) {
      const v = i.value.trim();
      if (i.dataset.in === "path") {
        if (!v) throw new Error(`paramètre « ${i.dataset.name} » obligatoire`);
        path = path.replace("{" + i.dataset.name + "}", encodeURIComponent(v));
      } else if (v) q.set(i.dataset.name, v);
      else if (i.dataset.req) throw new Error(`paramètre « ${i.dataset.name} » obligatoire`);
    }
    const url = path + (q.toString() ? "?" + q : "");
    let data;
    if (ta && ta.value.trim()) {
      try { data = JSON.stringify(JSON.parse(ta.value)); } catch (err) { throw new Error("corps JSON invalide : " + err.message); }
    }
    return { url, data };
  };
  const curl = () => {
    let r; try { r = build(); } catch { r = { url: e.p, data: e.body !== undefined ? JSON.stringify(e.body) : undefined }; }
    const parts = ["curl -sS"];
    if (e.m !== "GET") parts.push("-X " + e.m);
    if (auth.mode === "token" && tokenAllowed(e.scope) && e.scope !== "public") parts.push("-H @/etc/rempart/api.auth");
    else if (e.scope !== "public") { parts.push("-b rempart.cookies"); if (e.m !== "GET") parts.push("-H 'X-Rempart: 1'"); }
    else if (e.m !== "GET") parts.push("-H 'X-Rempart: 1'");
    if (r.data) parts.push("-H 'Content-Type: application/json'", "--data " + sq(r.data));
    if (e.file) parts.push("-o " + e.file);
    parts.push(sq(location.origin + r.url));
    return parts.join(" \\\n  ");
  };
  const refreshCurl = () => (curlPre.textContent = curl());
  curlBox.addEventListener("toggle", refreshCurl);
  inputs.forEach((i) => i.addEventListener("input", () => curlBox.open && refreshCurl()));
  ta?.addEventListener("input", () => curlBox.open && refreshCurl());
  cp.onclick = () => copy(curl(), "Commande curl copiée");
  if (ta) reset.onclick = () => { ta.value = pretty(e.body); refreshCurl(); };

  let armed = false, armTimer;
  run.onclick = async () => {
    let req;
    try { req = build(); } catch (err) { showError(result, err.message); return; }
    if (e.nav) { location.href = req.url; return; }
    if (e.danger && !armed) {
      armed = true; run.className = "btn danger"; run.textContent = `Confirmer : ${e.m} ${req.url}`;
      armTimer = setTimeout(() => { armed = false; run.className = "btn primary"; run.textContent = "Exécuter"; }, 6000);
      return;
    }
    clearTimeout(armTimer); armed = false; run.className = "btn primary"; run.textContent = "Exécuter";
    run.disabled = true;
    try { await execute(e, req, result); } finally { run.disabled = false; }
  };
  return body;
}

function showError(box, msg) {
  box.replaceChildren(h("div.callout.bad", {}, h("div", { text: msg })));
}

async function execute(e, req, box) {
  const headers = {};
  let credentials = "same-origin";
  if (auth.mode === "token" && e.scope !== "public") {
    if (!auth.token) { showError(box, "Collez d'abord un jeton dans « Authentification des requêtes », ou repassez en mode « Ma session »."); return; }
    headers.Authorization = "Bearer " + auth.token;
    credentials = "omit";
  } else if (e.m !== "GET") headers["X-Rempart"] = "1";
  if (req.data) headers["Content-Type"] = "application/json";
  const t0 = performance.now();
  let res;
  try {
    res = await fetch(req.url, { method: e.m, headers, body: req.data, credentials, cache: "no-store", redirect: "manual" });
  } catch (err) { showError(box, "Requête impossible : " + err.message); return; }
  const ms = Math.round(performance.now() - t0);
  const ct = res.headers.get("Content-Type") || "";
  const bar = h("div.bar", {}, h("span.code" + (res.ok ? "" : ".err"), { text: String(res.status || "redirection") }), h("span", { text: res.statusText || "" }), h("span.muted", { text: `${ms} ms` }), h("span.muted.small", { text: ct.split(";")[0] }));
  const out = h("div.result", {}, bar);
  if (/json/.test(ct)) {
    const txt = await res.text();
    let shown = txt; try { shown = pretty(JSON.parse(txt)); } catch {}
    bar.append(h("button.btn", { type: "button", onclick: () => copy(shown, "Réponse copiée") }, "Copier"));
    out.append(h("pre", {}, h("code", { text: shown })));
  } else if (/^text\//.test(ct) || ct === "") {
    const txt = await res.text();
    bar.append(h("button.btn", { type: "button", onclick: () => copy(txt, "Réponse copiée") }, "Copier"));
    out.append(h("pre", {}, h("code", { text: txt.length > 400000 ? txt.slice(0, 400000) + "\n… (tronqué à l'affichage)" : txt || "(réponse vide)" })));
  } else {
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const name = e.file || "rempart-reponse";
    out.append(h("div.bar", {}, h("span", { text: `Fichier de ${(blob.size / 1024).toLocaleString("fr-FR", { maximumFractionDigits: 1 })} Kio` }), h("a.btn.primary", { href: url, download: name, text: "Enregistrer " + name })));
  }
  box.replaceChildren(out);
  if (res.status === 401 && auth.mode === "session") checkWho();
  if (e.p === "/api/login" || e.p === "/api/logout" || e.p.startsWith("/api/login/")) checkWho();
}

// ---- authentification ----
const who = $("#who");
function setWho(state, text) { who.className = "who " + state; who.lastElementChild.textContent = text; }
async function checkWho() {
  setWho("", "Vérification…");
  const headers = {};
  if (auth.mode === "token") {
    if (!auth.token) { setWho("bad", "Aucun jeton saisi"); return; }
    headers.Authorization = "Bearer " + auth.token;
  }
  try {
    const r = await fetch("/api/me", { headers, credentials: auth.mode === "token" ? "omit" : "same-origin", cache: "no-store" });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { setWho("bad", auth.mode === "token" ? "Jeton refusé : " + (d.error || r.status) : "Pas de session ouverte"); return; }
    const role = { admin: "administrateur", operator: "opérateur", read: "lecture seule" }[d.role] || "";
    setWho("ok", auth.mode === "token" ? `Jeton valide (${d.user})` : `Connecté : ${d.name || d.user}${role ? " · " + role : ""}${d.source && d.source !== "local" ? " · " + d.source.toUpperCase() : ""}`);
  } catch (err) { setWho("bad", "Serveur injoignable"); }
}
function setMode(m) {
  auth.mode = m;
  $("#mode-session").setAttribute("aria-pressed", String(m === "session"));
  $("#mode-token").setAttribute("aria-pressed", String(m === "token"));
  $("#token-row").classList.toggle("hidden", m !== "token");
  $("#auth-help").textContent = m === "token"
    ? "Les requêtes partent avec Authorization: Bearer, sans cookie : exactement ce que verra un script. Le jeton reste en mémoire dans cet onglet et disparaît au rechargement."
    : "Les requêtes partent avec le cookie de votre session ouverte dans l'interface. Toutes les commandes sont possibles, selon votre rôle.";
  $$("details.op[open] details.curl[open]").forEach((d) => d.dispatchEvent(new Event("toggle")));
  checkWho();
}
$("#mode-session").onclick = () => setMode("session");
$("#mode-token").onclick = () => { setMode("token"); $("#token").focus(); };
$("#token").addEventListener("change", (ev) => { auth.token = ev.target.value.trim(); checkWho(); });
$("#token-check").onclick = () => { auth.token = $("#token").value.trim(); checkWho(); };
checkWho();

// ---- filtre ----
$("#filter").addEventListener("input", (ev) => {
  const words = ev.target.value.toLowerCase().split(/\s+/).filter(Boolean);
  const match = (s) => words.every((w) => s.includes(w));
  let any = false;
  tocLinks.forEach((a) => a.parentElement.classList.toggle("hidden", !match(a.dataset.search)));
  $$("#toc > div").forEach((g) => g.classList.toggle("hidden", !$$("li:not(.hidden)", g).length));
  $$("#ops section").forEach((sec) => {
    let n = 0;
    $$("details.op", sec).forEach((d) => { const m = match(d.dataset.search); d.classList.toggle("hidden", !m); if (m) n++; });
    sec.classList.toggle("hidden", !n); if (n) any = true;
  });
  $("#none").classList.toggle("hidden", any);
});

// ---- liens directs : #op-post-api-tokens ----
function openFromHash() {
  const id = decodeURIComponent(location.hash.slice(1));
  const d = id && document.getElementById(id);
  if (d && d.tagName === "DETAILS") { d.open = true; d.scrollIntoView({ block: "start" }); }
}
addEventListener("hashchange", openFromHash);
openFromHash();
