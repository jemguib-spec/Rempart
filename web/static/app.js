// app.js - interface d'administration de Rempart, sans dépendance ni CDN.
// Chaque valeur venant du serveur est échappée : les noms de domaine du
// journal sont des données contrôlées par n'importe qui sur Internet.
// Routes : #/<page>/<onglet>. CSP stricte : aucun style ni script en ligne.

class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
function html(strings, ...vals) {
  let out = "";
  strings.forEach((s, i) => {
    out += s;
    if (i < vals.length) {
      const v = vals[i];
      if (v instanceof Raw) out += v.s;
      else if (Array.isArray(v)) out += v.map((x) => (x instanceof Raw ? x.s : esc(x))).join("");
      else if (v !== false && v !== null && v !== undefined) out += esc(v);
    }
  });
  return new Raw(out);
}
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const arr = (x) => (Array.isArray(x) ? x : []);
const app = $("#app");
const checked = (b) => (b ? new Raw("checked") : "");
const selected = (b) => (b ? new Raw("selected") : "");

// ---- API ----
async function api(path, { method = "GET", body } = {}) {
  const res = await fetch("/api" + path, {
    method,
    headers: { "X-Rempart": "1", ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith("/login")) { showLogin(); throw new Error("session expirée"); }
  if (!res.ok) throw new Error(data.error || `erreur ${res.status}`);
  return data;
}

let toastTimer;
function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "show" + (err ? " err" : "");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), err ? 7000 : 2800);
}
async function act(btn, fn, okMsg) {
  if (btn) btn.disabled = true;
  try { const r = await fn(); if (okMsg) toast(okMsg); return r; }
  catch (e) { toast(e.message, true); }
  finally { if (btn) btn.disabled = false; }
}
const copy = (text, what = "Copié") => navigator.clipboard.writeText(text).then(() => toast(what), () => toast("Copie impossible : sélectionnez le texte", true));
function bindCopy(root) { $$("[data-copy]", root).forEach((b) => (b.onclick = () => copy(b.dataset.copy, b.dataset.copied || "Copié"))); }

// ---- formats ----
const nf = new Intl.NumberFormat("fr-FR");
const n = (x) => nf.format(x ?? 0);
const pct = (a, b) => (b ? ((100 * a) / b).toLocaleString("fr-FR", { maximumFractionDigits: 1 }) + " %" : "0 %");
const time = (s) => new Date(s).toLocaleTimeString("fr-FR");
const isSet = (s) => s && !String(s).startsWith("0001");
const date = (s) => (isSet(s) ? new Date(s).toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" }) : "jamais");
const day = (s) => (isSet(s) ? new Date(s).toLocaleDateString("fr-FR", { dateStyle: "medium" }) : "—");
const dur = (sec) => { const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60); return d ? `${d} j ${h} h` : h ? `${h} h ${m} min` : `${m} min`; };
const daysLeft = (s) => Math.floor((new Date(s) - Date.now()) / 86400000);
const statusLabel = { allowed: "résolue", blocked: "bloquée", cached: "cache", local: "zone locale", rewritten: "SafeSearch", error: "erreur", refused: "refusée" };
const lines = (s) => String(s || "").split("\n").map((x) => x.trim()).filter(Boolean);

// ---- icônes (traits 24×24) ----
const P = {
  home: "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  log: "M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01",
  filter: "M3 5h18l-7 8.5V20l-4-2v-4.5z",
  zone: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3.5 9h17M3.5 15h17M12 3c2.5 2.6 3.7 5.6 3.7 9s-1.2 6.4-3.7 9c-2.5-2.6-3.7-5.6-3.7-9S9.5 5.6 12 3z",
  shield: "M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z",
  gear: "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  more: "M5 12h.01M12 12h.01M19 12h.01",
  moon: "M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z",
  out: "M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 17l5-5-5-5M15 12H3",
  check: "M5 12.5l4.5 4.5L19 7.5",
  alert: "M12 8v5M12 16.5h.01M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z",
  info: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v5M12 8h.01",
  key: "M15.5 8.5a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0zM12 12v9M12 17h3M12 20h2",
  chip: "M7 7h10v10H7zM10 2v3M14 2v3M10 19v3M14 19v3M2 10h3M2 14h3M19 10h3M19 14h3",
  cert: "M4 4h16v11H4zM8 8h8M8 11h5M15 15l-1 6 2.5-1.5L19 21l-1-6",
  token: "M7 11V8a5 5 0 0 1 10 0v3M5 11h14v10H5zM12 15v2",
  audit: "M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 1 2-2h2a2 2 0 0 1 2 2v0a2 2 0 0 1-2 2h-2a2 2 0 0 1-2-2zM9 13l2 2 4-4",
  spark: "M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6",
  download: "M12 4v11M7 10l5 5 5-5M5 20h14",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  refresh: "M20 11a8 8 0 0 0-14.6-4.5L4 8M4 4v4h4M4 13a8 8 0 0 0 14.6 4.5L20 16M20 20v-4h-4",
  pause: "M8 5v14M16 5v14",
  eye: "M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  eyeoff: "M3 3l18 18M10.6 5.1A10.7 10.7 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-3.2 4.1M6.6 6.6C3.9 8.4 2 12 2 12s3.6 7 10 7c1.8 0 3.4-.5 4.8-1.3M9.9 9.9a3 3 0 0 0 4.2 4.2",
  arrow: "M5 12h14M13 6l6 6-6 6",
  phone: "M8 2.5h8a1.5 1.5 0 0 1 1.5 1.5v16a1.5 1.5 0 0 1-1.5 1.5H8A1.5 1.5 0 0 1 6.5 20V4A1.5 1.5 0 0 1 8 2.5zM11 18.5h2",
  play: "M7 4.5v15l12-7.5z",
  video: "M3 6.5h12.5v11H3zM15.5 10.5 21 7.5v9l-5.5-3",
  music: "M9 18V5.5l11-2V16M9 18a3 3 0 1 1-6 0 3 3 0 0 1 6 0zM20 16a3 3 0 1 1-6 0 3 3 0 0 1 6 0z",
  chat: "M4 5h16v11H9l-5 4z",
  game: "M7 5h10a5 5 0 0 1 4.9 6l-.8 4.3a2.5 2.5 0 0 1-4.3 1.2L14.5 14h-5l-2.3 2.5a2.5 2.5 0 0 1-4.3-1.2L2.1 11A5 5 0 0 1 7 5zM6 9.5h4M8 7.5v4M15.5 9.5h.01M18 11h.01",
  bag: "M5 8h14l-1 13H6zM9 8V6.5a3 3 0 0 1 6 0V8",
  heart: "M12 20s-7.5-4.6-7.5-10.2A4.2 4.2 0 0 1 12 7.2a4.2 4.2 0 0 1 7.5 2.6C19.5 15.4 12 20 12 20z",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM20 20l-4-4",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3.5 2",
  edit: "M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4",
  plus: "M12 5v14M5 12h14",
  x: "M6 6l12 12M18 6 6 18",
  chev: "M6 9l6 6 6-6",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 13h10l1-13M10 11v6M14 11v6",
  stop: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM5.6 5.6l12.8 12.8",
  wifi: "M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01",
  device: "M4 5h16v10H4zM9 19h6M12 15v4",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  mail: "M3 6h18v12H3zM3 7l9 6 9-6",
  text: "M5 6h14M5 12h14M5 18h9",
  server: "M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01",
  code: "M8 8l-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14",
  tablet: "M6 3h12a1.5 1.5 0 0 1 1.5 1.5v15A1.5 1.5 0 0 1 18 21H6a1.5 1.5 0 0 1-1.5-1.5v-15A1.5 1.5 0 0 1 6 3zM11 18h2",
  tv: "M3 5h18v12H3zM8 21h8M12 17v4",
  camera: "M4 7h3l2-2.5h6L17 7h3a1 1 0 0 1 1 1v11a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1zM12 17a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7z",
  printer: "M7 9V3h10v6M7 17H4v-7a1 1 0 0 1 1-1h14a1 1 0 0 1 1 1v7h-3M7 14h10v7H7z",
  users: "M15 19v-1a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v1M8.5 10.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM22 19v-1a4 4 0 0 0-3-3.9M15 3.6a3.5 3.5 0 0 1 0 6.8",
};
const icon = (name, cls = "i") => new Raw(`<svg class="${cls}" viewBox="0 0 24 24" aria-hidden="true"><path d="${P[name]}"/></svg>`);
const crenel = (cls = "") => new Raw(`<svg class="crenel ${cls}" viewBox="0 0 240 12" preserveAspectRatio="none" aria-hidden="true"><path fill="currentColor" d="${Array.from({ length: 12 }, (_, i) => `M${i * 20} 0h10v7h10V0`).join("")}V0H0z"/></svg>`);
const logo = new Raw(`<svg viewBox="0 0 32 32" aria-hidden="true"><path fill="#4cb7a5" d="M3 30V8h5v4h4V8h8v4h4V8h5v22z"/><path fill="#1d2b36" d="M13 30v-8a3 3 0 0 1 6 0v8z"/></svg>`);
const notice = (kind, content, ic) => html`<div class="notice ${kind}">${icon(ic || { good: "check", bad: "alert", plain: "info" }[kind] || "alert")}<div>${content}</div></div>`;

// ---- connexion ----
// Scène animée : des requêtes arrivent vers le rempart ; les publicités et
// traqueurs (rouge) s'y brisent, les requêtes légitimes (vert) passent la
// porte. Uniquement des classes CSS (CSP) ; rien n'anime si l'utilisateur a
// demandé moins de mouvement.
function loginScene() {
  const pk = Array.from({ length: 9 }, (_, i) => {
    const bad = [0, 2, 3, 5, 7].includes(i);
    const y = [88, 132, 110, 150, 96, 124, 142, 104, 118][i];
    return `<circle class="pk ${bad ? "bad" : "ok"} d${i}" cx="0" cy="${y}" r="${bad ? 4.5 : 4}"/>`;
  }).join("");
  return new Raw(`<svg class="scene" viewBox="0 0 360 220" aria-hidden="true">
    <defs><linearGradient id="lg-beam" x1="0" x2="1"><stop offset="0" stop-color="#4cb7a5" stop-opacity="0"/><stop offset="1" stop-color="#4cb7a5" stop-opacity=".55"/></linearGradient></defs>
    <g class="lanes">${[88, 104, 118, 132, 150].map((y) => `<line x1="0" x2="232" y1="${y}" y2="${y}"/>`).join("")}</g>
    ${pk}
    <path class="wallshape" d="M232 210V40h14v14h12V40h14v14h12V40h14v170zM254 210v-34a10 10 0 0 1 20 0v34z" fill-rule="evenodd"/>
    <rect class="gate" x="256" y="168" width="16" height="42" rx="2"/>
    <path class="beam" d="M300 118h60" stroke="url(#lg-beam)"/>
    <circle class="halo" cx="268" cy="22" r="7"/>
  </svg>`);
}

let challenge = "";
// Retour d'une connexion OIDC échouée : seul un code passe dans l'URL, jamais
// un texte (une URL forgée ne doit pas pouvoir afficher n'importe quel message).
const ssoErrors = {
  "bloque": "Trop d'échecs depuis cette adresse : réessayez plus tard.",
  "oidc-indisponible": "Le fournisseur d'identité est injoignable : réessayez, ou utilisez le compte local.",
  "oidc-session": "La connexion a expiré ou a été commencée dans un autre navigateur : recommencez.",
  "oidc-refus": "Connexion annulée chez le fournisseur d'identité.",
  "oidc-echec": "La réponse du fournisseur d'identité a été refusée (détails dans le journal d'audit).",
  "oidc-role": "Votre compte est reconnu mais n'a aucun rôle dans Rempart : demandez l'accès à un administrateur.",
  "oidc-acr": "Ce compte doit se connecter avec une authentification plus forte (double authentification).",
  "occupe": "Trop de connexions en cours : réessayez dans quelques minutes.",
};
let pendingLoginError = ssoErrors[new URLSearchParams(location.search).get("erreur")] || "";
if (location.search) history.replaceState(null, "", location.pathname + location.hash);
let me = {};
const roleNames = { admin: "administrateur", operator: "opérateur", read: "lecture seule" };

function showLogin(msg) {
  msg = msg || pendingLoginError;
  pendingLoginError = "";
  clearInterval(refreshTimer);
  shellRendered = false;
  challenge = "";
  app.innerHTML = html`
  <div class="login">
    <section class="login-hero">
      <div class="brand-l">${logo}<b>Rempart</b></div>
      ${loginScene()}
      <div class="pitch">
        <h1>Le DNS qui garde<br>la porte.</h1>
        <p>Publicités et traqueurs s'arrêtent au rempart. Le reste passe, chiffré.</p>
        <ul class="chips"><li>DNSSEC</li><li>HSM PKCS#11</li><li>Journal chiffré</li><li>DoH · DoT</li></ul>
      </div>
    </section>
    <section class="login-side">
      <div class="login-card" id="card">
        ${crenel()}
        <div class="steps-x" id="steps">
          <form id="f-pass" class="step on" autocomplete="on" novalidate>
            <div><h2>Connexion</h2><p class="muted small">Interface d'administration</p></div>
            <label class="field"><span>Utilisateur</span><input name="username" value="admin" autocomplete="username" required></label>
            <label class="field"><span>Mot de passe</span>
              <span class="pw"><input name="password" type="password" autocomplete="current-password" required autofocus>
              <button type="button" class="eye" id="eye" aria-label="Afficher le mot de passe" aria-pressed="false">${icon("eye")}</button></span>
            </label>
            <p class="caps" id="caps" hidden>${icon("alert")} Verr. Maj activé</p>
            <p class="err" id="err1" role="alert"></p>
            <button class="primary go" type="submit"><span>Se connecter</span>${icon("arrow")}</button>
            <button type="button" class="btn sso" id="pk-login" hidden>${icon("key")}<span>Se connecter avec une clé d'accès</span></button>
            <div id="sso" class="stack-s" hidden></div>
            <p class="muted small" id="login-hint">Mot de passe initial : REMPART_ADMIN_PASSWORD_FILE (scripts/init-secrets).</p>
          </form>
          <form id="f-otp" class="step" autocomplete="off" novalidate>
            <div class="otp-head"><span class="lock">${icon("phone")}</span><div><h2>Vérification</h2><p class="muted small" id="otp-help">Code à 6 chiffres de votre application d'authentification.</p></div></div>
            <div class="otp" id="otp-box">
              <input id="otp" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]*" maxlength="6" aria-label="Code à usage unique" spellcheck="false">
              <div class="cells" aria-hidden="true">${Array.from({ length: 6 }, () => new Raw("<i></i>"))}</div>
            </div>
            <label class="field rec" hidden><span>Code de secours</span><input id="rec" name="recovery" autocomplete="off" spellcheck="false" placeholder="xxxx-xxxx-xxxx-xxxx"></label>
            <div class="ring" aria-hidden="true"><span id="ttl-txt"></span><b><i id="ttl"></i></b></div>
            <p class="err" id="err2" role="alert"></p>
            <button class="primary go" type="submit"><span>Vérifier</span>${icon("arrow")}</button>
            <button type="button" class="btn sso" id="use-key" hidden>${icon("key")}<span>Utiliser ma clé d'accès</span></button>
            <div class="row between"><button type="button" class="link" id="back">← Retour</button><button type="button" class="link" id="use-rec">Utiliser un code de secours</button></div>
          </form>
        </div>
      </div>
    </section>
  </div>`;
  const card = $("#card"), fp = $("#f-pass"), fo = $("#f-otp");
  const pw = fp.password, otp = $("#otp"), rec = $("#rec");
  const fail = (el, text) => {
    el.textContent = text;
    card.classList.remove("shake"); void card.offsetWidth; card.classList.add("shake");
  };
  const busy = (form, on) => { const b = $(".go", form); b.disabled = on; b.classList.toggle("busy", on); };
  const success = async (r, form) => {
    const b = $(".go", form);
    b.classList.add("done");
    b.innerHTML = html`${icon("check")}<span>Bienvenue</span>`.s;
    card.classList.add("win");
    if (r && r.method === "code de secours") setTimeout(() => toast(`Code de secours utilisé : il en reste ${r.recovery_left}`, r.recovery_left < 3), 900);
    await new Promise((res) => setTimeout(res, matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 650));
    $(".login").classList.add("leave");
    await new Promise((res) => setTimeout(res, matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 280));
    route();
  };
  if (msg) $("#err1").textContent = msg;
  // Moyens de connexion configurés : annuaire LDAP, fournisseur OIDC.
  api("/auth/providers").then((pv) => {
    if (!$("#sso")) return;
    if (pv.ldap) {
      $("span", fp.username.closest(".field")).textContent = "Utilisateur de l'annuaire";
      if (fp.username.value === "admin" && document.activeElement !== fp.username) fp.username.value = "";
      fp.username.placeholder = "prenom.nom";
      $("#login-hint").textContent = "Compte de l'annuaire de l'entreprise. Le compte local reste utilisable en secours.";
    }
    if (pv.oidc) {
      const box = $("#sso");
      box.innerHTML = html`<div class="or"><span>ou</span></div>
        <a class="btn sso" href="/api/oidc/login">${icon("key")}<span>Se connecter avec ${pv.oidc_label}</span></a>`.s;
      box.hidden = false;
    }
    if (pv.ldap) fp.username.focus();
  }).catch(() => {});

  $("#eye").onclick = (e) => {
    const show = pw.type === "password";
    pw.type = show ? "text" : "password";
    e.currentTarget.setAttribute("aria-pressed", String(show));
    e.currentTarget.setAttribute("aria-label", show ? "Masquer le mot de passe" : "Afficher le mot de passe");
    e.currentTarget.innerHTML = icon(show ? "eyeoff" : "eye").s;
    pw.focus();
  };
  const caps = (e) => { if (e.getModifierState) $("#caps").hidden = !e.getModifierState("CapsLock"); };
  pw.addEventListener("keyup", caps); pw.addEventListener("keydown", caps);

  fp.addEventListener("submit", async (e) => {
    e.preventDefault();
    $("#err1").textContent = "";
    if (!pw.value) return fail($("#err1"), "Saisissez le mot de passe.");
    busy(fp, true);
    try {
      const r = await api("/login", { method: "POST", body: { username: fp.username.value, password: pw.value } });
      if (r.second_factor || r.otp_required) {
        challenge = r.challenge;
        pw.value = "";
        goOtp(r);
      } else await success(r, fp);
    } catch (err) { fail($("#err1"), err.message); }
    finally { busy(fp, false); }
  });

  // Étape 2 : cellules dessinées à partir d'un vrai champ (collage, saisie
  // automatique iOS/Android et lecteurs d'écran fonctionnent).
  const cells = $$(".cells i", fo);
  const paint = () => {
    const v = otp.value;
    cells.forEach((c, i) => { c.textContent = v[i] || ""; c.classList.toggle("on", i === Math.min(v.length, 5) && document.activeElement === otp); c.classList.toggle("full", !!v[i]); });
  };
  otp.addEventListener("input", () => {
    otp.value = otp.value.replace(/\D/g, "").slice(0, 6);
    $("#otp-box").classList.remove("bad");
    paint();
    if (otp.value.length === 6) fo.requestSubmit();
  });
  ["focus", "blur", "keyup", "click"].forEach((ev) => otp.addEventListener(ev, paint));
  let ttlTimer;
  const tick = () => {
    const left = 30 - (Math.floor(Date.now() / 1000) % 30), t = $("#ttl");
    if (!t) return clearInterval(ttlTimer);
    t.style.width = (left / 30) * 100 + "%";
    t.classList.toggle("low", left <= 5);
    $("#ttl-txt").textContent = `Nouveau code dans ${left} s`;
  };
  function goOtp(r = { otp_required: true }) {
    fp.classList.remove("on"); fp.classList.add("off");
    fo.classList.add("on");
    otp.value = ""; paint();
    const codes = r.otp_required !== false;
    // Clé d'accès seule : pas de code à saisir.
    $(".otp", fo).hidden = !codes; $(".ring", fo).hidden = !codes; $(".go", fo).hidden = !codes; $("#use-rec").hidden = !codes;
    $("#use-key").hidden = !(r.passkey && passkeySupported());
    $("#otp-help").textContent = codes ? "Code à 6 chiffres de votre application d'authentification." : "Confirmez avec votre clé d'accès.";
    if (codes) { setTimeout(() => otp.focus(), 60); clearInterval(ttlTimer); tick(); ttlTimer = setInterval(tick, 1000); }
    else if (r.passkey && passkeySupported()) setTimeout(() => $("#use-key").click(), 120);
  }
  const keyLogin = async (btn, pwChallenge, errEl) => {
    btn.disabled = true;
    try {
      const opts = await api("/login/passkey/begin", { method: "POST", body: pwChallenge ? { challenge: pwChallenge } : {} });
      const body = await passkeyGet(opts);
      const r = await api("/login/passkey/finish", { method: "POST", body });
      clearInterval(ttlTimer);
      await success(r, btn.closest("form"));
    } catch (err) {
      fail(errEl, passkeyError(err));
      if (/expirée|reconnectez/.test(err.message || "")) setTimeout(() => showLogin("Étape expirée : saisissez à nouveau le mot de passe."), 1200);
    } finally { btn.disabled = false; }
  };
  if (passkeySupported()) $("#pk-login").hidden = false;
  $("#pk-login").onclick = (e) => { $("#err1").textContent = ""; keyLogin(e.currentTarget, "", $("#err1")); };
  $("#use-key").onclick = (e) => { $("#err2").textContent = ""; keyLogin(e.currentTarget, challenge, $("#err2")); };
  $("#back").onclick = () => { challenge = ""; fo.classList.remove("on"); fp.classList.remove("off"); fp.classList.add("on"); pw.focus(); };
  let useRec = false;
  $("#use-rec").onclick = (e) => {
    useRec = !useRec;
    $(".otp", fo).hidden = useRec; $(".ring", fo).hidden = useRec; $(".rec", fo).hidden = !useRec;
    e.currentTarget.textContent = useRec ? "Utiliser l'application" : "Utiliser un code de secours";
    $("#otp-help").textContent = useRec ? "Chaque code de secours ne fonctionne qu'une fois." : "Code à 6 chiffres de votre application d'authentification.";
    (useRec ? rec : otp).focus();
  };
  fo.addEventListener("submit", async (e) => {
    e.preventDefault();
    const code = useRec ? rec.value.trim() : otp.value;
    $("#err2").textContent = "";
    if (!useRec && code.length !== 6) return fail($("#err2"), "Le code compte 6 chiffres.");
    if (useRec && code.replace(/[\s-]/g, "").length !== 16) return fail($("#err2"), "Un code de secours compte 16 caractères.");
    busy(fo, true);
    try {
      const r = await api("/login/otp", { method: "POST", body: { challenge, code } });
      clearInterval(ttlTimer);
      await success(r, fo);
    } catch (err) {
      $("#otp-box").classList.add("bad");
      otp.value = ""; paint();
      fail($("#err2"), err.message);
      if (/expirée|reconnectez/.test(err.message)) setTimeout(() => showLogin("Étape expirée : saisissez à nouveau le mot de passe."), 1200);
      else (useRec ? rec : otp).focus();
    } finally { busy(fo, false); }
  });
}

// ---- clés d'accès (WebAuthn) ----
const b64uEnc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uDec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const passkeySupported = () => !!(window.PublicKeyCredential && navigator.credentials && isSecureContext);
async function passkeyGet(opts) {
  const cred = await navigator.credentials.get({ publicKey: {
    challenge: b64uDec(opts.challenge), rpId: opts.rpId, timeout: opts.timeout, userVerification: opts.userVerification,
    allowCredentials: (opts.allowCredentials || []).map((c) => ({ type: c.type, id: b64uDec(c.id) })),
  } });
  const r = cred.response;
  return { challenge: opts.challenge, id: b64uEnc(cred.rawId), clientDataJSON: b64uEnc(r.clientDataJSON),
    authenticatorData: b64uEnc(r.authenticatorData), signature: b64uEnc(r.signature), userHandle: r.userHandle ? b64uEnc(r.userHandle) : "" };
}
async function passkeyCreate(opts) {
  const cred = await navigator.credentials.create({ publicKey: {
    ...opts, challenge: b64uDec(opts.challenge), user: { ...opts.user, id: b64uDec(opts.user.id) },
    excludeCredentials: (opts.excludeCredentials || []).map((c) => ({ type: c.type, id: b64uDec(c.id) })),
  } });
  return { challenge: opts.challenge, clientDataJSON: b64uEnc(cred.response.clientDataJSON), attestationObject: b64uEnc(cred.response.attestationObject) };
}
const passkeyError = (err) => err && err.name === "NotAllowedError" ? "Opération annulée ou délai dépassé." : err && err.name === "InvalidStateError" ? "Cette clé est déjà enregistrée." : (err && err.message) || String(err);

// Passage à un autre HSM : Rempart ne copie pas de clés non extractibles ;
// le constructeur clone le token, Rempart vérifie la copie puis bascule.
function cloneWizard(s) {
  const mods = arr(s.modules).filter((m) => !m.error);
  return html`<section class="panel stack-s" id="clone-wiz">
    <div class="panel-head"><h2>Passer à un autre HSM</h2>
      <p>Les clés sont non extractibles : seul l'outil du constructeur peut les copier (clonage de partition, sauvegarde et restauration). Rempart vérifie ensuite le token cible <b>sans rien y écrire</b> : mêmes clés publiques, clés non extractibles, KEK capable d'ouvrir les données actuelles. Puis il bascule au prochain démarrage, sans rechiffrement.</p></div>
    <div class="fields">
      <label class="field"><span>Bibliothèque PKCS#11</span><select id="c-mod">${mods.map((m) => html`<option value="${m.path}" ${selected(m.path === s.active_module)}>${m.path}</option>`)}</select></label>
      <label class="field"><span>Label du token cible</span><input id="c-token" required placeholder="rempart-secours"></label>
      <label class="field"><span>PIN du token cible</span><input id="c-pin" type="password" autocomplete="off" required></label>
    </div>
    <div class="row"><button class="primary" id="c-verify">${icon("check")}Vérifier le token</button></div>
    <div id="c-out"></div>
  </section>`;
}

// ---- coque et routage ----
const pages = [
  ["dashboard", "Tableau de bord", "home"],
  ["log", "Journal", "log"],
  ["filters", "Filtrage", "filter"],
  ["clients", "Appareils", "users"],
  ["zones", "Zones DNSSEC", "zone"],
  ["security", "Sécurité", "shield"],
  ["settings", "Réglages", "gear"],
];
let shellRendered = false;
let refreshTimer;

function toggleTheme() {
  const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = cur === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("rempart-theme", next); } catch {}
}
async function logout() {
  const r = await api("/logout", { method: "POST" }).catch(() => ({}));
  // Session OIDC : on termine aussi la session chez le fournisseur.
  if (r.redirect) { location.href = r.redirect; return; }
  showLogin();
}

function renderShell() {
  const mobileMain = pages.slice(0, 4);
  app.innerHTML = html`
  <div class="shell">
    <aside class="rail">
      ${crenel("top")}
      <div class="brand">${logo}<b>Rempart<small>Résolveur DNS filtrant</small></b></div>
      <nav class="nav" aria-label="Navigation principale">
        ${pages.map(([id, label, ic]) => html`<a href="#/${id}" data-page="${id}" title="${label}">${icon(ic)}<span>${label}</span></a>`)}
      </nav>
      <div class="rail-foot">
        <span id="side-user" class="side-user"></span>
        <span id="side-ver"></span>
        <a class="foot-link" href="aide.html" title="Aide">${icon("info")}<span>Aide</span></a>
        <a class="foot-link" href="api.html" title="Console API">${icon("code")}<span>Console API</span></a>
        <button id="theme" type="button" title="Changer de thème">${icon("moon")}<span>Changer de thème</span></button>
        <button id="logout" type="button" title="Se déconnecter">${icon("out")}<span>Se déconnecter</span></button>
      </div>
    </aside>
    <header class="topbar">${logo}<b>Rempart</b><span class="pill" id="top-pill"><i></i><span>…</span></span></header>
    <main id="main" tabindex="-1"></main>
    <nav class="tabbar" aria-label="Navigation">
      ${mobileMain.map(([id, label, ic]) => html`<a href="#/${id}" data-page="${id}">${icon(ic)}<span>${label.replace("Tableau de bord", "Accueil").replace("Zones DNSSEC", "Zones")}</span></a>`)}
      <button type="button" id="more" data-page="more">${icon("more")}<span>Plus</span></button>
    </nav>
    <div class="sheet" id="sheet"><div role="menu">
      ${pages.slice(4).map(([id, label, ic]) => html`<a href="#/${id}" role="menuitem">${icon(ic)}${label}</a>`)}
      <a href="aide.html" role="menuitem">${icon("info")}Aide</a>
      <a href="api.html" role="menuitem">${icon("code")}Console API</a>
      <button type="button" data-act="theme" role="menuitem">${icon("moon")}Changer de thème</button>
      <button type="button" data-act="logout" role="menuitem">${icon("out")}Se déconnecter</button>
    </div></div>
  </div>`;
  $("#logout").onclick = logout;
  $("#theme").onclick = toggleTheme;
  const sheet = $("#sheet");
  $("#more").onclick = () => sheet.classList.add("open");
  sheet.onclick = (e) => {
    const b = e.target.closest("[data-act]");
    if (b?.dataset.act === "theme") toggleTheme();
    if (b?.dataset.act === "logout") logout();
    sheet.classList.remove("open");
  };
  shellRendered = true;
}

function parseHash() {
  const [page, tab] = (location.hash.replace(/^#\/?/, "") || "dashboard").split("?")[0].split("/");
  return { page: pages.find(([p]) => p === page) ? page : "dashboard", tab: tab || "" };
}

async function route() {
  clearInterval(refreshTimer);
  const { page, tab } = parseHash();
  try { me = await api("/me"); } catch { return; }
  if (!shellRendered) renderShell();
  const su = $("#side-user");
  if (su) {
    su.textContent = me.name || me.user;
    su.title = `${me.user} · ${roleNames[me.role] || me.role}${me.source === "ldap" ? " · annuaire LDAP" : me.source === "oidc" ? " · OIDC" : ""}`;
  }
  $$("[data-page]").forEach((a) => {
    const on = a.dataset.page === page || (a.dataset.page === "more" && ["zones", "security", "settings"].includes(page));
    on ? a.setAttribute("aria-current", "page") : a.removeAttribute("aria-current");
  });
  const main = $("#main");
  main.innerHTML = '<div class="page"><p class="muted">Chargement…</p></div>';
  try {
    await views[page](main, tab);
    $(".page", main)?.classList.add("enter"); // animation d'entrée, pas aux rafraîchissements
  } catch (e) {
    main.innerHTML = html`<div class="page">${notice("bad", e.message)}</div>`;
  }
  refreshStatusPill();
}
window.addEventListener("hashchange", () => { route(); $("#main")?.focus({ preventScroll: true }); window.scrollTo(0, 0); });

async function refreshStatusPill() {
  try {
    const st = await api("/status");
    const paused = st.paused_until && new Date(st.paused_until) > new Date();
    const on = st.blocking_enabled && !paused;
    const pill = $("#top-pill");
    if (pill) { pill.className = "pill" + (on ? "" : " off"); $("span", pill).textContent = on ? "Protégé" : paused ? "En pause" : "Désactivé"; }
    const v = $("#side-ver");
    if (v) v.textContent = `Version ${st.version} · ${dur(st.uptime_s)}`;
  } catch {}
}

function tabs(page, list, current) {
  const cur = list.find(([id]) => id === current) ? current : list[0][0];
  return { cur, nav: html`<nav class="tabs" aria-label="Sections">${list.map(([id, label, dot]) => html`<a href="#/${page}/${id}" ${cur === id ? new Raw('aria-current="page"') : ""}>${label}${dot ? new Raw('<span class="dot" aria-label="action requise"></span>') : ""}</a>`)}</nav>` };
}
const head = (title, text, aside = "") => html`<div class="page-head"><div><h1>${title}</h1>${text ? html`<p>${text}</p>` : ""}</div>${aside}</div>`;
const sw = (name, on, label, help, attrs = "") => html`<label class="switch"><input type="checkbox" name="${name}" ${checked(on)} ${new Raw(attrs)}><span><b>${label}</b>${help ? html`<span class="muted">${help}</span>` : ""}</span></label>`;
const applyWidths = (root) => {
  $$("[data-w]", root).forEach((el) => (el.style.width = el.dataset.w + "%"));
  $$("[data-left]", root).forEach((el) => (el.style.left = el.dataset.left + "%"));
};

const views = {};

// ================= Tableau de bord =================
// Deux familles de données : des compteurs anonymes (séries, types,
// transports, motifs, latences, état des composants), toujours là, même
// sans journal ; et des classements nominatifs (domaines, clients, groupes),
// selon le mode de confidentialité.
const dashPref = {
  get(k, d) { try { return localStorage.getItem("rempart.dash." + k) || d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem("rempart.dash." + k, v); } catch {} },
};
const hhmm = (t) => new Date(t * 1000).toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit" });
const ms = (v) => (v >= 100 ? Math.round(v) : v >= 10 ? v.toFixed(0) : v.toFixed(1)).toLocaleString("fr-FR") + " ms";
const sum = (a, f) => arr(a).reduce((s, x) => s + (f ? f(x) : x), 0);

// Barres de la série : trafic total, part bloquée au sommet (un merlon du rempart).
function wallChart(series, range = "24h") {
  series = arr(series);
  if (!series.length || !series.some((p) => p.q)) return html`<p class="empty">Pas encore de données sur cette période.</p>`;
  const W = 1440, H = 200, gap = series.length > 100 ? 2 : 4;
  const bw = W / series.length;
  const max = Math.max(1, ...series.map((p) => p.q));
  const y = (v) => ((H - 6) * v) / max;
  const label = (t) => range === "7j"
    ? new Date(t * 1000).toLocaleString("fr-FR", { weekday: "short", hour: "2-digit", minute: "2-digit" })
    : hhmm(t);
  const unit = { "1h": "la minute", "24h": "ces 10 minutes", "7j": "cette heure" }[range];
  let bars = "";
  series.forEach((p, i) => {
    const x = i * bw, w = Math.max(bw - gap, 1), hq = y(p.q), hb = y(p.b);
    const tip = `${label(p.t)} : ${n(p.q)} requêtes, ${n(p.b)} bloquées sur ${unit}`;
    // Cible de survol pleine hauteur : la barre peut être minuscule.
    bars += `<g><title>${esc(tip)}</title><rect class="hit" x="${x}" y="0" width="${bw}" height="${H}"/>`;
    if (hq > 0) bars += `<rect class="${i === series.length - 1 ? "now" : "q"}" x="${x}" y="${H - hq}" width="${w}" height="${hq}" rx="2"/>`;
    if (hb > 0) bars += `<rect class="b" x="${x}" y="${H - hq}" width="${w}" height="${Math.max(hb, 1.5)}" rx="2"/>`;
    bars += "</g>";
  });
  let axis = "";
  series.forEach((p, i) => {
    const d = new Date(p.t * 1000);
    const show = range === "1h" ? d.getMinutes() % 10 === 0
      : range === "24h" ? d.getMinutes() === 0 && d.getHours() % 3 === 0
      : d.getHours() === 0;
    if (show) axis += `<span data-left="${(100 * i) / series.length}">${range === "7j" ? esc(d.toLocaleDateString("fr-FR", { weekday: "short", day: "numeric" })) : range === "1h" ? hhmm(p.t) : d.getHours() + " h"}</span>`;
  });
  const aria = { "1h": "Requêtes et blocages sur la dernière heure, minute par minute", "24h": "Requêtes et blocages sur 24 heures, par tranches de 10 minutes", "7j": "Requêtes et blocages sur 7 jours, heure par heure" }[range];
  return new Raw(`<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="${aria}">${bars}</svg><div class="axis">${axis}</div>`);
}

// Carte de chaleur jour × heure : un seul ton, du clair au foncé.
function weekHeat(week) {
  week = arr(week);
  if (!week.some((p) => p.q)) return html`<p class="empty">Il faut quelques heures d'activité pour remplir cette carte.</p>`;
  const rows = [];
  for (const p of week) {
    const d = new Date(p.t * 1000);
    const key = d.toDateString();
    let r = rows.find((x) => x.key === key);
    if (!r) rows.push((r = { key, d, cells: {} }));
    r.cells[d.getHours()] = p;
  }
  const max = Math.max(1, ...week.map((p) => p.q));
  const C = 26, R = 22, L = 74, T = 18;
  let s = "";
  for (let h = 0; h < 24; h += 3) s += `<text class="lbl" x="${L + h * C + C / 2}" y="12" text-anchor="middle">${h} h</text>`;
  rows.forEach((r, i) => {
    const y = T + i * R;
    s += `<text class="lbl" x="${L - 8}" y="${y + R / 2 + 4}" text-anchor="end">${esc(r.d.toLocaleDateString("fr-FR", { weekday: "short", day: "numeric" }))}</text>`;
    for (let h = 0; h < 24; h++) {
      const p = r.cells[h];
      const x = L + h * C;
      if (!p) { s += `<rect class="cell none" x="${x + 1}" y="${y + 1}" width="${C - 2}" height="${R - 2}" rx="3"/>`; continue; }
      const v = p.q / max;
      const tip = `${r.d.toLocaleDateString("fr-FR", { weekday: "long", day: "numeric", month: "long" })}, ${h} h : ${n(p.q)} requêtes, ${n(p.b)} bloquées (${pct(p.b, p.q)})`;
      s += `<g><title>${esc(tip)}</title><rect class="cell ${p.q ? "on" : "zero"}" x="${x + 1}" y="${y + 1}" width="${C - 2}" height="${R - 2}" rx="3" fill-opacity="${p.q ? (0.12 + 0.88 * v).toFixed(2) : 1}"/></g>`;
    }
  });
  const W = L + 24 * C, H = T + rows.length * R;
  return html`<svg class="heat" viewBox="0 0 ${W} ${H}" role="img" aria-label="Volume de requêtes par jour et par heure sur 7 jours">${new Raw(s)}</svg>
    <div class="heat-legend small muted"><span>moins</span><i class="s1"></i><i class="s2"></i><i class="s3"></i><i class="s4"></i><span>plus</span></div>`;
}

// Liste étiquetée : l'identité tient au texte, la couleur n'est qu'un accent.
function distRows(items, { empty = "Pas encore de données.", total, tone = "", mono = false } = {}) {
  items = arr(items).filter((x) => x.count > 0);
  if (!items.length) return html`<p class="empty">${empty}</p>`;
  const max = Math.max(...items.map((x) => x.count));
  const all = total ?? sum(items, (x) => x.count);
  return html`<ol class="bars dist">${items.map((t) => html`<li>
    <span class="${mono ? "domain" : ""}" title="${t.label ?? t.key}">${t.label ?? t.key}${t.hint ? html` <span class="muted small">${t.hint}</span>` : ""}</span>
    <span class="muted">${n(t.count)} · ${pct(t.count, all)}</span>
    <span class="meter"><i class="${t.tone || tone}" data-w="${(100 * t.count) / max}"></i></span></li>`)}</ol>`;
}
function topList(items, red, empty) {
  return distRows(items, { empty, tone: red ? "t-block" : "", mono: true });
}

const qtypeHint = { A: "adresse IPv4", AAAA: "adresse IPv6", HTTPS: "service web (SVCB)", SVCB: "service", CNAME: "alias", MX: "messagerie", TXT: "texte", PTR: "adresse → nom", SRV: "service", NS: "serveurs de noms", SOA: "zone", DS: "DNSSEC", DNSKEY: "DNSSEC", ANY: "tout (RFC 8482)", autre: "types peu courants" };
const protoName = { udp: ["DNS classique", "UDP, en clair"], tcp: ["DNS classique", "TCP, en clair"], dot: ["DNS-over-TLS", "chiffré"], doh: ["DNS-over-HTTPS", "chiffré"], doq: ["DNS-over-QUIC", "chiffré"], dnscrypt: ["DNSCrypt", "chiffré"] };
const rcodeName = { NOERROR: "réponse obtenue", NXDOMAIN: "nom inexistant", SERVFAIL: "échec de résolution", REFUSED: "refusée", FORMERR: "requête mal formée", NOTIMP: "non prise en charge", BADVERS: "EDNS non pris en charge" };

// État d'un composant : toujours un mot avec la couleur.
const hcard = (state, title, value, detail, href) => html`<li class="hcard ${state}">
  <span class="tag ${state === "good" ? "ok" : state === "bad" ? "bad" : state === "warn" ? "warn" : ""}">${{ good: "OK", warn: "À surveiller", bad: "Problème", plain: "Info" }[state]}</span>
  <b>${title}</b><strong>${value}</strong>${detail ? html`<span class="muted small">${detail}</span>` : ""}
  ${href ? html`<a class="small" href="${href}">Voir</a>` : ""}</li>`;

function healthCards(h, st) {
  const out = [];
  const c = h.cache || {};
  out.push(hcard("plain", "En service depuis", dur(h.uptime_s || st.uptime_s), `version ${st.version} · ${n(h.memory_mb)} Mo · ${n(h.goroutines)} tâches`));
  const L = h.lists || {};
  const old = L.oldest_update ? daysLeft(L.oldest_update) : null;
  out.push(hcard(L.errors ? "bad" : !L.enabled ? "warn" : old !== null && old < -7 ? "warn" : "good", "Listes de blocage",
    `${n(L.enabled)} active${L.enabled > 1 ? "s" : ""} sur ${n(L.total)}`,
    L.errors ? `${n(L.errors)} en échec de mise à jour` : L.oldest_update ? `plus ancienne mise à jour ${ago(L.oldest_update)}` : "aucune mise à jour encore", "#/filters/lists"));
  out.push(hcard("plain", "Cache", `${n(c.entries)} réponses`, `${pct(c.hits, (c.hits || 0) + (c.misses || 0))} des requêtes servies sans attendre l'amont`));
  if (h.dnssec) {
    const d = h.dnssec, tot = d.secure + d.insecure + d.bogus;
    out.push(hcard(d.bogus > Math.max(20, tot / 100) ? "warn" : "good", "Validation DNSSEC", `${pct(d.secure, tot)} des réponses signées`,
      d.bogus ? `${n(d.bogus)} réponse${d.bogus > 1 ? "s" : ""} falsifiée${d.bogus > 1 ? "s" : ""} refusée${d.bogus > 1 ? "s" : ""}` : `${n(tot)} réponses contrôlées, aucune falsifiée`));
  }
  if (h.tls) {
    const left = daysLeft(h.tls.not_after);
    out.push(hcard(left < 7 ? "bad" : left < 21 || h.tls.self_signed ? "warn" : "good", "Certificat", left < 0 ? "expiré" : `expire dans ${n(left)} j`,
      h.tls.self_signed ? "auto-signé : refusé par DoH/DoT des téléphones" : `obtenu par ${h.tls.mode === "acme" ? "ACME" : h.tls.mode === "manual" ? "import" : h.tls.mode}`, "#/security/tls"));
  }
  if (h.audit) out.push(hcard(h.audit.ok ? "good" : "bad", "Journal d'audit", h.audit.ok ? "intègre" : "chaîne rompue", `${n(h.audit.events)} événements signés`, "#/security/audit"));
  const Z = h.zones || {};
  if (Z.total) {
    const left = Z.signature_expiry ? daysLeft(Z.signature_expiry) : null;
    out.push(hcard(left !== null && left < 3 ? "bad" : "good", "Zones locales", `${n(Z.total)} zone${Z.total > 1 ? "s" : ""}, ${n(Z.signed)} signée${Z.signed > 1 ? "s" : ""}`,
      left !== null ? `signatures valables encore ${n(left)} j` : "", "#/zones"));
  }
  if (h.secondaries) out.push(hcard(h.secondaries.expired ? "bad" : "good", "Zones secondaires", `${n(h.secondaries.total)} copiée${h.secondaries.total > 1 ? "s" : ""}`, h.secondaries.expired ? `${n(h.secondaries.expired)} expirée(s), plus servie(s)` : "à jour", "#/zones"));
  if (h.rpz) out.push(hcard(h.rpz.errors ? "warn" : "good", "Flux de menaces RPZ", `${n(h.rpz.rules)} règles`, `${n(h.rpz.feeds)} flux${h.rpz.errors ? `, ${n(h.rpz.errors)} en échec` : ""}`, "#/filters/rpz"));
  if (h.replication) {
    const r = h.replication;
    const late = r.role === "replica" && r.last_sync && (!isSet(r.last_sync) || Date.now() - new Date(r.last_sync) > 300000);
    out.push(hcard(r.error || late ? "warn" : "good", "Réplication", r.role === "replica" ? "réplique" : "instance principale",
      r.role === "replica" ? `dernière synchronisation ${ago(r.last_sync)}` : "publie sa configuration", "#/settings/ops"));
  }
  if (h.syslog) out.push(hcard(h.syslog.error || h.syslog.pending > 100 ? "warn" : "good", "Copie vers le SIEM", `${n(h.syslog.sent)} événements remis`, h.syslog.pending ? `${n(h.syslog.pending)} en attente` : `dernière remise ${ago(h.syslog.last_ok)}`, "#/settings/ops"));
  if (h.dhcp) out.push(hcard("plain", "Serveur DHCP", `${n(h.dhcp.active)} bail${h.dhcp.active > 1 ? "x" : ""} en cours`, "", "#/clients/dhcp"));
  return out;
}

views.dashboard = async (main) => {
  let range = dashPref.get("range", "24h");
  let mode = dashPref.get("view", "");
  const draw = async () => {
    const [s, st] = await Promise.all([api("/stats"), api("/status")]);
    const h = s.health || {};
    const paused = st.paused_until && new Date(st.paused_until) > new Date();
    const active = st.blocking_enabled && !paused;
    // Vue « complète » par défaut quand l'instance a des fonctions d'entreprise.
    const pro = !!((h.zones && h.zones.total) || h.rpz || h.replication || h.syslog || h.secondaries || st.zones);
    if (!mode) mode = pro ? "full" : "simple";
    const full = mode === "full";
    const logMode = s.log_mode || st.log_mode;
    const resolved = Math.max(0, s.total - s.blocked - s.cached - s.local - s.errors - s.refused - (s.rewritten || 0));
    const hour = arr(s.last_hour);
    const lastMin = hour.length > 1 ? hour[hour.length - 2].q : 0; // minute complète
    const enc = sum(arr(s.protocols).filter((p) => ["dot", "doh", "doq", "dnscrypt"].includes(p.key)), (p) => p.count);
    const protoTotal = sum(s.protocols, (p) => p.count);
    const series = range === "1h" ? hour : range === "7j" ? s.week : s.series;
    const lat = s.latency || {};
    const cards = healthCards(h, st);
    const issues = cards.filter((c) => /hcard (warn|bad)/.test(c.s)).length;

    const outcome = [
      { key: "resolved", label: "Résolues en amont", count: resolved },
      { key: "cached", label: "Servies par le cache", count: s.cached, tone: "t-safe" },
      { key: "blocked", label: "Bloquées", count: s.blocked, tone: "t-block" },
      { key: "local", label: "Zones locales et noms DHCP", count: s.local, tone: "t-local" },
      { key: "rewritten", label: "Réécrites (SafeSearch, YouTube)", count: s.rewritten || 0, tone: "t-local" },
      { key: "errors", label: "Échecs (amont, DNSSEC)", count: s.errors, tone: "t-warn" },
      { key: "refused", label: "Refusées (client non autorisé)", count: s.refused, tone: "t-warn" },
    ];
    const latRows = arr(lat.counts).map((c, i, a) => {
      const b = arr(lat.bounds_ms);
      return { key: String(i), label: i === 0 ? `≤ ${b[0]} ms` : i === a.length - 1 ? `> ${n(b[i - 1])} ms` : `${n(b[i - 1])} – ${n(b[i])} ms`, count: c, hint: i === 0 ? "cache, zones locales" : "" };
    });
    const privacy = logMode === "full" ? ""
      : notice("plain", html`<p><b>Journal ${logMode === "none" ? "désactivé" : "en statistiques anonymes"}.</b> Les graphiques ci-dessous viennent de compteurs anonymes, sans domaine ni appareil, gardés en mémoire seulement. ${logMode === "none" ? "Les domaines bloqués et l'activité par groupe ne sont pas conservés." : "Les domaines les plus demandés et les clients ne sont pas conservés."} <a href="#/settings/privacy">Confidentialité</a></p>`, "eye");

    main.innerHTML = html`<div class="page dash">
    ${head(new Raw(html`<span class="status-line"><span class="shield ${active ? "" : "off"}"></span>${active ? "Protection active" : paused ? "Blocage en pause" : "Blocage désactivé"}</span>`.s),
      paused ? `Reprise automatique à ${time(st.paused_until)}.` : `${n(st.rules_block)} domaines bloqués par vos listes, ${n(st.rules_allow)} exceptions. Clés protégées par ${st.keystore_backend === "pkcs11" ? "le HSM" : "le keystore logiciel"}.`,
      html`<div class="dash-tools">
        <div class="seg" role="radiogroup" aria-label="Niveau de détail">
          <label><input type="radio" name="dview" value="simple" ${checked(!full)}><span>Essentiel</span></label>
          <label><input type="radio" name="dview" value="full" ${checked(full)}><span>Complet</span></label>
        </div>
        ${paused ? html`<button class="primary" data-pause="0">${icon("play")}Reprendre le blocage</button>`
          : html`<div class="pause-group"><span class="muted small">Pause</span><button data-pause="5">5 min</button><button data-pause="30">30 min</button><button data-pause="60">1 h</button></div>`}
      </div>`)}
    ${privacy ? html`<div class="mb">${privacy}</div>` : ""}

    <section class="panel">
      <div class="figures kpis ${full ? "k10" : "k6"}">
        <div class="figure"><strong>${n(s.total)}</strong><span>requêtes depuis le démarrage</span></div>
        <div class="figure block"><strong>${pct(s.blocked, s.total)}</strong><span>${n(s.blocked)} bloquées</span></div>
        <div class="figure"><strong>${pct(st.cache.hits, st.cache.hits + st.cache.misses)}</strong><span>servies depuis le cache</span></div>
        <div class="figure"><strong>${n(lastMin)}</strong><span>requêtes la dernière minute</span></div>
        <div class="figure"><strong>${lat.measured ? ms(lat.avg_ms) : "—"}</strong><span>temps de réponse moyen</span></div>
        <div class="figure"><strong>${n(s.peak_minute)}</strong><span>pic par minute${s.peak_at ? `, à ${hhmm(s.peak_at)}` : ""}</span></div>
        ${full ? html`
        <div class="figure"><strong>${lat.upstream_avg_ms ? ms(lat.upstream_avg_ms) : "—"}</strong><span>latence des résolveurs</span></div>
        <div class="figure"><strong>${pct(enc, protoTotal)}</strong><span>requêtes reçues chiffrées</span></div>
        <div class="figure"><strong>${n(s.local)}</strong><span>réponses de zones locales</span></div>
        <div class="figure ${s.errors ? "warn" : ""}"><strong>${pct(s.errors + s.refused, s.total)}</strong><span>échecs et refus</span></div>` : ""}
      </div>
    </section>

    <section class="panel mt">
      <div class="panel-head"><h2>Activité</h2>
        <div class="seg" role="radiogroup" aria-label="Période">
          ${[["1h", "1 h"], ["24h", "24 h"], ["7j", "7 jours"]].map(([v, l]) => html`<label><input type="radio" name="drange" value="${v}" ${checked(range === v)}><span>${l}</span></label>`)}
        </div>
        <p class="legend"><span><i class="k-q"></i>requêtes</span><span><i class="k-b"></i>bloquées</span><span><i class="k-now"></i>tranche en cours</span></p>
      </div>
      <div class="wall-chart">${wallChart(series, range)}</div>
      <p class="muted small">Sur la période : ${n(sum(series, (p) => p.q))} requêtes, ${n(sum(series, (p) => p.b))} bloquées (${pct(sum(series, (p) => p.b), sum(series, (p) => p.q))}). Statistiques gardées en mémoire, remises à zéro au redémarrage (${dur(st.uptime_s)}).</p>
    </section>

    <div class="dgrid ${logMode === "none" ? "c2" : "c3"} mt">
      <section class="panel"><h2>Issue des requêtes</h2>${distRows(outcome, { total: s.total })}</section>
      <section class="panel"><h2>Pourquoi c'est bloqué</h2>${distRows(s.block_reasons, { tone: "t-block", empty: "Rien de bloqué pour l'instant." })}</section>
      ${logMode === "none" ? "" : html`<section class="panel"><h2>Domaines les plus bloqués</h2>${topList(s.top_blocked, true, "Rien de bloqué pour l'instant.")}</section>`}
    </div>

    <section class="panel mt">
      <div class="panel-head"><h2>Rythme de la semaine</h2><span class="muted small">Requêtes par heure, jour par jour : repère les heures creuses, les pics et l'activité nocturne.</span></div>
      ${weekHeat(s.week)}
    </section>

    ${arr(s.groups).length ? html`<section class="panel mt">
      <div class="panel-head"><h2>Groupes d'appareils</h2><a class="small" href="#/clients/groups">Gérer les groupes</a></div>
      <div class="table-wrap"><table class="cards">
        <thead><tr><th>Groupe</th><th class="num">Requêtes</th><th class="num">Bloquées</th><th class="wide">Part bloquée</th></tr></thead>
        <tbody>${s.groups.map((g) => html`<tr><td class="first"><b>${g.name || "Politique générale"}</b></td><td class="num" data-label="Requêtes">${n(g.q)}</td><td class="num" data-label="Bloquées">${n(g.b)}</td>
          <td data-label="Part bloquée"><span class="meter inline"><i class="t-block" data-w="${g.q ? (100 * g.b) / g.q : 0}"></i></span> ${pct(g.b, g.q)}</td></tr>`)}</tbody>
      </table></div>
    </section>` : ""}

    ${full ? html`<div class="dgrid c2 mt">
      <section class="panel"><h2>Transports</h2>${distRows(arr(s.protocols).map((p) => ({ ...p, label: (protoName[p.key] || [p.key])[0], hint: (protoName[p.key] || [])[1] || "", tone: ["dot", "doh", "doq", "dnscrypt"].includes(p.key) ? "t-safe" : "" })))}</section>
      <section class="panel"><h2>Types de requêtes</h2>${distRows(arr(s.qtypes).map((q) => ({ ...q, hint: qtypeHint[q.key] || "" })))}</section>
      <section class="panel"><h2>Codes de réponse</h2>${distRows(arr(s.rcodes).map((r) => ({ ...r, hint: rcodeName[r.key] || "", tone: r.key === "NOERROR" ? "" : r.key === "NXDOMAIN" ? "t-local" : "t-warn" })))}
        <p class="muted small">Une hausse de « nom inexistant » peut signaler un appareil infecté qui cherche son serveur de commande.</p></section>
      <section class="panel"><h2>Temps de réponse</h2>${distRows(latRows, { empty: "Pas encore de mesure." })}
        ${lat.measured ? html`<p class="muted small">Moyenne ${ms(lat.avg_ms)}${lat.upstream_avg_ms ? html`, ${ms(lat.upstream_avg_ms)} quand il faut interroger l'amont` : ""}.</p>` : ""}</section>
    </div>` : ""}

    ${logMode === "full" ? html`<div class="dgrid c2 mt">
      <section class="panel"><h2>Domaines les plus demandés</h2>${topList(s.top_domains, false, "Pas encore de requêtes.")}</section>
      <section class="panel"><h2>Clients les plus actifs</h2>${topList(s.top_clients, false, "Pas encore de requêtes.")}</section>
    </div>` : ""}

    <section class="panel mt">
      <div class="panel-head"><h2>État du service</h2>${issues ? html`<span class="tag warn">${n(issues)} point${issues > 1 ? "s" : ""} à vérifier</span>` : html`<span class="tag ok">tout fonctionne</span>`}</div>
      ${full || issues ? html`<ul class="health">${full ? cards : cards.filter((c) => /hcard (warn|bad)/.test(c.s))}</ul>` : html`<p class="muted small">Listes, certificat, audit et validation DNSSEC sont en ordre. Passez en vue « Complet » pour le détail.</p>`}
    </section>

    <section class="panel mt">
      <div class="panel-head"><h2>Résolveurs en amont</h2><a class="small" href="#/settings/resolution">Choisir les résolveurs</a></div>
      <div class="table-wrap"><table class="cards">
        <thead><tr><th>Serveur</th><th>Transport</th><th class="num">Requêtes</th><th class="num">Échecs</th><th class="num">Latence</th></tr></thead>
        <tbody>${arr(st.upstreams).map((u) => html`<tr><td class="first domain">${u.domain ? html`<span class="tag local">${u.domain}</span> ` : ""}${u.name}</td><td data-label="Transport">${u.encrypted ? html`<span class="tag ok">chiffré</span>` : html`<span class="tag warn">en clair</span>`}</td><td class="num" data-label="Requêtes">${n(u.queries)}</td><td class="num" data-label="Échecs">${n(u.errors)}${u.queries ? html` <span class="muted small">(${pct(u.errors, u.queries)})</span>` : ""}</td><td class="num" data-label="Latence">${u.avg_ms ? u.avg_ms.toFixed(1) + " ms" : "—"}</td></tr>`)}</tbody>
      </table></div>
    </section></div>`;
    applyWidths(main);
    $$("[data-pause]", main).forEach((b) => (b.onclick = () => act(b, () => api("/pause", { method: "POST", body: { minutes: +b.dataset.pause } }), +b.dataset.pause ? "Blocage mis en pause" : "Blocage repris").then(() => { draw(); refreshStatusPill(); })));
    $$("input[name=drange]", main).forEach((r) => (r.onchange = () => { range = r.value; dashPref.set("range", range); draw().catch(() => {}); }));
    $$("input[name=dview]", main).forEach((r) => (r.onchange = () => { mode = r.value; dashPref.set("view", mode); draw().catch(() => {}); }));
  };
  await draw();
  refreshTimer = setInterval(() => { if (!document.hidden) draw().catch(() => {}); }, 10000);
};

// ================= Journal =================
views.log = async (main) => {
  const settings = await api("/settings");
  if (settings.log_mode !== "full") {
    main.innerHTML = html`<div class="page">${head("Journal des requêtes", "Le journal détaillé est désactivé : Rempart ne garde aucune trace des domaines consultés par chaque appareil.")}
    ${notice("plain", html`<p>Mode actuel : <b>${settings.log_mode === "none" ? "aucun journal" : "statistiques anonymes"}</b>. Pour enquêter sur un problème, activez « journal complet chiffré » dans <a href="#/settings/privacy">Réglages, Confidentialité</a>. Les entrées sont chiffrées sur disque et détruites après ${settings.retention_days} jours.</p>`)}</div>`;
    return;
  }
  const days = arr((await api("/querylog/days")).days);
  main.innerHTML = html`<div class="page">
  ${head("Journal des requêtes", `Clients pseudonymisés, journal chiffré sur disque avec une clé par jour, détruite après ${settings.retention_days} jours.`)}
  <section class="panel stack">
    <form class="row" id="lf">
      <input class="grow" name="q" type="search" placeholder="Filtrer par domaine ou client" aria-label="Filtrer">
      <select name="status" aria-label="Statut"><option value="">Tous les statuts</option>${Object.entries(statusLabel).map(([k, v]) => html`<option value="${k}">${v}</option>`)}</select>
      <select name="day" aria-label="Période"><option value="">En direct</option>${days.map((d) => html`<option value="${d}">Archive du ${d}</option>`)}</select>
      <button type="submit">${icon("refresh")}Actualiser</button>
    </form>
    <div class="table-wrap" id="lt"></div>
  </section></div>`;
  const form = $("#lf");
  const load = async () => {
    const f = new FormData(form);
    const d = f.get("day");
    const q = encodeURIComponent(f.get("q") || "");
    const data = d ? await api(`/querylog/days/${d}?q=${q}`) : await api(`/querylog?limit=300&q=${q}&status=${f.get("status") || ""}`);
    let entries = arr(data.entries);
    if (d && f.get("status")) entries = entries.filter((e) => e.s === f.get("status"));
    $("#lt").innerHTML = entries.length ? html`<table class="cards">
      <thead><tr><th>Heure</th><th>Domaine</th><th>Client</th><th>Type</th><th>Statut</th><th>Détail</th><th class="num">Durée</th><th></th></tr></thead>
      <tbody>${entries.map((e) => html`<tr>
        <td data-label="Heure">${time(e.t)}</td><td class="first domain">${e.n.replace(/\.$/, "")}</td><td class="mono" data-label="Client">${e.c}${e.g ? html`<br><span class="tag">${e.g}</span>` : ""}</td><td data-label="Type">${e.y}</td>
        <td data-label="Statut"><span class="tag ${e.s}">${statusLabel[e.s] || e.s}</span></td>
        <td class="small" data-label="Détail">${e.rule ? html`${e.rule}<br><span class="muted">${e.src}</span>` : html`<span class="muted">${e.u || e.p || ""}</span>`}</td>
        <td class="num" data-label="Durée">${(e.ms ?? 0).toFixed(1)} ms</td>
        <td class="act">${e.s === "blocked" ? html`<button class="link" data-allow="${e.n}">Autoriser</button>` : e.s !== "local" ? html`<button class="link danger" data-block="${e.n}">Bloquer</button>` : ""}</td>
      </tr>`)}</tbody></table>` : html`<p class="empty">Aucune requête ne correspond.</p>`;
    $$("[data-allow],[data-block]", main).forEach((b) => (b.onclick = () => {
      const allow = "allow" in b.dataset;
      const domain = (b.dataset.allow || b.dataset.block).replace(/\.$/, "");
      act(b, () => api("/rules", { method: "POST", body: { domain, allow } }), allow ? `${domain} autorisé` : `${domain} bloqué`);
    }));
  };
  form.onsubmit = (e) => { e.preventDefault(); load(); };
  form.onchange = () => load();
  await load();
  refreshTimer = setInterval(() => { if (!document.hidden && !new FormData(form).get("day")) load().catch(() => {}); }, 5000);
};

// ================= Filtrage =================
views.filters = async (main, tab) => {
  const sug = await api("/suggestions").catch(() => ({ items: [] }));
  const t = tabs("filters", [["lists", "Listes de blocage"], ["mine", "Ma liste"], ["rpz", "Flux RPZ"], ["suggestions", `Suggestions${arr(sug.items).length ? " (" + arr(sug.items).length + ")" : ""}`, arr(sug.items).length > 0]], tab);
  main.innerHTML = html`<div class="page">
  ${head("Filtrage", "Un domaine bloqué l'est aussi pour tous ses sous-domaines. Les exceptions l'emportent toujours sur les listes.")}
  <section class="panel">
    <form class="row" id="chk">
      <input class="grow" name="domain" placeholder="Tester un domaine, par exemple ads.example.com" aria-label="Domaine à tester" required>
      <button type="submit">Tester</button>
    </form>
    <div id="chk-res"></div>
  </section>
  <div class="mt">${t.nav}</div>
  <div id="tab"></div></div>`;
  $("#chk").onsubmit = async (e) => {
    e.preventDefault();
    const d = new FormData(e.target).get("domain").trim();
    const r = await act(e.submitter, () => api("/check?domain=" + encodeURIComponent(d)));
    if (!r) return;
    const msg = r.local_zone ? html`<b>${r.domain}</b> est servi par une zone locale.` : r.result.blocked ? html`<b>${r.domain}</b> est bloqué par la règle <code>${r.result.rule}</code> (${r.result.source}).` : r.result.allowed ? html`<b>${r.domain}</b> est autorisé explicitement (<code>${r.result.rule}</code>, ${r.result.source}).` : html`<b>${r.domain}</b> n'est pas bloqué.`;
    $("#chk-res").innerHTML = html`<div class="mt">${notice(r.result.blocked ? "bad" : "good", msg)}</div>`;
  };
  await filterTabs[t.cur]($("#tab"), sug);
};
const filterTabs = {};
filterTabs.lists = async (el) => {
  const lists = arr(await api("/lists"));
  el.innerHTML = html`<section class="panel stack">
    <div class="panel-head"><h2>Listes de blocage</h2><button id="refresh">${icon("refresh")}Mettre à jour maintenant</button></div>
    <div class="table-wrap"><table class="cards">
      <thead><tr><th>Active</th><th>Liste</th><th class="num">Règles</th><th>Mise à jour</th><th></th></tr></thead>
      <tbody>${lists.length ? lists.map((l) => html`<tr>
        <td data-label="Active"><label class="switch"><input type="checkbox" data-toggle="${l.id}" ${checked(l.enabled)} aria-label="Activer ${l.name}"></label></td>
        <td class="first"><b>${l.name}</b>${l.allow ? html` <span class="tag ok">exceptions</span>` : ""}${l.sha256 ? html` <span class="tag">empreinte épinglée</span>` : ""}<br><span class="domain muted">${l.url}</span>
          ${l.last_error ? html`<div class="mt">${notice("bad", l.last_error)}</div>` : ""}</td>
        <td class="num" data-label="Règles">${n(l.count)}</td>
        <td class="small" data-label="Mise à jour">${date(l.last_update)}</td>
        <td class="act"><button class="link danger" data-del="${l.id}" data-name="${l.name}">Supprimer</button></td>
      </tr>`) : html`<tr><td colspan="5" class="empty">Aucune liste. Ajoutez-en une ci-dessous pour commencer à bloquer.</td></tr>`}</tbody>
    </table></div>
    <hr>
    <h3>Ajouter une liste</h3>
    <form id="addlist" class="fields">
      <label class="field"><span>Nom</span><input name="name" placeholder="HaGeZi Light"></label>
      <label class="field"><span>Adresse</span><input name="url" type="url" placeholder="https://… (hosts, domaines ou Adblock)" required></label>
      <label class="field"><span>Empreinte SHA-256 (facultatif)</span><input name="sha256" pattern="[0-9a-fA-F]{64}" placeholder="pour une liste figée"></label>
      <div class="row">${sw("allow", false, "Liste d'exceptions", "")}<span class="grow"></span><button class="primary" type="submit">Ajouter la liste</button></div>
    </form>
  </section>`;
  const reload = () => filterTabs.lists(el);
  $("#refresh").onclick = (e) => act(e.currentTarget, () => api("/lists/refresh", { method: "POST" }), "Listes mises à jour").then(reload);
  $$("[data-toggle]", el).forEach((c) => (c.onchange = () => act(null, () => api("/lists/" + c.dataset.toggle, { method: "PATCH", body: { enabled: c.checked } }), c.checked ? "Liste activée" : "Liste désactivée")));
  $$("[data-del]", el).forEach((b) => (b.onclick = () => confirm(`Supprimer la liste « ${b.dataset.name} » ?`) && act(b, () => api("/lists/" + b.dataset.del, { method: "DELETE" }), "Liste supprimée").then(reload)));
  $("#addlist").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    act(e.submitter, () => api("/lists", { method: "POST", body: { name: f.get("name"), url: f.get("url"), sha256: f.get("sha256"), allow: !!f.get("allow") } }), "Liste ajoutée, téléchargement en cours").then(() => setTimeout(reload, 1500));
  };
};
filterTabs.mine = async (el) => {
  const rules = arr(await api("/rules"));
  const blocked = rules.filter((r) => !r.allow).length;
  el.innerHTML = html`<div class="grid wide">
  <section class="panel stack">
    <div class="panel-head"><h2>Ma liste</h2><p>${n(blocked)} domaines bloqués et ${n(rules.length - blocked)} exceptions, prioritaires sur toutes les listes.</p></div>
    <form id="addrule" class="row">
      <input class="grow" name="domain" placeholder="domaine.example" aria-label="Domaine" required>
      <input class="grow" name="comment" placeholder="Note (facultative)" aria-label="Note">
      <button type="submit" name="kind" value="block" class="danger">Bloquer</button>
      <button type="submit" name="kind" value="allow">Autoriser</button>
    </form>
    ${rules.length ? html`<div class="table-wrap"><table class="cards">
      <thead><tr><th>Domaine</th><th>Effet</th><th>Note</th><th>Ajoutée</th><th></th></tr></thead>
      <tbody>${rules.slice().reverse().map((r) => html`<tr><td class="first domain">${r.domain}</td><td data-label="Effet">${r.allow ? html`<span class="tag allowed">autorisé</span>` : html`<span class="tag blocked">bloqué</span>`}</td><td class="small" data-label="Note">${r.comment}</td><td class="small" data-label="Ajoutée">${date(r.created)}</td><td class="act"><button class="link danger" data-delrule="${r.domain}">Retirer</button></td></tr>`)}</tbody>
    </table></div>` : html`<p class="empty">Votre liste est vide. Ajoutez un domaine, importez une liste ou acceptez une suggestion.</p>`}
  </section>
  <div class="stack">
    <section class="panel stack">
      <h2>Importer</h2>
      <form id="bulk" class="stack-s">
        <textarea name="text" spellcheck="false" placeholder="Un domaine par ligne. Formats acceptés :&#10;ads.example.com&#10;0.0.0.0 tracker.example.net&#10;||pub.example.org^&#10;@@||exception.example.org^"></textarea>
        <input name="comment" placeholder="Note appliquée à chaque règle (facultative)" aria-label="Note">
        <div class="row">${sw("allow", false, "Importer comme exceptions", "")}<span class="grow"></span><button class="primary" type="submit">Importer</button></div>
      </form>
    </section>
    <section class="panel stack-s">
      <h2>Exporter</h2>
      <p class="muted small">Pour partager votre liste ou l'utiliser sur un autre Rempart, un Pi-hole ou AdGuard Home.</p>
      <div class="row">
        <a class="btn" href="/api/rules/export?format=adblock" download>${icon("download")}Adblock</a>
        <a class="btn" href="/api/rules/export?format=hosts" download>${icon("download")}hosts</a>
        <a class="btn" href="/api/rules/export?format=domains" download>${icon("download")}Domaines</a>
      </div>
    </section>
  </div></div>`;
  const reload = () => filterTabs.mine(el);
  $("#addrule").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const allow = e.submitter.value === "allow";
    act(e.submitter, () => api("/rules", { method: "POST", body: { domain: f.get("domain"), comment: f.get("comment"), allow } }), allow ? "Domaine autorisé" : "Domaine bloqué").then(reload);
  };
  $("#bulk").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    act(e.submitter, () => api("/rules/bulk", { method: "POST", body: { text: f.get("text"), comment: f.get("comment"), allow: !!f.get("allow") } })).then((r) => { if (r) { toast(`${r.added} règles importées${r.skipped ? `, ${r.skipped} lignes ignorées` : ""}`); reload(); } });
  };
  $$("[data-delrule]", el).forEach((b) => (b.onclick = () => act(b, () => api("/rules?domain=" + encodeURIComponent(b.dataset.delrule), { method: "DELETE" }), "Règle retirée").then(reload)));
};
const kindLabel = { cname: "traqueur caché", voisins: "voisins bloqués", "libellé": "nom publicitaire", "aléatoire": "nom suspect" };
filterTabs.suggestions = async (el, sug) => {
  const items = arr(sug.items);
  el.innerHTML = html`<section class="panel stack">
    <div class="panel-head"><h2>Suggestions</h2><p>Rempart analyse en mémoire les noms résolus, sans rien noter des appareils, et propose ce qui ressemble à de la publicité, du traçage ou un logiciel malveillant. Rien ne quitte le serveur.</p></div>
    ${!sug.enabled ? notice("plain", html`<p>L'analyse est désactivée. ${sug.log_mode === "none" ? "Elle n'est pas disponible en mode « aucun journal »." : ""} Activez-la dans <a href="#/settings/privacy">Réglages, Confidentialité</a>.</p>`) : ""}
    ${items.length ? html`<div class="table-wrap"><table class="cards">
      <thead><tr><th>Domaine</th><th>Indice</th><th>Pourquoi</th><th class="num">Vu</th><th></th></tr></thead>
      <tbody>${items.map((s) => html`<tr>
        <td class="first domain">${s.domain}</td>
        <td data-label="Indice"><span class="tag ${s.kind === "aléatoire" ? "warn" : s.score >= 0.8 ? "bad" : ""}">${kindLabel[s.kind] || s.kind}</span></td>
        <td class="small" data-label="Pourquoi">${s.reason}</td>
        <td class="num" data-label="Vu">${n(s.count)}</td>
        <td class="act"><button class="danger" data-sblock="${s.domain}" data-reason="${s.reason}">Bloquer</button> <button class="link" data-dismiss="${s.domain}">Ignorer</button></td>
      </tr>`)}</tbody></table></div>` : sug.enabled ? html`<p class="empty">Rien de suspect pour l'instant. Les suggestions apparaissent au fil des requêtes.</p>` : ""}
  </section>`;
  const reload = () => views.filters($("#main"), "suggestions");
  $$("[data-sblock]", el).forEach((b) => (b.onclick = () => act(b, () => api("/rules", { method: "POST", body: { domain: b.dataset.sblock, comment: "suggestion : " + b.dataset.reason, allow: false } }), `${b.dataset.sblock} bloqué`).then(reload)));
  $$("[data-dismiss]", el).forEach((b) => (b.onclick = () => act(b, () => api("/suggestions/dismiss", { method: "POST", body: { domain: b.dataset.dismiss } }), "Suggestion ignorée").then(reload)));
};

// ================= Appareils : groupes, profils, DHCP =================
const dayNames = ["Dim", "Lun", "Mar", "Mer", "Jeu", "Ven", "Sam"];
const dayOrder = [1, 2, 3, 4, 5, 6, 0];
const svcIcon = { social: "users", video: "video", music: "music", messaging: "chat", games: "game", ai: "spark", shopping: "bag", dating: "heart" };
const pausedNow = (s) => isSet(s) && new Date(s) > new Date();
const plural = (k, one, many = one + "s") => `${k} ${k > 1 ? many : one}`;
const hue = (s) => [...String(s)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7) % 6;
const initials = (s) => (String(s || "").trim().split(/\s+/).map((w) => [...w][0] || "").join("").slice(0, 2) || "+").toUpperCase();
const avatar = (name) => html`<span class="avatar h${hue(name)}" aria-hidden="true">${initials(name)}</span>`;
const ago = (s) => {
  if (!isSet(s)) return "jamais";
  const m = Math.round((Date.now() - new Date(s)) / 60000);
  return m < 1 ? "à l'instant" : m < 60 ? `il y a ${m} min` : m < 1440 ? `il y a ${Math.round(m / 60)} h` : date(s);
};

// Familles de services : celles annoncées par le serveur, puis toute
// catégorie inconnue (serveur plus récent que l'interface, ou l'inverse).
const svcGroupsOf = (d) => {
  const known = arr(d.service_groups);
  const extra = [...new Set(arr(d.services).map((s) => s.category))].filter((c) => !known.some((g) => g.id === c)).map((id) => ({ id, name: id, help: "" }));
  return [...known, ...extra];
};

// Sélecteur de services : une carte par famille, qu'on coche d'un bloc, puis
// on affine service par service. Recherche par nom ou par domaine.
const svcPicker = (name, d, sel) => {
  const services = arr(d.services);
  return html`<div class="svc">
  <div class="svc-bar">
    <label class="svc-search">${icon("search")}<input type="search" data-svcq placeholder="Chercher un service ou un domaine" aria-label="Chercher un service ou un domaine"></label>
    <span class="svc-total" data-svccount></span>
    <span class="grow"></span>
    <button type="button" class="link" data-svcdom>Voir les domaines</button>
    <button type="button" class="link" data-svcnone>Tout décocher</button>
  </div>
  <div class="svc-groups">${svcGroupsOf(d).map((g) => {
    const list = services.filter((s) => s.category === g.id);
    return list.length ? html`<div class="svc-group" data-cat="${g.id}">
      <div class="svc-head"><input type="checkbox" data-svcall aria-label="Bloquer toute la famille ${g.name}" title="Toute la famille"><button type="button" class="svc-toggle" data-svctog aria-expanded="false"><span class="svc-ic">${icon(svcIcon[g.id] || "filter")}</span><span class="svc-title"><b>${g.name}</b><small data-svcsel>${g.help}</small></span><span class="svc-n" data-svcn></span>${icon("chev", "i chev")}</button></div>
      <div class="svc-items">${list.map((s) => html`<label class="svc-item" title="${arr(s.domains).join(", ")}" data-q="${[s.name, s.id, ...arr(s.domains)].join(" ").toLowerCase()}"><input type="checkbox" name="${name}" value="${s.id}" ${checked(sel.includes(s.id))}><span><b>${s.name}</b>${s.note ? html`<small>${s.note}</small>` : ""}<small class="svc-dom">${arr(s.domains).join(" · ")}</small></span></label>`)}</div>
    </div>` : "";
  })}</div>
  <p class="empty small" data-svcempty hidden>Aucun service ne correspond.</p>
</div>`;
};

function bindSvc(root) {
  $$(".svc", root).forEach((box) => {
    if (box.dataset.bound) return;
    box.dataset.bound = "1";
    const sync = () => {
      let total = 0;
      $$(".svc-group", box).forEach((g) => {
        const items = $$(".svc-item input", g);
        const on = items.filter((x) => x.checked).length;
        total += on;
        const all = $("[data-svcall]", g);
        all.checked = on === items.length;
        all.indeterminate = on > 0 && on < items.length;
        $("[data-svcn]", g).textContent = on ? `${on} / ${items.length}` : `${items.length}`;
        const names = items.filter((x) => x.checked).map((x) => $("b", x.closest(".svc-item")).textContent);
        const selEl = $("[data-svcsel]", g);
        selEl.dataset.help ??= selEl.textContent;
        selEl.textContent = on === items.length ? "Toute la famille" : on ? names.join(", ") : selEl.dataset.help;
        g.classList.toggle("on", on > 0);
        g.classList.toggle("full", on === items.length);
      });
      const c = $("[data-svccount]", box);
      c.textContent = total ? plural(total, "service bloqué", "services bloqués") : "Aucun service bloqué";
      c.classList.toggle("on", total > 0);
    };
    box.addEventListener("change", (e) => {
      if (e.target.matches("[data-svcall]")) {
        // pendant une recherche, la case de la famille ne touche que les services affichés
        $$(".svc-item:not([hidden]) input", e.target.closest(".svc-group")).forEach((x) => (x.checked = e.target.checked));
      }
      sync();
    });
    const setOpen = (g, on) => { g.classList.toggle("open", on); $("[data-svctog]", g).setAttribute("aria-expanded", on); };
    box.addEventListener("click", (e) => { const t = e.target.closest("[data-svctog]"); if (t) { const g = t.closest(".svc-group"); setOpen(g, !g.classList.contains("open")); } });
    const q = $("[data-svcq]", box);
    q.addEventListener("keydown", (e) => e.key === "Enter" && e.preventDefault());
    q.addEventListener("input", () => {
      const s = q.value.trim().toLowerCase();
      let any = false;
      $$(".svc-group", box).forEach((g) => {
        let n = 0;
        $$(".svc-item", g).forEach((it) => { const ok = !s || it.dataset.q.includes(s); it.hidden = !ok; n += ok; });
        g.hidden = !n;
        setOpen(g, !!s && n > 0);
        any ||= n > 0;
      });
      $("[data-svcempty]", box).hidden = any;
    });
    $("[data-svcnone]", box).onclick = () => { $$(".svc-item input", box).forEach((x) => (x.checked = false)); sync(); };
    $("[data-svcdom]", box).onclick = (e) => { const on = box.classList.toggle("show-dom"); e.target.textContent = on ? "Masquer les domaines" : "Voir les domaines"; };
    sync();
  });
}

const schedRow = (s, d, i) => {
  const mode = s.block_all || !arr(s.services).length ? "all" : "svc";
  return html`<fieldset class="sched reveal" data-sched="${i}" data-mode="${mode}">
  <div class="sched-top">
    <span class="sched-ic">${icon("clock")}</span>
    <label class="field sched-name"><span>Nom de la plage</span><input name="s_name" value="${s.name || ""}" placeholder="Soirée, devoirs…"></label>
    <label class="field"><span>De</span><input name="s_start" type="time" value="${s.start || "21:00"}" required></label>
    <label class="field"><span>À</span><input name="s_end" type="time" value="${s.end || "07:00"}" required></label>
    <button type="button" class="icon-btn danger" data-rmsched title="Retirer la plage" aria-label="Retirer la plage">${icon("trash")}</button>
  </div>
  <div class="days" role="group" aria-label="Jours">${dayOrder.map((n) => html`<label class="day"><input type="checkbox" name="s_days" value="${n}" ${checked(arr(s.days).includes(n))}><span>${dayNames[n]}</span></label>`)}</div>
  <div class="seg" role="radiogroup" aria-label="Pendant la plage">
    <label><input type="radio" name="s_mode${i}" value="all" ${checked(mode === "all")}><span>Couper Internet</span></label>
    <label><input type="radio" name="s_mode${i}" value="svc" ${checked(mode === "svc")}><span>Bloquer des services</span></label>
  </div>
  <p class="muted small sched-all">Seuls les zones locales et les domaines toujours autorisés pour le groupe restent joignables.</p>
  <div class="sched-svc">${svcPicker("s_svc", d, arr(s.services))}</div>
  <p class="muted small">Une plage dont la fin précède le début se termine le lendemain.</p>
</fieldset>`;
};

const gsec = (ic, title, text, body) => html`<section class="gsec">
  <div class="gsec-h"><span class="gsec-ic">${icon(ic)}</span><div><h3>${title}</h3>${text ? html`<p>${text}</p>` : ""}</div></div>
  <div class="gsec-b">${body}</div>
</section>`;

function groupForm(g, d) {
  const lists = arr(d.lists);
  const extra = [...lists.map((l) => ({ id: l.id, name: l.name, note: l.enabled ? "déjà active partout" : "" })),
    ...arr(d.categories).filter((c) => !lists.some((l) => l.id === "cat-" + c.id)).map((c) => ({ id: "cat-" + c.id, name: c.name, note: c.help }))];
  const rules = arr(g.rules);
  const devs = arr(d.devices);
  const detected = arr(d.inventory?.entries).filter((e) => !e.device && (e.mac || arr(e.ips).length) && e.group !== g.id)
    .sort((a, b) => (!!a.group - !!b.group) || (b.online - a.online) || devTitle(a).localeCompare(devTitle(b), "fr", { numeric: true }));
  return html`<form class="group-form" data-gid="${g.id || ""}">
  ${gsec("users", "Groupe et appareils", "L'adresse exacte l'emporte sur la MAC, la MAC sur le réseau.", html`
    <div class="fields">
      <label class="field"><span>Nom du groupe</span><input name="name" value="${g.name || ""}" required maxlength="64" placeholder="Enfants"></label>
      <label class="field"><span>Appareils</span><textarea name="clients" rows="4" spellcheck="false" placeholder="192.168.1.40&#10;192.168.1.64/27&#10;aa:bb:cc:dd:ee:ff">${arr(g.clients).join("\n")}</textarea><small class="muted">Une entrée par ligne : adresse IP, réseau CIDR, adresse MAC, ou device:&lt;id&gt; (profil mobile).</small></label>
    </div>
    ${devs.length ? html`<div class="quick"><span class="muted small">Ajouter un profil mobile :</span>${devs.map((x) => html`<button type="button" class="chip" data-adddev="device:${x.id}">${icon("plus")}${x.name}</button>`)}</div>` : ""}
    ${detected.length ? html`<div class="quick"><span class="muted small">Appareils détectés sur le réseau :</span>${detected.slice(0, 24).map((e) => html`<button type="button" class="chip${e.group ? " other" : ""}" data-adddev="${e.mac || e.ips[0]}" title="${[...arr(e.ips), e.mac].filter(Boolean).join(" · ")}${e.group_name ? " · actuellement dans " + e.group_name : ""}">${icon(e.online ? "plus" : "device")}${devTitle(e)}</button>`)}${detected.length > 24 ? html`<a class="small" href="#/clients/all">tous les appareils ${icon("arrow")}</a>` : ""}</div>` : ""}`)}
  ${gsec("filter", "Filtrage publicitaire", "Listes, règles et services permanents. La pause du groupe ne suspend que ce filtrage.", html`
    ${sw("blocking", g.blocking ?? true, "Filtrer pour ce groupe", "")}
    ${sw("inherit_lists", g.inherit_lists ?? true, "Reprendre les listes actives partout", "Les listes cochées ci-dessous s'y ajoutent.")}
    ${sw("inherit_rules", g.inherit_rules ?? true, "Reprendre « Ma liste »", "Vos blocages et exceptions généraux.")}
    ${extra.length ? html`<div class="listpicks">${extra.map((l) => html`<label class="listpick"><input type="checkbox" name="lists" value="${l.id}" ${checked(arr(g.lists).includes(l.id))}><span><b>${l.name}</b>${l.note ? html`<small>${l.note}</small>` : ""}</span></label>`)}</div>` : ""}
    <div class="fields">
      <label class="field"><span>Bloquer pour ce groupe</span><textarea name="r_block" rows="3" spellcheck="false" placeholder="jeu.example">${rules.filter((r) => !r.allow).map((r) => r.domain).join("\n")}</textarea><small class="muted">Pour un domaine précis qui n'est dans aucun service.</small></label>
      <label class="field"><span>Toujours autoriser</span><textarea name="r_allow" rows="3" spellcheck="false" placeholder="ecole.example">${rules.filter((r) => r.allow).map((r) => r.domain).join("\n")}</textarea><small class="muted">Passe avant tout, plages horaires comprises.</small></label>
    </div>`)}
  ${gsec("stop", "Services bloqués en permanence", "Cochez une famille pour tout bloquer d'un coup, ou ouvrez-la pour choisir service par service. La recherche trouve aussi un domaine.", svcPicker("services", d, arr(g.services)))}
  ${gsec("shield", "Contrôle parental", "Actif même pendant la pause du groupe.", html`
    ${sw("safe_search", g.safe_search, "Imposer SafeSearch", "Google, Bing, DuckDuckGo, Yandex et Pixabay filtrent les résultats explicites.")}
    <div class="field"><span>YouTube</span><div class="seg" role="radiogroup" aria-label="YouTube">
      <label><input type="radio" name="youtube" value="" ${checked(!g.youtube)}><span>Sans restriction</span></label>
      <label><input type="radio" name="youtube" value="moderate" ${checked(g.youtube === "moderate")}><span>Restreint modéré</span></label>
      <label><input type="radio" name="youtube" value="strict" ${checked(g.youtube === "strict")}><span>Restreint strict</span></label>
    </div></div>`)}
  ${gsec("clock", "Plages horaires", html`Fuseau : <b>${d.time_zone}</b>. Elles s'appliquent même quand le filtrage du groupe est en pause.`, html`
    <div class="scheds">${arr(g.schedules).map((s, i) => schedRow(s, d, i))}</div>
    <button type="button" class="add-sched" data-addsched>${icon("plus")}Ajouter une plage horaire</button>`)}
  <div class="savebar">
    ${g.id ? html`<button type="button" class="link danger" data-delgroup>${icon("trash")}Supprimer le groupe</button>` : ""}
    <span class="grow"></span>
    <button type="button" data-cancel>Annuler</button>
    <button class="primary" type="submit">${icon("check")}${g.id ? "Enregistrer" : "Créer le groupe"}</button>
  </div>
</form>`;
}

function readGroup(f) {
  const v = (n) => f.elements[n]?.value ?? "";
  const on = (n) => !!f.elements[n]?.checked;
  const vals = (root, n) => $$(`input[name="${n}"]:checked`, root).map((x) => x.value);
  const rules = [...lines(v("r_block")).map((domain) => ({ domain, allow: false })), ...lines(v("r_allow")).map((domain) => ({ domain, allow: true }))];
  const schedules = $$("[data-sched]", f).map((fs) => {
    const all = $('input[name^="s_mode"]:checked', fs)?.value !== "svc";
    return { name: $('[name="s_name"]', fs).value, start: $('[name="s_start"]', fs).value, end: $('[name="s_end"]', fs).value,
      days: vals(fs, "s_days").map(Number), block_all: all, services: all ? [] : vals(fs, "s_svc") };
  });
  const services = $$('input[name="services"]:checked', f).filter((x) => !x.closest("[data-sched]")).map((x) => x.value);
  return { name: v("name"), clients: lines(v("clients")), blocking: on("blocking"), inherit_lists: on("inherit_lists"), inherit_rules: on("inherit_rules"),
    lists: vals(f, "lists"), rules, services, schedules, safe_search: on("safe_search"), youtube: v("youtube") };
}

const isMAC = (c) => /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(c);
function memberTag(c, d) {
  if (c.startsWith("device:")) {
    const dev = arr(d.devices).find((x) => "device:" + x.id === c);
    return html`<span class="mtag">${icon("phone")}<span>${dev ? dev.name : c}</span></span>`;
  }
  const known = d.names?.get(c.toLowerCase());
  return html`<span class="mtag" title="${c}"><i>${isMAC(c) ? "MAC" : c.includes("/") ? "réseau" : "IP"}</i>${known ? html`<span>${known}</span>` : html`<code>${c}</code>`}</span>`;
}

function groupCard(g, d) {
  const paused = pausedNow(g.paused_until);
  const [stLabel, stKind] = !g.blocking ? ["Sans filtrage pub", "warn"] : paused ? [`En pause jusqu'à ${time(g.paused_until)}`, "warn"] : ["Filtrage actif", "ok"];
  const cl = arr(g.clients);
  const svcName = (id) => (arr(d.services).find((s) => s.id === id) || {}).name || id;
  const svcs = arr(g.services);
  const facts = [];
  if (svcs.length) facts.push([ "stop", html`<b>${plural(svcs.length, "service bloqué", "services bloqués")}</b> <span class="muted">${svcs.slice(0, 3).map(svcName).join(", ")}${svcs.length > 3 ? "…" : ""}</span>`]);
  if (arr(g.schedules).length) facts.push(["clock", html`<b>${plural(arr(g.schedules).length, "plage horaire", "plages horaires")}</b> <span class="muted">${arr(g.schedules).map((s) => `${s.start}–${s.end}`).join(", ")}</span>`]);
  if (arr(g.lists).length) facts.push(["filter", html`<b>${plural(arr(g.lists).length, "liste en plus", "listes en plus")}</b>`]);
  if (g.safe_search || g.youtube) facts.push(["shield", html`<b>${[g.safe_search && "SafeSearch", g.youtube && `YouTube ${g.youtube === "strict" ? "strict" : "modéré"}`].filter(Boolean).join(" · ")}</b>`]);
  return html`<article class="gcard" data-group="${g.id}">
  <header>${avatar(g.name)}<div class="gcard-t"><h2>${g.name}</h2><span class="tag ${stKind}">${stLabel}</span></div></header>
  <div class="members">${cl.length ? [...cl.slice(0, 4).map((c) => memberTag(c, d)), cl.length > 4 ? html`<span class="mtag more">+${cl.length - 4}</span>` : ""] : html`<span class="muted small">${icon("alert")} Aucun appareil : ce groupe ne s'applique à personne.</span>`}</div>
  <ul class="facts">${facts.length ? facts.map(([ic, t]) => html`<li>${icon(ic)}<span>${t}</span></li>`) : html`<li class="muted">${icon("info")}<span>Politique générale, sans rien de plus.</span></li>`}</ul>
  <footer>
    ${paused ? html`<button data-gpause="0">${icon("play")}Reprendre</button>` : g.blocking ? html`<span class="muted small">${icon("pause")}</span><button class="mini" data-gpause="15">15 min</button><button class="mini" data-gpause="60">1 h</button>` : ""}
    <span class="grow"></span>
    <button class="soft" data-edit>${icon("edit")}Modifier</button>
  </footer>
</article>`;
}

views.clients = async (main, tab) => {
  const t = tabs("clients", [["all", "Tous les appareils"], ["groups", "Groupes"], ["devices", "Profils mobiles"], ["dhcp", "DHCP"]], tab);
  main.innerHTML = html`<div class="page">
  ${head("Appareils", "Les appareils de votre réseau et la politique de chacun : services, horaires et contrôle parental par groupe. Un appareil hors de tout groupe suit la politique générale.")}
  ${t.nav}<div id="tab"></div></div>`;
  await clientTabs[t.cur]($("#tab"));
};
const clientTabs = {};
// ---- inventaire : tous les appareils du réseau ----
// Réunit baux DHCP, table de voisinage, membres des groupes et profils
// mobiles. Ne vient pas du journal : rien sur ce que l'appareil consulte.
const kindName = { "": "Type non précisé", phone: "Téléphone", tablet: "Tablette", computer: "Ordinateur", tv: "Télévision", console: "Console de jeu", speaker: "Enceinte, assistant", camera: "Caméra", printer: "Imprimante", iot: "Objet connecté", server: "Serveur, NAS", network: "Box, borne, switch" };
const kindIcon = { phone: "phone", tablet: "tablet", computer: "device", tv: "tv", console: "game", speaker: "music", camera: "camera", printer: "printer", iot: "chip", server: "server", network: "wifi" };
// Devine un type d'après le nom annoncé au DHCP (affiché comme une supposition).
const guessKind = (h) => {
  h = String(h || "").toLowerCase();
  const rules = [[/iphone|android|pixel|galaxy|redmi|xiaomi|oneplus|huawei|honor|oppo|phone|moto/, "phone"], [/ipad|tab|kindle|surface-go/, "tablet"],
    [/tv|chromecast|roku|fire-?stick|bravia|shield|appletv|freebox-player|decodeur|apple-tv/, "tv"], [/ps[345]|playstation|xbox|switch|nintendo|steamdeck/, "console"],
    [/echo|alexa|sonos|homepod|nest-(mini|hub|audio)|google-home/, "speaker"], [/cam|ring|arlo|doorbell|blink/, "camera"], [/print|epson|canon|brother|hp[a-z0-9-]*jet|officejet|laserjet/, "printer"],
    [/nas|synology|qnap|raspberry|rpi|proxmox|server|srv/, "server"], [/esp[-_]?\w*|tasmota|shelly|tuya|sonoff|hue|tado|netatmo|roborock|dyson/, "iot"],
    [/box|router|livebox|freebox|bbox|unifi|ap-|switch|repeteur|mesh|deco|eero/, "network"], [/macbook|imac|laptop|desktop|pc|win|thinkpad|dell|lenovo|asus|mac/, "computer"]];
  return (rules.find(([re]) => re.test(h)) || [])[1] || "";
};
const devTitle = (e) => e.name || e.hostname || (e.device ? "Profil mobile" : "Appareil inconnu");
const matchName = { ip: "par adresse IP", mac: "par adresse MAC", cidr: "par réseau", device: "par profil mobile" };
const srcName = { dhcp: "DHCP", voisinage: "réseau local", groupe: "ajouté à la main", nom: "ajouté à la main", profil: "profil mobile" };
const randomHelp = "Adresse MAC privée (« adresse Wi-Fi privée » d'iOS, Android, Windows) : elle reste en général la même sur ce réseau, mais l'appareil peut en changer (rotation, réinitialisation). S'il disparaît de son groupe, désactivez la rotation pour ce réseau, ou rangez-le par profil mobile.";

// Table des noms connus (MAC, IP, device:<id>) pour afficher les membres d'un groupe.
const invIndex = (inv) => {
  const m = new Map();
  arr(inv?.entries).forEach((e) => { const t = devTitle(e); if (e.mac) m.set(e.mac, t); arr(e.ips).forEach((ip) => m.has(ip) || m.set(ip, t)); });
  return m;
};

function invRow(e, inv) {
  const kind = e.kind || guessKind(e.hostname);
  const groups = arr(inv.groups);
  const sub = [
    ...arr(e.ips).map((ip) => html`<code>${ip}</code>`),
    e.mac ? html`<code title="${e.random_mac ? randomHelp : "Adresse MAC"}">${e.mac}</code>` : "",
    e.device ? html`<span>${e.online ? "actif" : "vu " + ago(e.last_seen)}</span>` : "",
  ].filter(Boolean);
  const name = e.name ? html`<b>${e.name}</b>${e.hostname && e.hostname !== e.name ? html` <span class="muted small">${e.hostname}</span>` : ""}` : e.hostname ? html`<b>${e.hostname}</b>` : html`<b class="muted">${devTitle(e)}</b>`;
  return html`<article class="inv ${e.online ? "on" : ""}" data-key="${e.key}" data-mac="${e.mac || ""}" data-ip="${arr(e.ips)[0] || ""}" data-device="${e.device || ""}">
  <label class="inv-sel"><input type="checkbox" data-sel aria-label="Sélectionner ${devTitle(e)}"></label>
  <span class="inv-ic k-${kind || "none"}" title="${kindName[kind] || ""}${e.kind ? "" : kind ? " (supposé)" : ""}">${icon(kindIcon[kind] || "device")}<i class="inv-dot" title="${e.online ? "présent sur le réseau" : "absent ou inconnu"}"></i></span>
  <div class="inv-main">
    <div class="inv-name">${name}${e.device ? "" : html`<button type="button" class="icon-btn" data-rename title="Nommer cet appareil" aria-label="Nommer ${devTitle(e)}">${icon("edit")}</button>`}</div>
    <div class="inv-sub">${sub}</div>
    <div class="inv-tags">
      ${e.static ? html`<span class="tag ok">adresse réservée</span>` : e.lease ? html`<span class="tag">bail ${isSet(e.expires) ? "jusqu'au " + date(e.expires) : ""}</span>` : ""}
      ${e.random_mac ? html`<span class="tag warn" title="${randomHelp}">${icon("info")}MAC privée</span>` : ""}
      ${[...new Set(arr(e.sources).filter((s) => s !== "profil").map((s) => srcName[s] || s))].map((s) => html`<span class="tag" title="Source : ${s}">${s}</span>`)}
    </div>
  </div>
  <div class="inv-grp">
    <label class="sr" for="g-${e.key}">Groupe de ${devTitle(e)}</label>
    <select id="g-${e.key}" data-group>
      <option value="" ${selected(!e.group)}>Politique générale</option>
      ${groups.map((g) => html`<option value="${g.id}" ${selected(e.group === g.id)}>${g.name}</option>`)}
    </select>
    <small class="muted">${e.group ? (e.match === "cidr" ? html`${icon("info")}reconnu par son réseau` : matchName[e.match] || "") : "aucun groupe"}</small>
  </div>
  <div class="inv-act">
    ${arr(e.ips).length ? html`<button type="button" class="link" data-test>${icon("search")}Tester</button>` : ""}
    ${e.lease && !e.static && inv.dhcp_enabled ? html`<button type="button" class="link" data-reserve title="Garder toujours la même adresse (bail statique)">${icon("key")}Réserver l'adresse</button>` : ""}
    ${e.device ? html`<a class="link" href="#/clients/devices">${icon("phone")}Profil</a>` : ""}
  </div>
  <div class="inv-more" hidden></div>
</article>`;
}

clientTabs.all = async (el) => {
  let inv = await api("/inventory");
  let q = "", filt = "", sel = new Set();
  el.innerHTML = html`<div class="stack">
  <div class="kpis" id="inv-kpis"></div>
  <div id="inv-note"></div>
  <section class="panel stack-s">
    <div class="inv-bar">
      <label class="svc-search">${icon("search")}<input type="search" id="inv-q" placeholder="Nom, adresse IP ou MAC" aria-label="Chercher un appareil"></label>
      <select id="inv-f" aria-label="Filtrer">
        <option value="">Tous les appareils</option><option value="on">Présents sur le réseau</option><option value="none">Sans groupe</option><option value="unnamed">Sans nom</option><option value="random">MAC privée</option>
        ${arr(inv.groups).length ? html`<optgroup label="Groupe">${arr(inv.groups).map((g) => html`<option value="g:${g.id}">${g.name}</option>`)}</optgroup>` : ""}
      </select>
      <button type="button" class="icon-btn" id="inv-reload" title="Actualiser" aria-label="Actualiser">${icon("refresh")}</button>
    </div>
    <div class="inv-bulk" id="inv-bulk" hidden>
      <b id="inv-n"></b>
      <select id="inv-bg" aria-label="Groupe pour la sélection"><option value="">Politique générale</option>${arr(inv.groups).map((g) => html`<option value="${g.id}">${g.name}</option>`)}</select>
      <button type="button" class="primary" id="inv-apply">Ranger la sélection</button>
      <button type="button" class="link" id="inv-clear">Annuler</button>
    </div>
    <div class="invs" id="inv-list"></div>
  </section>
  <section class="panel stack-s">
    <div class="gsec-h"><span class="gsec-ic">${icon("plus")}</span><div><h3>Ajouter un appareil que Rempart ne voit pas</h3><p>Pour un appareil derrière un autre routeur, ou quand le conteneur n'a pas le réseau de l'hôte. Il sera reconnu par cette adresse.</p></div></div>
    <form id="inv-add" class="inv-add">
      <input name="addr" required placeholder="192.168.1.40 ou aa:bb:cc:dd:ee:ff" aria-label="Adresse IP ou MAC" spellcheck="false">
      <input name="name" maxlength="64" placeholder="Nom, par exemple Télé du salon" aria-label="Nom">
      <select name="group" aria-label="Groupe"><option value="">Politique générale</option>${arr(inv.groups).map((g) => html`<option value="${g.id}">${g.name}</option>`)}</select>
      <button class="primary" type="submit">Ajouter</button>
    </form>
  </section></div>`;

  const list = $("#inv-list", el);
  const shown = () => arr(inv.entries).filter((e) => {
    if (filt === "on" && !e.online) return false;
    if (filt === "none" && e.group) return false;
    if (filt === "unnamed" && e.name) return false;
    if (filt === "random" && !e.random_mac) return false;
    if (filt.startsWith("g:") && e.group !== filt.slice(2)) return false;
    if (!q) return true;
    return [e.name, e.hostname, e.mac, e.group_name, ...arr(e.ips)].join(" ").toLowerCase().includes(q);
  }).sort((a, b) => (b.online - a.online) || devTitle(a).localeCompare(devTitle(b), "fr", { numeric: true }));
  const kpis = () => {
    const all = arr(inv.entries);
    const on = all.filter((e) => e.online).length, grouped = all.filter((e) => e.group).length, rnd = all.filter((e) => e.random_mac).length;
    $("#inv-kpis", el).innerHTML = html`<div class="kpi on"><span>Présents sur le réseau</span><b>${n(on)}</b></div><div class="kpi"><span>Appareils connus</span><b>${n(all.length)}</b></div>
      <div class="kpi"><span>Dans un groupe</span><b>${n(grouped)}</b></div><div class="kpi"><span>Politique générale</span><b>${n(all.length - grouped)}</b></div>${rnd ? html`<div class="kpi warn" title="${randomHelp}"><span>MAC privées</span><b>${n(rnd)}</b></div>` : ""}`;
    $("#inv-note", el).innerHTML = !inv.neighbors && !inv.dhcp_enabled ? notice("plain", html`<p><b>Rempart ne voit pas les appareils du réseau.</b> Il les découvre par la table de voisinage de l'hôte, qui n'est visible que si le conteneur partage le réseau de l'hôte (<code>Network=host</code>), ou par son propre serveur DHCP (onglet DHCP). En attendant, ajoutez les appareils par leur adresse ci-dessous.</p>`) : "";
  };
  const render = () => {
    const rows = shown();
    list.innerHTML = rows.length ? html`${rows.map((e) => invRow(e, inv))}` : html`<p class="empty">${icon("device")}<br>${arr(inv.entries).length ? "Aucun appareil ne correspond." : "Aucun appareil connu pour l'instant."}</p>`;
    $$("[data-key]", list).forEach((r) => { $("[data-sel]", r).checked = sel.has(r.dataset.key); });
    bulk();
  };
  const bulk = () => {
    sel = new Set([...sel].filter((k) => arr(inv.entries).some((e) => e.key === k)));
    $("#inv-bulk", el).hidden = !sel.size;
    $("#inv-n", el).textContent = plural(sel.size, "appareil sélectionné", "appareils sélectionnés");
  };
  const refresh = async () => { inv = await api("/inventory"); kpis(); render(); };
  const who = (r) => ({ mac: r.dataset.mac, ip: r.dataset.ip, device: r.dataset.device });
  const assign = (btn, clients, group, label) => act(btn, () => api("/groups/assign", { method: "POST", body: { clients, group } }), label).then((r) => { if (r) { inv = r; sel.clear(); kpis(); render(); } return r; });

  list.addEventListener("change", (e) => {
    const r = e.target.closest("[data-key]");
    if (!r) return;
    if (e.target.matches("[data-sel]")) { e.target.checked ? sel.add(r.dataset.key) : sel.delete(r.dataset.key); bulk(); return; }
    if (e.target.matches("[data-group]")) {
      const g = arr(inv.groups).find((x) => x.id === e.target.value);
      const ent = arr(inv.entries).find((x) => x.key === r.dataset.key);
      assign(e.target, [who(r)], e.target.value, g ? `${devTitle(ent)} : groupe ${g.name}` : `${devTitle(ent)} : politique générale`).then((res) => {
        if (!res) { e.target.value = ent?.group || ""; return; }
        const now = arr(res.entries).find((x) => x.key === r.dataset.key);
        if (now && g && now.group !== g.id) toast(`Rangé dans ${g.name}, mais un autre groupe le désigne plus précisément (${now.group_name}).`, true);
      });
    }
  });
  list.addEventListener("click", async (e) => {
    const r = e.target.closest("[data-key]");
    if (!r) return;
    const ent = arr(inv.entries).find((x) => x.key === r.dataset.key);
    const more = $(".inv-more", r);
    if (e.target.closest("[data-rename]")) {
      const kind = ent.kind || guessKind(ent.hostname);
      more.hidden = false;
      more.innerHTML = html`<form class="inv-form" data-nameform>
        <input name="name" value="${ent.name || ent.hostname || ""}" maxlength="64" placeholder="Nom de l'appareil" aria-label="Nom" required>
        <select name="kind" aria-label="Type">${Object.entries(kindName).map(([k, t]) => html`<option value="${k}" ${selected(k === kind)}>${t}</option>`)}</select>
        <button class="primary" type="submit">Enregistrer</button>
        ${ent.name ? html`<button type="button" class="link danger" data-unname>Effacer le nom</button>` : ""}
        <button type="button" class="link" data-close>Annuler</button>
        <small class="muted">Nom propre à Rempart, sans effet sur le DHCP${ent.static ? "" : " ni sur le nom DNS de l'appareil"}.</small>
      </form>`;
      $("input", more).focus();
      $("input", more).select();
      return;
    }
    if (e.target.closest("[data-close]")) { more.hidden = true; more.innerHTML = ""; return; }
    if (e.target.closest("[data-unname]")) {
      if (await act(e.target, () => api("/inventory/name", { method: "PUT", body: { key: ent.mac || ent.ips[0], name: "", kind: "" } }), "Nom effacé")) refresh();
      return;
    }
    if (e.target.closest("[data-test]")) {
      more.hidden = false;
      more.innerHTML = html`<form class="inv-form" data-testform><input name="domain" required placeholder="Domaine à tester, par exemple tiktok.com" aria-label="Domaine à tester" spellcheck="false"><button class="primary" type="submit">Tester</button><button type="button" class="link" data-close>Fermer</button><div class="inv-res"></div></form>`;
      $("input", more).focus();
      return;
    }
    if (e.target.closest("[data-reserve]")) {
      const b = e.target.closest("[data-reserve]");
      const host = slug(ent.name || ent.hostname);
      if (!confirm(`Réserver ${ent.ips[0]} pour « ${devTitle(ent)} » ? L'appareil gardera toujours cette adresse${host && inv.dhcp_domain ? ` et sera joignable sous ${host}.${inv.dhcp_domain}` : ""}.`)) return;
      if (await act(b, () => api("/dhcp/reserve", { method: "POST", body: { mac: ent.mac, hostname: host } }), "Adresse réservée")) refresh();
    }
  });
  list.addEventListener("submit", async (e) => {
    e.preventDefault();
    const r = e.target.closest("[data-key]");
    const ent = arr(inv.entries).find((x) => x.key === r.dataset.key);
    const f = new FormData(e.target);
    if (e.target.matches("[data-nameform]")) {
      if (await act(e.submitter, () => api("/inventory/name", { method: "PUT", body: { key: ent.mac || ent.ips[0], name: f.get("name"), kind: f.get("kind") } }), "Appareil nommé")) refresh();
      return;
    }
    if (e.target.matches("[data-testform]")) {
      const res = await act(e.submitter, () => api(`/check/client?client=${encodeURIComponent(ent.ips[0])}&domain=${encodeURIComponent(String(f.get("domain")).trim())}`));
      if (!res) return;
      const g = res.group ? html`groupe <b>${res.group}</b>` : "politique générale";
      const msg = res.result.blocked ? html`<b>${res.domain}</b> est bloqué (${g}) : <code>${res.result.rule}</code>, ${res.result.source}.`
        : res.rewrite ? html`<b>${res.domain}</b> est redirigé vers <code>${res.rewrite}</code> (${g}).`
        : res.result.allowed ? html`<b>${res.domain}</b> est autorisé explicitement (${g}).` : html`<b>${res.domain}</b> n'est pas bloqué (${g}).`;
      $(".inv-res", e.target).innerHTML = notice(res.result.blocked ? "bad" : "good", msg);
    }
  });
  $("#inv-q", el).addEventListener("input", (e) => { q = e.target.value.trim().toLowerCase(); render(); });
  $("#inv-f", el).onchange = (e) => { filt = e.target.value; render(); };
  $("#inv-reload", el).onclick = (e) => act(e.currentTarget, refresh, "Liste actualisée");
  $("#inv-clear", el).onclick = () => { sel.clear(); render(); };
  $("#inv-apply", el).onclick = (e) => {
    const rows = [...sel].map((k) => $(`[data-key="${CSS.escape(k)}"]`, list)).filter(Boolean);
    const g = arr(inv.groups).find((x) => x.id === $("#inv-bg", el).value);
    assign(e.currentTarget, rows.map(who), $("#inv-bg", el).value, `${plural(rows.length, "appareil rangé", "appareils rangés")} : ${g ? g.name : "politique générale"}`);
  };
  $("#inv-add", el).onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const addr = String(f.get("addr")).trim();
    const isMac = isMAC(addr);
    const name = String(f.get("name")).trim();
    if (!isMac && !/^[0-9a-f.:]+$/i.test(addr)) return toast("Adresse IP ou MAC attendue (un réseau entier se range dans l'éditeur du groupe)", true);
    if (!name && !f.get("group")) return toast("Donnez-lui un nom ou choisissez un groupe", true);
    const ok = await act(e.submitter, async () => {
      await api("/groups/assign", { method: "POST", body: { clients: [isMac ? { mac: addr } : { ip: addr }], group: f.get("group") } });
      if (name) await api("/inventory/name", { method: "PUT", body: { key: addr, name, kind: "" } });
      return true;
    }, "Appareil ajouté");
    if (ok) { e.target.reset(); refresh(); }
  };
  kpis();
  render();
};

clientTabs.groups = async (el, openId) => {
  const [d, inventory] = await Promise.all([api("/groups"), api("/inventory").catch(() => null)]);
  d.inventory = inventory;
  d.names = invIndex(inventory);
  arr(d.devices).forEach((x) => d.names.set("device:" + x.id, x.name));
  const groups = arr(d.groups);
  el.innerHTML = html`<div class="stack">
  <div class="gcards">
    ${groups.map((g) => groupCard(g, d))}
    <button type="button" class="gcard add" data-new>${icon("plus")}<b>Nouveau groupe</b><span class="muted small">Enfants, invités, objets connectés…</span></button>
    <a class="gcard general" href="#/filters">${icon("home")}<b>Tous les autres appareils</b><span class="muted small">Politique générale : listes actives, Ma liste, réglages. ${icon("arrow")}</span></a>
  </div>
  <section class="panel editor" id="gedit" hidden></section>
  <section class="panel tester">
    <div class="gsec-h"><span class="gsec-ic">${icon("search")}</span><div><h3>Tester un domaine pour un appareil</h3><p>Indique le groupe appliqué et la règle qui bloque, s'il y en a une.</p></div></div>
    <form class="tester-f" id="cchk">
      <input name="client" placeholder="Adresse de l'appareil" aria-label="Adresse de l'appareil" required>
      <input name="domain" placeholder="Domaine, par exemple tiktok.com" aria-label="Domaine à tester" required>
      <button type="submit" class="primary">Tester</button>
    </form>
    <div id="cchk-res"></div>
  </section>
  </div>`;
  const reload = (id) => clientTabs.groups(el, id);
  const ed = $("#gedit", el);
  const close = () => { ed.hidden = true; ed.innerHTML = ""; $$(".gcard.editing", el).forEach((c) => c.classList.remove("editing")); };
  const open = (g) => {
    close();
    ed.innerHTML = html`<div class="editor-head">${avatar(g.name || "+")}<div class="grow"><h2>${g.id ? g.name : "Nouveau groupe"}</h2><p class="muted small">${g.id ? `${plural(arr(g.clients).length, "appareil")} · modifications appliquées à l'enregistrement` : "Choisissez les appareils, puis ce qu'il faut bloquer."}</p></div><button type="button" class="icon-btn" data-close aria-label="Fermer">${icon("x")}</button></div>${groupForm(g, d)}`;
    ed.hidden = false;
    if (g.id) $(`.gcard[data-group="${g.id}"]`, el)?.classList.add("editing");
    bindGroupForm($("form", ed), g);
    $("[data-close]", ed).onclick = close;
    ed.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const bindGroupForm = (f, g) => {
    let n = $$("[data-sched]", f).length;
    bindSvc(f);
    f.addEventListener("click", (e) => {
      const rm = e.target.closest("[data-rmsched]");
      if (rm) rm.closest("[data-sched]").remove();
      const dev = e.target.closest("[data-adddev]");
      if (dev) {
        const ta = f.elements.clients;
        if (!lines(ta.value).includes(dev.dataset.adddev)) ta.value = [...lines(ta.value), dev.dataset.adddev].join("\n");
        dev.disabled = true;
      }
    });
    f.addEventListener("change", (e) => {
      if (e.target.name?.startsWith("s_mode")) e.target.closest("[data-sched]").dataset.mode = e.target.value;
    });
    $$("[data-adddev]", f).forEach((b) => (b.disabled = lines(f.elements.clients.value).includes(b.dataset.adddev)));
    $("[data-addsched]", f).onclick = () => {
      $(".scheds", f).insertAdjacentHTML("beforeend", schedRow({ days: [1, 2, 3, 4, 0], block_all: true }, d, n++).s);
      bindSvc(f);
    };
    $("[data-cancel]", f).onclick = close;
    const del = $("[data-delgroup]", f);
    if (del) del.onclick = () => confirm(`Supprimer le groupe « ${g.name} » ? Ses appareils suivront la politique générale.`) && act(del, () => api("/groups/" + g.id, { method: "DELETE" }), "Groupe supprimé").then(() => reload());
    f.onsubmit = (e) => {
      e.preventDefault();
      const body = readGroup(f);
      act(e.submitter, () => api(g.id ? "/groups/" + g.id : "/groups", { method: g.id ? "PUT" : "POST", body }), g.id ? "Groupe enregistré" : "Groupe créé").then((r) => {
        if (!r) return;
        if (arr(r.moved).length) toast(`Retiré d'un autre groupe : ${r.moved.map((m) => d.names?.get(m.split(" ")[0]) ? m.replace(/^\S+/, d.names.get(m.split(" ")[0])) : m).join(", ")}. Un appareil n'appartient qu'à un groupe.`);
        reload();
      });
    };
  };
  $$("[data-edit]", el).forEach((b) => (b.onclick = () => open(groups.find((g) => g.id === b.closest("[data-group]").dataset.group))));
  $("[data-new]", el).onclick = () => open({});
  if (openId) { const g = groups.find((x) => x.id === openId); if (g) open(g); }
  else if (!groups.length) open({});
  $("#cchk").onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const r = await act(e.submitter, () => api(`/check/client?client=${encodeURIComponent(f.get("client").trim())}&domain=${encodeURIComponent(f.get("domain").trim())}`));
    if (!r) return;
    const who = r.group ? html`groupe <b>${r.group}</b>` : html`politique générale`;
    const msg = r.result.blocked ? html`<b>${r.domain}</b> est bloqué pour ${r.client} (${who}) : <code>${r.result.rule}</code>, ${r.result.source}.`
      : r.rewrite ? html`<b>${r.domain}</b> est redirigé vers <code>${r.rewrite}</code> pour ${r.client} (${who}).`
      : r.result.allowed ? html`<b>${r.domain}</b> est autorisé explicitement pour ${r.client} (${who}).` : html`<b>${r.domain}</b> n'est pas bloqué pour ${r.client} (${who}).`;
    $("#cchk-res").innerHTML = html`<div class="mt">${notice(r.result.blocked ? "bad" : "good", html`${msg}${r.mac ? html` <span class="muted small">MAC ${r.mac}</span>` : ""}`)}</div>`;
  };
  $$("[data-gpause]", el).forEach((b) => (b.onclick = () => act(b, () => api(`/groups/${b.closest("[data-group]").dataset.group}/pause`, { method: "POST", body: { minutes: +b.dataset.gpause } }), +b.dataset.gpause ? "Filtrage du groupe en pause" : "Filtrage du groupe repris").then(() => reload())));
};

clientTabs.devices = async (el) => {
  const [d, tl] = await Promise.all([api("/groups"), api("/tls").catch(() => ({ info: {} }))]);
  const names = arr(tl.info?.names).filter((x) => !x.startsWith("*.") && !/^[\d.:]+$/.test(x));
  const wild = arr(tl.info?.names).filter((x) => x.startsWith("*.")).map((x) => x.slice(2));
  const devices = arr(d.devices);
  el.innerHTML = html`<div class="stack">
  <section class="panel stack">
    <div class="gsec-h"><span class="gsec-ic">${icon("phone")}</span><div><h3>Profils mobiles</h3><p>Chaque appareil reçoit une adresse DoH qui lui est propre : Rempart le reconnaît, lui applique la politique de son groupe et le sert même hors du réseau local. Cette adresse est un secret, comme un mot de passe : révoquez-la si l'appareil est perdu.</p></div></div>
    ${tl.info?.self_signed ? notice("bad", html`<p>Le certificat actuel est <b>auto-signé</b> : iOS, Android et les navigateurs refuseront la connexion DoH/DoT. Obtenez un certificat par ACME ou par votre PKI (<a href="#/security/certificate">Sécurité, Certificat</a>), ou joignez l'AC de votre PKI au profil Apple.</p>`) : ""}
    ${devices.length ? html`<div class="devs">${devices.map((x) => { const g = arr(d.groups).find((gr) => arr(gr.clients).includes("device:" + x.id)); return html`<article class="dev">
      <span class="dev-ic">${icon("phone")}</span>
      <div class="dev-main"><b>${x.name}</b><span class="muted small mono">device:${x.id}</span>
        <span class="dev-meta">${g ? html`<span class="tag ok">${g.name}</span>` : html`<span class="tag">politique générale</span>`}<span class="muted small">créé le ${day(x.created)} · vu ${ago(x.last_seen)}</span></span></div>
      <div class="dev-act"><button class="link" data-rotate="${x.id}" data-name="${x.name}">Nouveau profil</button><button class="link danger" data-revoke="${x.id}" data-name="${x.name}">Révoquer</button></div>
    </article>`; })}</div>` : html`<p class="empty">${icon("phone")}<br>Aucun appareil enregistré.</p>`}
  </section>
  <section class="panel stack">
    <div class="gsec-h"><span class="gsec-ic">${icon("plus")}</span><div><h3>Ajouter un appareil</h3><p>Le profil créé ne s'affiche qu'une fois : gardez l'appareil à portée de main.</p></div></div>
    <form id="devf" class="stack-s">
      <div class="fields">
        <label class="field"><span>Nom</span><input name="name" required maxlength="64" placeholder="iPhone de Léa"></label>
        <label class="field"><span>Groupe</span><select name="group"><option value="">Politique générale</option>${arr(d.groups).map((g) => html`<option value="${g.id}">${g.name}</option>`)}</select></label>
        <label class="field"><span>Nom public du serveur</span><input name="host" list="tlsnames" required value="${names[0] || ""}" placeholder="dns.maison.example"><datalist id="tlsnames">${names.map((x) => html`<option value="${x}">`)}</datalist><small class="muted">Doit figurer dans le certificat et pointer vers Rempart depuis l'extérieur.</small></label>
      </div>
      <details class="help"><summary>AC de votre PKI à joindre au profil Apple (facultatif)</summary><textarea name="ca_pem" rows="4" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></details>
      <div class="row"><span class="grow"></span><button class="primary" type="submit">Créer le profil</button></div>
    </form>
    <div id="devres"></div>
  </section></div>`;
  const reload = () => clientTabs.devices(el);
  let lastBlob = "";
  const show = (r, host) => {
    if (lastBlob) URL.revokeObjectURL(lastBlob);
    // Profil signé (CMS) quand le serveur a pu le signer, sinon en clair.
    const prof = r.mobileconfig_signed ? Uint8Array.from(atob(r.mobileconfig_signed), (c) => c.charCodeAt(0)) : r.mobileconfig;
    const blob = lastBlob = prof ? URL.createObjectURL(new Blob([prof], { type: "application/x-apple-aspen-config" })) : "";
    const androidHost = r.dot_host && wild.some((w) => r.dot_host.endsWith("." + w) && r.dot_host.split(".").length === w.split(".").length + 1) ? r.dot_host : "";
    $("#devres").innerHTML = html`<div class="stack-s mt">${notice("good", html`<p>Profil de <b>${r.device.name}</b> prêt. <b>Cette adresse ne sera plus jamais affichée</b> : installez-la maintenant ou téléchargez le profil.</p>${r.ca_sha256 ? html`<p class="small">AC jointe, empreinte SHA-256 : <code>${r.ca_sha256}</code>. Vérifiez-la sur l'appareil avant de l'approuver.</p>` : ""}`)}
      ${r.doh_url ? html`<div class="secret"><code>${r.doh_url}</code><button type="button" data-copy="${r.doh_url}" data-copied="Adresse DoH copiée">${icon("copy")}Copier</button></div>
      <div class="row">${blob ? html`<a class="btn primary" href="${blob}" download="rempart-${r.device.id}.mobileconfig">${icon("download")}Profil iPhone, iPad, Mac</a>` : ""}</div>
      ${r.mobileconfig_signed ? html`<p class="muted small">Profil signé par le certificat de l'interface (${r.mobileconfig_signer}).${r.mobileconfig_self_signed ? " Ce certificat est auto-signé : l'appareil affichera encore « non vérifié » ; obtenez un certificat ACME ou de votre PKI pour un profil « vérifié »." : " L'appareil l'affiche « vérifié » si l'AC de ce certificat lui est connue."}</p>` : ""}` : notice("bad", "DNS-over-HTTPS n'est pas activé (doh.listen) : aucun profil Apple possible.")}
      <details class="help" open><summary>Installer</summary><ol>
        <li><b>iPhone, iPad</b> : ouvrez le fichier .mobileconfig sur l'appareil (AirDrop, courriel), puis Réglages → Profil téléchargé → Installer. Avec une AC jointe, activez-la ensuite dans Réglages → Général → Informations → Réglages des certificats.</li>
        <li><b>Mac</b> : double-cliquez le fichier, puis Réglages Système → Confidentialité et sécurité → Profils.</li>
        <li><b>Android 9 et plus</b> : Paramètres → Réseau → DNS privé → Nom d'hôte : ${androidHost ? html`<code>${androidHost}</code>. Ce nom circule en clair (résolution préalable, poignée de main TLS) : il identifie l'appareil sur votre réseau, mais n'ouvre pas l'accès depuis l'extérieur.` : html`<code>${r.dot_plain_host || host}</code>. Android n'utilise que DoT, sans chemin : l'appareil est reconnu par son adresse, sur votre réseau seulement. Avec un certificat couvrant <code>*.${host}</code>, le nom <code>&lt;jeton&gt;.${host}</code> l'identifierait.`} Hors du réseau, utilisez une application DoH (Intra, navigateur) avec l'adresse ci-dessus.</li>
        <li><b>Windows 11, Firefox, Chrome</b> : indiquez l'adresse DoH ci-dessus comme serveur DNS chiffré personnalisé.</li>
      </ol></details></div>`;
    bindCopy($("#devres"));
  };
  $("#devf").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    act(e.submitter, () => api("/devices", { method: "POST", body: { name: f.get("name"), group: f.get("group"), host: f.get("host"), ca_pem: f.get("ca_pem") } })).then((r) => r && show(r, f.get("host")));
  };
  $$("[data-rotate]", el).forEach((b) => (b.onclick = () => {
    const host = $("#devf").elements.host.value;
    confirm(`Créer un nouveau profil pour « ${b.dataset.name} » ? L'ancienne adresse cessera aussitôt de fonctionner.`) &&
      act(b, () => api("/devices", { method: "POST", body: { rotate: b.dataset.rotate, host, ca_pem: $("#devf").elements.ca_pem.value } })).then((r) => r && show(r, host));
  }));
  $$("[data-revoke]", el).forEach((b) => (b.onclick = () => confirm(`Révoquer « ${b.dataset.name} » ? Son adresse DoH cessera de fonctionner.`) && act(b, () => api("/devices/" + b.dataset.revoke, { method: "DELETE" }), "Appareil révoqué").then(reload)));
};

clientTabs.dhcp = async (el) => {
  const d = await api("/dhcp");
  const c = d.config;
  const ifs = arr(d.interfaces);
  el.innerHTML = html`<div class="stack">
  <section class="panel stack">
    <div class="gsec-h"><span class="gsec-ic">${icon("wifi")}</span><div><h3>Serveur DHCP</h3><p>Pour les box qui ne laissent pas changer le DNS annoncé : Rempart attribue les adresses et s'annonce comme serveur DNS. <b>Désactivez d'abord le DHCP de la box</b> : deux serveurs sur un même réseau se contredisent.</p></div></div>
    <div class="kpis"><div class="kpi ${c.enabled && d.running ? "on" : ""}"><span>État</span><b>${c.enabled ? (d.running ? "En service" : "Arrêté") : "Désactivé"}</b></div><div class="kpi"><span>Plage</span><b class="mono">${c.range_start && c.range_end ? `${c.range_start} – ${c.range_end}` : "—"}</b></div><div class="kpi"><span>Baux</span><b>${n(arr(d.leases).length)}</b></div><div class="kpi"><span>Domaine</span><b class="mono">${c.domain || "—"}</b></div></div>
    ${d.error ? notice("bad", d.error) : c.enabled && d.running ? notice("good", html`En service sur <b>${c.interface}</b>.`) : ""}
    ${notice("plain", html`<p>Le conteneur doit partager le réseau de l'hôte (<code>Network=host</code>) pour recevoir les diffusions DHCP sur le port 67.</p>`)}
    <form id="dhf" class="stack-s">
      ${sw("enabled", c.enabled, "Activer le serveur DHCP", "")}
      <div class="fields">
        <label class="field"><span>Interface</span><select name="interface">${ifs.map((i) => html`<option value="${i.name}" ${selected(i.name === c.interface)}>${i.name} ${i.addrs.join(", ")}</option>`)}${c.interface && !ifs.some((i) => i.name === c.interface) ? html`<option selected>${c.interface}</option>` : ""}</select></label>
        <label class="field"><span>Adresse de Rempart</span><input name="server_ip" value="${c.server_ip}" placeholder="192.168.1.2"></label>
        <label class="field"><span>Masque</span><input name="netmask" value="${c.netmask || "255.255.255.0"}"></label>
        <label class="field"><span>Passerelle (box)</span><input name="router" value="${c.router}" placeholder="192.168.1.1"></label>
        <label class="field"><span>Début de plage</span><input name="range_start" value="${c.range_start}" placeholder="192.168.1.100"></label>
        <label class="field"><span>Fin de plage</span><input name="range_end" value="${c.range_end}" placeholder="192.168.1.199"></label>
        <label class="field"><span>Durée du bail (heures)</span><input name="lease_hours" type="number" min="1" max="720" value="${c.lease_hours || 24}"></label>
        <label class="field"><span>Domaine des appareils</span><input name="domain" value="${c.domain}" placeholder="home.arpa"><small class="muted">Chaque appareil devient joignable par &lt;nom&gt;.${c.domain || "home.arpa"}.</small></label>
      </div>
      <label class="field"><span>Baux statiques</span><textarea name="static" rows="4" spellcheck="false" placeholder="aa:bb:cc:dd:ee:ff 192.168.1.10 nas">${arr(c.static).map((s) => `${s.mac} ${s.ip} ${s.hostname || ""}`.trim()).join("\n")}</textarea><small class="muted">Une ligne par appareil : MAC, adresse, nom (facultatif). L'adresse peut être hors de la plage.</small></label>
      <div class="row"><span class="grow"></span><button class="primary" type="submit">Enregistrer</button></div>
    </form>
  </section>
  <section class="panel stack">
    <h2>Baux</h2>
    ${arr(d.leases).length ? html`<div class="table-wrap"><table class="cards"><thead><tr><th>Appareil</th><th>Adresse</th><th>MAC</th><th>Expire</th><th></th></tr></thead><tbody>
      ${arr(d.leases).map((l) => html`<tr><td class="first"><b>${l.hostname || "—"}</b>${l.static ? html` <span class="tag ok">statique</span>` : ""}</td><td class="mono" data-label="Adresse">${l.ip}</td><td class="mono" data-label="MAC">${l.mac}</td>
        <td class="small" data-label="Expire">${l.static && !isSet(l.expires) ? "—" : date(l.expires)}</td><td class="act">${l.static ? "" : html`<button class="link" data-reserve="${l.mac}" data-host="${l.hostname || ""}" title="Garder toujours cette adresse">Réserver</button><button class="link danger" data-forget="${l.mac}">Oublier</button>`}</td></tr>`)}
    </tbody></table></div>` : html`<p class="empty">Aucun bail.</p>`}
  </section></div>`;
  const reload = () => clientTabs.dhcp(el);
  $("#dhf").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const stat = lines(f.get("static")).map((l) => { const [mac, ip, hostname = ""] = l.split(/\s+/); return { mac, ip, hostname }; });
    const body = { enabled: !!f.get("enabled"), interface: f.get("interface") || "", server_ip: f.get("server_ip").trim(), netmask: f.get("netmask").trim(), router: f.get("router").trim(),
      range_start: f.get("range_start").trim(), range_end: f.get("range_end").trim(), lease_hours: +f.get("lease_hours"), domain: f.get("domain").trim(), static: stat };
    if (body.enabled && !c.enabled && !confirm("Activer le serveur DHCP ? Assurez-vous que celui de la box est désactivé.")) return;
    act(e.submitter, () => api("/dhcp", { method: "PUT", body }), "Configuration DHCP enregistrée").then((r) => r && reload());
  };
  $$("[data-forget]", el).forEach((b) => (b.onclick = () => act(b, () => api("/dhcp/leases/" + encodeURIComponent(b.dataset.forget), { method: "DELETE" }), "Bail oublié").then(reload)));
  $$("[data-reserve]", el).forEach((b) => (b.onclick = () => act(b, () => api("/dhcp/reserve", { method: "POST", body: { mac: b.dataset.reserve, hostname: b.dataset.host } }), "Adresse réservée").then((r) => r && reload())));
};

// ---- zones : transferts, mises à jour, secondaires, clés TSIG ----
const keyOptions = (keys, cur, empty = "Aucune") => html`<option value="">${empty}</option>${arr(keys).map((k) => html`<option value="${k.name}" ${selected(k.name === cur)}>${k.name.replace(/\.$/, "")} (${k.algorithm.replace(/\.$/, "")})</option>`)}${cur && !arr(keys).some((k) => k.name === cur) ? html`<option selected>${cur}</option>` : ""}`;
const transferForm = (z, keys) => html`<details><summary>Secondaires et mises à jour dynamiques${arr(z.transfer.secondaries).length ? html` <span class="tag ok">${arr(z.transfer.secondaries).length} secondaire(s)</span>` : ""}${z.transfer.update_key ? html` <span class="tag">RFC 2136</span>` : ""}</summary>
  <form class="stack-s mt" data-transfer>
    <p class="muted small">Chaque opération exige à la fois une adresse autorisée et une signature TSIG valide (HMAC-SHA256 ou plus). Les secondaires reçoivent la zone signée par AXFR et un NOTIFY à chaque changement.</p>
    <div class="fields">
      <label class="field"><span>Secondaires (IP ou IP:port)</span><textarea name="secondaries" rows="3" spellcheck="false" placeholder="192.168.1.3&#10;10.0.0.53:53">${arr(z.transfer.secondaries).join("\n")}</textarea></label>
      <label class="field"><span>Clé TSIG des transferts</span><select name="key">${keyOptions(keys, z.transfer.key)}</select></label>
    </div>
    <div class="fields">
      <label class="field"><span>Mises à jour acceptées depuis</span><textarea name="update_from" rows="3" spellcheck="false" placeholder="192.168.1.0/24">${arr(z.transfer.update_from).join("\n")}</textarea><small class="muted">Adresses ou préfixes, par exemple votre serveur DHCP ou vos contrôleurs de domaine.</small></label>
      <label class="field"><span>Clé TSIG des mises à jour</span><select name="update_key">${keyOptions(keys, z.transfer.update_key, "Mises à jour refusées")}</select><small class="muted">Distincte de celle des transferts. Une mise à jour ne touche jamais les enregistrements saisis ici, ni SOA, NS de l'apex et DNSSEC.</small></label>
    </div>
    ${arr(z.dynamic).length ? html`<label class="field"><span>Enregistrements dynamiques (${arr(z.dynamic).length})</span><textarea readonly rows="4" spellcheck="false">${arr(z.dynamic).join("\n")}</textarea></label>` : ""}
    <div><button type="submit">Enregistrer</button></div>
  </form></details>`;

async function zonesExtra(main, zones) {
  const [keys, sec] = await Promise.all([api("/tsig").catch(() => null), api("/secondaries").catch(() => ({ config: [], status: [] }))]);
  const box = $("#zones-extra", main);
  const status = arr(sec.status);
  const own = arr(sec.config).filter((s) => !s.managed);
  box.innerHTML = html`
  <section class="panel stack">
    <div class="panel-head"><h2>Zones secondaires</h2><p>Zones copiées d'un serveur primaire (BIND, Knot, Windows DNS ou un autre Rempart) par AXFR signé TSIG, servies telles quelles, signatures DNSSEC du primaire comprises. Après le délai d'expiration du SOA sans contact, une zone n'est plus servie.</p></div>
    ${status.length ? html`<div class="table-wrap"><table class="cards"><thead><tr><th>Zone</th><th>Primaire</th><th class="num">Série</th><th>Dernier transfert</th><th>État</th></tr></thead><tbody>
      ${status.map((s) => html`<tr><td class="first domain">${s.name.replace(/\.$/, "")}${s.managed ? html` <span class="tag">réplication</span>` : ""}</td><td class="mono" data-label="Primaire">${s.primary}</td><td class="num mono" data-label="Série">${s.serial || "—"}</td><td class="small" data-label="Dernier transfert">${date(s.last_ok)}</td>
      <td data-label="État">${s.expired ? html`<span class="tag bad">expirée</span>` : s.last_error ? html`<span class="tag warn" title="${s.last_error}">erreur</span> <span class="small muted">${s.last_error}</span>` : isSet(s.last_ok) ? html`<span class="tag ok">à jour</span>` : html`<span class="tag">en attente</span>`}</td></tr>`)}
    </tbody></table></div>` : ""}
    ${keys ? html`<form id="secf" class="stack-s">
      <label class="field"><span>Zones secondaires (une par ligne : zone, primaire, clé TSIG)</span><textarea name="sec" rows="3" spellcheck="false" placeholder="corp.example.local 10.0.0.10 xfr.corp.example.local">${own.map((s) => `${s.name.replace(/\.$/, "")} ${s.primary} ${s.key.replace(/\.$/, "")}`).join("\n")}</textarea></label>
      <div><button type="submit">Enregistrer</button></div></form>` : ""}
  </section>
  ${keys ? html`<section class="panel stack">
    <div class="panel-head"><h2>Clés TSIG</h2><p>Secrets partagés des transferts, des NOTIFY, des mises à jour dynamiques, des flux RPZ et de la réplication. Le secret n'est affiché qu'à la création ; il reste ensuite dans l'état scellé.</p></div>
    ${keys.length ? html`<div class="table-wrap"><table class="cards"><thead><tr><th>Clé</th><th>Algorithme</th><th>Utilisée par</th><th></th></tr></thead><tbody>
      ${keys.map((k) => html`<tr><td class="first mono">${k.name.replace(/\.$/, "")}${k.managed ? html` <span class="tag">réplication</span>` : ""}</td><td data-label="Algorithme" class="mono small">${k.algorithm.replace(/\.$/, "")}</td>
      <td data-label="Utilisée par" class="small">${arr(k.used_by).join(", ") || html`<span class="muted">rien</span>`}</td><td class="act">${arr(k.used_by).length || k.managed ? "" : html`<button class="link danger" data-deltsig="${k.name}">Supprimer</button>`}</td></tr>`)}
    </tbody></table></div>` : html`<p class="empty">Aucune clé.</p>`}
    <form id="tsigf" class="fields">
      <label class="field"><span>Nom de la clé</span><input name="name" required placeholder="xfr.maison.lan"></label>
      <label class="field"><span>Algorithme</span><select name="algorithm"><option value="hmac-sha256">HMAC-SHA256</option><option value="hmac-sha384">HMAC-SHA384</option><option value="hmac-sha512">HMAC-SHA512</option></select></label>
      <label class="field"><span>Secret (base64, pour importer la clé d'un éditeur)</span><input name="secret" type="password" autocomplete="off" placeholder="vide : générer une clé"></label>
      <div class="row"><span class="grow"></span><button class="primary" type="submit">Créer la clé</button></div>
    </form>
    <div id="tsigres"></div>
  </section>` : ""}`;
  const reload = () => views.zones(main);
  $$("[data-transfer]", main).forEach((f) => (f.onsubmit = (e) => {
    e.preventDefault();
    const d = new FormData(f);
    const zone = f.closest("[data-zone]").dataset.zone;
    act(e.submitter, () => api("/zones/" + encodeURIComponent(zone) + "/transfer", { method: "PUT", body: { secondaries: lines(d.get("secondaries")), key: d.get("key") || "", update_key: d.get("update_key") || "", update_from: lines(d.get("update_from")) } }), "Transferts enregistrés : NOTIFY envoyé").then((r) => r && reload());
  }));
  const sf = $("#secf", box);
  if (sf) sf.onsubmit = (e) => {
    e.preventDefault();
    const body = lines(new FormData(sf).get("sec")).map((l) => { const [name, primary, key] = l.split(/\s+/); return { name, primary, key }; });
    act(e.submitter, () => api("/secondaries", { method: "PUT", body }), "Zones secondaires enregistrées").then((r) => r && reload());
  };
  const tf = $("#tsigf", box);
  if (tf) tf.onsubmit = async (e) => {
    e.preventDefault();
    const d = new FormData(tf);
    const r = await act(e.submitter, () => api("/tsig", { method: "POST", body: { name: d.get("name"), algorithm: d.get("algorithm"), secret: d.get("secret") } }));
    if (!r) return;
    if (!r.secret) { toast("Clé importée"); reload(); return; }
    $("#tsigres", box).innerHTML = html`<div class="stack-s mt">${notice("good", html`<p>Clé <b>${r.name}</b> créée. <b>Son secret ne sera plus jamais affiché</b> : recopiez-le maintenant dans la configuration de l'autre serveur.</p>`)}
      ${[["BIND (named.conf), ou fichier pour nsupdate -k", r.bind], ["Knot", r.knot]].map(([t, v]) => html`<label class="field"><span>${t}</span><div class="copy"><code>${v}</code><button type="button" data-copy="${v}" data-copied="Copié">${icon("copy")}Copier</button></div></label>`)}
      <div><button type="button" id="tsigdone">J'ai recopié le secret</button></div></div>`;
    bindCopy($("#tsigres", box));
    $("#tsigdone", box).onclick = reload;
  };
  $$("[data-deltsig]", box).forEach((b) => (b.onclick = () => confirm(`Supprimer la clé ${b.dataset.deltsig} ?`) && act(b, () => api("/tsig/" + encodeURIComponent(b.dataset.deltsig), { method: "DELETE" }), "Clé supprimée").then(reload)));
  return keys;
}
filterTabs.rpz = async (el) => {
  const [d, keys] = await Promise.all([api("/rpz"), api("/tsig").catch(() => [])]);
  const feeds = arr(d.feeds);
  const st = d.status || {};
  el.innerHTML = html`<section class="panel stack">
    <div class="panel-head"><h2>Flux de menaces (RPZ)</h2><p>Zones de politique de réponse (Response Policy Zones) fournies par les éditeurs de sécurité. Elles s'appliquent à tous les appareils, avant les groupes et leurs exceptions, et même quand le blocage est en pause. Le premier flux de la liste qui correspond l'emporte.</p></div>
    ${feeds.length ? html`<div class="table-wrap"><table class="cards"><thead><tr><th>Actif</th><th>Flux</th><th class="num">Règles</th><th>Mise à jour</th><th></th></tr></thead><tbody>
      ${feeds.map((f, i) => { const s = st[f.id] || {}; return html`<tr data-feed="${f.id}">
        <td data-label="Actif"><label class="switch"><input type="checkbox" data-rpzon ${checked(f.enabled)} aria-label="Activer ${f.name}"></label></td>
        <td class="first"><b>${f.name}</b> <span class="tag">${f.source === "axfr" ? "AXFR + TSIG" : "HTTPS"}</span><br><span class="domain muted">${f.zone.replace(/\.$/, "")} · ${f.source === "axfr" ? f.primary : f.url}</span>
          ${s.last_error ? html`<div class="mt">${notice("bad", s.last_error)}</div>` : ""}${s.skipped ? html`<div class="small muted">${n(s.skipped)} déclencheur(s) mal formé(s) ignoré(s)</div>` : ""}</td>
        <td class="num" data-label="Règles">${n(s.rules)}</td><td class="small" data-label="Mise à jour">${date(s.last_ok)}</td>
        <td class="act">${i > 0 ? html`<button class="link" data-up>Monter</button> ` : ""}<button class="link danger" data-delrpz>Supprimer</button></td></tr>`; })}
    </tbody></table></div>` : html`<p class="empty">Aucun flux. Votre éditeur (Infoblox, Spamhaus, DNS Firewall de votre CERT…) vous communique le nom de la zone RPZ, son serveur et une clé TSIG, ou une adresse HTTPS.</p>`}
    <hr>
    <h3>Ajouter un flux</h3>
    <form id="rpzf" class="stack-s">
      <div class="fields">
        <label class="field"><span>Nom</span><input name="name" required placeholder="Flux du CERT"></label>
        <label class="field"><span>Zone RPZ</span><input name="zone" required placeholder="rpz.editeur.example"></label>
        <label class="field"><span>Source</span><select name="source"><option value="axfr">AXFR signé TSIG</option><option value="https">HTTPS (fichier de zone)</option></select></label>
      </div>
      <div class="fields" data-src="axfr">
        <label class="field"><span>Serveur primaire (IP ou IP:port)</span><input name="primary" placeholder="198.51.100.53"></label>
        <label class="field"><span>Clé TSIG</span><select name="key">${keyOptions(keys, "", "Choisir une clé")}</select><small class="muted">Importez la clé de l'éditeur dans Zones DNSSEC, Clés TSIG.</small></label>
      </div>
      <div class="fields" data-src="https" hidden>
        <label class="field"><span>Adresse</span><input name="url" type="url" placeholder="https://…"></label>
      </div>
      <label class="field"><span>Rafraîchissement (minutes, 0 : selon le SOA)</span><input name="minutes" type="number" min="0" max="1440" value="0"></label>
      <div class="row"><span class="grow"></span><button class="primary" type="submit">Ajouter le flux</button></div>
    </form>
  </section>`;
  const reload = () => filterTabs.rpz(el);
  const f = $("#rpzf", el);
  const sync = () => $$("[data-src]", f).forEach((x) => (x.hidden = x.dataset.src !== f.elements.source.value));
  f.elements.source.onchange = sync;
  f.onsubmit = (e) => {
    e.preventDefault();
    const v = new FormData(f);
    act(e.submitter, () => api("/rpz", { method: "POST", body: { name: v.get("name"), zone: v.get("zone"), source: v.get("source"), primary: v.get("primary"), key: v.get("key"), url: v.get("url"), minutes: +v.get("minutes"), enabled: true } }), "Flux ajouté, chargement en cours").then((r) => r && setTimeout(reload, 1200));
  };
  const feedOf = (b) => feeds.find((x) => x.id === b.closest("[data-feed]").dataset.feed);
  $$("[data-rpzon]", el).forEach((c) => (c.onchange = () => act(null, () => api("/rpz/" + feedOf(c).id, { method: "PUT", body: { ...feedOf(c), enabled: c.checked } }), c.checked ? "Flux activé" : "Flux désactivé")));
  $$("[data-delrpz]", el).forEach((b) => (b.onclick = () => confirm(`Supprimer le flux « ${feedOf(b).name} » ?`) && act(b, () => api("/rpz/" + feedOf(b).id, { method: "DELETE" }), "Flux supprimé").then(reload)));
  $$("[data-up]", el).forEach((b) => (b.onclick = () => {
    const ids = feeds.map((x) => x.id);
    const i = ids.indexOf(feedOf(b).id);
    [ids[i - 1], ids[i]] = [ids[i], ids[i - 1]];
    act(b, () => api("/rpz/order", { method: "PUT", body: ids }), "Ordre enregistré").then(reload);
  }));
};

const opsTab = async (el) => {
  const [sys, rep] = await Promise.all([api("/syslog").catch(() => null), api("/replication").catch(() => null)]);
  const origin = location.origin;
  el.innerHTML = html`<div class="stack">
  <section class="panel stack-s">
    <h2>Supervision (Prometheus)</h2>
    <p>Les métriques sont exposées sur <code>${origin}/metrics</code> : requêtes par issue et par transport, latence, cache, résolveurs en amont, listes, flux RPZ, zones (série, expiration des signatures), secondaires, certificat, intégrité de l'audit, DHCP, réplication. Aucune ne porte l'adresse ni le nom d'un appareil.</p>
    <p class="muted small">Créez un jeton de portée « métriques » (Sécurité, Accès API), rangez-le dans un fichier lisible par Prometheus seul, puis :</p>
    <div class="copy"><code class="pre">- job_name: rempart\n  scheme: https\n  authorization: { credentials_file: /etc/prometheus/rempart.token }\n  static_configs: [{ targets: ['${location.host}'] }]</code></div>
  </section>
  ${sys ? html`<section class="panel stack-s">
    <h2>Copie de l'audit vers un syslog ou un SIEM</h2>
    <p>Chaque événement du journal d'audit part en RFC 5424 (facilité « log audit »), avec son chaînage et sa signature : le SIEM peut vérifier qu'aucun n'a été modifié. La copie relit le journal à partir du dernier événement remis : un collecteur injoignable ne fait rien perdre.</p>
    ${sys.status && sys.config.enabled ? (sys.status.last_error ? notice("bad", html`<p>${sys.status.last_error}</p><p class="small">${n(sys.status.pending)} événement(s) en attente.</p>`) : notice("good", html`${n(sys.status.sent)} événement(s) remis depuis le démarrage, dernier le ${date(sys.status.last_ok)}. ${n(sys.status.pending)} en attente.`)) : ""}
    <form id="sysf" class="stack-s">
      ${sw("enabled", sys.config.enabled, "Copier l'audit", "")}
      <div class="fields">
        <label class="field"><span>Transport</span><select name="network">
          <option value="tls" ${selected(sys.config.network !== "tcp" && sys.config.network !== "udp")}>TLS (RFC 5425, recommandé)</option>
          <option value="tcp" ${selected(sys.config.network === "tcp")}>TCP en clair</option>
          <option value="udp" ${selected(sys.config.network === "udp")}>UDP en clair (sans garantie de remise)</option></select></label>
        <label class="field"><span>Collecteur (hôte:port)</span><input name="address" value="${sys.config.address}" placeholder="siem.corp.example:6514"></label>
        <label class="field"><span>Nom de cette instance</span><input name="hostname" value="${sys.config.hostname || ""}" placeholder="nom de la machine"></label>
      </div>
      <details class="help"><summary>AC du collecteur (PKI interne)</summary><textarea name="ca_bundle" rows="4" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${sys.config.ca_bundle || ""}</textarea></details>
      <div><button class="primary" type="submit">Enregistrer</button></div>
    </form>
  </section>` : ""}
  <section class="panel stack-s">
    <h2>Sauvegarde</h2>
    <p>L'archive contient le dossier de données et le keystore logiciel, avec un manifeste d'empreintes SHA-256. Les rotations de KEK attendent la fin de la copie : données et keystore viennent toujours de la même génération. Avec un HSM, les clés n'y sont pas : sauvegardez aussi le token par le mécanisme du constructeur.</p>
    <div class="row"><a class="btn primary" href="/api/backup" download>${icon("download")}Télécharger une sauvegarde</a><a class="btn" href="/api/backup?lists=1" download>Avec les copies des listes</a></div>
    <details class="help"><summary>Sauvegarde automatique et restauration</summary><ol>
      <li>Créez un jeton de portée « sauvegarde » (il ne sert qu'à cela), puis chaque nuit : <code>curl -fsS -H @/etc/rempart/backup.auth ${origin}/api/backup -o rempart-$(date +%F).tar.gz</code></li>
      <li>Vérifiez une archive sans toucher au serveur : <code>podman run --rm -v ./:/b:Z --secret keystore_passphrase,type=env,target=REMPART_KEYSTORE_PASSPHRASE localhost/rempart backup verify -config /etc/rempart/rempart.yaml /b/archive.tar.gz</code></li>
      <li>Restaurez, Rempart arrêté : <code>podman run --rm -v rempart-data:/var/lib/rempart -v ./:/b:Z localhost/rempart restore -config /etc/rempart/rempart.yaml -force /b/archive.tar.gz</code>. Le contenu actuel est mis de côté dans <code>.avant-restauration-&lt;date&gt;</code>, jamais supprimé. Redémarrez avec la phrase de passe ou le quorum <b>en vigueur à la date de la sauvegarde</b>.</li>
    </ol></details>
  </section>
  ${rep ? html`<section class="panel stack-s">
    <h2>Réplication</h2>
    <p>Deux instances ou plus : l'instance principale publie sa configuration de filtrage (listes, règles, groupes, appareils, résolution, flux RPZ) et ses zones ; les répliques la recopient toutes les 30 secondes et reçoivent les zones signées par AXFR. Chaque instance garde son compte, ses annuaires, son certificat, son keystore, son DHCP et ses journaux. Annoncez les deux serveurs aux clients (DHCP : « second serveur DNS »).</p>
    ${rep.config.acting ? notice("bad", html`<p><b>Instance principale par intérim</b> (époque ${rep.config.epoch}) : l'instance principale habituelle était injoignable. Elle reprendra son rôle à son retour, avec les modifications faites ici.</p>`) : ""}
    ${rep.status ? (rep.status.last_error ? notice("bad", rep.status.last_error) : notice("good", html`${rep.config.role === "replica" ? html`Dernière synchronisation : ${date(rep.status.last_sync)}.` : "Autre instance joignable."}${rep.status.peer ? html` Autre instance : ${rep.status.peer.role === "primary" ? "principale" : "réplique"}${rep.status.peer.acting ? " par intérim" : ""}, époque ${rep.status.peer.epoch}.` : ""}`)) : ""}
    <form id="repf" class="stack-s">
      <div class="choices">
        ${radioChoice("role", "", rep.config.role, "Instance seule", "Pas de réplication.")}
        ${radioChoice("role", "primary", rep.config.role, "Instance principale", "Publie sa configuration et ses zones.")}
        ${radioChoice("role", "replica", rep.config.role, "Réplique", "Recopie une instance principale ; sa configuration de filtrage devient en lecture seule.")}
      </div>
      <div class="fields" data-role="primary">
        <label class="field"><span>Adresses des répliques</span><textarea name="replicas" rows="2" spellcheck="false" placeholder="192.168.1.3">${arr(rep.config.replicas).join("\n")}</textarea><small class="muted">Seules ces adresses obtiennent la configuration et les transferts.</small></label>
        <label class="field"><span>Clé TSIG des transferts vers les répliques</span><input name="key" value="${(rep.config.key || "").replace(/\.$/, "")}" placeholder="repl.maison.lan"><small class="muted">Créée dans Zones DNSSEC, Clés TSIG. Elle est transmise aux répliques.</small></label>
      </div>
      <div data-role="primary replica">${sw("failover", rep.config.failover, "Bascule automatique (deux instances)", "Si l'instance principale reste injoignable, la réplique prend le relais ; à son retour, elle recopie les modifications et reprend son rôle. Chaque instance a besoin d'un jeton « synchronisation » de l'autre.")}
        <label class="field" data-failover><span>Délai avant la bascule (minutes)</span><input type="number" name="failover_minutes" min="2" max="1440" value="${rep.config.failover_minutes || 5}"></label></div>
      <div class="fields" data-role="replica" data-peer>
        <label class="field"><span>Interface de l'autre instance</span><input name="primary_url" value="${rep.config.primary_url}" placeholder="https://rempart-1.maison.lan:8080"></label>
        <label class="field"><span>DNS de l'autre instance (IP ou IP:port)</span><input name="primary_dns" value="${rep.config.primary_dns}" placeholder="192.168.1.2"></label>
        <label class="field"><span>Jeton de synchronisation</span><input name="token" type="password" autocomplete="off" placeholder="${rep.token_set ? "inchangé" : "rmp_… (portée « synchronisation »)"}"></label>
      </div>
      <details class="help" data-role="replica" data-peer><summary>AC de l'autre instance (PKI interne)</summary><textarea name="ca_bundle" rows="4" spellcheck="false">${rep.config.ca_bundle || ""}</textarea></details>
      <div><button class="primary" type="submit">Enregistrer</button></div>
    </form>
  </section>` : ""}
  </div>`;
  const sf = $("#sysf", el);
  if (sf) sf.onsubmit = (e) => {
    e.preventDefault();
    const d = new FormData(sf);
    act(e.submitter, () => api("/syslog", { method: "PUT", body: { enabled: !!d.get("enabled"), network: d.get("network"), address: d.get("address").trim(), hostname: d.get("hostname").trim(), ca_bundle: d.get("ca_bundle") } }), "Copie de l'audit enregistrée").then((r) => r && setTabs.ops(el));
  };
  const rf = $("#repf", el);
  if (rf) {
    const show = () => {
      const d = new FormData(rf), role = d.get("role") || "", fo = !!d.get("failover");
      $$("[data-role]", rf).forEach((x) => (x.hidden = !x.dataset.role.split(" ").includes(role) && !(x.hasAttribute("data-peer") && role === "primary" && fo)));
      $$("[data-failover]", rf).forEach((x) => (x.hidden = !fo));
    };
    rf.onchange = show;
    show();
    rf.onsubmit = (e) => {
      e.preventDefault();
      const d = new FormData(rf);
      const role = d.get("role") || "";
      if (role === "replica" && rep.config.role !== "replica" && !confirm("Devenir une réplique ? La configuration de filtrage de cette instance sera remplacée par celle de l'instance principale.")) return;
      act(e.submitter, () => api("/replication", { method: "PUT", body: { role, replicas: lines(d.get("replicas")), key: d.get("key").trim(), primary_url: d.get("primary_url").trim(), primary_dns: d.get("primary_dns").trim(), token: d.get("token"), ca_bundle: d.get("ca_bundle"), failover: !!d.get("failover"), failover_minutes: +d.get("failover_minutes") || 0 } }), "Réplication enregistrée").then((r) => r && setTabs.ops(el));
    };
  }
};

// ================= Zones DNSSEC =================
const keyState = { published: ["publiée", ""], ready: ["DS attendu", "warn"], active: ["active", "ok"], retired: ["retirée", ""], presign: ["signe, pas encore publiée", ""], postsign: ["retirée, signe encore", ""] };
// Où les clés KSK et ZSK d'une nouvelle zone seront générées.
function zoneKeyLocation(ks, name) {
  const z = (name || "").trim().toLowerCase().replace(/\.$/, "") || "<zone>";
  const labels = html`<code>zone-${z}-ksk</code> et <code>zone-${z}-zsk</code>`;
  if (ks.backend === "pkcs11") return notice("good", html`<p><b>Clés générées dans le HSM</b> : ${ks.keystore}.</p><p class="small">KSK et ZSK : ${labels}, créées dans le token, non exportables (<code>CKA_EXTRACTABLE=false</code>, <code>CKA_SENSITIVE=true</code>). Seule la clé publique (DNSKEY, DS) en sort.</p>`, "key");
  if (ks.hsm_pending) return notice("bad", html`<p><b>Bascule vers le HSM programmée, pas encore faite.</b> Une zone créée maintenant aura ses clés dans le keystore logiciel ; au redémarrage, elles seront importées dans le HSM et marquées « importée ». Pour des clés générées dans le HSM, créez la zone après le redémarrage.</p>`);
  return notice("plain", html`<p><b>Clés générées dans le keystore logiciel</b> (${ks.keystore}) : ${labels}, chiffrées par la KEK. Aucun HSM n'est en service : Sécurité → Clés et HSM.</p>`);
}

// ---- lecture des lignes de fichier de zone ----
// Sert seulement à l'affichage et à l'assistant : le serveur reste seul juge
// (POST /api/zones/check, puis signature à l'enregistrement).
const RRTYPES = new Set(["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "NS", "CAA", "SSHFP", "TLSA", "HTTPS", "SVCB", "DNAME", "NAPTR", "LOC", "HINFO", "URI", "DS"]);
function rrTokens(l) {
  const out = [];
  let cur = "", q = false;
  for (let i = 0; i < l.length; i++) {
    const c = l[i];
    if (q) { cur += c; if (c === "\\" && i + 1 < l.length) cur += l[++i]; else if (c === '"') q = false; continue; }
    if (c === '"') { q = true; cur += c; continue; }
    if (c === ";") break;
    if (/\s/.test(c)) { if (cur) out.push(cur), (cur = ""); continue; }
    cur += c;
  }
  if (cur) out.push(cur);
  return out;
}
const isTTL = (t) => /^(\d+[smhdw]?)+$/i.test(t);
const ttlSec = (t) => { if (!t) return 300; let s = 0; for (const [, n, u] of String(t).matchAll(/(\d+)([smhdw]?)/gi)) s += +n * ({ "": 1, s: 1, m: 60, h: 3600, d: 86400, w: 604800 })[u.toLowerCase()]; return s; };
// Nom complet d'un propriétaire, sans point final.
const ownerFull = (o, zn) => (o === "@" ? zn : o.endsWith(".") ? o.slice(0, -1).toLowerCase() : `${o}.${zn}`.toLowerCase());
// Nom relatif à la zone (« @ » pour la zone elle-même), ou nom complet si hors zone.
const relName = (full, zn) => (full === zn ? "@" : full.endsWith("." + zn) ? full.slice(0, -zn.length - 1) : full + ".");
// Une cible (alias, messagerie, service) telle qu'on la lit : relative si dans la zone.
const targetFull = (t, zn) => (t === "@" ? zn : t.endsWith(".") ? t.slice(0, -1) : `${t}.${zn}`).toLowerCase();
function parseRR(line, zn) {
  const raw = line.trim();
  if (!raw || raw.startsWith("$") || /[()]/.test(raw)) return { raw, adv: true };
  const t = rrTokens(raw);
  if (t.length < 3) return { raw, adv: true };
  let i = 1, ttl = "";
  for (let k = 0; k < 2 && i < t.length; k++) {
    if (!ttl && isTTL(t[i])) ttl = t[i++];
    else if (/^(IN|CH|HS)$/i.test(t[i])) i++;
  }
  const type = (t[i] || "").toUpperCase(), data = t.slice(i + 1);
  if (!RRTYPES.has(type) || !data.length) return { raw, adv: true };
  return { raw, adv: false, full: ownerFull(t[0], zn), ttl: ttlSec(ttl), type, data };
}
const unquote = (s) => s.replace(/^"|"$/g, "").replace(/\\(.)/g, "$1");
const typeName = { A: "Adresse IPv4", AAAA: "Adresse IPv6", CNAME: "Alias", MX: "Messagerie", TXT: "Texte", SRV: "Service", PTR: "Nom inverse", NS: "Délégation", CAA: "Autorités de certification", DS: "Délégation signée" };
const kindOf = (type) => ({ A: "host", AAAA: "host", CNAME: "alias", MX: "mail", TXT: "text", SRV: "service" })[type] || "raw";
function rrValue(r, zn) {
  const short = (t) => targetFull(t, zn);
  switch (r.type) {
    case "A": case "AAAA": return r.data[0];
    case "CNAME": return short(r.data[0]);
    case "MX": return `${short(r.data[1] || "")} (priorité ${r.data[0]})`;
    case "TXT": return r.data.map(unquote).join("");
    case "SRV": return `${short(r.data[3] || "")}, port ${r.data[2]}`;
    default: return r.data.join(" ");
  }
}

// ---- contrôles de saisie ----
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const isIPv4 = (s) => IPV4.test(s);
const isIPv6 = (s) => { if (!s.includes(":") || !/^[0-9a-f:.]+$/i.test(s)) return false; try { new URL(`http://[${s}]/`); return true; } catch { return false; } };
const privateIP = (s) => {
  if (isIPv4(s)) { const [a, b] = s.split(".").map(Number); return a === 10 || a === 127 || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b < 128); }
  return /^(f[cd]|fe[89ab])/i.test(s) || s === "::1";
};
// « Salle de bain ! » → « salle-de-bain » : ce que la plupart des débutants
// tapent devient un nom valide, et l'aperçu montre le résultat.
const slug = (s) => String(s || "").normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().trim()
  .replace(/[\s_]+/g, "-").replace(/[^a-z0-9.*-]/g, "").replace(/-+/g, "-").replace(/(^|\.)-+|-+($|\.)/g, "$1$2").replace(/\.{2,}/g, ".").replace(/^\.|\.$/g, "");
const LABEL = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
// Nom saisi → nom relatif propre (« » ou « @ » = la zone elle-même).
function cleanOwner(v, zn, { service = false } = {}) {
  let s = String(v || "").trim().toLowerCase().replace(/\.$/, "");
  if (s === "" || s === "@" || s === zn) return { rel: "@", full: zn };
  if (s.endsWith("." + zn)) s = s.slice(0, -zn.length - 1);
  if (!service) s = slug(s);
  const labels = s.split(".");
  const ok = labels.every((l, i) => LABEL.test(l) || (i === 0 && l === "*") || (service && /^_?[a-z0-9-]{1,63}$/.test(l)));
  if (!s || !ok) return { err: "Lettres, chiffres et tirets seulement (pas d'espace ni d'accent)." };
  if (s.length + zn.length > 252) return { err: "Nom trop long." };
  return { rel: s, full: `${s}.${zn}` };
}
// Cible : « nas » → nas de cette zone ; « www.exemple.fr » → nom complet.
function cleanTarget(v, zn) {
  let s = String(v || "").trim().toLowerCase().replace(/\.$/, "");
  if (!s) return { err: "Indiquez vers quel nom pointer." };
  if (s === "@" || s === zn) return { rel: "@", full: zn };
  if (isIPv4(s) || isIPv6(s)) return { err: "Il faut un nom, pas une adresse IP. Pour une adresse, créez plutôt « Un appareil »." };
  if (s.endsWith("." + zn)) s = s.slice(0, -zn.length - 1);
  if (!s.split(".").every((l) => LABEL.test(l) || /^_[a-z0-9-]+$/.test(l))) return { err: "Nom invalide : lettres, chiffres, tirets et points." };
  // Un nom avec un point est lu comme complet (www.exemple.fr) ; sans point, dans la zone.
  return s.includes(".") ? { rel: s + ".", full: s } : { rel: s, full: `${s}.${zn}` };
}
const txtQuote = (s) => { const e = String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"'); const parts = []; for (let i = 0; i < e.length || !parts.length; i += 250) parts.push(`"${e.slice(i, i + 250)}"`); return parts.join(" "); };

const TTLS = [[300, "5 minutes (conseillé)"], [3600, "1 heure"], [86400, "1 jour"]];
const SRV_PRESETS = [
  ["minecraft", "tcp", 25565, "Serveur Minecraft (Java)"],
  ["sip", "udp", 5060, "Téléphonie SIP"],
  ["sips", "tcp", 5061, "Téléphonie SIP chiffrée"],
  ["xmpp-client", "tcp", 5222, "Messagerie XMPP (clients)"],
  ["caldavs", "tcp", 443, "Agenda CalDAV"],
  ["carddavs", "tcp", 443, "Contacts CardDAV"],
  ["ldap", "tcp", 389, "Annuaire LDAP"],
  ["kerberos", "udp", 88, "Kerberos"],
  ["", "tcp", "", "Autre service"],
];

const KINDS = {
  host: { ic: "device", title: "Un appareil", sub: "Donner un nom à un NAS, une imprimante, une caméra, un serveur…", ex: "nas → 192.168.1.10" },
  alias: { ic: "link", title: "Un alias", sub: "Un deuxième nom pour un nom qui existe déjà.", ex: "photos → nas" },
  mail: { ic: "mail", title: "La messagerie", sub: "Indiquer quel serveur reçoit le courrier du domaine.", ex: "@ → mail, priorité 10" },
  text: { ic: "text", title: "Un texte", sub: "Vérification de propriété, SPF, note…", ex: "@ → « v=spf1 -all »" },
  service: { ic: "server", title: "Un service", sub: "Pour les logiciels qui trouvent leur serveur tout seuls : Minecraft, SIP, LDAP…", ex: "_minecraft._tcp → jeux:25565" },
  raw: { ic: "code", title: "Saisie libre", sub: "Une ligne au format fichier de zone, pour les autres types (CAA, PTR, SSHFP…).", ex: "@ IN CAA 0 issue \"letsencrypt.org\"" },
};

// Message gardé d'un rechargement de la page à l'autre (après un ajout).
let zoneFlash = null;

// ---- liste lisible des enregistrements d'une zone ----
function recordsTable(z, zn) {
  const recs = arr(z.records).map((l, i) => ({ ...parseRR(l, zn), i }));
  const dyn = arr(z.dynamic).map((l) => parseRR(l, zn));
  if (!recs.length && !dyn.length) return html`<div class="rr-empty"><p><b>Aucun nom pour l'instant.</b></p><p class="muted small">Ajoutez votre premier appareil : par exemple <code>nas.${zn}</code> pour votre NAS, ou <code>imprimante.${zn}</code>.</p></div>`;
  const row = (r, dynamic) => r.adv
    ? html`<tr${new Raw(dynamic ? "" : ` data-rr="${r.i}"`)}><td class="first" colspan="3"><span class="tag">ligne avancée</span> <code class="rr-raw">${r.raw}</code></td>
        <td class="act">${dynamic ? html`<span class="tag">dynamique</span>` : html`<button class="link" data-rr-edit="${r.i}">${icon("edit")}Modifier</button><button class="link danger" data-rr-del="${r.i}" aria-label="Supprimer">${icon("trash")}</button>`}</td></tr>`
    : html`<tr${new Raw(dynamic ? "" : ` data-rr="${r.i}"`)}><td class="first"><span class="rr-name">${r.full}</span></td>
        <td data-label="Type"><span class="tag ${r.type === "CNAME" ? "local" : ""}" title="${r.type}">${typeName[r.type] || r.type}</span></td>
        <td data-label="Pointe vers"><div class="rr-val"><span class="domain">${rrValue(r, zn)}</span><span class="rr-test" data-rr-out></span></div></td>
        <td class="act">${!["TXT", "SRV", "MX", "CAA", "NS", "DS"].includes(r.type) ? html`<button class="link" data-rr-test="${r.full}" data-type="${r.type === "CNAME" ? "A" : r.type}">${icon("search")}Tester</button>` : ""}
          ${dynamic ? html`<span class="tag">dynamique</span>` : html`<button class="link" data-rr-edit="${r.i}">${icon("edit")}Modifier</button><button class="link danger" data-rr-del="${r.i}" aria-label="Supprimer ${r.full}">${icon("trash")}</button>`}</td></tr>`;
  return html`<div class="table-wrap"><table class="cards rr-table">
    <thead><tr><th>Nom</th><th>Type</th><th>Pointe vers</th><th></th></tr></thead>
    <tbody>${recs.map((r) => row(r, false))}${dyn.map((r) => row(r, true))}</tbody></table></div>
    ${dyn.length ? html`<p class="muted small">Les noms marqués « dynamique » sont enregistrés par un serveur DHCP ou des postes (RFC 2136) et ne se modifient pas ici.</p>` : ""}`;
}

// ---- assistant d'ajout et de modification d'un nom ----
function kindPicker() {
  return html`<div class="kinds">${Object.entries(KINDS).map(([k, v]) => html`<button type="button" class="kind" data-kind="${k}">
    <span class="kind-ic">${icon(v.ic)}</span><span><b>${v.title}</b><span class="muted">${v.sub}</span><span class="kind-ex mono">${v.ex}</span></span></button>`)}</div>`;
}
const ttlSelect = (cur) => {
  const known = TTLS.some(([v]) => v === cur);
  return html`<label class="field"><span>Durée de mémorisation</span><select name="ttl">${TTLS.map(([v, l]) => html`<option value="${v}" ${selected(v === cur)}>${l}</option>`)}${known ? "" : html`<option value="${cur}" selected>${cur} secondes</option>`}</select>
    <small class="muted">Combien de temps les appareils gardent la réponse. Court : un changement d'adresse se voit vite.</small></label>`;
};
const nameField = (zn, val, label, help, extra = "") => html`<label class="field"><span>${label}</span>
  <div class="suffixed"><input name="owner" value="${val}" autocomplete="off" spellcheck="false" ${new Raw(extra)}><span class="mono">.${zn}</span></div>
  ${help ? html`<small class="muted">${help}</small>` : ""}<small class="ferr" data-err="owner"></small></label>`;

function kindForm(kind, zn, v, ctx) {
  const names = [...new Set(ctx.recs.filter((r) => !r.adv && r.full !== zn).map((r) => relName(r.full, zn)))];
  const dl = html`<datalist id="rr-names">${names.map((n) => html`<option value="${n}">`)}</datalist>`;
  const leases = arr(ctx.leases).filter((l) => l.ip);
  switch (kind) {
    case "host": return html`
      ${leases.length ? html`<label class="field"><span>Choisir un appareil connu du réseau</span><select name="lease"><option value="">— ou saisir le nom et l'adresse ci-dessous —</option>
        ${leases.map((l) => html`<option value="${l.ip}" data-host="${l.hostname || ""}" data-static="${l.static ? 1 : ""}">${l.hostname || "appareil sans nom"} — ${l.ip}</option>`)}</select>
        <small class="muted">Appareils qui ont reçu une adresse du DHCP de Rempart.</small></label>` : ""}
      <div class="fields">
        ${nameField(zn, v.owner, "Nom de l'appareil", "Court et parlant : nas, imprimante, camera-garage. Laissez vide pour le nom de la zone elle-même.")}
        <label class="field"><span>Adresse IP</span><input name="ip" value="${v.ip || ""}" inputmode="decimal" autocomplete="off" spellcheck="false" placeholder="192.168.1.10"><small class="ferr" data-err="ip"></small></label>
      </div>
      <details class="help"><summary>Où trouver l'adresse IP d'un appareil ?</summary><ul class="small muted">
        <li>Dans l'interface de votre box : liste des appareils connectés (souvent « Réseau » ou « DHCP »).</li>
        <li>Sur l'appareil lui-même : réglages réseau ou Wi-Fi, ou page de configuration de l'imprimante.</li>
        <li>Pensez à la rendre fixe (bail statique sur la box, ou Appareils → DHCP dans Rempart) : sinon elle peut changer et le nom pointera ailleurs.</li></ul></details>`;
    case "alias": return html`${dl}<div class="fields">
        ${nameField(zn, v.owner, "Nouveau nom", "Le nom supplémentaire, par exemple photos.")}
        <label class="field"><span>Pointe vers</span><input name="target" value="${v.target || ""}" list="rr-names" autocomplete="off" spellcheck="false" placeholder="nas"><small class="muted">Un nom de cette zone (nas) ou un nom complet (www.exemple.fr).</small><small class="ferr" data-err="target"></small></label>
      </div>`;
    case "mail": return html`${dl}<div class="fields">
        ${nameField(zn, v.owner, "Courrier adressé à", "Vide : les adresses en @" + zn + ".")}
        <label class="field"><span>Serveur de messagerie</span><input name="target" value="${v.target || ""}" list="rr-names" autocomplete="off" spellcheck="false" placeholder="mail"><small class="ferr" data-err="target"></small></label>
        <label class="field"><span>Priorité</span><input name="prio" type="number" min="0" max="65535" value="${v.prio ?? 10}"><small class="muted">Le plus petit nombre est essayé en premier.</small><small class="ferr" data-err="prio"></small></label>
      </div>`;
    case "text": return html`<div class="fields">
        ${nameField(zn, v.owner, "Nom", "Vide pour le nom de la zone ; certains services demandent un nom précis (_dmarc, par exemple).", 'data-service="1"')}
      </div>
      <label class="field"><span>Texte</span><textarea name="text" class="short" spellcheck="false" placeholder="v=spf1 -all">${v.text || ""}</textarea><small class="muted">Collez le texte tel qu'on vous l'a donné, sans guillemets.</small><small class="ferr" data-err="text"></small></label>`;
    case "service": {
      const cur = SRV_PRESETS.find(([s, p]) => s === v.svc && p === v.proto) || (v.svc ? SRV_PRESETS[SRV_PRESETS.length - 1] : SRV_PRESETS[0]);
      return html`${dl}<label class="field"><span>Service</span><select name="preset">${SRV_PRESETS.map(([s, p, port, l], i) => html`<option value="${i}" ${selected(cur[0] === s && cur[1] === p)}>${l}${s ? ` (_${s}._${p})` : ""}</option>`)}</select></label>
      <div class="fields" data-custom ${cur[0] ? new Raw("hidden") : ""}>
        <label class="field"><span>Nom du service</span><input name="svc" value="${v.svc || ""}" placeholder="monservice" spellcheck="false"><small class="ferr" data-err="svc"></small></label>
        <label class="field"><span>Protocole</span><select name="proto"><option value="tcp" ${selected(v.proto !== "udp")}>TCP</option><option value="udp" ${selected(v.proto === "udp")}>UDP</option></select></label>
      </div>
      <div class="fields">
        <label class="field"><span>Serveur qui rend le service</span><input name="target" value="${v.target || ""}" list="rr-names" autocomplete="off" spellcheck="false" placeholder="jeux"><small class="ferr" data-err="target"></small></label>
        <label class="field"><span>Port</span><input name="port" type="number" min="1" max="65535" value="${v.port ?? cur[2]}"><small class="ferr" data-err="port"></small></label>
      </div>
      <details class="help"><summary>Options avancées du service</summary><div class="fields mt">
        <label class="field"><span>Sous-domaine</span><input name="sub" value="${v.sub || ""}" placeholder="(aucun)" spellcheck="false"><small class="muted">Rarement utile : par exemple « jeux » donne _minecraft._tcp.jeux.${zn}.</small></label>
        <label class="field"><span>Priorité</span><input name="prio" type="number" min="0" max="65535" value="${v.prio ?? 0}"></label>
        <label class="field"><span>Poids</span><input name="weight" type="number" min="0" max="65535" value="${v.weight ?? 0}"></label>
      </div></details>`;
    }
    default: return html`<label class="field"><span>Ligne de fichier de zone</span><input name="raw" class="mono" value="${v.raw || ""}" autocomplete="off" spellcheck="false" placeholder='@ 3600 IN CAA 0 issue "letsencrypt.org"'>
      <small class="muted">Nom relatif à la zone (@ pour la zone elle-même), durée facultative, IN, type, valeur. SOA, NS de la zone, DNSKEY, RRSIG et NSEC sont gérés par Rempart.</small><small class="ferr" data-err="raw"></small></label>`;
  }
}

// Valeurs du formulaire à partir d'un enregistrement existant (modification).
function valuesOf(r, zn) {
  const owner = r.adv ? "" : relName(r.full, zn) === "@" ? "" : relName(r.full, zn).replace(/\.$/, "");
  if (r.adv) return { raw: r.raw };
  const t = (x) => { const f = targetFull(x, zn); return f === zn ? "@" : f.endsWith("." + zn) ? f.slice(0, -zn.length - 1) : f; };
  switch (r.type) {
    case "A": case "AAAA": return { owner, ip: r.data[0], ttl: r.ttl };
    case "CNAME": return { owner, target: t(r.data[0]), ttl: r.ttl };
    case "MX": return { owner, prio: +r.data[0], target: t(r.data[1]), ttl: r.ttl };
    case "TXT": return { owner, text: r.data.map(unquote).join(""), ttl: r.ttl };
    case "SRV": {
      const m = owner.match(/^_([^.]+)\._(tcp|udp)(?:\.(.+))?$/) || [];
      return { svc: m[1] || "", proto: m[2] || "tcp", sub: m[3] || "", prio: +r.data[0], weight: +r.data[1], port: +r.data[2], target: t(r.data[3]), ttl: r.ttl };
    }
    default: return { raw: r.raw };
  }
}

// Lit le formulaire : { line, full, type, sentence } ou { errors }, plus des
// avertissements qui n'empêchent pas d'enregistrer.
function readKind(kind, f, zn, ctx) {
  const errors = {}, warns = [], v = (n) => (f.elements[n]?.value ?? "").trim();
  const ttl = +v("ttl") || 300;
  const others = ctx.recs.filter((r) => r.i !== ctx.index);
  const at = (full) => others.filter((r) => !r.adv && r.full === full).concat(arr(ctx.dyn).filter((r) => !r.adv && r.full === full));
  let out = null;
  const owner = (opts) => { const o = cleanOwner(v("owner"), zn, opts); if (o.err) errors.owner = o.err; return o; };
  if (kind === "host") {
    const o = owner(), ip = v("ip");
    const type = isIPv4(ip) ? "A" : isIPv6(ip) ? "AAAA" : "";
    if (!ip) errors.ip = "Indiquez l'adresse IP de l'appareil.";
    else if (!type) errors.ip = "Adresse IP invalide : 4 nombres de 0 à 255 séparés par des points (192.168.1.10), ou une adresse IPv6.";
    if (!errors.owner && !errors.ip) {
      const here = at(o.full);
      if (here.some((r) => r.type === "CNAME")) errors.owner = `« ${o.full} » est déjà un alias : choisissez un autre nom, ou supprimez l'alias.`;
      else if (here.some((r) => r.type === type && r.data[0] === ip)) errors.owner = "Ce nom a déjà cette adresse.";
      else if (here.some((r) => r.type === type)) warns.push(html`<b>${o.full}</b> a déjà l'adresse ${here.find((r) => r.type === type).data[0]}. Les deux adresses seront données, à tour de rôle. Pour <b>remplacer</b> l'adresse, fermez l'assistant et utilisez « Modifier » sur la ligne existante.`);
      if (!privateIP(ip)) warns.push(html`${ip} n'est pas une adresse de réseau local. C'est possible (serveur sur Internet), mais vérifiez que ce n'est pas une faute de frappe.`);
      const lease = arr(ctx.leases).find((l) => l.ip === ip);
      if (lease && !lease.static) warns.push(html`Cette adresse a été attribuée automatiquement par le DHCP et peut changer. Réservez-la dans Appareils → DHCP (bail statique) pour que le nom pointe toujours au bon endroit.`);
      out = { line: `${o.rel} ${ttl} IN ${type} ${ip}`, full: o.full, type, sentence: html`<b>${o.full}</b> donnera l'adresse <b>${ip}</b>.` };
    }
  } else if (kind === "alias") {
    const o = owner(), t = cleanTarget(v("target"), zn);
    if (t.err) errors.target = t.err;
    if (!errors.owner && o.rel === "@") errors.owner = "Un alias ne peut pas porter le nom de la zone elle-même : choisissez un nom, par exemple www.";
    if (!errors.owner && !t.err) {
      if (t.full === o.full) errors.target = "Un alias ne peut pas pointer vers lui-même.";
      const here = at(o.full);
      if (here.length) errors.owner = `« ${o.full} » existe déjà (${here.map((r) => typeName[r.type] || r.type).join(", ")}). Un alias doit être seul sur son nom.`;
      if (t.full.endsWith(zn) && !others.some((r) => !r.adv && r.full === t.full) && !arr(ctx.dyn).some((r) => r.full === t.full)) warns.push(html`<b>${t.full}</b> n'existe pas encore dans cette zone : l'alias ne répondra qu'une fois ce nom créé.`);
      out = { line: `${o.rel} ${ttl} IN CNAME ${t.rel}`, full: o.full, type: "A", sentence: html`<b>${o.full}</b> renverra vers <b>${t.full}</b>.` };
    }
  } else if (kind === "mail") {
    const o = owner(), t = cleanTarget(v("target"), zn), prio = +v("prio");
    if (t.err) errors.target = t.err;
    if (!Number.isInteger(prio) || prio < 0 || prio > 65535) errors.prio = "Priorité de 0 à 65535.";
    if (!errors.owner && !t.err) {
      if (at(o.full).some((r) => r.type === "CNAME")) errors.owner = `« ${o.full} » est un alias : la messagerie doit être déclarée sur le nom de destination.`;
      if (at(t.full).some((r) => r.type === "CNAME")) warns.push("Le serveur de messagerie est un alias : la norme demande un nom qui a directement une adresse.");
      out = { line: `${o.rel} ${ttl} IN MX ${prio} ${t.rel}`, full: o.full, type: "MX", sentence: html`Le courrier pour <b>@${o.full}</b> sera remis à <b>${t.full}</b>.` };
    }
  } else if (kind === "text") {
    const o = owner({ service: true }), text = f.elements.text.value.trim().replace(/^"|"$/g, "");
    if (!text) errors.text = "Le texte est vide.";
    if (!errors.owner && !errors.text) {
      if (at(o.full).some((r) => r.type === "CNAME")) errors.owner = `« ${o.full} » est un alias : un texte ne peut pas s'y ajouter.`;
      out = { line: `${o.rel} ${ttl} IN TXT ${txtQuote(text)}`, full: o.full, type: "TXT", sentence: html`<b>${o.full}</b> portera le texte « ${text.length > 80 ? text.slice(0, 80) + "…" : text} ».` };
    }
  } else if (kind === "service") {
    const p = SRV_PRESETS[+v("preset")] || SRV_PRESETS[0];
    const svc = p[0] || v("svc").replace(/^_/, "").toLowerCase(), proto = p[0] ? p[1] : v("proto");
    if (!/^[a-z0-9-]{1,63}$/.test(svc)) errors.svc = "Nom du service : lettres, chiffres et tirets.";
    const t = cleanTarget(v("target"), zn), port = +v("port"), prio = +v("prio") || 0, weight = +v("weight") || 0;
    if (t.err) errors.target = t.err;
    if (!Number.isInteger(port) || port < 1 || port > 65535) errors.port = "Port de 1 à 65535.";
    const sub = v("sub") ? cleanOwner(v("sub"), zn) : { rel: "@" };
    if (sub.err) errors.svc = "Sous-domaine : " + sub.err;
    if (!Object.keys(errors).length) {
      const rel = `_${svc}._${proto}` + (sub.rel === "@" ? "" : "." + sub.rel);
      out = { line: `${rel} ${ttl} IN SRV ${prio} ${weight} ${port} ${t.rel}`, full: `${rel}.${zn}`, type: "SRV", sentence: html`Le service <b>${p[0] ? p[3] : svc}</b> sera cherché sur <b>${t.full}</b>, port <b>${port}</b>.` };
    }
  } else {
    const raw = v("raw");
    const r = parseRR(raw, zn);
    if (!raw) errors.raw = "Saisissez une ligne.";
    else if (r.adv) warns.push("Ligne non reconnue par l'assistant : le serveur la vérifiera à l'enregistrement.");
    if (!errors.raw) out = { line: raw, full: r.full || "", type: r.type || "", sentence: html`Ligne ajoutée telle quelle.` };
  }
  return Object.keys(errors).length ? { errors, warns } : { ...out, warns };
}

function openAssistant(card, z, zn, ctx, { kind, index } = {}) {
  const box = $("[data-assist]", card);
  const recs = arr(z.records).map((l, i) => ({ ...parseRR(l, zn), i }));
  const dyn = arr(z.dynamic).map((l) => parseRR(l, zn));
  const c = { ...ctx, recs, dyn, index: index ?? -1 };
  const editing = index !== undefined;
  const close = () => { box.innerHTML = ""; box.hidden = true; $("[data-rr-add]", card).hidden = false; };
  $("[data-rr-add]", card).hidden = true;
  box.hidden = false;
  if (!kind) {
    box.innerHTML = html`<div class="assist reveal"><div class="assist-head"><h3>Que voulez-vous ajouter ?</h3><button type="button" class="link" data-close>${icon("x")}Fermer</button></div>${kindPicker()}</div>`.s;
    $("[data-close]", box).onclick = close;
    $$("[data-kind]", box).forEach((b) => (b.onclick = () => openAssistant(card, z, zn, ctx, { kind: b.dataset.kind })));
    $("[data-kind]", box).focus();
    return;
  }
  const vals = editing ? valuesOf(recs[index], zn) : { ttl: 300 };
  const k = KINDS[kind];
  box.innerHTML = html`<form class="assist reveal" novalidate>
    <div class="assist-head"><h3><span class="kind-ic">${icon(k.ic)}</span>${editing ? "Modifier" : "Ajouter"} : ${k.title.toLowerCase()}</h3>
      <div class="row">${editing ? "" : html`<button type="button" class="link back" data-back>${icon("arrow")}Changer de type</button>`}<button type="button" class="link" data-close>${icon("x")}Fermer</button></div></div>
    ${kindForm(kind, zn, vals, c)}
    ${kind !== "raw" ? html`<details class="help"><summary>Options avancées</summary><div class="fields mt">${ttlSelect(vals.ttl || 300)}</div></details>` : ""}
    <div class="preview" aria-live="polite" data-preview></div>
    <div class="row end"><button type="button" class="ghost" data-close>Annuler</button><button class="primary" type="submit">${icon("check")}${editing ? "Enregistrer" : "Ajouter"}</button></div>
  </form>`.s;
  const f = $("form", box);
  $$("[data-close]", box).forEach((b) => (b.onclick = close));
  $("[data-back]", box)?.addEventListener("click", () => openAssistant(card, z, zn, ctx));
  const preview = $("[data-preview]", box);
  let touched = editing;
  const render = () => {
    const r = readKind(kind, f, zn, c);
    $$("[data-err]", f).forEach((e) => (e.textContent = touched ? r.errors?.[e.dataset.err] || "" : ""));
    preview.innerHTML = r.errors ? (touched ? notice("bad", html`<p>Il reste ${Object.keys(r.errors).length > 1 ? "des points" : "un point"} à corriger ci-dessus.</p>`).s : "")
      : html`<div class="preview-line">${icon("arrow")}<p>${r.sentence}</p></div>
        ${r.warns.map((w) => notice("", html`<p>${w}</p>`))}
        <p class="muted small">Ligne écrite dans la zone : <code>${r.line}</code></p>`.s;
    return r;
  };
  f.addEventListener("input", (e) => { if (e.target.name !== "lease") touched = touched || !!e.target.value; render(); });
  f.addEventListener("change", render);
  // Appareil connu du DHCP : nom et adresse remplis d'un coup.
  f.elements.lease?.addEventListener("change", (e) => {
    const o = e.target.selectedOptions[0];
    if (!o.value) return;
    f.elements.ip.value = o.value;
    if (!f.elements.owner.value) f.elements.owner.value = slug(o.dataset.host);
    touched = true;
    render();
  });
  f.elements.preset?.addEventListener("change", (e) => {
    const p = SRV_PRESETS[+e.target.value];
    $("[data-custom]", f).hidden = !!p[0];
    if (p[2]) f.elements.port.value = p[2];
  });
  // Le nom saisi est nettoyé à la sortie du champ (accents, espaces).
  f.elements.owner?.addEventListener("blur", (e) => { if (!e.target.dataset.service) { const s = slug(e.target.value); if (s !== e.target.value && s) { e.target.value = s; render(); } } });
  render();
  (f.elements.lease || f.elements.owner || f.elements.preset || f.elements.raw)?.focus();
  f.onsubmit = async (e) => {
    e.preventDefault();
    touched = true;
    const r = render();
    if (r.errors) { $(".ferr:not(:empty)", f)?.closest(".field")?.querySelector("input, select, textarea")?.focus(); return; }
    const lines = arr(z.records).slice();
    if (editing) lines[index] = r.line; else lines.push(r.line);
    const ok = await act(e.submitter, () => api("/zones/" + encodeURIComponent(z.name), { method: "PUT", body: { records: lines, dnssec: z.dnssec } }));
    if (!ok) return;
    // Vérification immédiate : le nom répond-il comme prévu ?
    let test = null;
    if (r.full && ["A", "AAAA", "TXT", "MX", "SRV"].includes(r.type)) test = await api(`/zones/${encodeURIComponent(z.name)}/lookup?q=${encodeURIComponent(r.full)}&type=${r.type}`).catch(() => null);
    const vals2 = arr(test?.answers).map((a) => a.split("\t").pop());
    zoneFlash = { zone: z.name, html: notice("good", html`<p><b>${editing ? "Modifié" : "C'est en place"}${z.dnssec ? " et signé" : ""}.</b> ${r.sentence}</p>
      ${vals2.length ? html`<p class="small">Test : <code>${r.full}</code> répond <code>${vals2.join(", ")}</code>.</p>` : ""}
      ${["A", "AAAA"].includes(r.type) ? html`<p class="small muted">Depuis un appareil qui utilise Rempart comme serveur DNS, essayez par exemple <code>ping ${r.full}</code> ou <code>http://${r.full}</code>.</p>` : ""}`) };
    toast(editing ? "Enregistrement modifié" : "Nom ajouté");
    ctx.reload();
  };
}

// ---- assistant de création de zone ----
const PUBLIC_TLD = new Set("com net org info biz io co fr de be ch lu ca uk eu es it nl pt pl se no dk fi at ie us me tv app dev cloud online site shop tech xyz top ai re gp mq yt nc pf bzh paris corsica alsace".split(" "));
function zoneNameVerdict(name, ctx) {
  const n = String(name || "").trim().toLowerCase().replace(/\.$/, "");
  if (!n) return { err: "Choisissez ou saisissez un nom." };
  if (!/^[a-z0-9.-]+$/.test(n) || !n.split(".").every((l) => LABEL.test(l))) return { err: "Lettres, chiffres, tirets et points seulement (pas d'espace ni d'accent)." };
  if (arr(ctx.zones).some((z) => z.name.replace(/\.$/, "") === n)) return { err: "Cette zone existe déjà." };
  const labels = n.split("."), tld = labels[labels.length - 1];
  if (labels.length === 1 && !["lan", "home", "internal", "localdomain"].includes(n)) return { err: html`« ${n} » est un domaine de premier niveau : tous les sites en .${n} deviendraient injoignables. Choisissez home.arpa, maison.lan ou un sous-domaine à vous.` };
  const d = (ctx.dhcpDomain || "").replace(/\.$/, "");
  if (d && (d === n || d.endsWith("." + n) || n.endsWith("." + d))) return { err: html`Ce nom recouvre <b>${d}</b>, le domaine des appareils du DHCP de Rempart (ces noms-là ne sont pas signés). Choisissez un autre nom, par exemple <b>${d === "home.arpa" ? "maison.lan" : "home.arpa"}</b>.` };
  const warns = [];
  if (tld === "local") warns.push(html`<b>.local</b> est réservé à Bonjour/mDNS : imprimantes AirPrint, Chromecast, partages Mac risquent de ne plus être trouvés. Préférez home.arpa.`);
  if (labels.length === 1) warns.push("Un nom sans point est mal géré par certains appareils (ils y ajoutent leur propre suffixe). Préférez maison.lan ou home.arpa.");
  if (labels.length === 2 && PUBLIC_TLD.has(tld)) warns.push(html`Si <b>${n}</b> existe sur Internet, son vrai site et sa vraie messagerie deviendront injoignables depuis votre réseau. Si c'est votre domaine, préférez un sous-domaine : <b>interne.${n}</b>.`);
  if (["lan", "home"].includes(tld) && labels.length > 1) warns.push(html`.${tld} n'est pas réservé officiellement : il fonctionne chez vous, mais home.arpa est le seul nom garanti pour cet usage (RFC 8375).`);
  return { ok: n, warns };
}

function newZoneForm(ctx, algs, firstAlg, zks) {
  const leases = arr(ctx.leases).filter((l) => l.ip && l.hostname);
  return html`<form id="addzone" class="stack" novalidate>
    <ol class="steps">
      <li class="current" data-zstep="1"><h3>Choisir le nom de votre domaine privé</h3><div class="body">
        <div class="choices">
          <label class="choice"><input type="radio" name="pick" value="home.arpa" checked><span><b>home.arpa</b> <span class="tag ok">recommandé</span><span class="muted">Réservé aux réseaux domestiques (RFC 8375) : aucun conflit possible avec Internet. Vos noms : nas.home.arpa.</span></span></label>
          <label class="choice"><input type="radio" name="pick" value="lan"><span><b>maison.lan</b><span class="muted">Court et facile à taper. Fonctionne chez vous, sans être un nom officiel.</span></span></label>
          <label class="choice"><input type="radio" name="pick" value="sub"><span><b>Un sous-domaine d'un domaine à vous</b><span class="muted">Si vous possédez par exemple mondomaine.fr : interne.mondomaine.fr.</span></span></label>
          <label class="choice"><input type="radio" name="pick" value="other"><span><b>Un autre nom</b><span class="muted">Pour reprendre un nom existant (domaine Active Directory, par exemple).</span></span></label>
        </div>
        <div class="fields" data-pick="sub" hidden>
          <label class="field"><span>Votre domaine</span><input name="own" placeholder="mondomaine.fr" autocomplete="off" spellcheck="false"></label>
          <label class="field"><span>Préfixe</span><input name="prefix" value="interne" autocomplete="off" spellcheck="false"></label>
        </div>
        <div class="fields" data-pick="other" hidden><label class="field"><span>Nom de la zone</span><input name="custom" placeholder="corp.exemple.local" autocomplete="off" spellcheck="false"></label></div>
        <div data-zverdict aria-live="polite"></div>
      </div></li>
      <li class="current" data-zstep="2"><h3>Protéger les réponses</h3><div class="body">
        ${sw("dnssec", true, "Signer la zone avec DNSSEC (conseillé)", "Chaque réponse porte une signature : un appareil qui la vérifie détecte une fausse réponse. Rempart crée et renouvelle les clés tout seul ; rien à faire de votre côté.")}
        <details class="help"><summary>Options avancées</summary><div class="stack-s mt">
          <label class="field"><span>Algorithme de signature</span><select name="algorithm">
            ${algs.map((a) => html`<option value="${a.id}" ${selected(a.id === firstAlg)} ${a.supported ? "" : new Raw("disabled")} title="${a.reason || ""}">${a.name}${a.supported ? "" : " — non pris en charge par ce HSM"}</option>`)}</select></label>
          <div id="zone-keyloc">${zks ? zoneKeyLocation(zks, "") : ""}</div>
        </div></details>
      </div></li>
      <li class="current" data-zstep="3"><h3>Vos premiers noms <span class="muted small">(facultatif)</span></h3><div class="body">
        ${leases.length ? html`<p class="muted small">Ces appareils ont reçu une adresse du DHCP de Rempart. Cochez ceux à nommer dans la zone :</p>
          <div class="lease-picks">${leases.map((l) => html`<label class="switch"><input type="checkbox" name="lease" value="${l.ip}" data-host="${slug(l.hostname)}"><span><b class="mono">${slug(l.hostname)}</b><span class="muted">${l.ip}${l.static ? "" : " · adresse automatique, à réserver dans Appareils → DHCP"}</span></span></label>`)}</div>`
        : html`<p class="muted small">Vous ajouterez vos appareils juste après, avec l'assistant : il suffit d'un nom et d'une adresse IP.</p>`}
      </div></li>
    </ol>
    <div class="row end"><button class="primary" type="submit">${icon("plus")}Créer la zone</button></div>
  </form>`;
}

function bindNewZone(main, ctx, zks) {
  const f = $("#addzone", main);
  if (!f) return;
  const verdictBox = $("[data-zverdict]", f);
  const current = () => {
    const pick = f.elements.pick.value;
    if (pick === "home.arpa") return "home.arpa";
    if (pick === "lan") return "maison.lan";
    if (pick === "sub") { const own = f.elements.own.value.trim().toLowerCase().replace(/^\.|\.$/g, ""); const pre = slug(f.elements.prefix.value) || "interne"; return own ? `${pre}.${own}` : ""; }
    return f.elements.custom.value;
  };
  const upd = () => {
    const pick = f.elements.pick.value;
    $$("[data-pick]", f).forEach((d) => (d.hidden = d.dataset.pick !== pick));
    const v = zoneNameVerdict(current(), ctx);
    $("[data-zstep='1']", f).className = v.ok ? "done" : "current";
    verdictBox.innerHTML = v.err ? (current() || pick === "home.arpa" || pick === "lan" ? notice("bad", html`<p>${v.err}</p>`).s : "")
      : html`<div class="preview-line">${icon("zone")}<p>Votre zone : <b>${v.ok}</b>. Vos appareils s'appelleront par exemple <b>nas.${v.ok}</b>.</p></div>${v.warns.map((w) => notice("", html`<p>${w}</p>`))}`.s;
    const kl = $("#zone-keyloc", f);
    if (kl && zks) kl.innerHTML = f.elements.dnssec.checked ? zoneKeyLocation(zks, v.ok || "").s : "";
    return v;
  };
  f.addEventListener("input", upd);
  f.addEventListener("change", upd);
  // Choix par défaut : le premier nom proposé qui ne pose pas de problème.
  if (upd().err) for (const r of $$("[name=pick]", f).slice(0, 2)) { r.checked = true; if (!upd().err) break; }
  f.onsubmit = (e) => {
    e.preventDefault();
    const v = upd();
    if (!v.ok) { verdictBox.scrollIntoView({ block: "center", behavior: "smooth" }); return; }
    const seen = new Set();
    const records = $$("[name=lease]:checked", f).map((c) => { let h = c.dataset.host || "appareil", n = h, i = 2; while (seen.has(n)) n = `${h}-${i++}`; seen.add(n); return `${n} 300 IN ${isIPv6(c.value) ? "AAAA" : "A"} ${c.value}`; });
    act(e.submitter, () => api("/zones", { method: "POST", body: { name: v.ok, algorithm: f.elements.algorithm.value, dnssec: f.elements.dnssec.checked, records } }), "Zone créée").then((r) => {
      if (!r) return;
      zoneFlash = { zone: v.ok + ".", html: notice("good", html`<p><b>La zone ${v.ok} est créée${f.elements.dnssec.checked ? " et signée" : ""}.</b> ${records.length ? `${records.length} nom(s) ajouté(s).` : "Ajoutez maintenant vos appareils."}</p>
        <p class="small">Dernière étape, si ce n'est pas déjà fait : vos appareils doivent utiliser Rempart comme serveur DNS (réglage DNS de la box, ou Appareils → DHCP). Sinon ils ne connaîtront pas ces noms.</p>`) };
      ctx.reload();
    });
  };
}

views.zones = async (main) => {
  const [zones, tkeys, zks, dhcp] = await Promise.all([api("/zones").then(arr), api("/tsig").catch(() => []), api("/dnssec/keystore").catch(() => null), api("/dhcp").catch(() => null)]);
  const algs = arr(zks?.algorithms).length ? arr(zks.algorithms) : [{ id: "ECDSAP256SHA256", name: "ECDSA P-256 (recommandé)", supported: true }, { id: "ECDSAP384SHA384", name: "ECDSA P-384", supported: true }, { id: "ED25519", name: "Ed25519", supported: true }];
  const firstAlg = algs.find((a) => a.supported)?.id;
  const ctx = { zones, leases: arr(dhcp?.leases), dhcpDomain: dhcp?.config?.domain ? String(dhcp.config.domain).toLowerCase().replace(/\.$/, "") : "", reload: () => views.zones(main) };
  const flash = zoneFlash;
  zoneFlash = null;
  main.innerHTML = html`<div class="page">
  ${head("Zones DNSSEC", "Vos noms internes, servis avec autorité et signés DNSSEC. Les clés restent dans le keystore ; avec un HSM, elles n'en sortent jamais.")}
  <div class="stack">
    <details class="panel intro" ${zones.length ? "" : new Raw("open")}><summary><b>Comment ça marche ?</b></summary>
      <div class="intro-grid mt">
        <div><span class="kind-ic">${icon("zone")}</span><p><b>Une zone, c'est votre domaine privé</b>, par exemple <code>home.arpa</code>. Il n'existe que chez vous.</p></div>
        <div><span class="kind-ic">${icon("device")}</span><p><b>Vous y nommez vos appareils</b> : <code>nas.home.arpa</code> au lieu de <code>192.168.1.10</code>. Plus besoin de retenir des adresses.</p></div>
        <div><span class="kind-ic">${icon("wifi")}</span><p><b>Ces noms marchent sur les appareils qui utilisent Rempart</b> comme serveur DNS. Ils ne sont pas visibles depuis Internet.</p></div>
      </div></details>
    ${zones.map((z) => { const zn = z.name.replace(/\.$/, ""); const count = arr(z.records).length + arr(z.dynamic).length; return html`<section class="panel zone" data-zone="${z.name}">
      <div class="panel-head"><h2>${zn}</h2>
        <div class="row"><span class="tag">${count} ${count > 1 ? "noms" : "nom"}</span>${z.dnssec ? html`<span class="tag ok">${icon("check")}signée</span>` : html`<span class="tag warn">non signée</span>`}
        <button class="link danger" data-delzone="${z.name}">Supprimer la zone</button></div></div>
      ${flash && flash.zone === z.name ? flash.html : ""}
      ${z.dnssec && arr(z.pending_ds).length ? notice("", html`<p><b>Rotation de KSK : publiez ce DS chez le parent</b> (bureau d'enregistrement ou administrateur de la zone parente), puis confirmez. ${z.cds ? "Si le parent lit les CDS (RFC 8078), il le fera seul et Rempart le constatera." : ""}</p>
          ${arr(z.pending_ds).map((d) => html`<div class="copy"><code>${d}</code><button type="button" data-copy="${d}" data-copied="DS copié">${icon("copy")}Copier</button></div>`)}
          <div><button class="primary" data-dsok="${z.name}">J'ai publié le DS</button></div>`) : ""}
      <div class="rr-head"><h3>Noms de la zone</h3><button class="primary" data-rr-add>${icon("plus")}Ajouter un nom</button></div>
      <div data-assist hidden></div>
      ${recordsTable(z, zn)}
      <details data-expert><summary>Mode expert : fichier de zone</summary>
        <div class="stack-s mt">
          <label class="field"><span>Enregistrements</span>
            <textarea spellcheck="false" data-records>${arr(z.records).join("\n")}</textarea>
            <span class="small">Syntaxe de fichier de zone, relative à la zone, par exemple <code>nas 300 IN A 192.168.1.10</code>. SOA, NS, DNSKEY, CDS, RRSIG et NSEC sont gérés par Rempart.</span></label>
          <div data-check-out></div>
          <div class="row end"><button type="button" data-check>${icon("check")}Vérifier sans enregistrer</button><button class="primary" data-save="${z.name}">Enregistrer et signer</button></div>
        </div>
      </details>
      <details data-dnssec-box ${arr(z.pending_ds).length ? new Raw("open") : ""}><summary>Signature DNSSEC${z.dnssec ? html` · ${z.algorithm}` : ""}</summary><div class="stack mt">
        ${sw("dnssec", z.dnssec, "Signer avec DNSSEC", z.dnssec ? "Désactiver retire les signatures : les appareils qui les vérifient ne pourront plus détecter une fausse réponse." : "Recommandé : Rempart crée et renouvelle les clés tout seul.", "data-dnssec")}
        ${z.dnssec ? html`
        <div class="table-wrap"><table class="cards keys">
          <thead><tr><th>Clé</th><th>Tag</th><th>État</th><th>Depuis</th><th>Origine</th></tr></thead>
          <tbody>${arr(z.keys).map((k) => html`<tr><td class="first">${k.role.toUpperCase()} <span class="mono muted small">${k.label}</span>${z.next_algorithm ? html` <span class="tag">${k.algorithm}</span>` : ""}</td><td data-label="Tag" class="mono">${k.tag}</td>
            <td data-label="État"><span class="tag ${keyState[k.state]?.[1] || ""}">${keyState[k.state]?.[0] || k.state}</span></td>
            <td data-label="Depuis" class="small">${day(k.changed)}</td>
            <td data-label="Origine" class="small">${k.imported ? html`<span class="tag warn">importée</span>` : z.key_store === "pkcs11" ? "HSM" : "keystore logiciel"}</td></tr>`)}</tbody>
        </table></div>
        <dl class="kv">
          ${z.key_store_desc ? html`<dt>Clés</dt><dd>${z.key_store === "pkcs11" ? html`dans le HSM, non exportables : ${z.key_store_desc}` : html`keystore logiciel, chiffrées par la KEK (${z.key_store_desc})`}</dd>` : ""}
          <dt>DS à publier</dt><dd>${arr(z.ds).map((d) => html`<div class="copy"><code>${d}</code><button type="button" data-copy="${d}" data-copied="DS copié">${icon("copy")}Copier</button></div>`)}
            <span class="muted small">Seulement si la zone est un sous-domaine d'un domaine public signé : à donner à qui gère le domaine parent. Pour home.arpa ou maison.lan, rien à faire.</span></dd>
          <dt>Signatures</dt><dd>créées le ${date(z.signed_at)}, valides jusqu'au ${date(z.expires)}, renouvelées automatiquement</dd>
        </dl>
        <div class="row">
          <button data-roll="zsk" ${z.rolling.zsk ? new Raw("disabled") : ""}>${icon("refresh")}${z.rolling.zsk ? "Rotation ZSK en cours" : "Changer la ZSK"}</button>
          <button data-roll="ksk" ${z.rolling.ksk ? new Raw("disabled") : ""}>${icon("key")}${z.rolling.ksk ? "Rotation KSK en cours" : "Changer la KSK"}</button>
          <button data-resign="${z.name}" class="ghost">Re-signer maintenant</button>
        </div>
        ${z.next_algorithm ? notice("plain", html`<p><b>Changement d'algorithme en cours</b> : ${z.algorithm} → ${z.next_algorithm}. Les nouvelles clés signent d'abord sans être publiées, puis sont publiées ; publiez ensuite le nouveau DS chez le parent (ou confirmez-le ci-dessus pour une zone interne). Les anciennes clés sont retirées seules. Comptez quelques heures, plus la durée de vie du DS chez le parent.</p>`) : html`
        <details><summary>Changer d'algorithme</summary>
          <form class="row" data-algroll>
            <label class="field"><span>Nouvel algorithme</span><select name="algorithm">
              ${algs.filter((a) => a.supported && a.id.replace(/SHA\d+$/, "") !== String(z.algorithm).replace(/SHA\d+$/, "")).map((a) => html`<option value="${a.id}">${a.name}</option>`)}</select></label>
            <div><button type="submit">${icon("key")}Démarrer</button></div>
          </form>
          <p class="muted small">Méthode prudente de la RFC 6781 : les deux algorithmes signent la zone pendant la transition, aucun résolveur validant ne voit de réponse invalide. Un nouveau DS devra être publié chez le parent.</p>
        </details>`}
        <details><summary>Rotation automatique</summary>
          <form class="stack-s" data-policy>
            ${sw("auto_rollover", z.policy.auto_rollover, "Changer les clés automatiquement", "Selon les durées ci-dessous ; 0 jour = seulement à la main.")}
            ${sw("publish_cds", z.policy.publish_cds, "Publier CDS et CDNSKEY", "Le parent peut alors mettre son DS à jour seul (RFC 7344, RFC 8078).")}
            ${sw("nsec3", z.policy.nsec3, "Masquer la liste des noms (NSEC3)", "Les réponses négatives ne permettent plus d'énumérer les noms de la zone (RFC 5155, paramètres RFC 9276).")}
            <div class="fields">
              <label class="field"><span>ZSK : tous les (jours)</span><input type="number" name="zsk_days" min="0" max="3650" value="${z.policy.zsk_days}"></label>
              <label class="field"><span>KSK : tous les (jours)</span><input type="number" name="ksk_days" min="0" max="3650" value="${z.policy.ksk_days}"></label>
            </div>
            <div><button type="submit">Enregistrer la politique</button></div>
          </form>
        </details>` : ""}
      </div></details>
      ${transferForm(z, tkeys)}
    </section>`; })}
    <section class="panel" id="newzone">
      <div class="panel-head"><h2>${zones.length ? "Nouvelle zone" : "Créer votre première zone"}</h2>
        ${zones.length ? html`<button data-newzone>${icon("plus")}Nouvelle zone</button>` : ""}
        <p>${zones.length ? "Une autre zone : un second domaine privé, ou un sous-domaine d'un domaine à vous." : "Trois étapes : un nom, la protection DNSSEC, et si vous le souhaitez vos premiers appareils."}</p></div>
      <div data-newzone-body ${zones.length ? new Raw("hidden") : ""}>${newZoneForm(ctx, algs, firstAlg, zks)}</div>
    </section>
    <div id="zones-extra" class="stack"></div>
  </div></div>`;
  await zonesExtra(main, zones);
  const reload = ctx.reload;
  const zurl = (el) => "/zones/" + encodeURIComponent(el.closest("[data-zone]").dataset.zone);
  const zoneOf = (el) => zones.find((z) => z.name === el.closest("[data-zone]").dataset.zone);
  bindCopy(main);
  bindNewZone(main, ctx, zks);
  $("[data-newzone]", main)?.addEventListener("click", (e) => { const b = $("[data-newzone-body]", main); b.hidden = !b.hidden; e.currentTarget.hidden = !b.hidden; if (!b.hidden) $("[name=pick]", b)?.focus(); });
  $$("[data-zone]", main).forEach((card) => {
    const z = zoneOf(card), zn = z.name.replace(/\.$/, "");
    $("[data-rr-add]", card).onclick = () => openAssistant(card, z, zn, ctx);
    $$("[data-rr-edit]", card).forEach((b) => (b.onclick = () => {
      const i = +b.dataset.rrEdit, r = parseRR(z.records[i], zn);
      openAssistant(card, z, zn, ctx, { kind: r.adv ? "raw" : kindOf(r.type), index: i });
      card.querySelector("[data-assist]").scrollIntoView({ block: "nearest", behavior: "smooth" });
    }));
    $$("[data-rr-del]", card).forEach((b) => (b.onclick = () => {
      const i = +b.dataset.rrDel, r = parseRR(z.records[i], zn);
      const what = r.adv ? r.raw : `${r.full} (${typeName[r.type] || r.type} : ${rrValue(r, zn)})`;
      if (!confirm(`Supprimer ${what} ?`)) return;
      const lines = z.records.filter((_, k) => k !== i);
      act(b, () => api(zurl(b), { method: "PUT", body: { records: lines, dnssec: z.dnssec } }), "Nom supprimé").then((x) => x && reload());
    }));
    $$("[data-rr-test]", card).forEach((b) => (b.onclick = async () => {
      const out = $("[data-rr-out]", b.closest("tr"));
      const r = await act(b, () => api(`${zurl(b)}/lookup?q=${encodeURIComponent(b.dataset.rrTest)}&type=${b.dataset.type}`));
      if (!r) return;
      const vals = arr(r.answers).map((a) => a.split("\t").pop());
      out.innerHTML = (vals.length ? html`<span class="tag ok">${icon("check")}répond ${vals[vals.length - 1]}</span>` : html`<span class="tag bad">ne répond pas (${r.rcode})</span>`).s;
    }));
    $("[data-dnssec]", card).onchange = (e) => {
      const on = e.target.checked;
      if (!on && !confirm(`Ne plus signer ${zn} ? Les signatures seront retirées ; les clés restent dans le keystore.`)) { e.target.checked = true; return; }
      act(e.target, () => api(zurl(card), { method: "PUT", body: { records: z.records, dnssec: on } }), on ? "Zone signée" : "Signature retirée").then((r) => (r ? reload() : (e.target.checked = !on)));
    };
    const ta = $("[data-records]", card), out = $("[data-check-out]", card);
    $("[data-check]", card).onclick = async (e) => {
      const r = await act(e.currentTarget, () => api("/zones/check", { method: "POST", body: { zone: z.name, records: ta.value.split("\n") } }));
      if (!r) return;
      const bad = arr(r.lines).filter((l) => l.error);
      out.innerHTML = (r.ok ? notice("good", html`<p><b>Tout est correct</b> : ${arr(r.lines).length} ligne(s), rien n'a encore été enregistré.</p>`)
        : notice("bad", html`<p><b>${r.error}</b></p>${bad.length ? html`<ul class="check-list">${bad.map((l) => html`<li><b>Ligne ${l.line}</b> <code>${l.text}</code><br><span>${l.error}</span></li>`)}</ul>` : ""}`)).s;
    };
    $("[data-save]", card).onclick = (e) => act(e.currentTarget, () => api(zurl(card), { method: "PUT", body: { records: ta.value.split("\n"), dnssec: z.dnssec } }), "Zone enregistrée et signée").then((r) => r && reload());
  });
  $$("[data-roll]", main).forEach((b) => (b.onclick = () => {
    const role = b.dataset.roll;
    const msg = role === "ksk" ? "Démarrer une rotation de KSK ? Il faudra publier un nouveau DS chez le parent." : "Démarrer une rotation de ZSK ? Elle se termine seule en quelques heures.";
    confirm(msg) && act(b, () => api(zurl(b) + "/rollover", { method: "POST", body: { role } }), "Rotation démarrée").then((r) => r && reload());
  }));
  $$("[data-algroll]", main).forEach((f) => (f.onsubmit = (e) => {
    e.preventDefault();
    const alg = new FormData(f).get("algorithm");
    confirm(`Passer la zone en ${alg} ? Il faudra publier un nouveau DS chez le parent.`) && act(e.submitter, () => api(zurl(f) + "/algorithm", { method: "POST", body: { algorithm: alg } }), "Changement d'algorithme démarré").then((r) => r && reload());
  }));
  $$("[data-dsok]", main).forEach((b) => (b.onclick = () => act(b, () => api(zurl(b) + "/ds-confirm", { method: "POST" }), "DS confirmé : la nouvelle KSK est active").then((r) => r && reload())));
  $$("[data-resign]", main).forEach((b) => (b.onclick = () => act(b, () => api(zurl(b) + "/resign", { method: "POST" }), "Zone re-signée").then(reload)));
  $$("[data-delzone]", main).forEach((b) => (b.onclick = () => confirm(`Supprimer la zone ${b.dataset.delzone} et tous ses noms ? Les clés restent dans le keystore.`) && act(b, () => api("/zones/" + encodeURIComponent(b.dataset.delzone), { method: "DELETE" }), "Zone supprimée").then(reload)));
  $$("[data-policy]", main).forEach((f) => (f.onsubmit = (e) => {
    e.preventDefault();
    const d = new FormData(f);
    act(e.submitter, () => api(zurl(f) + "/policy", { method: "PUT", body: { auto_rollover: !!d.get("auto_rollover"), publish_cds: !!d.get("publish_cds"), nsec3: !!d.get("nsec3"), zsk_days: +d.get("zsk_days"), ksk_days: +d.get("ksk_days") } }), "Politique enregistrée").then((r) => r && reload());
  }));
};

// ================= Sécurité =================
views.security = async (main, tab) => {
  // Les clés, le quorum, les jetons et les comptes sont réservés au rôle administrateur.
  const admin = me.role === "admin";
  const hsm = admin ? await api("/hsm") : {};
  const pending = hsm.override?.pending_migration;
  const t = tabs("security", admin
    ? [["keys", "Clés et HSM", pending], ...(hsm.backend === "software" ? [["quorum", "Quorum et rotation"]] : []), ["tls", "Certificat"], ["tokens", "Accès API"], ["identity", "Comptes et annuaires"], ["audit", "Journal d'audit"]]
    : [["tls", "Certificat"], ["audit", "Journal d'audit"]], tab);
  main.innerHTML = html`<div class="page">
  ${head("Sécurité", "Où sont vos clés, ce qui les protège, le certificat présenté aux clients et la preuve que personne n'a modifié l'historique.")}
  ${t.nav}<div id="tab"></div></div>`;
  await secTabs[t.cur]($("#tab"), hsm);
};
const secTabs = {};
function usage(label) {
  if (label === "rempart-audit") return "signature de l'audit";
  if (label === "rempart-tls") return "TLS (interface, DoT, DoH)";
  if (label === "rempart-acme-account") return "compte ACME";
  const m = label.match(/^zone-(.+)-(ksk|zsk)(-\d+)?$/);
  if (m) return `${m[2].toUpperCase()} de ${m[1]}`;
  return "—";
}
secTabs.keys = async (el, s) => {
  const ov = s.override;
  const sec = await api("/security");
  const keysTable = html`<div class="table-wrap"><table class="cards">
    <thead><tr><th>Clé</th><th>Usage</th><th>Algorithme</th><th>Origine</th><th>Empreinte</th></tr></thead>
    <tbody>${arr(s.keys).map((k) => html`<tr><td class="first mono">${k.label}</td><td data-label="Usage">${usage(k.label)}</td><td data-label="Algorithme">${k.algorithm}</td>
      <td data-label="Origine">${k.origin === "générée" ? html`<span class="tag ok">générée dans le HSM</span>` : k.origin === "importée" ? html`<span class="tag warn">importée</span>` : html`<span class="tag">logiciel</span>`}</td>
      <td class="mono small" data-label="Empreinte">${k.fingerprint}</td></tr>`)}</tbody></table></div>`;
  let wizard = "";
  if (s.backend === "software" && !ov) wizard = hsmWizard(s);
  const cloneSwitch = s.backend === "pkcs11" && ov && !ov.pending_migration && !isSet(ov.migrated_at) && ov.token_label !== s.active_token;
  if (s.backend === "pkcs11" && !cloneSwitch) wizard = cloneWizard(s);
  el.innerHTML = html`<div class="stack">
    <section class="panel stack">
      <div class="panel-head"><h2>Keystore</h2>${s.backend === "pkcs11" ? html`<span class="tag ok">${icon("chip")}HSM PKCS#11</span>` : html`<span class="tag">logiciel</span>`}</div>
      ${s.backend === "pkcs11" ? notice("good", html`<p>Clés générées et utilisées dans le HSM : <b>${s.keystore}</b>. Elles ne sont pas extractibles.</p>`)
        : notice("plain", html`<p>Keystore logiciel : les clés sont chiffrées sur disque par une KEK, elle-même protégée par la clé racine (phrase de passe serveur et/ou quorum de dépositaires, voir <a href="#/security/quorum">Quorum et rotation</a>). ${s.pkcs11_available ? "Vous pouvez les placer dans un HSM ci-dessous." : "Ce binaire a été compilé sans support HSM."}</p>`)}
      ${ov?.pending_migration ? notice("", html`<p><b>Bascule vers le HSM programmée</b> : token « ${ov.token_label} » (${ov.module}), demandée par ${ov.requested_by} le ${date(ov.requested_at)}.</p>
        ${pinSnippet(s.pin_configured)}
        <p>Au prochain démarrage, Rempart importe les clés dans le HSM, rechiffre ses données, puis met de côté l'ancien keystore. En cas d'échec, il continue avec le keystore logiciel et l'erreur s'affiche ici.</p>
        <div><button class="danger" id="cancel-hsm">Annuler la bascule</button></div>`) : ""}
      ${cloneSwitch ? notice("", html`<p><b>Passage au token « ${ov.token_label} » programmé</b> (${ov.module}), demandé par ${ov.requested_by} le ${date(ov.requested_at)}. Ses clés ont été vérifiées identiques à celles du token en service.</p>
        <p>Redémarrez Rempart avec le PIN de ce token (<code>REMPART_PKCS11_PIN_FILE</code>). Aucune donnée n'est rechiffrée.</p>
        <div><button class="danger" id="cancel-hsm">Annuler</button></div>`) : ""}
      ${s.failed ? notice("bad", html`<p><b>La dernière bascule a échoué</b> : ${s.failed.last_error}</p><p>Le keystore logiciel est resté en service. Corrigez la cause, puis recommencez l'assistant.</p>`) : ""}
      ${ov && !ov.pending_migration && ov.migrated_at ? notice("good", html`<p>Migration effectuée le ${date(ov.migrated_at)} : ${arr(ov.migrated_keys).length} clés importées. Les clés importées ont existé hors du HSM : changez-les quand c'est possible (rotation DNSSEC, nouveau certificat).</p>`) : ""}
      ${arr(s.retired).length && s.backend === "pkcs11" ? html`<div class="stack-s"><h3>Anciennes copies chiffrées</h3>
        <p class="muted small">L'ancien keystore logiciel et les sauvegardes de migration ne servent plus. Détruisez-les une fois le HSM vérifié.</p>
        ${arr(s.retired).map((d) => html`<div class="row"><code class="grow">${d}</code><button class="danger" data-destroy="${d}">Détruire</button></div>`)}</div>` : ""}
      ${keysTable}
      <p class="muted small">Une clé AES-256 du keystore chiffre aussi l'état de Rempart, la clé de chaque journal quotidien et la tête du journal d'audit.</p>
    </section>
    ${wizard}
    <div class="grid">
      <section class="panel stack-s">
        <h2>Durcissement du processus</h2>
        ${arr(sec.hardening).length ? html`<ul>${arr(sec.hardening).map((h) => html`<li>${h}</li>`)}</ul>` : html`<p class="muted">Non applicable sur ce système.</p>`}
        <p class="muted small">Journaux chiffrés présents : ${arr(sec.querylog_days).length ? arr(sec.querylog_days).join(", ") : "aucun"}.</p>
      </section>
    </div></div>`;
  const reload = () => views.security($("#main"), "keys");
  $("#cancel-hsm")?.addEventListener("click", (e) => act(e.currentTarget, () => api("/hsm/pending", { method: "DELETE" }), "Bascule annulée").then(reload));
  $("#c-verify", el)?.addEventListener("click", async (e) => {
    const module = $("#c-mod", el).value, token = $("#c-token", el).value.trim(), pin = $("#c-pin", el).value;
    if (!token || !pin) return toast("Indiquez le token et son PIN", true);
    const rep = await act(e.currentTarget, () => api("/hsm/clone/verify", { method: "POST", body: { module, token, pin } }));
    $("#c-pin", el).value = "";
    if (!rep) return;
    const out = $("#c-out", el);
    out.innerHTML = html`${notice(rep.ok ? "good" : "bad", html`<p><b>${rep.ok ? "Le token cible est une copie conforme." : "Le token cible ne convient pas."}</b></p>
      <ul class="check-list">${arr(rep.keys).map((k) => html`<li>${k.ok ? "✓" : "✗"} <code>${k.label}</code>${k.error ? html` : ${k.error}` : ""}</li>`)}
        <li>${rep.kek.ok ? "✓" : "✗"} KEK <code>${rep.kek.label}</code>${rep.kek.error ? html` : ${rep.kek.error}` : " : ouvre les données actuelles"}</li></ul>`)}
      ${rep.ok ? html`<div class="row"><button class="primary" id="c-apply">Programmer la bascule</button></div>` : ""}`.s;
    $("#c-apply", out)?.addEventListener("click", (ev) => act(ev.currentTarget, () => api("/hsm/clone/apply", { method: "POST", body: { module, token } }), "Bascule programmée : redémarrez avec le PIN du nouveau token").then((r) => r && reload()));
  });
  $$("[data-destroy]", el).forEach((b) => (b.onclick = () => confirm(`Détruire définitivement ${b.dataset.destroy} ? Cette action est irréversible.`) && act(b, () => api("/hsm/destroy-retired", { method: "POST", body: { path: b.dataset.destroy } }), "Copie détruite").then(reload)));
  bindCopy(el);
  if (wizard) bindWizard(el, s);
};
function pinSnippet(configured) {
  const snippet = `services:\n  rempart:\n    environment:\n      REMPART_PKCS11_PIN_FILE: /run/secrets/hsm_pin\n    secrets: [hsm_pin]\nsecrets:\n  hsm_pin: { file: ./secrets/hsm_pin.txt }   # fichier en 0600, hors dépôt git`;
  return configured ? html`<p>Le PIN du HSM est déjà fourni à Rempart par son environnement.</p>`
    : html`<p>Fournissez le PIN par un secret avant de redémarrer : il ne passe jamais par l'interface ni par la ligne de commande.</p>
      <div class="copy"><pre class="code">${snippet}</pre><button type="button" data-copy="${snippet}">${icon("copy")}Copier</button></div>`;
}
function hsmWizard(s) {
  if (!s.pkcs11_available) return "";
  const mods = arr(s.modules);
  return html`<section class="panel stack" id="wizard">
    <div class="panel-head"><h2>Placer les clés dans un HSM</h2><p>Thales Luna, Entrust nShield, YubiHSM 2, Nitrokey HSM ou SoftHSM pour essayer. Rempart teste le token, puis migre au prochain démarrage.</p></div>
    <ol class="steps">
      <li class="current" data-step="1"><h3>Bibliothèque PKCS#11</h3><div class="body">
        ${mods.length ? html`<div class="row"><select class="grow" id="w-module" aria-label="Module PKCS#11">${mods.map((m) => html`<option>${m}</option>`)}</select><button id="w-probe">Lister les tokens</button></div>`
          : notice("plain", html`<p>Aucune bibliothèque trouvée. Montez celle du constructeur dans le conteneur, dans l'un de ces dossiers (modifiable par <code>keystore.pkcs11.module_dirs</code>) :</p><p class="mono small">${arr(s.module_dirs).join("  ")}</p>`)}
        <p class="muted small">Seules les bibliothèques de ces dossiers peuvent être chargées : charger un module PKCS#11 exécute son code dans Rempart.</p>
      </div></li>
      <li class="locked" data-step="2"><h3>Token</h3><div class="body" id="w-tokens"></div></li>
      <li class="locked" data-step="3"><h3>Connexion et auto-test</h3><div class="body">
        <form id="w-test" class="stack-s" autocomplete="off">
          <label class="field"><span>PIN utilisateur (CKU_USER)</span><input type="password" name="pin" autocomplete="off" required></label>
          <p class="muted small">Le PIN sert au test puis est effacé de la mémoire ; il n'est ni enregistré ni journalisé. Attention : plusieurs PIN erronés verrouillent la plupart des HSM.</p>
          <label class="switch" id="w-final" hidden><input type="checkbox" name="final"><span><b>Tenter malgré le dernier essai</b><span class="muted">Le token signale qu'un PIN faux le verrouillera.</span></span></label>
          <div><button class="primary" type="submit">Tester la connexion</button></div>
        </form>
        <div id="w-report"></div>
      </div></li>
      <li class="locked" data-step="4"><h3>Programmer la bascule</h3><div class="body">
        <label class="field"><span>Label de la KEK AES-256</span><input id="w-kek" value="rempart-kek"></label>
        <p class="muted small">Au redémarrage : import des clés comme objets non extractibles (CKA_SENSITIVE, CKA_EXTRACTABLE faux), vérification de chaque signature, rechiffrement de l'état, de l'audit et des journaux par la KEK du HSM, sauvegarde des originaux.</p>
        <div><button class="primary" id="w-apply">Programmer la bascule</button></div>
      </div></li>
    </ol>
  </section>`;
}
function bindWizard(el, s) {
  const step = (k, st) => { const li = $(`[data-step="${k}"]`, el); li.className = st; };
  let module = "", token = "";
  $("#w-probe")?.addEventListener("click", async (e) => {
    module = $("#w-module").value;
    const r = await act(e.currentTarget, () => api("/hsm/probe", { method: "POST", body: { module } }));
    if (!r) return;
    step(1, "done"); step(2, "current"); step(3, "locked"); step(4, "locked");
    const toks = arr(r.tokens);
    $("#w-tokens").innerHTML = html`<p class="muted small">${r.module.manufacturer} ${r.module.description}, version ${r.module.version}, Cryptoki ${r.module.cryptoki}</p>
      ${toks.length ? html`<div class="choices">${toks.map((t) => html`<label class="choice"><input type="radio" name="w-token" value="${t.label}" data-final="${t.pin_final_try ? 1 : ""}" ${t.pin_locked || !t.initialized ? new Raw("disabled") : ""}>
        <span><b>${t.label || "(sans label)"}</b><span class="muted">${t.manufacturer} ${t.model}, série ${t.serial}, slot ${t.slot}</span>
        ${t.pin_locked ? html`<span class="tag bad">PIN verrouillé</span>` : t.pin_final_try ? html`<span class="tag bad">dernier essai</span>` : t.pin_count_low ? html`<span class="tag warn">PIN déjà erroné</span>` : ""}
        ${!t.initialized ? html`<span class="tag warn">non initialisé</span>` : ""}</span></label>`)}</div>`
        : notice("plain", "Aucun token présent. Initialisez-en un avec l'outil du constructeur (lunacm, ppmk, softhsm2-util…).")}`;
    $$("[name=w-token]", el).forEach((r) => (r.onchange = () => {
      token = r.value;
      $("#w-final").hidden = !r.dataset.final;
      step(2, "done"); step(3, "current"); step(4, "locked");
    }));
  });
  $("#w-test")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const body = { module, token, pin: f.pin.value, allow_final_try: f.final.checked };
    f.pin.value = "";
    const r = await act(e.submitter, () => api("/hsm/test", { method: "POST", body }));
    if (!r) return;
    const rep = r.report || {};
    $("#w-report").innerHTML = html`${notice(r.ok ? "good" : "bad", r.ok ? html`<p><b>Token prêt.</b> Connexion réussie, chiffrement AES-GCM et signature ECDSA vérifiés avec des objets temporaires.</p>` : html`<p>${r.error}</p>`)}
      ${arr(rep.mechanisms).length ? html`<div class="mech mt">${arr(rep.mechanisms).map((m) => html`<span class="tag ${m.present ? "ok" : m.required ? "bad" : ""}">${m.name}${m.required ? "" : " (facultatif)"}</span>`)}</div>` : ""}`;
    if (r.ok) { step(3, "done"); step(4, "current"); }
  });
  $("#w-apply")?.addEventListener("click", (e) => {
    if (!confirm("Programmer la migration vers ce HSM au prochain démarrage de Rempart ?")) return;
    act(e.currentTarget, () => api("/hsm/apply", { method: "POST", body: { module, token, kek_label: $("#w-kek").value } }), "Bascule programmée : fournissez le PIN puis redémarrez Rempart").then((r) => r && views.security($("#main"), "keys"));
  });
}

// ---- quorum M-sur-N et rotation des KEK (keystore logiciel) ----
const opLabel = (op) => ({ reconfigure: "Modifier le quorum (nouvelle clé racine)", destroy: `Détruire la KEK de génération ${op.gen}`, policy: op.days ? `Rotation tous les ${op.days} jours` : "Désactiver la rotation planifiée" })[op.kind] || op.kind;
const pwField = (label = "Votre mot de passe administrateur") => html`<label class="field"><span>${label}</span><input name="password" type="password" autocomplete="current-password" required></label>`;

let quorumSeq = 0;
secTabs.quorum = async (el) => {
  clearInterval(refreshTimer);
  const seq = ++quorumSeq;
  const q = await api("/quorum");
  if (seq !== quorumSeq || !el.isConnected) return; // un rendu plus récent a pris la main
  if (q.backend !== "software") { el.innerHTML = notice("plain", "Keystore HSM : le contrôle M sur N et la rotation se règlent sur le HSM lui-même (PED, quorum du constructeur).").s; return; }
  const s = q.status, op = q.op, use = q.usage || {};
  const on = s.quorum_enabled, gens = arr(s.generations);
  const reload = () => secTabs.quorum(el);
  const genState = (g) => g.current ? html`<span class="tag ok">en service</span>` : g.retired ? html`<span class="tag">retirée le ${day(g.retired)}</span>` : html`<span class="tag warn">encore utilisée</span>`;
  el.innerHTML = html`<div class="stack">
    ${op ? approvalPanel(op, s) : ""}
    <section class="panel stack">
      <div class="panel-head"><h2>Protection de la clé racine</h2>${on ? html`<span class="tag ok">quorum ${s.threshold} sur ${s.custodians.length}</span>` : html`<span class="tag warn">sans quorum</span>`}
        <p>La clé racine protège toutes les KEK. ${on ? "Aucune opération sensible (changement de dépositaires, de mode ou de politique, destruction d'une KEK) ne se fait sans l'approbation de M dépositaires, vérifiée par la reconstitution de la clé racine." : "Configurez un quorum : M dépositaires sur N devront approuver chaque opération sensible, ou déverrouiller Rempart à chaque démarrage."}</p></div>
      <dl class="kv">
        <dt>Démarrage</dt><dd>${s.mode === "quorum" ? html`<b>verrouillé</b> jusqu'à la présentation de ${s.threshold} dépositaires (<code>podman exec -it rempart rempart unseal</code>)` : s.server_passphrase === "none" ? html`<span class="tag bad">automatique, clé racine en clair sur disque</span>` : "automatique, par la phrase de passe serveur (secret du conteneur)"}</dd>
        ${on ? html`<dt>Dépositaires</dt><dd>${s.custodians.map((c) => html`<span class="tag ${s.terminal_only ? (c.terminal_set ? "ok" : "warn") : ""}" title="${c.terminal_set ? "phrase fixée au terminal" : "phrase saisie dans l'interface"}">${c.name}</span> `)}<span class="muted small">depuis le ${day(s.since)}</span></dd>
        <dt>Approbations</dt><dd>${s.terminal_only ? html`au terminal du serveur seulement (<code>rempart approve</code>)` : "interface ou terminal"}</dd>` : ""}
        <dt>Clé racine</dt><dd><code>${s.root_id}</code> <span class="muted small">créée le ${day(s.root_created)}</span></dd>
        <dt>Dérivation des phrases</dt><dd>Argon2id, ${s.argon2id}</dd>
      </dl>
      ${on && s.terminal_only && s.custodians.some((c) => !c.terminal_set) ? notice("", html`<p><b>${s.custodians.filter((c) => !c.terminal_set).map((c) => c.name).join(", ")}</b> : phrase saisie dans cette interface, donc potentiellement connue de l'administrateur. Tant que chacun ne l'a pas changée lui-même, ses approbations sont refusées :</p><div class="copy"><code>podman exec -it rempart rempart passwd</code><button type="button" data-copy="podman exec -it rempart rempart passwd">${icon("copy")}Copier</button></div>`) : ""}
      ${s.server_passphrase === "none" ? notice("bad", "Aucune phrase de passe serveur : quiconque copie le dossier du keystore obtient les clés. Fournissez REMPART_KEYSTORE_PASSPHRASE_FILE, ou passez en mode quorum au démarrage.") : ""}
      <div id="ceremony"></div>
      ${op ? "" : html`<div class="row"><button class="primary" id="q-edit">${icon("key")}${on ? "Modifier le quorum" : "Configurer le quorum"}</button></div>`}
    </section>
    <section class="panel stack">
      <div class="panel-head"><h2>Rotation des clés de chiffrement (KEK)</h2>
        <p>La KEK en service chiffre toute nouvelle donnée. Après une rotation, Rempart rechiffre l'état, les clés du journal et les clés de signature, puis retire l'ancienne génération ; sa destruction efface cryptographiquement les sauvegardes qu'elle chiffrait.</p></div>
      <div class="table-wrap"><table class="cards"><thead><tr><th>Génération</th><th>Créée</th><th>État</th><th>Fichiers</th><th></th></tr></thead>
        <tbody>${gens.map((g) => html`<tr><td class="first">${g.gen}${g.legacy ? html` <span class="tag warn">héritée v1</span>` : ""}</td><td data-label="Créée">${day(g.created)}</td><td data-label="État">${genState(g)}</td>
          <td data-label="Fichiers">${use[g.gen] || 0}</td><td class="act">${!g.current && g.retired ? html`<button class="link danger" data-destroy-gen="${g.gen}">Détruire…</button>` : ""}</td></tr>`)}</tbody></table></div>
      ${gens.some((g) => g.legacy && g.current) ? notice("", "La KEK en service vient de l'ancien format (dérivée directement de la phrase de passe) : faites une rotation.") : ""}
      <p>${s.rotate_days ? html`Rotation planifiée tous les <b>${s.rotate_days} jours</b>${s.next_rotation ? html`, prochaine le <b>${day(s.next_rotation)}</b>` : ""}.` : html`<b>Pas de rotation planifiée.</b>`}</p>
      <div class="row"><button id="k-rotate">${icon("refresh")}Rotation maintenant</button>${Object.keys(use).some((g) => +g !== s.current) ? html`<button id="k-rewrap">Réchiffrer les données</button>` : ""}
        <span class="grow"></span><label class="row small">Période (jours)<input id="k-days" type="number" min="0" max="3650" value="${s.rotate_days}" class="days"></label><button id="k-policy">Modifier</button></div>
      <div id="k-act"></div>
    </section></div>`;

  // Action protégée : directe sans quorum (mot de passe), sinon demande d'approbation.
  const guarded = async (btn, kind, extra, run) => {
    if (on) { await act(btn, () => api("/quorum/ops", { method: "POST", body: { kind, ...extra } }), "Demande ouverte : faites approuver par les dépositaires"); return reload(); }
    const box = $("#k-act", el);
    box.innerHTML = html`<form class="fields reveal" id="k-confirm">${pwField()}<div class="row"><button class="primary" type="submit">Confirmer</button><button type="button" class="ghost" data-cancel>Annuler</button></div></form>`.s;
    $("[data-cancel]", box).onclick = () => (box.innerHTML = "");
    $("#k-confirm", box).onsubmit = async (e) => { e.preventDefault(); if (await act(e.submitter, () => run(e.target.password.value), "Fait")) reload(); };
  };
  $("#q-edit")?.addEventListener("click", (e) => {
    e.currentTarget.hidden = true;
    if (on) return showPlan($("#ceremony", el), s, reload);
    showCeremony($("#ceremony", el), s, reload);
  });
  const rot = (rotate) => async (e) => {
    const box = $("#k-act", el);
    box.innerHTML = html`<form class="fields reveal" id="k-run">${pwField()}<div class="row"><button class="primary" type="submit">${rotate ? "Créer une nouvelle KEK" : "Réchiffrer"}</button><button type="button" class="ghost" data-cancel>Annuler</button></div></form>`.s;
    $("[data-cancel]", box).onclick = () => (box.innerHTML = "");
    $("#k-run", box).onsubmit = async (ev) => {
      ev.preventDefault();
      const r = await act(ev.submitter, () => api("/kek/rotate", { method: "POST", body: { password: ev.target.password.value, rotate } }));
      if (!r) return;
      const pend = Object.entries(r.pending || {});
      toast(`Génération ${r.gen} : ${r.keys} clé(s) de signature et ${r.querylog} clé(s) du journal rechiffrées${arr(r.retired).length ? `, génération ${r.retired.join(", ")} retirée` : ""}`);
      await reload();
      if (pend.length) $("#k-act", el).innerHTML = notice("", html`<p>Encore chiffrés par une ancienne génération :</p><ul>${pend.map(([g, f]) => html`<li>génération ${g} : ${f.join(", ")}</li>`)}</ul>`).s;
    };
  };
  $("#k-rotate").onclick = rot(true);
  $("#k-rewrap")?.addEventListener("click", rot(false));
  $("#k-policy").onclick = (e) => { const days = +$("#k-days", el).value; guarded(e.currentTarget, "policy", { days }, (password) => api("/kek/policy", { method: "POST", body: { password, days } })); };
  $$("[data-destroy-gen]", el).forEach((b) => (b.onclick = () => {
    const gen = +b.dataset.destroyGen;
    if (!confirm(`Détruire la KEK de génération ${gen} ? Les sauvegardes qu'elle chiffre deviendront illisibles. C'est irréversible.`)) return;
    guarded(b, "destroy", { gen }, (password) => api("/kek/destroy", { method: "POST", body: { password, gen } }));
  }));
  bindCopy(el);
  if (op) bindApproval(el, op, s, reload);
};

function approvalPanel(op, s) {
  const got = arr(op.approved_by), need = s.threshold, done = got.length >= need;
  const left = s.custodians.filter((c) => !got.includes(c.name));
  return html`<section class="panel stack approval reveal">
    <div class="panel-head"><h2>${icon("key")}${opLabel(op)}</h2><span class="tag ${done ? "ok" : "warn"}">${got.length} / ${need} approbations</span>
      <p>Demandée par ${op.by}, valable jusqu'à ${time(op.expires)}. Chaque dépositaire saisit lui-même sa phrase de passe ; elle est vérifiée puis oubliée, seule sa part reste en mémoire jusqu'à l'exécution.</p></div>
    ${op.plan ? planSummary(op.plan, s) : ""}
    <div class="meter"><i class="${done ? "full" : ""}" data-w="${Math.min(100, (100 * got.length) / need)}"></i></div>
    ${got.length ? html`<p class="small">Ont approuvé : ${got.map((n) => html`<span class="tag ok">${n}</span> `)}</p>` : ""}
    ${done ? html`<div id="q-exec"></div>` : s.terminal_only ? html`<div class="stack-s"><p>Chaque dépositaire approuve sur le serveur, où il lit l'opération exacte avant de saisir sa phrase :</p>
      <div class="copy"><code>podman exec -it rempart rempart approve</code><button type="button" data-copy="podman exec -it rempart rempart approve">${icon("copy")}Copier</button></div>
      <p class="muted small">Cette page se met à jour toute seule.</p></div>` : html`<form id="q-approve" class="fields" autocomplete="off">
      <label class="field"><span>Dépositaire</span><select name="name">${left.map((c) => html`<option>${c.name}</option>`)}</select></label>
      <label class="field"><span>Phrase de passe du dépositaire</span><input name="passphrase" type="password" autocomplete="off" required></label>
      <div class="row"><button class="primary" type="submit">Approuver</button></div></form>`}
    <div class="row"><button class="ghost danger" id="q-cancel">Abandonner la demande</button></div>
  </section>`;
}

function bindApproval(el, op, s, reload) {
  applyWidths(el);
  bindCopy(el);
  if (s.terminal_only && !$("#q-exec", el)) {
    // Suivi des approbations faites au terminal.
    refreshTimer = setInterval(() => { if (!document.hidden && el.isConnected) reload(); }, 4000);
  }
  $("#q-cancel", el).onclick = (e) => act(e.currentTarget, () => api("/quorum/ops", { method: "DELETE" }), "Demande abandonnée").then(reload);
  const f = $("#q-approve", el);
  if (f) {
    f.passphrase.focus();
    f.onsubmit = async (e) => {
      e.preventDefault();
      const r = await act(e.submitter, () => api("/quorum/ops/approve", { method: "POST", body: { id: op.id, name: f.name.value, passphrase: f.passphrase.value } }));
      f.passphrase.value = "";
      if (r) { toast(`Approbation ${r.approved} sur ${r.need}`); reload(); }
    };
    return;
  }
  const box = $("#q-exec", el);
  if (!box) return; // approbations attendues au terminal
  if (op.kind === "reconfigure") return showExecute(box, s, op, reload);
  box.innerHTML = html`<form class="fields" id="q-run">${pwField()}<div class="row"><button class="primary ${op.kind === "destroy" ? "danger solid" : ""}" type="submit">Exécuter</button></div></form>`.s;
  $("#q-run", box).onsubmit = async (e) => {
    e.preventDefault();
    const body = { op_id: op.id, password: e.target.password.value, gen: op.gen, days: op.days };
    const path = op.kind === "destroy" ? "/kek/destroy" : "/kek/policy";
    if (op.kind === "destroy") delete body.days; else delete body.gen;
    if (await act(e.submitter, () => api(path, { method: "POST", body }), "Opération exécutée")) reload();
  };
}

const nameOf = (s, id) => (s.custodians.find((c) => c.id === id) || {}).name || id;
function planSummary(p, s) {
  return html`<dl class="kv plan">
    <dt>Démarrage</dt><dd>${p.mode === "quorum" ? "sous quorum (verrouillé à chaque redémarrage)" : "automatique (phrase serveur)"}</dd>
    <dt>Seuil</dt><dd><b>${p.threshold}</b> sur ${arr(p.keep).length + arr(p.add).length}</dd>
    <dt>Conservés</dt><dd>${arr(p.keep).length ? arr(p.keep).map((id) => html`<span class="tag">${nameOf(s, id)}</span> `) : "aucun"}</dd>
    <dt>Nouveaux</dt><dd>${arr(p.add).length ? arr(p.add).map((n) => html`<span class="tag warn">${n}</span> `) : "aucun"}</dd>
    <dt>Retirés</dt><dd>${s.custodians.filter((c) => !arr(p.keep).includes(c.id)).map((c) => html`<span class="tag bad">${c.name}</span> `)}</dd>
    <dt>Approbations</dt><dd>${p.terminal_only ? "au terminal du serveur seulement" : "interface ou terminal"}</dd>
    <dt>Clés</dt><dd>nouvelle clé racine, nouvelle KEK, générations précédentes détruites</dd></dl>
    <p class="small muted">Vérifiez ce plan avant d'approuver : l'exécution devra lui correspondre exactement.</p>`;
}

const modeChoice = (mode) => html`<div class="choices">
  <label class="choice"><input type="radio" name="mode" value="auto" ${checked(mode !== "quorum")}><span><b>Démarrage automatique</b><span class="muted small">La phrase serveur ouvre le keystore ; le quorum protège les opérations sensibles et sert de secours.</span></span></label>
  <label class="choice"><input type="radio" name="mode" value="quorum" ${checked(mode === "quorum")}><span><b>Démarrage sous quorum</b><span class="muted small">Après chaque redémarrage, pas de DNS tant que M dépositaires ne se sont pas présentés.</span></span></label></div>`;
const newRow = (name = "", withName = true) => html`<div class="fields custodian reveal" data-new>
  <label class="field"><span>Nom</span><input name="cname" value="${name}" maxlength="64" required autocomplete="off" ${withName ? "" : new Raw("readonly")}></label>
  <label class="field"><span>Phrase de passe</span><input name="cpass" type="password" minlength="12" required autocomplete="new-password"></label>
  <label class="field"><span>Confirmation</span><input name="cpass2" type="password" required autocomplete="new-password"></label>
  ${withName ? html`<button type="button" class="link danger" data-rm>Retirer</button>` : html`<span></span>`}</div>`;
function bindThreshold(f, count) {
  const thr = $("[name=threshold]", f);
  const sync = () => {
    const n = count(), cur = +thr.value || 2;
    thr.innerHTML = Array.from({ length: Math.max(0, n - 1) }, (_, i) => `<option ${i + 2 === Math.min(cur, n) ? "selected" : ""}>${i + 2}</option>`).join("");
    $(".thr-n", f).textContent = `sur ${n}`;
  };
  sync();
  return sync;
}
const readNew = (root) => {
  const out = [];
  for (const r of $$("[data-new]", root)) {
    const c = { name: $("[name=cname]", r).value.trim(), passphrase: $("[name=cpass]", r).value };
    if (c.passphrase !== $("[name=cpass2]", r).value) throw new Error(`Les deux saisies de ${c.name || "un dépositaire"} diffèrent`);
    out.push(c);
  }
  return out;
};
const confirmMode = (mode, m) => mode !== "quorum" || confirm(`Mode quorum au démarrage : après chaque redémarrage, Rempart ne servira aucune requête DNS tant que ${m} dépositaires n'auront pas saisi leur phrase. Continuer ?`);

const termSwitch = (on) => html`<label class="switch"><input type="checkbox" name="terminal" ${checked(on)}><span><b>Approbations au terminal du serveur seulement</b><span class="muted">Les dépositaires approuvent avec <code>podman exec -it rempart rempart approve</code> : leur phrase ne passe jamais par le navigateur de l'administrateur. Recommandé dès que l'administrateur web n'est pas lui-même dépositaire.</span></span></label>`;
const rekeyNote = html`<p class="muted small">Toute reconfiguration met en service une KEK neuve, rechiffre les données et détruit les générations précédentes : les sauvegardes antérieures du dossier de données deviennent illisibles, et une copie de l'ancien master.json ne déchiffre rien de ce qui s'écrit ensuite.</p>`;
const reconfResult = (r) => {
  if (!r) return;
  if (r.rewrap_error || r.purge_error) toast(`Configuration en place, mais : ${r.rewrap_error || r.purge_error}`, true);
  else toast(`Configuration en place${arr(r.destroyed).length ? ` ; générations ${r.destroyed.join(", ")} détruites` : ""}${arr(r.left).length ? ` ; générations ${r.left.join(", ")} encore utilisées` : ""}`);
};

// Première cérémonie (aucun quorum encore) : tous les dépositaires sont nouveaux.
function showCeremony(box, s, reload) {
  box.innerHTML = html`<form id="cer" class="stack reveal">
    <h3>Cérémonie initiale</h3>
    <p class="muted small">Réunissez les dépositaires. Chacun tape lui-même sa phrase (12 caractères au moins), sans la dire. Les changements suivants exigeront l'approbation de M d'entre eux.</p>
    ${modeChoice(s.mode)}
    <div id="rows" class="stack-s">${["", "", ""].map(() => newRow())}</div>
    <div class="row"><button type="button" id="add-c">+ Dépositaire</button><span class="grow"></span>
      <label class="row">Seuil M<select name="threshold"></select><span class="muted small thr-n"></span></label></div>
    ${termSwitch(false)}${rekeyNote}
    <div class="fields">${pwField()}</div>
    <div class="row"><button class="primary" type="submit">${icon("key")}Créer la clé racine et répartir les parts</button><button type="button" class="ghost" id="cer-cancel">Annuler</button></div>
  </form>`.s;
  const f = $("#cer", box), rows = $("#rows", f);
  const sync = bindThreshold(f, () => $$(".custodian", rows).length);
  const bindRm = () => $$("[data-rm]", rows).forEach((b) => { b.disabled = $$(".custodian", rows).length <= 2; b.onclick = () => { b.closest(".custodian").remove(); sync(); bindRm(); }; });
  bindRm();
  $("#add-c", f).onclick = () => { if ($$(".custodian", rows).length < 16) { rows.insertAdjacentHTML("beforeend", newRow().s); sync(); bindRm(); } };
  $("#cer-cancel", f).onclick = reload;
  f.onsubmit = async (e) => {
    e.preventDefault();
    let add;
    try { add = readNew(rows); } catch (err) { return toast(err.message, true); }
    const body = { password: f.password.value, mode: f.mode.value, threshold: +f.threshold.value, terminal_only: f.terminal.checked, keep: [], add };
    if (!confirmMode(body.mode, body.threshold)) return;
    const r = await act(e.submitter, () => api("/quorum/reconfigure", { method: "POST", body }));
    $$("input[type=password]", f).forEach((i) => (i.value = ""));
    reconfResult(r);
    if (r) reload();
  };
}

// Sous quorum : on décrit d'abord le plan (qui reste, qui arrive, seuil,
// mode), que M dépositaires approuvent ; l'exécution vient ensuite.
function showPlan(box, s, reload) {
  box.innerHTML = html`<form id="plan" class="stack reveal">
    <h3>Nouvelle configuration</h3>
    ${modeChoice(s.mode)}
    <div class="stack-s">${s.custodians.map((c) => html`<label class="switch"><input type="checkbox" name="keep" value="${c.id}" checked><span><b>Conserver ${c.name}</b><span class="muted">garde sa phrase actuelle</span></span></label>`)}</div>
    <div id="adds" class="stack-s"></div>
    <p class="muted small">Moins de M nouveaux dépositaires par reconfiguration : leurs phrases passent par cette session, et aucun quorum ne doit pouvoir être formé sans au moins un dépositaire déjà en place.</p>
    <div class="row"><button type="button" id="add-n">+ Nouveau dépositaire</button><span class="grow"></span>
      <label class="row">Seuil M<select name="threshold"></select><span class="muted small thr-n"></span></label></div>
    ${termSwitch(s.terminal_only)}${rekeyNote}
    <div class="row"><button class="primary" type="submit">Demander l'approbation</button><button type="button" class="ghost" id="plan-cancel">Annuler</button></div>
  </form>`.s;
  const f = $("#plan", box), adds = $("#adds", f);
  const count = () => $$("[name=keep]:checked", f).length + $$("[name=nname]", adds).length;
  const sync = bindThreshold(f, count);
  $$("[name=keep]", f).forEach((c) => (c.onchange = sync));
  $("#add-n", f).onclick = () => {
    adds.insertAdjacentHTML("beforeend", html`<div class="row reveal"><label class="field grow"><span>Nom du nouveau dépositaire</span><input name="nname" maxlength="64" required></label><button type="button" class="link danger" data-rm>Retirer</button></div>`.s);
    $$("[data-rm]", adds).forEach((b) => (b.onclick = () => { b.closest(".row").remove(); sync(); }));
    sync();
  };
  $("#plan-cancel", f).onclick = reload;
  f.onsubmit = async (e) => {
    e.preventDefault();
    const plan = { mode: f.mode.value, threshold: +f.threshold.value, keep: $$("[name=keep]:checked", f).map((c) => c.value), add: $$("[name=nname]", adds).map((i) => i.value.trim()), terminal_only: f.terminal.checked };
    if (plan.keep.length + plan.add.length && plan.keep.length + plan.add.length < 2) return toast("Il faut au moins deux dépositaires, ou aucun pour supprimer le quorum", true);
    if (await act(e.submitter, () => api("/quorum/ops", { method: "POST", body: { kind: "reconfigure", plan } }), "Plan soumis : faites-le approuver")) reload();
  };
}

// Exécution d'un plan approuvé : les conservés qui n'ont pas approuvé
// confirment leur phrase actuelle ; les nouveaux choisissent la leur.
function showExecute(box, s, op, reload) {
  const p = op.plan, approved = arr(op.approved_by);
  const toConfirm = arr(p.keep).filter((id) => !approved.includes(nameOf(s, id)));
  box.innerHTML = html`<form id="exe" class="stack reveal">
    ${toConfirm.length && s.terminal_only ? notice("bad", html`<p>${toConfirm.map((id) => nameOf(s, id)).join(", ")} n'${toConfirm.length > 1 ? "ont" : "a"} pas approuvé au terminal : en mode « terminal seulement », chaque dépositaire conservé doit approuver avec <code>rempart approve</code>. Abandonnez la demande et recommencez.</p>`) : ""}
    ${toConfirm.length && !s.terminal_only ? html`<h3>Dépositaires conservés : confirmation</h3>${toConfirm.map((id) => html`<label class="field"><span>Phrase actuelle de ${nameOf(s, id)}</span><input type="password" data-keep="${id}" required autocomplete="off"></label>`)}` : ""}
    ${arr(p.add).length ? html`<h3>Nouveaux dépositaires</h3><div class="stack-s">${arr(p.add).map((n) => newRow(n, false))}</div>` : ""}
    <div class="fields">${pwField()}</div>
    <div class="row"><button class="primary" type="submit">${icon("key")}Exécuter le plan approuvé</button></div>
  </form>`.s;
  const f = $("#exe", box);
  f.onsubmit = async (e) => {
    e.preventDefault();
    let add;
    try { add = readNew(f); } catch (err) { return toast(err.message, true); }
    const keep = arr(p.keep).map((id) => ({ id, passphrase: ($(`[data-keep="${id}"]`, f) || {}).value || "" }));
    const body = { op_id: op.id, password: f.password.value, mode: p.mode, threshold: p.threshold, terminal_only: !!p.terminal_only, keep, add };
    if (!confirmMode(p.mode, p.threshold)) return;
    const r = await act(e.submitter, () => api("/quorum/reconfigure", { method: "POST", body }));
    $$("input[type=password]", f).forEach((i) => (i.value = ""));
    reconfResult(r);
    reload();
  };
}

secTabs.tls = async (el) => {
  const t = await api("/tls");
  const i = t.info, c = t.config, ac = c.acme || {};
  const left = daysLeft(i.not_after);
  const life = Math.max(1, (new Date(i.not_after) - new Date(i.not_before)) / 86400000);
  const dirs = arr(t.directories);
  const known = dirs.find((d) => !d.template && d.url === ac.directory_url);
  const modeLabel = { selfsigned: "auto-signé", acme: "ACME", manual: "importé", file: "fichier de configuration" }[i.mode] || i.mode;
  el.innerHTML = html`<div class="stack">
    <section class="panel stack">
      <div class="panel-head"><h2>Certificat en service</h2><span class="tag ${i.self_signed ? "warn" : "ok"}">${modeLabel}</span></div>
      <div class="stack-s"><div class="validity ${left < life / 3 ? "low" : ""}"><i data-w="${Math.max(2, Math.min(100, (100 * left) / life))}"></i></div>
        <p class="small muted">Valide jusqu'au ${day(i.not_after)} (${left} jours restants)${t.needs_renewal && c.mode === "acme" ? ", renouvellement imminent" : ""}.</p></div>
      <dl class="kv">
        <dt>Noms</dt><dd>${arr(i.names).join(", ")}</dd>
        <dt>Émetteur</dt><dd>${i.issuer}</dd>
        <dt>Clé privée</dt><dd>${i.source}${i.key_label ? html` <span class="mono muted small">${i.key_label}</span>` : ""}</dd>
        <dt>Empreinte</dt><dd class="mono small">SHA-256 ${i.cert_sha256}</dd>
      </dl>
      ${t.locked ? notice("plain", "Ce certificat est imposé par le fichier de configuration (tls.cert_file, tls.key_file) : retirez ces lignes pour le gérer ici.") : ""}
    </section>
    ${t.locked ? "" : html`
    <section class="panel stack">
      <div class="panel-head"><h2>Obtenir un certificat</h2><p>La clé reste dans le keystore (dans le HSM s'il est configuré) : seule une demande signée en sort.</p></div>
      <div class="seg" role="radiogroup" aria-label="Méthode">
        <label><input type="radio" name="how" value="acme" ${checked(c.mode !== "manual")}><span>ACME automatique</span></label>
        <label><input type="radio" name="how" value="csr" ${checked(c.mode === "manual")}><span>CSR et import</span></label>
      </div>
      <form id="tls-names" class="stack-s">
        <label class="field"><span>Noms du certificat</span><textarea class="short" name="names" spellcheck="false" placeholder="rempart.example.fr&#10;dns.example.fr">${arr(c.names).join("\n")}</textarea>
          <span class="small">Un nom par ligne : ceux que vos appareils utilisent pour joindre Rempart (DoT, DoH, interface).</span></label>
      </form>
      <div id="how-acme" class="stack">
        <form id="acme-cfg" class="stack-s">
          <label class="field"><span>Autorité</span><select name="dir" id="acme-dir">${dirs.map((d) => html`<option value="${d.id}" ${selected(known ? known.id === d.id : d.id === "custom" && ac.directory_url)}>${d.name}</option>`)}</select></label>
          <p class="muted small" id="acme-note"></p>
          <label class="field"><span>URL de l'annuaire ACME</span><input name="url" id="acme-url" value="${ac.directory_url || ""}" placeholder="https://…/directory" spellcheck="false"></label>
          <div class="fields">
            <label class="field"><span>Adresse de contact</span><input name="email" type="email" value="${ac.email || ""}" placeholder="pki@example.fr"></label>
            <div class="field"><span>Défi</span><div class="seg" role="radiogroup" aria-label="Défi">
              <label><input type="radio" name="challenge" value="http-01" ${checked(ac.challenge !== "dns-01")}><span>http-01</span></label>
              <label><input type="radio" name="challenge" value="dns-01" ${checked(ac.challenge === "dns-01")}><span>dns-01</span></label></div></div>
          </div>
          <p class="muted small">http-01 : l'AC contacte Rempart sur ${t.http01_listen || ":80"} pendant la validation. dns-01 : Rempart publie lui-même le TXT dans votre zone locale signée ; l'AC doit interroger Rempart pour ce nom (PKI interne).</p>
          <details ${ac.ca_bundle ? new Raw("open") : ""}><summary>AC interne : certificats de confiance</summary>
            <label class="field"><span>AC racine et intermédiaires (PEM)</span><textarea class="short" name="ca" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${ac.ca_bundle || ""}</textarea>
            <span class="small">Pour joindre une AC dont le certificat n'est pas reconnu par le système, sans jamais désactiver la vérification TLS.</span></label>
          </details>
          <div><button type="submit">Enregistrer</button></div>
        </form>
        <hr>
        <div class="stack-s">
          <h3>Compte ACME</h3>
          ${ac.account_url ? html`<p class="small">Inscrit : <span class="mono">${ac.account_url}</span>${ac.eab_key_id ? html` (EAB ${ac.eab_key_id})` : ""}</p>` : html`<p class="muted small">Pas encore inscrit auprès de cette autorité.</p>`}
          <form id="acme-reg" class="stack-s" autocomplete="off">
            <details><summary>Liaison de compte externe (EAB)</summary><div class="fields">
              <label class="field"><span>Identifiant de clé (KID)</span><input name="kid" autocomplete="off" value="${ac.eab_key_id || ""}"></label>
              <label class="field"><span>Clé HMAC</span><input name="hmac" type="password" autocomplete="off" placeholder="base64url"></label></div>
              <p class="muted small">Fournis par l'AC (EJBCA, Horizon, ZeroSSL…). La clé HMAC sert à l'inscription puis est effacée ; elle n'est pas enregistrée.</p></details>
            <label class="switch"><input type="checkbox" name="tos" required><span><b>J'accepte les conditions de l'autorité</b></span></label>
            <div><button type="submit">${ac.account_url ? "Réinscrire le compte" : "Inscrire le compte"}</button></div>
          </form>
        </div>
        <hr>
        <div class="row"><button class="primary" id="acme-issue" ${ac.account_url ? "" : new Raw("disabled")}>${icon("cert")}Obtenir le certificat maintenant</button>
          <span class="muted small">Renouvellement automatique au dernier tiers de la validité.</span></div>
        ${ac.last_error ? notice("bad", html`<p><b>Dernière tentative le ${date(ac.last_attempt)} :</b> ${ac.last_error}</p>`) : isSet(ac.last_success) ? notice("good", html`<p>Dernier certificat obtenu le ${date(ac.last_success)}.</p>`) : ""}
      </div>
      <div id="how-csr" class="stack" hidden>
        <div class="row"><button id="csr-gen">Générer la demande (CSR)</button><span class="muted small">À faire signer par votre PKI : EJBCA, Horizon, ADCS…</span></div>
        <div id="csr-out"></div>
        <form id="csr-import" class="stack-s">
          <label class="field"><span>Chaîne signée (PEM, certificat du serveur d'abord)</span><textarea name="chain" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----"></textarea></label>
          <div><button class="primary" type="submit">Installer le certificat</button></div>
        </form>
      </div>
      <div class="row end"><button class="link danger" id="selfsigned">Revenir à un certificat auto-signé</button></div>
    </section>`}
  </div>`;
  applyWidths(el);
  if (t.locked) return;
  const reload = () => secTabs.tls(el);
  const names = () => lines($("#tls-names").names.value);
  const how = () => $("[name=how]:checked", el).value;
  const showHow = () => { $("#how-acme").hidden = how() !== "acme"; $("#how-csr").hidden = how() !== "csr"; };
  $$("[name=how]", el).forEach((r) => (r.onchange = showHow));
  showHow();
  const dirSel = $("#acme-dir");
  const syncDir = (fill) => {
    const d = dirs.find((x) => x.id === dirSel.value);
    $("#acme-note").textContent = d ? d.note + (d.eab === "required" ? " Liaison de compte (EAB) obligatoire." : "") : "";
    if (fill && d) $("#acme-url").value = d.url;
  };
  dirSel.onchange = () => syncDir(true);
  syncDir(!$("#acme-url").value);
  const saveCfg = (btn) => {
    const f = $("#acme-cfg");
    return act(btn, () => api("/tls/config", { method: "PUT", body: { names: names(), acme: { directory_url: f.url.value.trim(), email: f.email.value.trim(), challenge: f.challenge.value, ca_bundle: f.ca.value } } }), "Configuration enregistrée");
  };
  $("#acme-cfg").onsubmit = (e) => { e.preventDefault(); saveCfg(e.submitter).then((r) => r && reload()); };
  $("#acme-reg").onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    const body = { eab_key_id: f.kid.value.trim(), eab_hmac: f.hmac.value.trim(), accept_tos: f.tos.checked };
    f.hmac.value = "";
    if (!(await saveCfg(null))) return;
    act(e.submitter, () => api("/tls/acme/register", { method: "POST", body }), "Compte ACME inscrit").then((r) => r && reload());
  };
  $("#acme-issue").onclick = (e) => act(e.currentTarget, () => api("/tls/acme/issue", { method: "POST" }), "Certificat obtenu et mis en service").then(reload);
  $("#csr-gen").onclick = async (e) => {
    const r = await act(e.currentTarget, () => api("/tls/csr", { method: "POST", body: { names: names() } }));
    if (!r) return;
    $("#csr-out").innerHTML = html`<div class="copy"><pre class="code">${r.csr}</pre><button type="button" data-copy="${r.csr}" data-copied="CSR copiée">${icon("copy")}Copier</button></div>`;
    bindCopy(el);
  };
  $("#csr-import").onsubmit = (e) => { e.preventDefault(); act(e.submitter, () => api("/tls/certificate", { method: "POST", body: { chain: e.target.chain.value } }), "Certificat installé").then((r) => r && reload()); };
  $("#selfsigned").onclick = (e) => confirm("Remplacer le certificat actuel par un certificat auto-signé ?") && act(e.currentTarget, () => api("/tls/selfsigned", { method: "POST" }), "Certificat auto-signé en service").then(reload);
};

const scopeLabel = { read: "lecture", tls: "certificats", dnssec: "DNSSEC", admin: "administration", metrics: "métriques", backup: "sauvegarde", sync: "synchronisation" };
secTabs.tokens = async (el) => {
  const toks = arr(await api("/tokens"));
  el.innerHTML = html`<div class="grid wide">
    <section class="panel stack">
      <div class="panel-head"><h2>Jetons d'API</h2><p>Pour automatiser sans mot de passe : renouveler un certificat depuis votre PKI, publier un DS, lire l'état. Chaque appel est consigné dans l'audit sous le nom du jeton.</p></div>
      ${toks.length ? html`<div class="table-wrap"><table class="cards">
        <thead><tr><th>Nom</th><th>Portées</th><th>Expire</th><th>Dernière utilisation</th><th></th></tr></thead>
        <tbody>${toks.map((k) => html`<tr><td class="first">${k.name}</td><td data-label="Portées">${arr(k.scopes).map((s) => html`<span class="tag">${scopeLabel[s] || s}</span> `)}</td>
          <td data-label="Expire" class="small">${isSet(k.expires) ? day(k.expires) : "jamais"}</td><td data-label="Utilisé" class="small">${date(k.last_used)}</td>
          <td class="act"><button class="link danger" data-revoke="${k.id}" data-name="${k.name}">Révoquer</button></td></tr>`)}</tbody></table></div>` : html`<p class="empty">Aucun jeton.</p>`}
      <div id="new-token"></div>
    </section>
    <section class="panel stack">
      <h2>Nouveau jeton</h2>
      <form id="tok" class="stack-s">
        <label class="field"><span>Nom</span><input name="name" placeholder="ansible-pki" required maxlength="64"></label>
        <div class="field"><span>Portées</span>
          ${Object.entries(scopeLabel).map(([k, v]) => html`<label class="switch"><input type="checkbox" name="scope" value="${k}" ${checked(k === "read")}><span><b>${v}</b><span class="muted">${{ read: "consulter l'état, les zones, les certificats", tls: "certificat : CSR, import, ACME", dnssec: "rotations et DS des zones", admin: "toutes les modifications (sauf jetons, mot de passe et HSM)", metrics: "lire /metrics (Prometheus), rien d'autre", backup: "télécharger une sauvegarde complète, rien d'autre (non inclus dans « administration »)", sync: "pour une réplique : lire la configuration à recopier (non inclus dans « administration »)" }[k]}</span></span></label>`)}</div>
        <label class="field"><span>Validité (jours, 0 = sans expiration)</span><input name="days" type="number" min="0" max="730" value="90"></label>
        <div><button class="primary" type="submit">Créer le jeton</button></div>
      </form>
    </section></div>`;
  const reload = () => secTabs.tokens(el);
  $$("[data-revoke]", el).forEach((b) => (b.onclick = () => confirm(`Révoquer le jeton « ${b.dataset.name} » ?`) && act(b, () => api("/tokens/" + b.dataset.revoke, { method: "DELETE" }), "Jeton révoqué").then(reload)));
  $("#tok").onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    const r = await act(e.submitter, () => api("/tokens", { method: "POST", body: { name: f.get("name"), scopes: f.getAll("scope"), days: +f.get("days") } }));
    if (!r) return;
    await reload();
    const header = `Authorization: Bearer ${r.token}`;
    const ex = `# Le jeton reste dans un fichier (0600), jamais sur la ligne de commande :\ncurl -H @/run/secrets/rempart-auth https://${location.host}/api/zones/maison.lan/ds?format=text`;
    $("#new-token").innerHTML = html`${notice("", html`<p><b>Copiez ce jeton maintenant :</b> il ne sera plus affiché. Seule son empreinte est conservée.</p>
      <div class="copy"><code>${header}</code><button type="button" data-copy="${header}" data-copied="En-tête copié">${icon("copy")}Copier</button></div>
      <pre class="code">${ex}</pre>`)}`;
    bindCopy(el);
  };
};

// ---- comptes externes : annuaire LDAP et OpenID Connect (Keycloak) ----
const ldapPresets = {
  ad: { label: "Active Directory", user_filter: "(&(objectClass=user)(objectCategory=person)(sAMAccountName={user})(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", user_attr: "sAMAccountName", display_attr: "displayName", group_attr: "memberOf", group_filter: "" },
  openldap: { label: "OpenLDAP", user_filter: "(&(objectClass=inetOrgPerson)(uid={user}))", user_attr: "uid", display_attr: "cn", group_attr: "", group_filter: "(&(objectClass=groupOfNames)(member={dn}))" },
  ipa: { label: "FreeIPA / 389-DS", user_filter: "(&(objectClass=person)(uid={user}))", user_attr: "uid", display_attr: "displayName", group_attr: "memberOf", group_filter: "" },
};
const roleBoxes = (p, rg, hint) => html`<div class="fields roles">
  <label class="field"><span>Administrateurs</span><textarea class="short" name="${p}_admin" spellcheck="false" placeholder="${hint.admin}">${arr(rg?.admin).join("\n")}</textarea><small class="muted">Tout, y compris clés, jetons et comptes.</small></label>
  <label class="field"><span>Opérateurs</span><textarea class="short" name="${p}_operator" spellcheck="false" placeholder="${hint.operator}">${arr(rg?.operator).join("\n")}</textarea><small class="muted">Filtrage, zones, certificat. Pas la sécurité.</small></label>
  <label class="field"><span>Lecture seule</span><textarea class="short" name="${p}_read" spellcheck="false" placeholder="${hint.read}">${arr(rg?.read).join("\n")}</textarea><small class="muted">Consultation uniquement.</small></label>
</div>`;
const readRoles = (f, p) => ({ admin: lines(f[p + "_admin"].value), operator: lines(f[p + "_operator"].value), read: lines(f[p + "_read"].value) });

secTabs.identity = async (el) => {
  const st = await api("/identity");
  const l = st.ldap, o = st.oidc;
  const local = me.source === "local";
  const redirect = o.redirect_url || `${location.origin}/api/oidc/callback`;
  el.innerHTML = html`<form id="idf" class="stack" autocomplete="off">
    ${notice("plain", html`<p>Connectez les administrateurs avec leur compte d'entreprise. Leur rôle dans Rempart découle de leurs groupes, relus à chaque connexion ; un compte sans groupe reconnu n'entre pas. Le compte local <b>${st.local_user}</b> reste toujours utilisable : c'est l'accès de secours si l'annuaire ou le fournisseur tombent.</p>`)}
    ${local ? "" : notice("bad", html`<p>Seul le compte local <b>${st.local_user}</b> peut modifier ces réglages : un administrateur d'annuaire ne doit pas pouvoir s'octroyer des droits lui-même. Vous pouvez tester la configuration.</p>`)}
    <fieldset class="panel stack">
      <div class="panel-head"><h2>Annuaire LDAP</h2>${l.enabled ? html`<span class="tag ok">Actif</span>` : html`<span class="tag">Inactif</span>`}
        <p>Active Directory, OpenLDAP, FreeIPA, 389-DS. Le mot de passe saisi à la connexion est vérifié par l'annuaire ; il ne passe qu'en TLS et n'est jamais conservé.</p></div>
      ${sw("l_enabled", l.enabled, "Autoriser la connexion par l'annuaire", "Tout nom d'utilisateur autre que le compte local est vérifié auprès de l'annuaire.")}
      <div class="row wrap"><span class="muted small">Modèle :</span>${Object.entries(ldapPresets).map(([k, v]) => html`<button type="button" class="ghost" data-preset="${k}">${v.label}</button>`)}</div>
      <div class="fields">
        <label class="field"><span>URL de l'annuaire</span><input name="l_urls" value="${l.urls}" placeholder="ldaps://dc1.corp.example:636 ldaps://dc2.corp.example:636" spellcheck="false"><small class="muted">Plusieurs URL séparées par des espaces : essayées dans l'ordre.</small></label>
        <div class="field"><span>Chiffrement</span>${sw("l_starttls", l.starttls, "StartTLS sur ldap://", "Sinon ldaps:// (TLS direct). Aucune liaison en clair n'est possible.")}</div>
      </div>
      <div class="fields">
        <label class="field"><span>Compte de service (DN)</span><input name="l_bind_dn" value="${l.bind_dn}" placeholder="CN=svc-rempart,OU=Services,DC=corp,DC=example" spellcheck="false"></label>
        <label class="field"><span>Mot de passe du compte de service</span><input name="l_bind_password" type="password" autocomplete="new-password" placeholder="${st.ldap_bind_password_set ? "enregistré — laisser vide pour le garder" : ""}"><small class="muted">À ressaisir si l'URL ou le compte changent.</small></label>
      </div>
      <div class="fields">
        <label class="field"><span>Base des utilisateurs</span><input name="l_user_base" value="${l.user_base}" placeholder="OU=Utilisateurs,DC=corp,DC=example" spellcheck="false"></label>
        <label class="field"><span>Filtre des utilisateurs</span><input name="l_user_filter" value="${l.user_filter}" placeholder="(&(objectClass=person)(uid={user}))" spellcheck="false" class="mono"><small class="muted">{user} est remplacé par le nom saisi, échappé (RFC 4515).</small></label>
      </div>
      <div class="fields">
        <label class="field"><span>Attribut du nom de connexion</span><input name="l_user_attr" value="${l.user_attr}" placeholder="uid ou sAMAccountName"></label>
        <label class="field"><span>Attribut du nom affiché</span><input name="l_display_attr" value="${l.display_attr}" placeholder="displayName"></label>
        <label class="field"><span>Attribut des groupes</span><input name="l_group_attr" value="${l.group_attr}" placeholder="memberOf"></label>
      </div>
      <div class="fields">
        <label class="field"><span>Base des groupes (facultatif)</span><input name="l_group_base" value="${l.group_base}" placeholder="OU=Groupes,DC=corp,DC=example" spellcheck="false"></label>
        <label class="field"><span>Filtre des groupes (facultatif)</span><input name="l_group_filter" value="${l.group_filter}" placeholder="(&(objectClass=groupOfNames)(member={dn}))" spellcheck="false" class="mono"><small class="muted">{dn} : DN de l'utilisateur. Groupes imbriqués d'AD : (member:1.2.840.113556.1.4.1941:={dn}).</small></label>
      </div>
      <label class="field"><span>AC de l'annuaire (PEM, facultatif)</span><textarea class="short" name="l_ca_bundle" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${l.ca_bundle}</textarea><small class="muted">Ajoutée aux racines du système. Le certificat de l'annuaire est toujours vérifié.</small></label>
      <h3>Groupes autorisés <span class="muted small">(DN complets, un par ligne)</span></h3>
      ${roleBoxes("l", l.roles, { admin: "CN=Rempart-Admins,OU=Groupes,DC=corp,DC=example", operator: "CN=Rempart-Ops,OU=Groupes,DC=corp,DC=example", read: "CN=Rempart-Lecture,OU=Groupes,DC=corp,DC=example" })}
      <div class="row wrap"><input name="l_test_user" placeholder="utilisateur à rechercher (facultatif)" class="grow" spellcheck="false"><button type="button" id="l-test">${icon("refresh")}Tester l'annuaire</button></div>
      <div id="l-res"></div>
    </fieldset>

    <fieldset class="panel stack">
      <div class="panel-head"><h2>OpenID Connect (Keycloak)</h2>${o.enabled ? html`<span class="tag ok">Actif</span>` : html`<span class="tag">Inactif</span>`}
        <p>Un bouton de connexion renvoie vers Keycloak (ou Entra ID, Authentik, Okta…). Rempart reçoit un jeton signé, vérifié avec les clés publiées par le fournisseur. La double authentification se règle chez le fournisseur.</p></div>
      ${sw("o_enabled", o.enabled, "Autoriser la connexion OIDC", "Code d'autorisation avec PKCE (S256), state et nonce à usage unique.")}
      <div class="fields">
        <label class="field"><span>Émetteur (issuer)</span><input name="o_issuer" value="${o.issuer}" placeholder="https://keycloak.corp.example/realms/corp" spellcheck="false"></label>
        <label class="field"><span>Texte du bouton</span><input name="o_label" value="${o.label || "Keycloak"}" maxlength="40"></label>
      </div>
      <div class="fields">
        <label class="field"><span>Identifiant du client</span><input name="o_client_id" value="${o.client_id}" placeholder="rempart" spellcheck="false"></label>
        <label class="field"><span>Secret du client</span><input name="o_client_secret" type="password" autocomplete="new-password" placeholder="${st.oidc_client_secret_set ? "enregistré — laisser vide pour le garder" : "Credentials → Client secret"}"></label>
        <div class="field"><span>Type de client</span>${sw("o_public", false, "Client public (sans secret)", "PKCE seul. Efface le secret enregistré.")}</div>
      </div>
      <div class="fields">
        <label class="field"><span>URL de retour</span><input name="o_redirect_url" value="${redirect}" spellcheck="false"><small class="muted">À déclarer telle quelle dans Keycloak (Valid redirect URIs).</small></label>
        <label class="field"><span>Portées</span><input name="o_scopes" value="${arr(o.scopes).length ? arr(o.scopes).join(" ") : "profile email"}" spellcheck="false"><small class="muted">openid est toujours demandé.</small></label>
      </div>
      <div class="fields">
        <label class="field"><span>Revendication du nom d'utilisateur</span><input name="o_username_claim" value="${o.username_claim || "preferred_username"}" spellcheck="false"></label>
        <label class="field"><span>Revendication des rôles ou groupes</span><input name="o_roles_claim" value="${o.roles_claim || "realm_access.roles"}" spellcheck="false" list="claims"><small class="muted">Rôles du royaume, rôles du client (resource_access.rempart.roles) ou groupes.</small>
          <datalist id="claims"><option value="realm_access.roles"><option value="resource_access.rempart.roles"><option value="groups"></datalist></label>
        <label class="field"><span>Niveau exigé (acr, facultatif)</span><input name="o_required_acr" value="${o.required_acr}" placeholder="ex. 2 ou gold" spellcheck="false"><small class="muted">Refuse une connexion sans le niveau demandé (OTP dans Keycloak).</small></label>
      </div>
      <label class="field"><span>AC du fournisseur (PEM, facultatif)</span><textarea class="short" name="o_ca_bundle" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${o.ca_bundle}</textarea></label>
      <h3>Rôles ou groupes autorisés <span class="muted small">(un par ligne, tels qu'ils figurent dans le jeton)</span></h3>
      ${roleBoxes("o", o.roles, { admin: "rempart-admin", operator: "rempart-operateur", read: "rempart-lecture" })}
      <details class="help"><summary>Préparer Keycloak</summary><ol>
        <li>Clients → Create client : type <b>OpenID Connect</b>, identifiant <code>rempart</code>.</li>
        <li>Client authentication : <b>On</b> ; flux : <b>Standard flow</b> seul (décochez Direct access grants).</li>
        <li>Valid redirect URIs : <code>${redirect}</code> ; Valid post logout redirect URIs : <code>${location.origin}/</code>.</li>
        <li>Advanced → Proof Key for Code Exchange : <b>S256</b>.</li>
        <li>Realm roles : créez <code>rempart-admin</code>, <code>rempart-operateur</code>, <code>rempart-lecture</code> et attribuez-les (ou à des groupes).</li>
        <li>Pour des groupes plutôt que des rôles : Client scopes → rempart-dedicated → Add mapper « Group Membership », nom <code>groups</code>, Full group path désactivé.</li>
        <li>Credentials : copiez le secret du client ci-dessus.</li>
      </ol></details>
      <div class="row"><button type="button" id="o-test">${icon("refresh")}Tester la découverte</button></div>
      <div id="o-res"></div>
    </fieldset>

    ${local ? html`<section class="panel stack-s">
      <h2>Enregistrer</h2>
      <p class="muted small">Confirmez avec le mot de passe du compte local${st.local_otp ? " et un code de double authentification" : ""}. Les sessions ouvertes par l'annuaire ou le fournisseur sont fermées.</p>
      <div class="fields">
        <label class="field"><span>Mot de passe de ${st.local_user}</span><input name="password" type="password" autocomplete="current-password" required></label>
        ${st.local_otp ? html`<label class="field"><span>Code de l'application ou de secours</span><input name="code" autocomplete="one-time-code" inputmode="numeric" required></label>` : ""}
      </div>
      <div class="row"><button class="primary" type="submit">Enregistrer les comptes externes</button></div>
    </section>` : ""}
  </form>`;
  const f = $("#idf", el);
  const ldapBody = () => ({
    enabled: f.l_enabled.checked, urls: f.l_urls.value, starttls: f.l_starttls.checked, ca_bundle: f.l_ca_bundle.value,
    bind_dn: f.l_bind_dn.value, bind_password: f.l_bind_password.value, user_base: f.l_user_base.value, user_filter: f.l_user_filter.value,
    user_attr: f.l_user_attr.value, display_attr: f.l_display_attr.value, group_attr: f.l_group_attr.value,
    group_base: f.l_group_base.value, group_filter: f.l_group_filter.value, roles: readRoles(f, "l"),
  });
  const oidcBody = () => ({
    enabled: f.o_enabled.checked, label: f.o_label.value, issuer: f.o_issuer.value.trim().replace(/\/+$/, ""), client_id: f.o_client_id.value,
    client_secret: f.o_public.checked ? "" : f.o_client_secret.value, redirect_url: f.o_redirect_url.value, scopes: f.o_scopes.value.split(/\s+/).filter(Boolean),
    ca_bundle: f.o_ca_bundle.value, username_claim: f.o_username_claim.value, roles_claim: f.o_roles_claim.value,
    required_acr: f.o_required_acr.value, roles: readRoles(f, "o"),
  });
  $$("[data-preset]", el).forEach((b) => (b.onclick = () => {
    const p = ldapPresets[b.dataset.preset];
    for (const k of ["user_filter", "user_attr", "display_attr", "group_attr", "group_filter"]) f["l_" + k].value = p[k];
    toast(`Modèle ${p.label} appliqué : vérifiez les bases de recherche`);
  }));
  f.o_public.onchange = () => { f.o_client_secret.disabled = f.o_public.checked; };
  // Hors compte local : lecture et tests seulement.
  if (!local) $$("input, textarea, button", f).forEach((x) => { if (!["l-test", "o-test"].includes(x.id) && x.name !== "l_test_user") x.disabled = true; });
  $("#l-test", el).onclick = async (e) => {
    const r = await act(e.currentTarget, () => api("/identity/ldap/test", { method: "POST", body: { ldap: ldapBody(), username: f.l_test_user.value.trim() } }));
    if (!r) return;
    $("#l-res", el).innerHTML = (r.dn
      ? notice(r.role ? "good" : "bad", html`<p><b>${r.name || r.dn}</b> trouvé : <code>${r.dn}</code></p>
          <p>Groupes (${arr(r.groups).length}) : ${arr(r.groups).length ? arr(r.groups).map((g) => html`<code>${g}</code> `) : "aucun"}</p>
          <p>Rôle dans Rempart : <b>${r.role ? roleNames[r.role] : "aucun — cet utilisateur ne pourra pas se connecter"}</b></p>`)
      : notice("good", "Connexion TLS et compte de service acceptés par l'annuaire.")).s;
  };
  $("#o-test", el).onclick = async (e) => {
    const r = await act(e.currentTarget, () => api("/identity/oidc/test", { method: "POST", body: { oidc: oidcBody() } }));
    if (!r) return;
    $("#o-res", el).innerHTML = notice("good", html`<p>Fournisseur trouvé : <code>${r.issuer}</code></p>
      <p class="small">Autorisation : <code>${r.authorization_endpoint}</code><br>Jetons : <code>${r.token_endpoint}</code><br>Déconnexion : ${r.end_session_endpoint ? html`<code>${r.end_session_endpoint}</code>` : "non annoncée"}<br>Algorithmes : ${arr(r.algorithms).join(", ") || "non annoncés"}</p>
      <p class="small muted">Pour vérifier les rôles, enregistrez puis connectez-vous avec le bouton depuis une fenêtre privée : le résultat est consigné dans le journal d'audit.</p>`).s;
  };
  f.onsubmit = async (e) => {
    e.preventDefault();
    const body = { ldap: ldapBody(), oidc: oidcBody(), clear_oidc_secret: f.o_public.checked, password: f.password.value, code: f.code ? f.code.value.trim() : "" };
    const r = await act(e.submitter, () => api("/identity", { method: "PUT", body }), "Comptes externes enregistrés");
    if (r) secTabs.identity(el);
  };
};

secTabs.audit = async (el) => {
  const a = await api("/audit");
  el.innerHTML = html`<section class="panel stack">
    <div class="panel-head"><h2>Journal d'audit signé</h2><button id="verify">${icon("audit")}Vérifier l'intégrité</button></div>
    ${notice(a.verify.ok ? "good" : "bad", a.verify.ok ? html`<p>Intégrité vérifiée : ${n(a.verify.count)} événements chaînés et signés (clé ${a.verify.key_fingerprint}).</p>` : html`<p>Altération détectée : ${a.verify.problem}</p>`)}
    <div class="table-wrap"><table class="cards">
      <thead><tr><th>Action</th><th class="num">N°</th><th>Date</th><th>Acteur</th><th>Détail</th></tr></thead>
      <tbody>${arr(a.events).map((e) => html`<tr><td class="first">${e.action}</td><td data-label="N°" class="num">${e.seq}</td><td class="small" data-label="Date">${date(e.time)}</td><td data-label="Acteur">${e.actor}</td><td class="small" data-label="Détail">${e.detail}</td></tr>`)}</tbody>
    </table></div>
  </section>`;
  $("#verify").onclick = (e) => act(e.currentTarget, () => api("/audit")).then((r) => r && (r.verify.ok ? toast(`Intégrité vérifiée (${r.verify.count} événements)`) : toast(r.verify.problem, true)));
};

// ================= Réglages =================
views.settings = async (main, tab) => {
  const t = tabs("settings", [["general", "Blocage"], ["resolution", "Résolution DNS"], ["encryption", "Chiffrement"], ["privacy", "Confidentialité"], ["ops", "Exploitation"], ["account", "Compte"]], tab);
  main.innerHTML = html`<div class="page">${head("Réglages", "Chaque modification est enregistrée dans le journal d'audit signé.")}${t.nav}<div id="tab"></div></div>`;
  await setTabs[t.cur]($("#tab"));
};
const setTabs = {};
setTabs.ops = opsTab;
async function saveSettings(btn, patch) {
  const s = await api("/settings");
  return act(btn, () => api("/settings", { method: "PUT", body: { ...s, ...patch } }), "Réglages enregistrés");
}
const radioChoice = (name, value, cur, label, help) => html`<label class="choice"><input type="radio" name="${name}" value="${value}" ${checked(cur === value)}><span><b>${label}</b><span class="muted">${help}</span></span></label>`;
setTabs.general = async (el) => {
  const s = await api("/settings");
  el.innerHTML = html`<form id="sf" class="stack">
    <section class="panel stack-s">
      <h2>Blocage</h2>
      ${sw("blocking_enabled", s.blocking_enabled, "Bloquer les domaines des listes", "Pour une coupure temporaire, préférez la pause du tableau de bord.")}
      <h3 class="mt">Réponse aux domaines bloqués</h3>
      <div class="choices">
        ${radioChoice("blocking_mode", "zero", s.blocking_mode, "Adresse nulle", "0.0.0.0 et :: — recommandé, les applications échouent immédiatement.")}
        ${radioChoice("blocking_mode", "nxdomain", s.blocking_mode, "Domaine inexistant", "NXDOMAIN : le domaine semble ne pas exister.")}
        ${radioChoice("blocking_mode", "refused", s.blocking_mode, "Refus", "REFUSED : certaines applications réessaient ailleurs.")}
      </div>
    </section>
    <section class="panel stack-s">
      <h2>Protections</h2>
      ${sw("block_cname_cloaking", s.block_cname_cloaking, "Démasquer les traqueurs cachés derrière un CNAME", "Bloque metrics.site.fr quand il pointe vers un domaine de traçage.")}
      ${sw("rebind_protection", s.rebind_protection, "Protection contre le DNS rebinding", "Refuse qu'un domaine public renvoie une adresse de votre réseau local.")}
      ${sw("dnssec_validation", !s.dnssec_validation_off, "Valider DNSSEC sur ce serveur", "Rempart vérifie lui-même les signatures depuis la racine : un résolveur en amont compromis ne peut plus falsifier un domaine signé. Les réponses falsifiées sont refusées (SERVFAIL).")}
      ${sw("block_doh_canary", s.block_doh_canary, "Empêcher les navigateurs de contourner Rempart", "Signale à Firefox et à iCloud Private Relay d'utiliser ce résolveur.")}
    </section>
    <section class="panel stack-s">
      <h2>Heure</h2>
      <label class="field"><span>Fuseau horaire des plages horaires</span><input name="time_zone" value="${s.time_zone || ""}" placeholder="Europe/Paris"><small class="muted">Nom IANA. Vide : fuseau du serveur (souvent UTC dans un conteneur).</small></label>
    </section>
    <div class="row"><button class="primary" type="submit">Enregistrer</button><button type="button" id="flush">Vider le cache DNS</button></div>
  </form>`;
  $("#sf").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    saveSettings(e.submitter, { blocking_enabled: !!f.get("blocking_enabled"), blocking_mode: f.get("blocking_mode"), block_cname_cloaking: !!f.get("block_cname_cloaking"), rebind_protection: !!f.get("rebind_protection"), dnssec_validation_off: !f.get("dnssec_validation"), block_doh_canary: !!f.get("block_doh_canary"), time_zone: f.get("time_zone").trim() });
  };
  $("#flush").onclick = (e) => act(e.currentTarget, () => api("/cache/flush", { method: "POST" }), "Cache vidé");
};
setTabs.encryption = async (el) => {
  const [e, tl] = await Promise.all([api("/encryption"), api("/tls").catch(() => ({ info: {} }))]);
  const line = (key, x, label, help) => x.listen
    ? html`${sw(key, x.enabled, label, help)}
      <p class="muted small">Écoute <code>${x.listen}</code>${x.path ? html`, chemin <code>${x.path}</code>` : ""} : ${x.running ? html`<span class="tag ok">en service</span>` : html`<span class="tag warn">arrêté</span>`}</p>
      ${x.error ? notice("bad", html`<p>${x.error}</p>`) : ""}`
    : notice("plain", html`<p><b>${label}</b> : aucune adresse d'écoute dans le fichier de configuration (<code>${key}.listen</code>).</p>`);
  el.innerHTML = html`<form id="ef" class="stack">
    <section class="panel stack-s">
      <h2>DNS chiffré</h2>
      <p class="muted small">Les appareils interrogent Rempart en HTTPS, TLS, QUIC ou DNSCrypt : le réseau ne voit plus les noms demandés. Appliqué immédiatement, sans redémarrage. L'adresse et le port se règlent dans le fichier de configuration, car ils doivent correspondre aux ports publiés par le conteneur.</p>
      ${tl.info?.self_signed ? notice("bad", html`<p>Le certificat actuel est <b>auto-signé</b> : Windows, les navigateurs et les téléphones refuseront DoH et DoT. Obtenez-en un par ACME ou par votre PKI (<a href="#/security/tls">Sécurité, Certificat</a>).</p>`) : ""}
      ${line("doh", e.doh, "DNS-over-HTTPS (DoH)", "Windows 11, Firefox, Chrome, iPhone. Adresses par appareil dans Appareils, Profils mobiles.")}
      ${line("dot", e.dot, "DNS-over-TLS (DoT)", "Android (DNS privé), routeurs, résolveurs secondaires.")}
      ${e.doq ? line("doq", e.doq, "DNS-over-QUIC (DoQ)", "RFC 9250, en UDP : plus rapide sur les réseaux mobiles. AdGuard, applications DoQ, routeurs récents.") : ""}
      ${e.dnscrypt ? line("dnscrypt", e.dnscrypt, "DNSCrypt", "dnscrypt-proxy, Simple DNSCrypt, routeurs OpenWrt. Clés de résolveur renouvelées toutes les heures ; clé de fournisseur dans le keystore.") : ""}
      ${e.dnscrypt?.stamp ? html`<div class="stack-s"><span class="small muted">Tampon à donner aux clients (fournisseur ${e.dnscrypt_provider}) :</span>
        <div class="copy"><code class="small">${e.dnscrypt.stamp}</code><button type="button" data-copy="${e.dnscrypt.stamp}" data-copied="Tampon copié">${icon("copy")}Copier</button></div>
        <span class="small muted">L'adresse annoncée vient de <code>dnscrypt.stamp_addr</code> : mettez l'adresse publique vue par les clients.</span></div>` : ""}
    </section>
    <div><button class="primary" type="submit">Enregistrer</button></div>
  </form>`;
  bindCopy(el);
  $("#ef").onsubmit = async (ev) => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    const body = { doh_enabled: e.doh.listen ? !!f.get("doh") : false, dot_enabled: e.dot.listen ? !!f.get("dot") : false, doq_enabled: e.doq?.listen ? !!f.get("doq") : false, dnscrypt_enabled: e.dnscrypt?.listen ? !!f.get("dnscrypt") : false };
    await act(ev.submitter, () => api("/encryption", { method: "PUT", body }), "Chiffrement enregistré");
    setTabs.encryption(el);
  };
};
setTabs.privacy = async (el) => {
  const s = await api("/settings");
  el.innerHTML = html`<form id="pf" class="stack">
    <section class="panel stack-s">
      <h2>Journalisation</h2>
      <div class="choices">
        ${radioChoice("log_mode", "none", s.log_mode, "Aucun journal", "Seulement des compteurs anonymes. Ni domaine, ni appareil.")}
        ${radioChoice("log_mode", "stats", s.log_mode, "Statistiques anonymes", "Compteurs et domaines bloqués les plus fréquents, jamais par appareil.")}
        ${radioChoice("log_mode", "full", s.log_mode, "Journal complet chiffré", "Chaque requête, chiffrée sur disque avec une clé par jour protégée par le keystore.")}
      </div>
      <div class="fields mt">
        <label class="field"><span>Identification des appareils</span><select name="client_ids">
          <option value="pseudonymize" ${selected(s.client_ids === "pseudonymize")}>Pseudonyme (change chaque jour)</option>
          <option value="truncate" ${selected(s.client_ids === "truncate")}>Adresse tronquée (/24, /48)</option>
          <option value="clear" ${selected(s.client_ids === "clear")}>Adresse IP complète</option></select></label>
        <label class="field"><span>Conservation (jours)</span><input name="retention_days" type="number" min="1" max="3650" value="${s.retention_days}"></label>
      </div>
      <p class="muted small">À l'expiration, la clé du jour est détruite : le journal devient illisible, même sur une sauvegarde.</p>
    </section>
    <section class="panel stack-s">
      <h2>Suggestions de blocage</h2>
      ${sw("suggestions", s.suggestions, "Analyser les domaines résolus", "En mémoire seulement, sans aucune information sur les appareils, effacé dès la désactivation. Indisponible en mode « aucun journal ».")}
    </section>
    <div><button class="primary" type="submit">Enregistrer</button></div>
  </form>`;
  $("#pf").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    saveSettings(e.submitter, { log_mode: f.get("log_mode"), client_ids: f.get("client_ids"), retention_days: +f.get("retention_days"), suggestions: !!f.get("suggestions") });
  };
};
setTabs.resolution = async (el) => {
  const r = await api("/resolvers");
  const cfg = r.resolvers;
  let profile = cfg.profile || "perso";
  const presets = arr(r.presets);
  const inUse = new Set(arr(cfg.upstreams));
  const presetOn = (p) => arr(p.specs).some((s) => inUse.has(s));
  const custom = arr(cfg.upstreams).filter((u) => !presets.some((p) => arr(p.specs).includes(u)));
  const draw = () => {
    el.innerHTML = html`<form id="rf" class="stack">
      <section class="panel stack-s">
        <h2>Profil</h2>
        <div class="choices">
          ${radioChoice("profile", "perso", profile, "Personnel", "Maison ou petit bureau : résolveurs publics chiffrés, choisis selon leur juridiction.")}
          ${radioChoice("profile", "entreprise", profile, "Entreprise", "Résolveurs internes, transfert des domaines Active Directory, AC internes.")}
        </div>
      </section>
      <section class="panel stack-s">
        <div class="panel-head"><h2>${profile === "entreprise" ? "Résolveurs pour Internet" : "Résolveurs par défaut"}</h2><p>Rempart interroge deux résolveurs en parallèle et garde la première réponse. Tous ceux proposés ici sont chiffrés (DoH et DoT).</p></div>
        ${profile === "entreprise" ? html`<p class="muted small">Pour passer uniquement par les résolveurs de l'entreprise, décochez tout et indiquez-les plus bas.</p>` : ""}
        <div class="choices">${presets.map((p) => html`<label class="choice"><input type="checkbox" name="preset" value="${p.id}" ${checked(presetOn(p))}><span><b>${p.name}</b><span class="muted">${p.jurisdiction}, ${p.filtering}</span><span class="muted mono small">${arr(p.specs)[0]}</span></span></label>`)}</div>
        <label class="field"><span>${profile === "entreprise" ? "Résolveurs de l'entreprise" : "Autres résolveurs"}</span>
          <textarea class="short" name="custom" spellcheck="false" placeholder="https://doh.example.fr/dns-query&#10;tls://dns.example.fr&#10;10.0.0.53">${custom.join("\n")}</textarea>
          <span class="small">Un par ligne : https:// (DoH), tls:// (DoT), ou une adresse IP (DNS en clair, à réserver au réseau interne). « #IP » épingle l'adresse d'un résolveur DoH.</span></label>
      </section>
      ${profile === "entreprise" ? html`
      <section class="panel stack-s">
        <div class="panel-head"><h2>Transfert conditionnel</h2><p>Ces domaines et leurs sous-domaines sont envoyés à leurs serveurs, par exemple vos contrôleurs Active Directory. La protection anti-rebinding ne s'y applique pas.</p></div>
        <div id="fwd" class="stack-s">${(arr(cfg.forwards).length ? arr(cfg.forwards) : [{ domain: "", servers: [] }]).map((f) => fwdRow(f))}</div>
        <div><button type="button" id="addfwd">Ajouter un domaine</button></div>
      </section>
      <section class="panel stack-s">
        <h2>PKI interne</h2>
        <label class="field"><span>AC de confiance supplémentaires (PEM)</span><textarea class="short" name="cas" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----">${cfg.extra_cas || ""}</textarea>
          <span class="small">Pour valider le certificat de vos résolveurs DoT ou DoH internes. La vérification TLS n'est jamais désactivée.</span></label>
        <label class="field"><span>Bootstrap (adresses IP)</span><input name="bootstrap" value="${arr(cfg.bootstrap).join(", ")}" placeholder="${arr(r.default_bootstrap).join(", ")}">
          <span class="small">DNS en clair servant seulement à trouver l'adresse des résolveurs désignés par un nom. Vide : ${arr(r.default_bootstrap).join(", ")}.</span></label>
      </section>` : ""}
      <div><button class="primary" type="submit">Appliquer</button></div>
    </form>`;
    $$("[name=profile]", el).forEach((x) => (x.onchange = () => { profile = x.value; draw(); }));
    $("#addfwd")?.addEventListener("click", () => $("#fwd").insertAdjacentHTML("beforeend", fwdRow({ domain: "", servers: [] }).s));
    $("#rf").onsubmit = (e) => {
      e.preventDefault();
      const f = e.target;
      const ups = [];
      $$("[name=preset]:checked", f).forEach((c) => ups.push(...arr(presets.find((p) => p.id === c.value)?.specs)));
      ups.push(...lines(f.custom.value));
      const forwards = profile === "entreprise" ? $$(".fwd", f).map((row) => ({ domain: $("[name=fd]", row).value.trim(), servers: $("[name=fs]", row).value.split(/[\s,]+/).filter(Boolean) })).filter((x) => x.domain) : arr(cfg.forwards);
      const body = { profile, upstreams: ups, forwards, extra_cas: f.cas ? f.cas.value : cfg.extra_cas || "", bootstrap: f.bootstrap ? f.bootstrap.value.split(/[\s,]+/).filter(Boolean) : arr(cfg.bootstrap) };
      act(e.submitter, () => api("/resolvers", { method: "PUT", body }), "Résolution appliquée");
    };
  };
  draw();
};
const fwdRow = (f) => html`<div class="fields fwd"><label class="field"><span>Domaine</span><input name="fd" value="${f.domain}" placeholder="corp.example.local"></label><label class="field"><span>Serveurs</span><input name="fs" value="${arr(f.servers).join(", ")}" placeholder="10.0.0.10, 10.0.0.11"></label></div>`;
setTabs.account = async (el) => {
  if (me.source !== "local") {
    const where = me.source === "oidc" ? "votre fournisseur d'identité" : "l'annuaire de l'entreprise";
    el.innerHTML = html`<section class="panel stack-s">
      <div class="panel-head"><h2>Votre compte</h2><span class="tag">${roleNames[me.role] || me.role}</span></div>
      <p><b>${me.name}</b> <span class="muted">(${me.user})</span></p>
      ${notice("plain", html`<p>Ce compte est géré par ${where} : mot de passe et double authentification se changent là-bas. Votre rôle dans Rempart découle de vos groupes ; il est relu à chaque connexion.</p>`)}
    </section>`;
    return;
  }
  el.innerHTML = html`<div class="stack"><section class="panel stack-s" id="otp-panel"><p class="muted">Chargement…</p></section>
  <section class="panel stack-s" id="pk-panel"><p class="muted">Chargement…</p></section>
  <section class="panel stack-s">
    <h2>Mot de passe administrateur</h2>
    <form id="pw" class="fields">
      <label class="field"><span>Mot de passe actuel</span><input name="old" type="password" autocomplete="current-password" required></label>
      <label class="field"><span>Nouveau mot de passe</span><input name="new" type="password" autocomplete="new-password" minlength="12" required placeholder="12 caractères minimum"></label>
      <div class="row"><button class="primary" type="submit">Changer le mot de passe</button></div>
    </form>
    <p class="muted small">Toutes les sessions ouvertes sont fermées après le changement.</p>
  </section></div>`;
  $("#pw").onsubmit = (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    act(e.submitter, () => api("/password", { method: "POST", body: { old: f.get("old"), new: f.get("new") } }), "Mot de passe changé, reconnectez-vous").then((r) => r && showLogin());
  };
  await otpPanel($("#otp-panel"));
  await passkeyPanel($("#pk-panel"));
};

// Clés d'accès : inscription (mot de passe, et code si TOTP), liste, retrait.
async function passkeyPanel(el) {
  const [keys, otpSt] = await Promise.all([api("/passkeys"), api("/otp")]);
  const auth = (id, label, danger) => html`<form class="fields reveal" id="${id}">
      ${id === "pk-new" ? html`<label class="field"><span>Nom de la clé</span><input name="name" maxlength="60" required placeholder="YubiKey, iPhone, Windows Hello…"></label>` : ""}
      <label class="field"><span>Mot de passe</span><input name="password" type="password" autocomplete="current-password" required></label>
      ${otpSt.enabled ? html`<label class="field"><span>Code de l'application ou de secours</span><input name="code" autocomplete="one-time-code" inputmode="numeric" required></label>` : ""}
      <div class="row"><button class="${danger ? "danger solid" : "primary"}" type="submit">${label}</button><button type="button" class="ghost" data-cancel>Annuler</button></div>
    </form>`;
  el.innerHTML = html`<div class="panel-head"><h2>Clés d'accès</h2>${keys.length ? html`<span class="tag ok">${keys.length} clé(s)</span>` : html`<span class="tag">Aucune</span>`}
      <p>Passkeys et clés de sécurité FIDO2 (YubiKey, Windows Hello, Touch ID, téléphone). Elles remplacent le code à 6 chiffres, et permettent de se connecter sans mot de passe quand la clé vérifie votre PIN ou votre empreinte. Impossible à hameçonner : la clé ne répond qu'à ce site.</p></div>
    ${keys.length ? html`<div class="table-wrap"><table class="cards"><thead><tr><th>Nom</th><th>Site</th><th>Ajoutée</th><th>Dernière utilisation</th><th></th></tr></thead><tbody>
      ${keys.map((k) => html`<tr><td class="first">${k.name}${k.synced ? html` <span class="tag">synchronisée</span>` : ""}</td><td data-label="Site" class="mono small">${k.rp_id}</td>
        <td data-label="Ajoutée" class="small">${day(k.created)}</td><td data-label="Dernière utilisation" class="small">${isSet(k.last_used) ? day(k.last_used) : "jamais"}</td>
        <td><button class="danger ghost" data-pk-del="${k.id}">Retirer</button></td></tr>`)}</tbody></table></div>` : ""}
    ${passkeySupported() ? html`<div class="row"><button class="primary" id="pk-add">${icon("key")}Ajouter une clé d'accès</button></div>`
      : notice("plain", html`<p>Ce navigateur ou cette adresse ne permet pas les clés d'accès : ouvrez l'interface en HTTPS, par son nom (pas par une adresse IP).</p>`)}
    <div id="pk-act"></div>
    <p class="muted small">Une clé est liée au nom utilisé pour ouvrir l'interface (${location.hostname}). Tout perdu : redémarrez une fois avec <code>REMPART_RESET_OTP=1</code>.</p>`;
  const box = $("#pk-act", el);
  const open = (id, label, danger, run) => {
    box.innerHTML = auth(id, label, danger).s;
    const f = $("#" + id, box);
    (f.name || f.password).focus();
    $("[data-cancel]", f).onclick = () => (box.innerHTML = "");
    f.onsubmit = async (e) => { e.preventDefault(); await run(f, e.submitter); };
  };
  $("#pk-add", el) && ($("#pk-add", el).onclick = () => open("pk-new", "Enregistrer", false, async (f, btn) => {
    btn.disabled = true;
    try {
      const opts = await api("/passkeys/begin", { method: "POST", body: { password: f.password.value, code: f.code ? f.code.value : "" } });
      const body = await passkeyCreate(opts);
      await api("/passkeys/finish", { method: "POST", body: { ...body, name: f.name.value.trim() } });
      toast("Clé d'accès ajoutée");
      passkeyPanel(el);
    } catch (err) { toast(passkeyError(err), true); btn.disabled = false; }
  }));
  $$("[data-pk-del]", el).forEach((b) => (b.onclick = () => open("pk-del", "Retirer la clé", true, async (f, btn) => {
    const r = await act(btn, () => api(`/passkeys/${encodeURIComponent(b.dataset.pkDel)}/delete`, { method: "POST", body: { password: f.password.value, code: f.code ? f.code.value : "" } }), "Clé retirée");
    if (r) passkeyPanel(el);
  })));
}

// Double authentification : inscription en trois temps (scanner, confirmer,
// conserver les codes de secours), puis gestion.
async function otpPanel(el) {
  const st = await api("/otp");
  const reauth = (id, label, danger) => html`<form class="fields reveal" id="${id}">
      <label class="field"><span>Mot de passe</span><input name="password" type="password" autocomplete="current-password" required></label>
      <label class="field"><span>Code de l'application ou de secours</span><input name="code" autocomplete="one-time-code" inputmode="numeric" required></label>
      <div class="row"><button class="${danger ? "danger solid" : "primary"}" type="submit">${label}</button><button type="button" class="ghost" data-cancel>Annuler</button></div>
    </form>`;
  if (st.enabled) {
    el.innerHTML = html`<div class="panel-head"><h2>Double authentification</h2><span class="tag ok">Active</span>
      <p>Un code à usage unique est demandé après le mot de passe. Codes de secours restants : <b>${st.recovery_left}</b> sur 10.</p></div>
      ${st.recovery_left < 3 ? notice("bad", "Il vous reste peu de codes de secours : générez-en de nouveaux.") : ""}
      <div class="row"><button id="otp-regen">${icon("refresh")}Nouveaux codes de secours</button><button class="danger" id="otp-off">Désactiver</button></div>
      <div id="otp-act"></div>
      <p class="muted small">Les jetons d'API ne sont pas concernés : ils restent un second moyen d'accès, à protéger comme tel.</p>`;
    const box = $("#otp-act", el);
    const open = (id, label, danger, path, done) => {
      box.innerHTML = reauth(id, label, danger).s;
      const f = $("#" + id, box);
      f.password.focus();
      $("[data-cancel]", f).onclick = () => (box.innerHTML = "");
      f.onsubmit = async (e) => {
        e.preventDefault();
        const r = await act(e.submitter, () => api(path, { method: "POST", body: { password: f.password.value, code: f.code.value } }));
        if (r) done(r);
      };
    };
    $("#otp-regen", el).onclick = () => open("f-regen", "Générer", false, "/otp/recovery", (r) => showCodes(el, r.recovery, () => otpPanel(el)));
    $("#otp-off", el).onclick = () => open("f-off", "Désactiver la double authentification", true, "/otp/disable", () => { toast("Double authentification désactivée"); otpPanel(el); });
    return;
  }
  el.innerHTML = html`<div class="panel-head"><h2>Double authentification</h2><span class="tag warn">Inactive</span>
    <p>Ajoutez un code à usage unique (TOTP) généré par une application : Aegis, 2FAS, Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden… Le secret reste dans l'état scellé du serveur.</p></div>
    <div class="row"><button class="primary" id="otp-start">${icon("phone")}Activer</button></div>`;
  $("#otp-start", el).onclick = async (e) => {
    const r = await act(e.currentTarget, () => api("/otp/setup", { method: "POST" }));
    if (!r) return;
    const grouped = r.secret.match(/.{1,4}/g).join(" ");
    el.innerHTML = html`<div class="panel-head"><h2>Activer la double authentification</h2></div>
      <ol class="enroll reveal">
        <li><h3>Scannez le QR code</h3>
          <div class="qr-wrap"><img class="qr" src="${r.qr}" alt="QR code à scanner avec l'application d'authentification" width="200" height="200">
            <div class="stack-s"><p class="muted small">Ou saisissez la clé à la main (compte ${r.account}, type « basé sur le temps ») :</p>
            <code class="secret">${grouped}</code>
            <div class="row"><button type="button" data-copy="${r.secret}" data-copied="Clé copiée">${icon("copy")}Copier la clé</button></div></div></div></li>
        <li><h3>Confirmez</h3>
          <form id="otp-confirm" class="fields">
            <label class="field"><span>Code affiché</span><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="123456"></label>
            <label class="field"><span>Mot de passe</span><input name="password" type="password" autocomplete="current-password" required></label>
            <div class="row"><button class="primary" type="submit">Activer</button><button type="button" class="ghost" id="otp-cancel">Annuler</button></div>
          </form></li>
      </ol>
      <p class="muted small">La clé n'est affichée que pendant l'inscription (10 minutes), puis n'est plus jamais renvoyée.</p>`;
    bindCopy(el);
    $("#otp-cancel", el).onclick = () => otpPanel(el);
    const f = $("#otp-confirm", el);
    f.code.focus();
    f.onsubmit = async (ev) => {
      ev.preventDefault();
      const res = await act(ev.submitter, () => api("/otp/enable", { method: "POST", body: { code: f.code.value.trim(), password: f.password.value } }), "Double authentification activée");
      if (res) showCodes(el, res.recovery, () => otpPanel(el));
    };
  };
}

function showCodes(el, codes, done) {
  const text = "Rempart DNS - codes de secours\n" + new Date().toLocaleString("fr-FR") + "\nChaque code ne sert qu'une fois.\n\n" + codes.join("\n") + "\n";
  el.innerHTML = html`<div class="panel-head"><h2>Codes de secours</h2>
    <p>Conservez-les hors de cet ordinateur (gestionnaire de mots de passe, papier). Ils remplacent l'application si vous la perdez, une fois chacun. Ils ne seront plus affichés.</p></div>
    <ul class="codes reveal">${codes.map((c) => html`<li><code>${c}</code></li>`)}</ul>
    <div class="row"><button data-copy="${text}" data-copied="Codes copiés">${icon("copy")}Copier</button><button id="dl">${icon("download")}Télécharger (.txt)</button></div>
    <label class="switch"><input type="checkbox" id="kept"><span><b>J'ai mis ces codes en lieu sûr</b></span></label>
    <div class="row"><button class="primary" id="fin" disabled>Terminer</button></div>`;
  bindCopy(el);
  $("#dl", el).onclick = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = "rempart-codes-de-secours.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  $("#kept", el).onchange = (e) => ($("#fin", el).disabled = !e.target.checked);
  $("#fin", el).onclick = done;
}

// ---- démarrage ----
try { const th = localStorage.getItem("rempart-theme"); if (th) document.documentElement.dataset.theme = th; } catch {}
route();
