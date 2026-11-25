// ui-shared.js - comportements communs à l'interface (app.js) et aux pages
// d'aide et d'API (docs-common.js) : thème, zones défilantes au clavier,
// validation des champs annoncée aux lecteurs d'écran.

// ---- thème ----
// Source de vérité : <meta name="color-scheme"> (« light dark » = système),
// posée avant l'affichage par theme.js et reprise par app.css/docs.css.
// Bouton à deux états : le contraire de ce qui est affiché. Revenir à la
// couleur du système efface le choix, au lieu de figer le thème.
const THEME_KEY = "rempart-theme";
const systemDark = matchMedia("(prefers-color-scheme: dark)");
const meta = () => document.querySelector('meta[name="color-scheme"]');
const override = () => { const c = meta()?.content; return c === "light" || c === "dark" ? c : null; };
const system = () => (systemDark.matches ? "dark" : "light");
const shown = () => override() || system();

function syncThemeButtons() {
  const target = shown() === "dark" ? "light" : "dark";
  const label = target === "dark" ? "Thème sombre" : "Thème clair";
  document.querySelectorAll("[data-theme-toggle]").forEach((b) => {
    b.title = label;
    const text = b.querySelector("[data-theme-label]");
    if (text) text.textContent = label;
    // toggleAttribute : un <svg> n'a pas de propriété .hidden.
    b.querySelectorAll("[data-theme-icon]").forEach((i) => i.toggleAttribute("hidden", i.dataset.themeIcon !== target));
  });
}
function applyTheme(value) {
  const m = meta();
  if (m) m.content = value || "light dark";
  syncThemeButtons();
}
export function toggleTheme() {
  const target = shown() === "dark" ? "light" : "dark";
  const value = target === system() ? null : target;
  try { value ? localStorage.setItem(THEME_KEY, value) : localStorage.removeItem(THEME_KEY); } catch {}
  applyTheme(value); // appliqué même si le stockage est refusé
}
// À appeler après chaque rendu qui contient des boutons [data-theme-toggle].
export function initThemeToggles(root = document) {
  root.querySelectorAll("[data-theme-toggle]").forEach((b) => {
    if (b.dataset.themeBound) return;
    b.dataset.themeBound = "1";
    b.addEventListener("click", toggleTheme);
  });
  syncThemeButtons();
}
systemDark.addEventListener("change", syncThemeButtons);
addEventListener("storage", (e) => {
  if (e.key !== THEME_KEY && e.key !== null) return; // autre onglet
  const v = e.newValue === "light" || e.newValue === "dark" ? e.newValue : null;
  applyTheme(v);
});

// ---- zones défilantes ----
// Un tableau ou un bloc de code plus large que son cadre doit pouvoir défiler
// au clavier : le cadre devient alors une région nommée et focalisable
// (Safari ne rend pas les zones défilantes focalisables). Sans débordement,
// il n'a ni tabindex ni rôle, pour ne pas ajouter d'arrêt inutile.
const scrollers = new ResizeObserver((entries) => entries.forEach((e) => syncScroller(e.target.closest("[data-scroller]") || e.target)));
function syncScroller(el) {
  if (!el.isConnected) return;
  if (el.scrollWidth > el.clientWidth + 1) {
    el.tabIndex = 0;
    el.setAttribute("role", "region");
    const cap = el.querySelector("caption")?.textContent.trim();
    el.setAttribute("aria-label", el.dataset.scrollLabel || cap || (el.localName === "pre" ? "Bloc de code" : "Contenu défilant"));
  } else {
    el.removeAttribute("tabindex");
    el.removeAttribute("role");
    el.removeAttribute("aria-label");
  }
}
export function watchScrollers(root, selector) {
  root.querySelectorAll(selector).forEach((el) => {
    if (el.dataset.scroller) return syncScroller(el);
    el.dataset.scroller = "1";
    scrollers.observe(el);
    if (el.firstElementChild) scrollers.observe(el.firstElementChild); // le contenu change de largeur sans le cadre
  });
}

// ---- validation des champs ----
// :user-invalid (après interaction ou tentative d'envoi) pilote le style ;
// le même état est reporté dans aria-invalid, et le message du navigateur
// est relié par aria-describedby. Tant que l'utilisateur n'a pas interagi,
// aria-invalid vaut "false" : Firefox et Safari annoncent sinon un champ
// requis vide comme invalide dès l'affichage. Le message est aria-hidden pour
// ne pas entrer dans le nom du champ quand il est dans son <label> ;
// aria-describedby le lit quand même.
const controls = "input, select, textarea";
let errSeq = 0;
const errorOf = new WeakMap(); // champ -> élément de message
const supportsUserInvalid = (() => { try { document.querySelector(":user-invalid"); return true; } catch { return false; } })();
const userInvalid = (el) => (supportsUserInvalid ? el.matches(":user-invalid") : el.dataset.touched === "1" && !el.validity.valid);
const fieldName = (el) => el.getAttribute("aria-label") || el.labels?.[0]?.querySelector("span")?.textContent.trim() || el.name || "";
const validated = (el) => el.matches(controls) && el.willValidate && !el.closest("form[novalidate]") && el.type !== "hidden";

export function markFields(root) {
  root.querySelectorAll(controls).forEach((el) => { if (validated(el) && !el.hasAttribute("aria-invalid")) el.setAttribute("aria-invalid", "false"); });
}
function describe(el, id, on) {
  const ids = (el.getAttribute("aria-describedby") || "").split(/\s+/).filter((x) => x && x !== id);
  if (on) ids.push(id);
  ids.length ? el.setAttribute("aria-describedby", ids.join(" ")) : el.removeAttribute("aria-describedby");
}
// Erreur calculée par la page (assistant de zone…) : même contrat que la
// validation du navigateur. msgEl est le texte affiché, souvent dans le
// <label> : aria-hidden l'écarte du nom du champ, aria-describedby le lit.
export function linkError(field, msgEl, bad) {
  if (!msgEl.id) msgEl.id = `field-err-${++errSeq}`;
  msgEl.setAttribute("aria-hidden", "true");
  field.setAttribute("aria-invalid", String(bad));
  describe(field, msgEl.id, bad);
}
function syncField(el, announce) {
  const bad = userInvalid(el);
  const was = el.getAttribute("aria-invalid") === "true";
  el.setAttribute("aria-invalid", String(bad));
  let msg = errorOf.get(el);
  if (bad) {
    if (!msg?.isConnected) {
      msg = document.createElement("span");
      msg.className = "field-err";
      msg.id = `field-err-${++errSeq}`;
      msg.setAttribute("aria-hidden", "true");
      const label = el.closest("label");
      label ? label.append(msg) : el.after(msg);
      errorOf.set(el, msg);
    }
    msg.textContent = el.validationMessage;
    describe(el, msg.id, true);
    if (!was && announce) announce(`${fieldName(el)} : ${el.validationMessage}`);
  } else if (msg) {
    describe(el, msg.id, false);
    msg.remove();
    errorOf.delete(el);
  }
}
export function initValidation(announce) {
  const on = (type, fn) => document.addEventListener(type, (e) => { if (e.target instanceof Element && validated(e.target)) fn(e.target, e); }, true);
  // Champ quitté : l'erreur apparaît et elle est annoncée.
  on("focusout", (el) => { if (el.value !== "" || el.dataset.touched) el.dataset.touched = "1"; syncField(el, announce); });
  // Saisie : l'erreur disparaît dès que la valeur est bonne, sans annonce.
  on("input", (el) => syncField(el, null));
  on("change", (el) => { el.dataset.touched = "1"; syncField(el, null); });
  // Envoi refusé par le navigateur : il met le focus sur le premier champ
  // invalide, qui lit son erreur via aria-describedby.
  on("invalid", (el) => { el.dataset.touched = "1"; setTimeout(() => syncField(el, null)); });
}

// ---- rendus dynamiques ----
// Appelle fn(racine) pour chaque sous-arbre ajouté, regroupé par image.
export function onRender(root, fn) {
  let queued = false;
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => { queued = false; fn(root); });
  }).observe(root, { childList: true, subtree: true });
  fn(root);
}
