// docs-common.js - éléments partagés par aide.html et api.html :
// thème (même clé que l'interface), menu latéral sur téléphone, notification.

export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// h("tag.cls", {attr}, ...enfants) : construit le DOM sans innerHTML, donc
// sans risque d'injection pour les valeurs venant du serveur.
export function h(tag, attrs = {}, ...kids) {
  const [name, ...cls] = tag.split(".");
  const el = document.createElement(name);
  if (cls.length) el.className = cls.join(" ");
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) el.append(k.nodeType ? k : document.createTextNode(String(k)));
  return el;
}

export function initTheme() {
  try { const t = localStorage.getItem("rempart-theme"); if (t) document.documentElement.dataset.theme = t; } catch {}
  const b = $("#theme");
  if (b) b.onclick = () => {
    const cur = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("rempart-theme", next); } catch {}
  };
}

export function initMenu() {
  const side = $("#side"), btn = $("#menu");
  if (!side || !btn) return;
  btn.onclick = () => { const o = side.classList.toggle("open"); btn.setAttribute("aria-expanded", String(o)); };
  side.addEventListener("click", (e) => { if (e.target.closest("a")) { side.classList.remove("open"); btn.setAttribute("aria-expanded", "false"); } });
  addEventListener("keydown", (e) => {
    if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement?.tagName)) { e.preventDefault(); $("#filter")?.focus(); }
    if (e.key === "Escape") side.classList.remove("open");
  });
}

let tt;
export function toast(msg) {
  const t = $("#toast"); if (!t) return;
  t.textContent = msg; t.classList.add("show");
  clearTimeout(tt); tt = setTimeout(() => t.classList.remove("show"), 2400);
}
export const copy = (s, what = "Copié") => navigator.clipboard.writeText(s).then(() => toast(what), () => toast("Copie impossible : sélectionnez le texte"));

// Surligne dans la table des matières la section visible.
export function trackActive(links, targets) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) if (e.isIntersecting) {
      links.forEach((a) => a.classList.toggle("active", a.getAttribute("href") === "#" + e.target.id));
    }
  }, { rootMargin: "-60px 0px -70% 0px" });
  targets.forEach((t) => io.observe(t));
}
