// aide.js - sommaire et recherche de la page d'aide.
import { $, $$, h, initTheme, initMenu, trackActive } from "./docs-common.js";

initTheme();
initMenu();

const doc = $("#doc"), toc = $("#toc");

// Regroupe chaque titre h2 et ce qui le suit dans une <section>, pour
// pouvoir filtrer section par section.
const sections = [];
let cur = null;
for (const el of [...doc.children]) {
  if (el.tagName === "H2") { cur = h("section"); el.before(cur); sections.push(cur); }
  if (cur && el.id !== "none") cur.append(el);
}

const list = h("ul");
const links = [];
for (const s of sections) {
  const h2 = $("h2", s);
  const a = h("a", { href: "#" + h2.id, text: h2.textContent });
  links.push(a);
  const li = h("li", {}, a);
  li.dataset.sec = h2.id;
  list.append(li);
  for (const h3 of $$("h3[id]", s)) {
    const sub = h("li.sub", {}, h("a", { href: "#" + h3.id, text: h3.textContent }));
    sub.dataset.sec = h2.id;
    list.append(sub);
  }
  s.dataset.text = s.textContent.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "");
}
toc.append(h("h3", { text: "Sommaire" }), list);
trackActive(links, sections.map((s) => $("h2", s)));

$("#filter").addEventListener("input", (ev) => {
  const words = ev.target.value.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").split(/\s+/).filter(Boolean);
  let any = false;
  for (const s of sections) {
    const m = words.every((w) => s.dataset.text.includes(w));
    s.classList.toggle("hidden", !m);
    if (m) any = true;
    const id = $("h2", s).id;
    $$(`li[data-sec="${id}"]`, toc).forEach((li) => li.classList.toggle("hidden", !m));
  }
  $("#none").classList.toggle("hidden", any);
  $$(".cards", doc).forEach((c) => c.classList.toggle("hidden", words.length > 0));
});
