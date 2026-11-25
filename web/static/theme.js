// theme.js - applique le thème choisi avant le premier affichage, sans flash.
// Script classique et bloquant, placé juste après <meta name="color-scheme"> :
// la CSP interdit les scripts en ligne. Sans JavaScript, la page suit le
// réglage du système (meta « light dark »). Le bouton est dans ui-shared.js.
try {
  const t = localStorage.getItem("rempart-theme");
  if (t === "light" || t === "dark") document.querySelector('meta[name="color-scheme"]').content = t;
} catch {}
