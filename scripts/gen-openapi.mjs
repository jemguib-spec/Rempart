// gen-openapi.mjs - produit web/static/openapi.json depuis web/static/api-spec.js.
// Usage, à la racine du dépôt : node scripts/gen-openapi.mjs
// (à relancer après toute modification d'api-spec.js).
import { writeFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const { GROUPS, SCOPES } = await import(pathToFileURL(join(root, "web/static/api-spec.js")).href);

const schemaOf = (v) => {
  if (Array.isArray(v)) return { type: "array", items: v.length ? schemaOf(v[0]) : {} };
  if (v === null) return { nullable: true };
  if (typeof v === "object") return { type: "object", properties: Object.fromEntries(Object.entries(v).map(([k, x]) => [k, schemaOf(x)])) };
  if (typeof v === "number") return { type: Number.isInteger(v) ? "integer" : "number" };
  return { type: typeof v };
};

const paths = {};
for (const g of GROUPS) for (const e of g.endpoints) {
  const params = [...(e.params || [])];
  for (const m of e.p.matchAll(/\{(\w+)\}/g)) if (!params.some((p) => p.n === m[1])) params.push({ n: m[1], in: "path", req: true });
  const op = {
    tags: [g.title],
    summary: e.sum,
    description: [e.text, `Portée : ${e.scope} — ${SCOPES[e.scope].text}`].filter(Boolean).join("\n\n"),
    operationId: (e.m.toLowerCase() + e.p).replace(/[{}]/g, "").replace(/[^a-z0-9]+/gi, "_"),
    "x-rempart-scope": e.scope,
    parameters: params.map((p) => ({ name: p.n, in: p.in, required: !!(p.req || p.in === "path"), description: p.d, schema: { type: "string" }, example: p.ex || undefined })),
    responses: {
      200: e.file ? { description: "Archive", content: { "application/gzip": { schema: { type: "string", format: "binary" } } } }
        : e.raw ? { description: "Texte", content: { "text/plain": { schema: { type: "string" } } } }
        : { description: "Succès", content: { "application/json": e.resp !== undefined ? { schema: schemaOf(e.resp), example: e.resp } : { schema: { type: "object" } } } },
      400: { $ref: "#/components/responses/Error" }, 401: { $ref: "#/components/responses/Error" }, 403: { $ref: "#/components/responses/Error" },
    },
    security: e.scope === "public" ? [] : e.scope === "session" || e.scope === "local" ? [{ session: [] }] : [{ bearer: [] }, { session: [] }],
  };
  if (e.body !== undefined) op.requestBody = { required: true, content: { "application/json": { schema: schemaOf(e.body), example: e.body } } };
  const key = e.p.replace(/^\/metrics$/, "/metrics");
  (paths[key] ||= {})[e.m.toLowerCase()] = op;
}

const doc = {
  openapi: "3.0.3",
  info: { title: "API Rempart DNS", version: "1.1", description: "API REST de Rempart. Session (cookie rempart_session + en-tête X-Rempart: 1 sur les requêtes qui modifient) ou jeton porteur rmp_…. Les champs inconnus sont refusés (400)." },
  servers: [{ url: "/" }],
  tags: GROUPS.map((g) => ({ name: g.title, description: g.text })),
  paths,
  components: {
    securitySchemes: {
      bearer: { type: "http", scheme: "bearer", description: "Jeton rmp_… créé dans Sécurité → Accès API ou par POST /api/tokens." },
      session: { type: "apiKey", in: "cookie", name: "rempart_session", description: "Cookie posé par POST /api/login." },
    },
    responses: { Error: { description: "Erreur", content: { "application/json": { schema: { type: "object", properties: { error: { type: "string" } } } } } } },
  },
};
writeFileSync(join(root, "web/static/openapi.json"), JSON.stringify(doc, null, 2) + "\n");
console.log(`openapi.json : ${Object.values(paths).reduce((n, p) => n + Object.keys(p).length, 0)} opérations`);
