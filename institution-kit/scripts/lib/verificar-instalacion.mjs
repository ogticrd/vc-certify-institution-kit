#!/usr/bin/env node
// Verificación de una instalación del kit contra su URL pública (R8, D4). Lo ejecuta
// scripts/verify-install.sh, con `node` local o dentro de `node:22-alpine`.
//
//   node scripts/lib/verificar-instalacion.mjs --url <https://…/.well-known/openid-credential-issuer>
//        --as <servidor de autorización> [--muestra <credencial-muestra.json>]
//        [--privadas auto|si|no]
//
// QUÉ HACE. Es un envoltorio: NO reimplementa el diagnóstico de OGTIC. Ejecuta el
// `diagnostico/cli.mjs` vendorizado, sin modificarlo, con `--json`, y presenta su informe en
// español, una línea por comprobación. Encima añade lo que el motor no cubre:
//
//   - Cobertura de firma de la credencial de muestra del kit (generated/credencial-muestra.json).
//     `cli.mjs --muestra` no sirve: `evaluarMuestra` exige `proof` (una credencial FIRMADA) y la
//     muestra del kit va sin firma, porque la firma la pone Certify al emitir. Se expande con
//     `jsonld.mjs`, igual que el motor (valores marcadores: no hace falta ningún valor real) y
//     que la prueba de T2, cargando los contextos por su URL pública, como un verificador.
//   - Que el `@context` que publica la metadata esté completo (W3C + propio + suite). El motor
//     añade la suite por su cuenta al medir la cobertura (comprobación 8), así que no avisa si la
//     metadata no la lista.
//
// Y una política del kit: el motor da AVISO (no FALLA) a un logo que no es PNG y a un contexto sin
// `Cache-Control: no-cache`; R8 los exige, así que aquí cuentan como FALLA.
//
// `cli.mjs` no admite `hostsInternos` (solo `server.mjs` lo lee de HOSTS_INTERNOS): su equivalente
// por línea de comandos es `--privadas`, que se activa en `auto` cuando la URL pública resuelve a
// una dirección privada o de bucle (el propio servidor, un proxy interno).
//
// Nunca se imprime un valor de la credencial de muestra: solo nombres de campo y recuentos.
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { mkdtempSync, openSync, closeSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import dns from "node:dns";
import net from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { crearRed, esPrivada } from "../../diagnostico/red.mjs";
import { canonizarDocumento } from "../../diagnostico/jsonld.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const CLI = join(AQUI, "..", "..", "diagnostico", "cli.mjs");
const V1 = "https://www.w3.org/2018/credentials/v1";
const V2 = "https://www.w3.org/ns/credentials/v2";
const ED2020 = "https://w3id.org/security/suites/ed25519-2020/v1";
const AJENOS = /^https:\/\/(www\.w3\.org|w3id\.org)\//;
const MAX_MUESTRA = 64 * 1024;
// Comprobaciones del motor cuyo AVISO el kit trata como FALLA (R8: logo PNG, contexto con no-cache).
const AVISO_ES_FALLA = new Set(["logo", "contextos"]);

const OK = "ok", FALLA = "falla", AVISO = "aviso", PENDIENTE = "pendiente";
const ETIQUETA = { [OK]: "OK", [FALLA]: "FALLA", [AVISO]: "AVISO", [PENDIENTE]: "PENDIENTE" };

// --- argumentos ---------------------------------------------------------------------
const args = process.argv.slice(2);
const opcion = (n) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : null; };
const url = opcion("--url");
const as = opcion("--as");
const muestra = opcion("--muestra");
const modoPrivadas = opcion("--privadas") ?? "auto";
if (!url || !as || !["auto", "si", "no"].includes(modoPrivadas) || args.length) {
  console.error("uso: node verificar-instalacion.mjs --url <metadata_url> --as <servidor> [--muestra <fichero>] [--privadas auto|si|no]");
  process.exit(2);
}

// --- ayudas -------------------------------------------------------------------------
const recortar = (s, n = 200) => { const t = String(s ?? "").replace(/\s+/g, " ").trim(); return t.length > n ? t.slice(0, n - 1) + "…" : t; };
const comoLista = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);

function resolverPrivada(host) {
  const literal = host.replace(/^\[|\]$/g, "");
  if (net.isIP(literal)) return Promise.resolve(esPrivada(literal));
  return new Promise((ok) => dns.lookup(host, { all: true }, (err, dirs) => ok(!err && dirs.some((d) => esPrivada(d.address)))));
}

// OJO: la salida de `cli.mjs --json` NO se lee por una tubería. cli.mjs termina con
// `console.log(JSON…)` seguido de `process.exit()`, y con stdout en una tubería el proceso puede salir
// antes de vaciarla: medido en macOS, el informe llega cortado en 8192 bytes (JSON inválido). En un
// fichero la escritura es síncrona y no se pierde nada. Se arregla en el origen con
// `process.exitCode = …` en vez de `process.exit(…)`; mientras tanto, un fichero temporal.
function ejecutarCli(argumentos) {
  return new Promise((resolver) => {
    const dir = mkdtempSync(join(tmpdir(), "verificar-"));
    const ruta = join(dir, "informe.json");
    const fd = openSync(ruta, "w");
    const limpiar = () => { try { closeSync(fd); } catch {} };
    const p = spawn(process.execPath, [CLI, ...argumentos], { env: process.env, stdio: ["ignore", fd, "pipe"] });
    const error = [];
    p.stderr.on("data", (b) => error.push(b));
    const fin = (codigo, extra = "") => {
      limpiar();
      let stdout = "";
      try { stdout = readFileSync(ruta, "utf8"); } catch {}
      rmSync(dir, { recursive: true, force: true });
      resolver({ codigo, stdout, stderr: Buffer.concat(error).toString("utf8") + extra });
    };
    p.on("error", (e) => fin(-1, String(e.message)));
    p.on("close", (codigo) => fin(codigo));
  });
}

const T_CTX = "El @context de la metadata está completo (W3C, propio y suite)";
const T_COB = "Cobertura de firma sobre la credencial de muestra";
const lineas = [];
const filas = []; // {rotulo, estado, titulo, resumen, accion, detalles}
const fila = (rotulo, estado, titulo, resumen, accion = null, detalles = []) => filas.push({ rotulo, estado, titulo, resumen, accion, detalles: detalles.filter(Boolean) });

// --- 1. el motor ---------------------------------------------------------------------
let informe = null;
let privadas = modoPrivadas === "si";
{
  const argumentos = [url, "--as", as, "--json"];
  if (modoPrivadas === "auto") {
    let host = "";
    try { host = new URL(url).hostname; } catch {}
    privadas = host ? await resolverPrivada(host) : false;
  }
  if (privadas) argumentos.push("--privadas");
  lineas.push(`Direcciones privadas: ${!privadas ? "no permitidas" : modoPrivadas === "si" ? "permitidas (indicado)" : "permitidas (la URL pública resuelve a una dirección privada: el propio servidor o una red interna)"}`);

  const r = await ejecutarCli(argumentos);
  try { informe = JSON.parse(r.stdout); } catch { informe = null; }
  if (!informe || !Array.isArray(informe.comprobaciones)) {
    const motivo = r.codigo === 2 ? "la URL no es https (el motor solo diagnostica por https)" : `el motor no produjo un informe (código ${r.codigo})`;
    fila("1", FALLA, "El diagnóstico se ejecutó", `${motivo}.`,
      "Compruebe CERTIFY_PUBLIC_URL (https://…) y que este servidor llegue a esa URL.", [r.stderr ? `Salida de error: ${recortar(r.stderr)}` : null]);
  } else {
    for (const c of informe.comprobaciones) {
      let estado = c.estado;
      let resumen = c.resumen;
      if (estado === AVISO && AVISO_ES_FALLA.has(c.id)) { estado = FALLA; resumen = resumen.replace(/\.$/, "") + " (el kit lo exige: R8)."; }
      fila(String(c.n), estado, c.titulo, resumen, c.accion, c.detalles);
    }
  }
}

const estadoDe = (id) => informe?.comprobaciones?.find((c) => c.id === id)?.estado ?? null;
const sinMetadata = !informe || ![OK, AVISO].includes(estadoDe("metadata"));

// --- 2. el @context de la metadata y el credential_endpoint ----------------------------
const red = crearRed({ espera: Number(process.env.ESPERA ?? 8000), permitirPrivadas: privadas });
let credentialEndpoint = null;
{
  const titulo = T_CTX;
  let wk = null;
  if (!sinMetadata) {
    try {
      const r = await red.traer(url);
      if (r.estado === 200) wk = JSON.parse(r.cuerpo.toString("utf8"));
    } catch { wk = null; }
  }
  if (!wk || typeof wk !== "object" || !wk.credential_configurations_supported) {
    fila("+", PENDIENTE, titulo, "Depende de la comprobación 1: sin metadata no se puede evaluar.");
  } else {
    credentialEndpoint = typeof wk.credential_endpoint === "string" ? wk.credential_endpoint : null;
    const problemas = [];
    let evaluadas = 0;
    for (const [nombre, c] of Object.entries(wk.credential_configurations_supported)) {
      if (c?.format !== "ldp_vc") continue;
      evaluadas++;
      const def = c.credential_definition ?? {};
      const contextos = comoLista(def["@context"]);
      const tipos = comoLista(def.type);
      const cadenas = contextos.filter((x) => typeof x === "string");
      if (!cadenas.includes(V2) && !cadenas.includes(V1)) problemas.push(`${nombre}: falta el contexto de W3C (${V2})`);
      if (!cadenas.includes(ED2020)) problemas.push(`${nombre}: falta el contexto de la suite de firma (${ED2020})`);
      if (!cadenas.some((x) => !AJENOS.test(x))) problemas.push(`${nombre}: falta el contexto propio de la institución (…/contextos/<clave>.json)`);
      if (!tipos.includes("VerifiableCredential")) problemas.push(`${nombre}: falta el tipo VerifiableCredential`);
    }
    if (!evaluadas) fila("+", OK, titulo, "No hay credenciales ldp_vc: no aplica.");
    else if (problemas.length) fila("+", FALLA, titulo, `${problemas[0]}.`,
      "Revise el contexto de la credencial (scripts/apply-credential.sh) y reinicie Certify, que guarda la configuración en caché.", problemas.slice(1));
    else fila("+", OK, titulo, `${evaluadas} ${evaluadas === 1 ? "credencial publica" : "credenciales publican"} el contexto de W3C, el propio y el de la suite.`);
  }
}

// --- 3. cobertura de firma de la muestra ------------------------------------------------
{
  const titulo = T_COB;
  const pendiente = estadoDe("contextos") === FALLA || estadoDe("metadata") === FALLA || !informe;
  let texto = null;
  try {
    if (!muestra) throw Object.assign(new Error("sin muestra"), { sinMuestra: true });
    texto = await readFile(muestra, "utf8");
  } catch (e) {
    fila("+", FALLA, titulo, e.sinMuestra ? "No se indicó la credencial de muestra." : "No se pudo leer generated/credencial-muestra.json.",
      "Ejecute scripts/generate-config.sh: genera la muestra junto con el contexto.");
    texto = null;
  }
  if (texto !== null) {
    let vc = null;
    if (Buffer.byteLength(texto, "utf8") > MAX_MUESTRA) fila("+", FALLA, titulo, `La muestra supera ${MAX_MUESTRA / 1024} KB.`);
    else {
      try { vc = JSON.parse(texto); } catch { fila("+", FALLA, titulo, "La credencial de muestra no es JSON válido.", "Regénerela con scripts/generate-config.sh."); }
    }
    if (vc) {
      const sujeto = vc.credentialSubject;
      const ctx = comoLista(vc["@context"]);
      if (!sujeto || typeof sujeto !== "object" || Array.isArray(sujeto) || !ctx.length) {
        fila("+", FALLA, titulo, "La muestra no tiene @context o credentialSubject (objeto).", "Regénerela con scripts/generate-config.sh.");
      } else {
        const problemas = [];
        if (ctx[0] !== V1 && ctx[0] !== V2) problemas.push("el primer @context no es el de W3C");
        if (!ctx.includes(ED2020)) problemas.push("falta el contexto de la suite de firma");
        const nombres = Object.keys(sujeto).filter((k) => k !== "id" && k !== "type");
        const marca = (i) => `__valor_${i}__`;
        // Se firma lo que sobrevive a la expansión: cada atributo lleva un valor marcador y se
        // mira cuáles aparecen como objeto de alguna cuádrupla. Los valores reales no se usan.
        const doc = { ...vc, credentialSubject: { ...(sujeto.id !== undefined ? { id: sujeto.id } : {}), ...Object.fromEntries(nombres.map((a, i) => [a, marca(i)])) } };
        delete doc.proof;
        const cargar = async (u) => {
          const r = await red.traer(u);
          if (r.estado !== 200) throw new Error(`${u} responde ${r.estado}`);
          try { return JSON.parse(r.cuerpo.toString("utf8")); } catch { throw new Error(`${u} no es JSON`); }
        };
        let r = null, error = null;
        try { r = await canonizarDocumento(doc, { cargar }); } catch (e) { error = e; }
        if (error) {
          if (pendiente) fila("+", PENDIENTE, titulo, "Depende de las comprobaciones 1 y 7: no se puede descargar algún @context.");
          else fila("+", FALLA, titulo, `No se pudo expandir la credencial de muestra: ${recortar(error.message, 160)}.`,
            "Revise que todos sus contextos se puedan descargar y sean compatibles entre sí.");
        } else {
          const cubiertos = nombres.filter((_, i) => r.cuads.some((q) => q.o.tipo === "literal" && q.o.valor === marca(i)));
          const fuera = nombres.filter((a) => !cubiertos.includes(a));
          const otros = [...new Set(r.descartados.map((d) => d.termino))].filter((t) => !nombres.includes(t) && t !== "id" && t !== "type");
          const detalles = [
            fuera.length ? `No firmados: ${fuera.join(", ")}` : `Atributos firmados: ${nombres.join(", ")}`,
            otros.length ? `Fuera de credentialSubject también se descartan: ${otros.join(", ")}` : null,
            ...problemas.map((p) => `✗ ${p}`),
          ];
          if (!nombres.length) fila("+", FALLA, titulo, "La muestra no tiene atributos en credentialSubject.");
          else if (fuera.length || problemas.length) fila("+", FALLA, titulo,
            fuera.length ? `${cubiertos.length} de ${nombres.length} atributos firmados: la firma NO cubre ${fuera.length === 1 ? "uno" : "algunos"}.` : `${problemas[0]}.`,
            fuera.length ? "Defina esos atributos en el contexto propio, con el mismo nombre, y publíquelo en una URL nueva (clave nueva)." : "Corrija la plantilla de la credencial (scripts/apply-credential.sh).",
            detalles);
          else fila("+", OK, titulo, `${cubiertos.length} de ${nombres.length} atributos firmados (cobertura 100 %): ${nombres.join(", ")}.`);
        }
      }
    }
  }
}

// --- salida ---------------------------------------------------------------------------------
const total = informe?.comprobaciones?.length ?? 11;
const diagnostico = filas.filter((f) => f.rotulo !== "+");
const extras = filas.filter((f) => f.rotulo === "+");
const cuenta = (e) => filas.filter((f) => f.estado === e).length;
const okDiagnostico = diagnostico.filter((f) => f.estado === OK).length;

console.log(`Verificación de la instalación: ${url}`);
console.log(`Servidor de autorización esperado: ${as}`);
for (const l of lineas) console.log(l);
if (credentialEndpoint) console.log(`credential_endpoint: ${credentialEndpoint}`);
console.log("");
for (const f of [...diagnostico, ...extras]) {
  console.log(`${f.rotulo.padStart(3)}. ${ETIQUETA[f.estado].padEnd(9)} ${f.titulo}: ${f.resumen}`);
  if (f.estado !== OK) {
    if (f.accion) console.log(`       -> ${f.accion}`);
    for (const d of f.detalles.slice(0, 12)) console.log(`       · ${d}`);
  }
}
console.log("");
// Orden de las filas extra en el resumen: primero la cobertura, luego el @context de la metadata.
const extraOrden = [[T_COB, "+cobertura"], [T_CTX, "+@context de la metadata"]]
  .map(([t, nombre]) => [extras.find((f) => f.titulo === t), nombre]).filter(([f]) => f)
  .map(([f, nombre]) => `${nombre} ${ETIQUETA[f.estado]}`);
console.log(`Resumen: ${okDiagnostico}/${total} (${extraOrden.join(", ")}) · FALLA ${cuenta(FALLA)} · AVISO ${cuenta(AVISO)} · PENDIENTE ${cuenta(PENDIENTE)}`);
if (cuenta(FALLA)) console.log(`Resultado: la verificación FALLÓ (${cuenta(FALLA)} ${cuenta(FALLA) === 1 ? "comprobación" : "comprobaciones"}).`);
else if (cuenta(PENDIENTE)) console.log("Resultado: sin fallas, pero hay comprobaciones que no se pudieron evaluar.");
else console.log("Resultado: la instalación pasa la verificación.");
process.exit(cuenta(FALLA) ? 1 : 0);
