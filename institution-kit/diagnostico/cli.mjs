#!/usr/bin/env node
// Diagnóstico de un emisor desde la terminal. El mismo motor que la página
// /diagnostico/<enlace>, pensado para el kit de instituciones: una institución
// puede correrlo contra su propio entorno de pruebas antes de pedirnos nada.
//
// Uso:
//   node diagnostico/cli.mjs <metadata_url> [--as <servidor>] [--muestra <fichero.json>] [--json]
//
//   --as        servidor de autorización esperado (por defecto Cuenta Única)
//   --muestra   credencial emitida CON DATOS DE PRUEBA, para las comprobaciones
//               de orden de contextos, cobertura real y firma (11a-11f) y para la
//               12, la lista de estado (revocación) que declara. Se lee y se olvida.
//   --json      salida en JSON, para encadenar con otras herramientas
//   --privadas  permite consultar direcciones privadas (entornos internos)
//
// Sale con código 1 si hay algún bloqueante, 0 si no. Requiere Node 22, sin
// dependencias.
import { readFile } from "node:fs/promises";
import { diagnosticar, evaluarMuestra, estadoSinMuestra, veredictoMuestra, resumenGeneral, AS_CUENTA_UNICA, OK, FALLA, AVISO } from "./motor.mjs";
import { crearRed } from "./red.mjs";

const args = process.argv.slice(2);
const opcion = (n) => { const i = args.indexOf(n); return i >= 0 ? args.splice(i, 2)[1] : null; };
const bandera = (n) => { const i = args.indexOf(n); if (i >= 0) args.splice(i, 1); return i >= 0; };
const as = opcion("--as") ?? AS_CUENTA_UNICA;
const muestra = opcion("--muestra");
const comoJson = bandera("--json");
const privadas = bandera("--privadas");
const url = args[0];
if (!url || !/^https:\/\//.test(url)) {
  console.error("uso: node diagnostico/cli.mjs <metadata_url https> [--as <servidor>] [--muestra <fichero.json>] [--json]");
  process.exit(2);
}

const red = crearRed({ espera: Number(process.env.ESPERA ?? 8000), permitirPrivadas: privadas });
const r = await diagnosticar({ metadata_url: url, as_esperado: as }, { red });
let m = null;
if (muestra) m = await evaluarMuestra(await readFile(muestra, "utf8"), { red, base: r });

const vm = m && !m.error ? veredictoMuestra(m) : null;
const total = resumenGeneral(r, vm ? m : null);
if (comoJson) {
  // `estado` es la comprobación 12 y sale SIEMPRE: evaluada (la misma que `muestra.estado`) si hay muestra, y
  // «no evaluable» si no la hay, para que quien lee el JSON la vea. `resumen` es el «N/12».
  console.log(JSON.stringify({ ...r, muestra: m, estado: m && !m.error ? m.estado : estadoSinMuestra(), resumen: total }, null, 2));
} else {
  const ICONO = { ok: "✅", falla: "❌", aviso: "⚠️ ", pendiente: "⏸ " };
  const tty = process.stdout.isTTY;
  const gris = (s) => (tty ? `\x1b[2m${s}\x1b[0m` : s);
  const fuerte = (s) => (tty ? `\x1b[1m${s}\x1b[0m` : s);
  const pinta = (c, n) => {
    console.log(`${ICONO[c.estado]} ${fuerte(`${n}. ${c.titulo}`)}`);
    console.log(`   ${c.resumen}`);
    if (c.accion) console.log(`   → ${c.accion}`);
    for (const d of c.detalles) console.log(gris(`     · ${d}`));
  };
  console.log(fuerte(`Diagnóstico de ${url}`));
  console.log(gris(`${new Date(r.momento).toISOString()} · ${r.duracion} ms`));
  console.log(`\n${fuerte(r.veredicto.texto)}\n`);
  r.comprobaciones.forEach((c) => pinta(c, c.n));
  if (m?.error) console.log(`\n❌ Credencial de muestra: ${m.error}`);
  else if (m) {
    console.log(`\n${fuerte("Credencial de muestra (11a-11f y 12)")} ${gris(`(${m.bytes} bytes, procesada en memoria)`)}`);
    console.log(fuerte(vm.texto) + "\n");
    m.comprobaciones.forEach((c, i) => pinta(c, `11${"abcdef"[i]}`));
    pinta(m.estado, m.estado.n);
  }
  console.log(`\n${fuerte(`Comprobaciones resueltas: ${total.texto}`)}${total.doce_evaluada ? "" : gris(" · la 12 (lista de estado) necesita --muestra")}`);
}
// Se vacía la salida ANTES de salir: con `process.exit` a secas, una tubería (`cli.mjs --json | jq`) puede quedarse con
// la salida cortada a medias (visto en macOS con el JSON de más de unos KB).
const codigo = r.veredicto.falla || vm?.falla ? 1 : 0;
process.stdout.write("", () => process.exit(codigo));
