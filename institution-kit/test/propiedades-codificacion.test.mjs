// T8 · K4 (media): INSTITUTION_DISPLAY_NAME con acentos salía como mojibake en la metadata, y con «'» rompía el mapa SpEL.
// Java (y Spring Boot) leen los .properties como ISO-8859-1: el generador escribe los no ASCII como \uXXXX y escapa
// la comilla simple del literal SpEL; lo que no se puede escapar con seguridad se rechaza.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { prepararEntorno } from "./helpers/entorno.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const HAY_JAVA = spawnSync("java", ["-version"], { encoding: "utf8" }).status === 0;

// Cargador de .properties de Java, en pequeño: ISO-8859-1, líneas con «\» final, escapes \uXXXX, \\, \n, \t…
function cargarProperties(buf) {
  const texto = buf.toString("latin1");
  const props = {};
  const lineas = texto.split(/\r?\n/);
  for (let i = 0; i < lineas.length; i++) {
    let l = lineas[i].replace(/^\s+/, "");
    if (!l || l.startsWith("#") || l.startsWith("!")) continue;
    while (/(^|[^\\])(\\\\)*\\$/.test(l) && i + 1 < lineas.length) l = l.slice(0, -1) + lineas[++i].replace(/^\s+/, "");
    const m = l.match(/^((?:\\.|[^=:\s\\])+)\s*[=:\s]\s*(.*)$/s);
    if (!m) continue;
    const desescapa = (s) => s.replace(/\\u([0-9a-fA-F]{4})|\\(.)/gs, (_, u, c) => (u ? String.fromCharCode(parseInt(u, 16)) : ({ n: "\n", t: "\t", r: "\r", f: "\f" }[c] ?? c)));
    props[desescapa(m[1])] = desescapa(m[2]);
  }
  return props;
}

// Recorre el valor del mapa SpEL y devuelve el texto de cada literal entre comillas simples (con «''» = «'»).
function literalesSpel(valor) {
  const lits = [];
  for (let i = 0; i < valor.length; i++) {
    if (valor[i] !== "'") continue;
    let s = "";
    for (i++; i < valor.length; i++) {
      if (valor[i] === "'" && valor[i + 1] === "'") { s += "'"; i++; continue; }
      if (valor[i] === "'") break;
      s += valor[i];
    }
    assert.ok(i < valor.length, `literal sin cerrar en: ${valor}`);
    lits.push(s);
  }
  return lits;
}

// Las líneas que Java interpreta (las de comentario pueden llevar acentos: no se leen).
const sinComentarios = (buf) => Buffer.from(buf.toString("latin1").split("\n").filter((l) => !l.trim().startsWith("#")).join("\n"), "latin1");
const displayDe = (props) => props["mosip.certify.credential-config.issuer.display"];
const generar = (nombre) => prepararEntorno({ extra: { INSTITUTION_DISPLAY_NAME: nombre } });

describe("K4 · INSTITUTION_DISPLAY_NAME en las properties", () => {
  test("«Dirección General de Migración»: el fichero es ASCII puro y, leído como Java, recupera el nombre exacto", () => {
    const e = generar("Dirección General de Migración");
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const buf = readFileSync(e.rutas.propiedadesDefault);
      assert.ok(sinComentarios(buf).every((b) => b < 0x80), "ningún byte no ASCII en las líneas con valores");
      const t = buf.toString("latin1");
      assert.match(t, /Direcci\\u00F3n General de Migraci\\u00F3n/i);
      const lits = literalesSpel(displayDe(cargarProperties(buf)));
      assert.deepEqual(lits, ["name", "Dirección General de Migración", "locale", "es"]);
      assert.doesNotMatch(sinComentarios(buf).toString("latin1"), /Ã|Â/, "ni mojibake");
    } finally { e.limpiar(); }
  });

  test("Java real (java.util.Properties, ISO-8859-1) lee el mismo valor", { skip: !HAY_JAVA && "no hay java" }, () => {
    const e = generar("Dirección General de Migración");
    try {
      const r = spawnSync("java", [join(AQUI, "helpers", "Props.java"), e.rutas.propiedadesDefault, "mosip.certify.credential-config.issuer.display"], { encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(literalesSpel(r.stdout.replace(/\s+/g, " ")), ["name", "Dirección General de Migración", "locale", "es"]);
    } finally { e.limpiar(); }
  });

  test("«Ministerio d'Obras Públicas»: la comilla se duplica y el mapa SpEL sigue cerrando bien", () => {
    const e = generar("Ministerio d'Obras Públicas");
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const buf = readFileSync(e.rutas.propiedadesDefault);
      const valor = displayDe(cargarProperties(buf));
      assert.match(valor, /d''Obras/);
      assert.deepEqual(literalesSpel(valor), ["name", "Ministerio d'Obras Públicas", "locale", "es"]);
      // Estructura: {{ 'name': '…', 'locale': 'es' }} sin nada más fuera de los literales.
      const fuera = valor.replace(/'(?:[^']|'')*'/g, "''").replace(/\s+/g, "");
      assert.equal(fuera, "{{'':'','':''}}");
    } finally { e.limpiar(); }
  });

  test("caracteres fuera del plano básico (emoji): par sustituto \\uD83D\\uDE00", () => {
    const e = generar("Instituto 😀");
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const buf = readFileSync(e.rutas.propiedadesDefault);
      assert.ok(sinComentarios(buf).every((b) => b < 0x80));
      assert.match(buf.toString("latin1"), /\\uD83D\\uDE00/i);
      assert.deepEqual(literalesSpel(displayDe(cargarProperties(buf))), ["name", "Instituto 😀", "locale", "es"]);
    } finally { e.limpiar(); }
  });

  test("un nombre ASCII queda tal cual (sin escapes innecesarios)", () => {
    const e = generar("Instituto Nacional de Prueba");
    try {
      assert.match(readFileSync(e.rutas.propiedadesDefault, "utf8"), /'name': 'Instituto Nacional de Prueba'/);
    } finally { e.limpiar(); }
  });

  for (const [nombre, valor] of [
    ["una barra invertida", "Instituto \\ Nacional"],
    ["«${…}» (Spring lo resolvería)", "Instituto ${HOME}"],
    ["un «$» suelto", "Instituto $ Nacional"],
    ["una llave «}»", "Instituto } Nacional"],
    ["una llave «{»", "Instituto { Nacional"],
    ["un salto de línea", "Instituto\nNacional"],
    ["un tabulador", "Instituto\tNacional"],
  ]) {
    test(`se rechaza ${nombre}, con mensaje que nombra la variable, y no genera nada`, () => {
      const e = generar(valor);
      try {
        assert.notEqual(e.salida.status, 0, "debía fallar");
        assert.match(e.salida.stderr, /INSTITUTION_DISPLAY_NAME/);
        assert.equal(e.existe("propiedadesDefault"), false);
      } finally { e.limpiar(); }
    });
  }

  test("UTF-8 inválido en el nombre: error claro, sin mojibake en silencio", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const r = e.ejecutar('source scripts/lib/common.sh; spel_properties_literal "$(printf "Instituto \\377 X")"');
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /UTF-8/);
    } finally { e.limpiar(); }
  });
});
