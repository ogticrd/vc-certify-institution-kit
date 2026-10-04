// T8 · la documentación de T7 no se queda desfasada: la comprobación manual de T7 («33/33 variables de .env.example
// documentadas») pasa a ser una prueba, y las variables y mensajes que la subsanación retiró no siguen apareciendo como vigentes.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { KIT_ORIGEN } from "./helpers/entorno.mjs";

const leer = (...r) => readFileSync(join(KIT_ORIGEN, ...r), "utf8");
const GUIA = leer("docs", "02-GUIA-DE-INSTALACION.md");
const CHANGELOG = leer("CHANGELOG.md");
const README = leer("README.md");

describe("la guía documenta cada variable de .env.example", () => {
  const variables = [...new Set([...leer(".env.example").matchAll(/^#? ?([A-Z][A-Z0-9_]+)=/gm)].map((m) => m[1]))];
  test("hay variables que comprobar", () => assert.ok(variables.length >= 30, `${variables.length}`));
  for (const v of variables) {
    test(`${v} tiene su fila en la tabla 4.1`, () => assert.match(GUIA, new RegExp(`^\\| \`${v}\``, "m")));
  }
});

describe("variables de uso avanzado que el código lee están en la guía", () => {
  for (const v of ["KIT_FORZAR_CONTEXTO", "KIT_PERMITIR_HTTP", "NODE_EXTRA_CA_CERTS", "NO_REGENERAR", "DRY_RUN", "KIT_NODE", "VERIFY_PRIVADAS", "KIT_FORCE_DOCKER"]) {
    test(`${v}`, () => assert.match(GUIA, new RegExp(`^\\| \`${v}[=\`]`, "m")));
  }
});

describe("lo que la subsanación retiró no queda como vigente", () => {
  test("KIT_CONSERVAR_SECRETOS_POR_DEFECTO solo aparece para decir que ya no existe", () => {
    for (const [nombre, texto] of [["guía", GUIA], ["CHANGELOG", CHANGELOG], ["README", README], [".env.example", leer(".env.example")]]) {
      for (const linea of texto.split("\n").filter((l) => l.includes("KIT_CONSERVAR_SECRETOS_POR_DEFECTO"))) {
        assert.match(linea, /ya no existe|desaparece|se ignora/i, `${nombre}: ${linea.slice(0, 120)}`);
      }
    }
  });
  test("la guía ya no dice que las properties llevan contraseñas ni que `docker compose down` deja la base atrás", () => {
    assert.doesNotMatch(GUIA, /properties contienen contraseñas/);
    assert.doesNotMatch(GUIA, /no declara un volumen con nombre/);
    assert.doesNotMatch(GUIA, /no use `docker compose down`/i);
    assert.doesNotMatch(GUIA, /Hoy tienen permisos de lectura para todos/);
  });
  test("la guía describe el comportamiento nuevo: huella del contexto, reinicio automático, lista blanca, volumen con nombre", () => {
    assert.match(GUIA, /contexto nuevo = clave nueva/i);
    assert.match(GUIA, /\.sha256/);
    assert.match(GUIA, /KIT_FORZAR_CONTEXTO/);
    assert.match(GUIA, /Certify se reinicia solo/);
    assert.match(GUIA, /lista blanca/i);
    assert.match(GUIA, /pgdata/);
    assert.match(GUIA, /rotarlas a mano/);
  });
  test("el CHANGELOG cita lo que no se pudo probar", () => {
    assert.match(CHANGELOG, /no ha podido ejecutarse con Docker, Caddy ni Certify reales/);
  });
});

describe("cada script o fichero que citan los documentos existe", () => {
  const recorre = (d, acc = []) => { for (const n of readdirSync(d)) { const r = join(d, n); statSync(r).isDirectory() ? recorre(r, acc) : acc.push(r); } return acc; };
  const existentes = new Set(recorre(KIT_ORIGEN).map((r) => r.slice(KIT_ORIGEN.length + 1)));
  test("los scripts/*.sh citados", () => {
    for (const s of new Set([...(GUIA + CHANGELOG + README).matchAll(/scripts\/([a-z0-9-]+\.(?:sh|mjs))/g)].map((m) => m[1]))) {
      assert.ok(existentes.has(`scripts/${s}`), `scripts/${s}`);
    }
  });
});
