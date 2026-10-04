// T8 · K5 (alta) y T7-1: el contexto JSON-LD publicado es INMUTABLE. «Contexto nuevo = clave nueva».
// Medido por la evaluación adversarial: cambiar CREDENTIAL_ATTRIBUTES y volver a generar sobrescribía
// generated/contextos/<clave>.json (Caddy lo sirve al instante, también con DRY_RUN=1) y las credenciales ya
// emitidas dejaban de verificar sin que nadie lo notara; apply-credential.sh no reiniciaba Certify (caché 3600 s).
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, readdirSync, statSync, rmSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { join } from "node:path";
import { prepararEntorno } from "./helpers/entorno.mjs";

const sha = (b) => createHash("sha256").update(b).digest("hex");
const CLAVE = "PruebaLicencia";
const contexto = (e) => join(e.generated, "contextos", `${CLAVE}.json`);
const huellaDe = (e) => join(e.generated, "contextos", `${CLAVE}.sha256`);
const generar = (e, extra = {}) => e.ejecutar('bash "$PWD/scripts/generate-config.sh"', extra);
// Cambia una variable del .env (el arnés escribe KEY="valor").
function cambiarEnv(e, clave, valor) {
  const ruta = join(e.kit, ".env");
  const t = readFileSync(ruta, "utf8").split("\n").filter((l) => !l.startsWith(`${clave}=`)).join("\n");
  writeFileSync(ruta, `${t}\n${clave}="${valor}"\n`);
}
const foto = (dir) => Object.fromEntries(readdirSync(dir).map((n) => [n, readFileSync(join(dir, n), "utf8")]));

describe("K5 · huella del contexto publicado", () => {
  test("la primera generación escribe <clave>.json y <clave>.sha256 (formato sha256sum, con la huella real)", () => {
    const e = prepararEntorno();
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.ok(existsSync(contexto(e)) && existsSync(huellaDe(e)));
      const linea = readFileSync(huellaDe(e), "utf8");
      assert.equal(linea, `${sha(readFileSync(contexto(e)))}  ${CLAVE}.json\n`);
    } finally { e.limpiar(); }
  });

  test("segunda ejecución con la MISMA lista de atributos: ok y los ficheros no cambian (ni el contenido ni la fecha)", () => {
    const e = prepararEntorno();
    try {
      const antes = foto(join(e.generated, "contextos"));
      const m1 = statSync(contexto(e)).mtimeMs;
      const r = generar(e);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(foto(join(e.generated, "contextos")), antes);
      assert.equal(statSync(contexto(e)).mtimeMs, m1, "no se reescribió");
    } finally { e.limpiar(); }
  });

  test("segunda ejecución con atributos DISTINTOS: falla con «contexto nuevo = clave nueva» y no toca nada publicado", () => {
    const e = prepararEntorno();
    try {
      const antes = foto(join(e.generated, "contextos"));
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      const r = generar(e);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /contexto nuevo = clave nueva/i);
      assert.match(r.stderr, /CREDENTIAL_CONFIG_KEY_ID/);
      assert.match(r.stderr, /inactive/);
      assert.match(r.stderr, /KIT_FORZAR_CONTEXTO=1/);
      assert.match(r.stderr, /PruebaLicencia/);
      assert.deepEqual(foto(join(e.generated, "contextos")), antes, "el contexto publicado sigue igual");
    } finally { e.limpiar(); }
  });

  test("también se bloquea al cambiar un atributo de sitio, agregar uno, cambiar el tipo, INSTITUTION_ID o la URL pública", () => {
    for (const [clave, valor] of [
      ["CREDENTIAL_ATTRIBUTES", "nombre,apellido,numeroLicencia,categoria"],
      ["CREDENTIAL_ATTRIBUTES", "nombre,apellido,numeroLicenciaX"],
      ["CREDENTIAL_TYPE", "VerifiableCredential,OtroTipoCredential"],
      ["INSTITUTION_ID", "otra"],
      ["CERTIFY_PUBLIC_HOST", "otro.prueba.invalid"],
    ]) {
      const e = prepararEntorno();
      try {
        const antes = foto(join(e.generated, "contextos"));
        cambiarEnv(e, clave, valor);
        const r = generar(e);
        assert.notEqual(r.status, 0, `${clave}=${valor} debía bloquearse`);
        assert.match(r.stderr, /contexto nuevo = clave nueva/i);
        assert.deepEqual(foto(join(e.generated, "contextos")), antes);
      } finally { e.limpiar(); }
    }
  });

  test("reordenar los MISMOS atributos no cambia el contexto (los términos son los mismos): ok y no se reescribe lo publicado", () => {
    const e = prepararEntorno();
    try {
      const antes = foto(join(e.generated, "contextos"));
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "apellido,numeroLicencia,nombre");
      const r = generar(e);
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(foto(join(e.generated, "contextos")), antes);
    } finally { e.limpiar(); }
  });

  test("la clave nueva (con la vieja intacta) sí se genera: cada clave tiene su contexto y su huella", () => {
    const e = prepararEntorno();
    try {
      const viejo = readFileSync(contexto(e), "utf8");
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      cambiarEnv(e, "CREDENTIAL_CONFIG_KEY_ID", "PruebaLicenciaV2");
      const r = generar(e);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(readFileSync(contexto(e), "utf8"), viejo, "el viejo sigue publicado, sin cambios");
      assert.ok(existsSync(join(e.generated, "contextos", "PruebaLicenciaV2.json")));
      assert.ok(existsSync(join(e.generated, "contextos", "PruebaLicenciaV2.sha256")));
    } finally { e.limpiar(); }
  });

  test("KIT_FORZAR_CONTEXTO=1 sobrescribe, con un aviso que dice que invalida lo emitido, y actualiza la huella", () => {
    const e = prepararEntorno();
    try {
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      const r = generar(e, { KIT_FORZAR_CONTEXTO: "1" });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /AVISO: KIT_FORZAR_CONTEXTO=1/);
      assert.match(r.stderr, /invalida/i);
      const ctx = readFileSync(contexto(e));
      assert.equal(JSON.parse(ctx)["@context"].numeroLicencia, undefined);
      assert.equal(readFileSync(huellaDe(e), "utf8"), `${sha(ctx)}  ${CLAVE}.json\n`);
      // Y con otro valor que no sea 1, no fuerza.
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre");
      const r2 = generar(e, { KIT_FORZAR_CONTEXTO: "0" });
      assert.notEqual(r2.status, 0);
    } finally { e.limpiar(); }
  });

  test("instalación anterior (contexto publicado sin .sha256): mismo contenido, ok y crea la huella; contenido distinto, falla", () => {
    const e = prepararEntorno();
    try {
      rmSync(huellaDe(e));
      const r = generar(e);
      assert.equal(r.status, 0, r.stderr);
      assert.ok(existsSync(huellaDe(e)), "creó la huella");
      rmSync(huellaDe(e));
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      const r2 = generar(e);
      assert.notEqual(r2.status, 0);
      assert.match(r2.stderr, /contexto nuevo = clave nueva/i);
    } finally { e.limpiar(); }
  });

  test("si falta el .json pero queda la huella, un contexto distinto también se bloquea (no se republica otra cosa en su sitio)", () => {
    const e = prepararEntorno();
    try {
      rmSync(contexto(e));
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      const r = generar(e);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /contexto nuevo = clave nueva/i);
      assert.equal(existsSync(contexto(e)), false);
    } finally { e.limpiar(); }
  });

  test("el bloqueo ocurre ANTES de escribir lo demás: no cambia ni las properties ni el SQL", () => {
    const e = prepararEntorno();
    try {
      const sql = readFileSync(e.rutas.sql, "utf8");
      const props = readFileSync(e.rutas.propiedadesDefault, "utf8");
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      cambiarEnv(e, "INSTITUTION_DISPLAY_NAME", "Otro nombre");
      const r = generar(e);
      assert.notEqual(r.status, 0);
      assert.equal(readFileSync(e.rutas.sql, "utf8"), sql);
      assert.equal(readFileSync(e.rutas.propiedadesDefault, "utf8"), props);
    } finally { e.limpiar(); }
  });
});

describe("K5 · apply-credential.sh", () => {
  test("DRY_RUN=1 no toca generated/contextos/ (ni crea ni sobrescribe) y avisa de qué contexto habría", () => {
    const e = prepararEntorno();
    try {
      const dir = join(e.generated, "contextos");
      const antes = foto(dir);
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(foto(dir), antes);
      // Ni siquiera un contexto que falta se crea en DRY_RUN
      rmSync(contexto(e)); rmSync(huellaDe(e));
      const r2 = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.equal(r2.status, 0, r2.stderr);
      assert.deepEqual(readdirSync(dir), []);
    } finally { e.limpiar(); }
  });

  test("DRY_RUN=1 con atributos distintos: falla (avisa del bloqueo) y deja intacto lo publicado", () => {
    const e = prepararEntorno();
    try {
      const dir = join(e.generated, "contextos");
      const antes = foto(dir);
      cambiarEnv(e, "CREDENTIAL_ATTRIBUTES", "nombre,apellido");
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /contexto nuevo = clave nueva/i);
      assert.deepEqual(foto(dir), antes);
    } finally { e.limpiar(); }
  });

  test("DRY_RUN=1 imprime también el comando que reiniciaría Certify", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /^docker compose -f docker-compose\.yml -f docker-compose\.tls\.yml --env-file generated\/\.env\.runtime restart certify$/m);
    } finally { e.limpiar(); }
  });

  test("aplicación real (docker falso): psql primero, y después reinicia SOLO certify", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      const registro = join(e.raiz, "docker.log");
      writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$@" >> "${registro}"\ncat > /dev/null < /dev/null\nexit 0\n`);
      chmodSync(join(bin, "docker"), 0o755);
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { PATH: `${bin}:${process.env.PATH}` });
      assert.equal(r.status, 0, r.stderr + r.stdout);
      const l = readFileSync(registro, "utf8").trim().split("\n");
      const iPsql = l.findIndex((x) => /exec -T database psql/.test(x));
      const iRestart = l.findIndex((x) => /restart certify$/.test(x));
      assert.ok(iPsql !== -1, l.join("\n"));
      assert.ok(iRestart > iPsql, "reinicia después de aplicar");
      assert.equal(l.filter((x) => /\brestart\b/.test(x)).length, 1);
      assert.doesNotMatch(l.join("\n"), /restart (caddy|database)|\bdown\b/);
      assert.match(r.stdout, /Certify.*caché|caché.*Certify/i);
    } finally { e.limpiar(); }
  });

  test("si psql falla, NO reinicia Certify y sale con error", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      const registro = join(e.raiz, "docker.log");
      writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$@" >> "${registro}"\ncase "$*" in *psql*) exit 3;; esac\nexit 0\n`);
      chmodSync(join(bin, "docker"), 0o755);
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { PATH: `${bin}:${process.env.PATH}` });
      assert.notEqual(r.status, 0);
      assert.doesNotMatch(readFileSync(registro, "utf8"), /restart/);
    } finally { e.limpiar(); }
  });
});
