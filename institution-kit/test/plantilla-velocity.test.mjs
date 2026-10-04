// T8 · K9 (media): la plantilla Velocity ponía "${atributo}" sin escapar y sin tratar nulos.
//   (a) un valor con «"», «\» o salto de línea (apellido «De "La" Cruz») daba JSON inválido: 500 al ciudadano;
//   (b) un campo ausente dejaba la referencia sin resolver y Velocity imprimía el texto literal «${apellido}»: el kit
//       FIRMABA una credencial con ese valor.
// Corrección: "$!{_esc.java($atributo)}". `_esc` es el EscapeTool de velocity-tools-generic 3.1, que Certify mete en el
// contexto (VelocityTemplatingEngineImpl.format); NO tiene `json()` (la evaluación adversarial proponía `_esc.json`,
// que no existe en 3.1: medido con Velocity real), pero `java()` produce literales de cadena que también son JSON
// válido (\", \\, \n, \uXXXX; comprobado con los 63 489 caracteres BMP y un par sustituto). `$!` imprime vacío si
// el valor es nulo.
//
// La prueba REAL necesita Velocity 1.7 + velocity-tools 3.1 (las versiones de certify-service/pom.xml) y `java`:
//   KIT_VELOCITY_CP=<jars separados por ':'> fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
// El CI (.github/workflows/kit.yml) los baja de Maven Central; sin ellos esa parte se omite (y queda para T9).
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { prepararEntorno, plantillaDesdeSql } from "./helpers/entorno.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const CP = process.env.KIT_VELOCITY_CP;
const HAY_JAVA = spawnSync("java", ["-version"], { encoding: "utf8" }).status === 0;
const SIN_VELOCITY = (!CP && "KIT_VELOCITY_CP no apunta a velocity 1.7 + velocity-tools 3.1 (se omite; lo ejecuta el CI y T9)") || (!HAY_JAVA && "no hay java");

function renderizar(textoPlantilla, valores) {
  const dir = mkdtempSync(join(tmpdir(), "velocity-"));
  try {
    const ruta = join(dir, "plantilla.vm");
    writeFileSync(ruta, textoPlantilla);
    const pares = Object.entries(valores).flat();
    const r = spawnSync("java", ["-cp", CP, join(AQUI, "helpers", "RenderVelocity.java"), ruta, ...pares], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    return r.stdout;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

describe("K9 · la plantilla escapa y trata nulos", () => {
  test("cada atributo va como $!{_esc.java($atributo)}, nunca como ${atributo} (estructura)", () => {
    const e = prepararEntorno({ extra: { CREDENTIAL_ATTRIBUTES: "nombre,apellido,_interno,numero2" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const t = plantillaDesdeSql(e.leer("sql"));
      for (const a of ["nombre", "apellido", "_interno", "numero2"]) assert.equal(t.credentialSubject[a], `$!{_esc.java($${a})}`, a);
      // lo que Certify genera (no el titular ni el API de datos) sigue sin escapar: son DID y fechas propios
      assert.equal(t.issuer, "${_issuer}");
      assert.equal(t.credentialSubject.id, "${_holderId}");
      assert.equal(t.validFrom, "${validFrom}");
    } finally { e.limpiar(); }
  });

  test("la plantilla sigue siendo JSON válido sin renderizar (la columna vc_template la lee Certify como texto)", () => {
    const e = prepararEntorno();
    try { assert.doesNotThrow(() => plantillaDesdeSql(e.leer("sql"))); } finally { e.limpiar(); }
  });

  test("la muestra sin firma (verify-install.sh) no cambia: lleva valores ficticios, no marcadores Velocity", () => {
    const e = prepararEntorno();
    try {
      const m = JSON.parse(e.leer("muestra"));
      for (const v of Object.values(m.credentialSubject)) assert.doesNotMatch(String(v), /[$#]\{?|_esc/);
    } finally { e.limpiar(); }
  });

  const real = { skip: SIN_VELOCITY };

  test("Velocity real: un apellido con comillas, barra, salto de línea y acentos da JSON válido con el valor exacto", real, () => {
    const e = prepararEntorno();
    try {
      const texto = Buffer.from(JSON.stringify(plantillaDesdeSql(e.leer("sql"))), "utf8").toString("utf8");
      const apellido = 'De "La" Cruz \\ Núñez\nSegunda línea\t€ 😀';
      const salida = renderizar(texto, { nombre: "María", apellido, numeroLicencia: "A-123" });
      const vc = JSON.parse(salida);
      assert.equal(vc.credentialSubject.apellido, apellido);
      assert.equal(vc.credentialSubject.nombre, "María");
      assert.equal(vc.credentialSubject.numeroLicencia, "A-123");
      assert.equal(vc.credentialSubject.id, "did:jwk:titular-de-prueba");
      assert.equal(vc.issuer, "did:web:emisor.prueba.invalid");
    } finally { e.limpiar(); }
  });

  test("Velocity real: un valor que parece Velocity o JSON no se interpreta", real, () => {
    const e = prepararEntorno();
    try {
      const texto = JSON.stringify(plantillaDesdeSql(e.leer("sql")));
      for (const raro of ["${apellido}", "$x #foo #if(1)", '"},"inyectado":"1', "\\u0041", "</script>"]) {
        const vc = JSON.parse(renderizar(texto, { nombre: "n", apellido: raro, numeroLicencia: "l" }));
        assert.equal(vc.credentialSubject.apellido, raro);
        assert.deepEqual(Object.keys(vc.credentialSubject), ["id", "nombre", "apellido", "numeroLicencia"], "sin claves inyectadas");
      }
    } finally { e.limpiar(); }
  });

  test("Velocity real: un campo ausente o nulo NO deja «${apellido}» firmado: sale vacío", real, () => {
    const e = prepararEntorno();
    try {
      const texto = JSON.stringify(plantillaDesdeSql(e.leer("sql")));
      for (const valores of [{ nombre: "n", numeroLicencia: "l" }, { nombre: "n", apellido: "__NULL__", numeroLicencia: "l" }]) {
        const salida = renderizar(texto, valores);
        assert.doesNotMatch(salida, /\$\{?apellido|\$!\{/, salida);
        assert.equal(JSON.parse(salida).credentialSubject.apellido, "");
      }
    } finally { e.limpiar(); }
  });

  test("Velocity real: con la plantilla ANTERIOR el mismo apellido daba JSON inválido y el campo ausente imprimía el texto literal (el defecto)", real, () => {
    const anterior = JSON.stringify({ credentialSubject: { id: "${_holderId}", apellido: "${apellido}" } });
    const roto = renderizar(anterior, { apellido: 'De "La" Cruz' });
    assert.throws(() => JSON.parse(roto), "JSON inválido con comillas");
    assert.equal(JSON.parse(renderizar(anterior, {})).credentialSubject.apellido, "${apellido}");
  });
});
