// T9 · I6 (integración real, 4-oct-2026): el paso `mvn dependency:go-offline … -q || true` del Dockerfile FALLABA siempre
// (180 s perdidos y un «[ERROR] Failed to execute goal … go-offline» al principio de la construcción): intenta resolver
// org.hyperledger:indy:1.14.0, dependencia transitiva de ld-signatures-java que Maven Central no tiene y que solo vive en
// repo.sovrin.org, cuyo certificado hoy no corresponde al dominio (el empaquetado no la necesita). El `|| true` lo tapaba y `mvn package` descargaba el resto (177 s) en cada
// cambio de código. Con `dependency:resolve -DincludeScope=runtime` (lo que el empaquetado necesita) el paso termina bien y
// `mvn package` queda en 43 s (medido sin caché).
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { KIT_ORIGEN } from "./helpers/entorno.mjs";

describe("I6 · el calentamiento de dependencias de Maven del Dockerfile", () => {
  const d = readFileSync(join(KIT_ORIGEN, "Dockerfile"), "utf8");
  const ejecutables = d.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  test("no usa dependency:go-offline (resuelve dependencias transitivas que no están en Maven Central)", () => {
    assert.doesNotMatch(ejecutables, /dependency:go-offline/);
  });
  test("calienta solo las de ejecución y no esconde el fallo con `|| true`", () => {
    const m = ejecutables.match(/^RUN mvn [^\n]*dependency:resolve[^\n]*$/m);
    assert.ok(m, "falta el paso dependency:resolve");
    assert.match(m[0], /-DincludeScope=runtime/);
    assert.doesNotMatch(m[0], /\|\|\s*true/);
  });
  test("va antes de copiar el código (para que un cambio de código no repita la descarga) y de `mvn package`", () => {
    const iResolve = ejecutables.indexOf("dependency:resolve");
    const iCopiaCodigo = ejecutables.indexOf("COPY certify-core certify-core");
    const iPackage = ejecutables.indexOf("-am package");
    assert.ok(iResolve > 0 && iResolve < iCopiaCodigo && iCopiaCodigo < iPackage);
  });
});
