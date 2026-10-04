// T9 · I5 (integración real, Docker + Certify construido desde la rama, 4-oct-2026): defecto que solo apareció al
// ejecutar el kit de verdad.
//
//  I5 · `sql/00-schema.sql` creaba `status_list_credential.capacity`; Certify 0.14 lee `capacity_in_kb` (la columna
//       la renombró db_upgrade_script/…/0.12.2_to_0.13.0_upgrade.sql). Con `credential_status_purpose = {revocation}`
//       (el SQL del kit) cada emisión consulta esa tabla: «ERROR: column slc1_0.capacity_in_kb does not exist».
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { KIT_ORIGEN } from "./helpers/entorno.mjs";

const RAIZ = dirname(KIT_ORIGEN); // raíz del fork de Certify (el kit es institution-kit/)

// Columnas de cada CREATE TABLE de un SQL: nombre -> Set de columnas (sin restricciones de tabla).
function columnasPorTabla(sql) {
  const limpio = sql.replace(/--.*$/gm, "");
  const tablas = new Map();
  for (const m of limpio.matchAll(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(?:certify\.)?(\w+)\s*\(([\s\S]*?)\n?\)\s*;/gi)) {
    const columnas = new Set();
    let hondo = 0, actual = "";
    const partes = [];
    for (const c of m[2]) { // separa por comas de primer nivel (hay paréntesis en tipos y en CHECK)
      if (c === "(") hondo++; else if (c === ")") hondo--;
      if (c === "," && hondo === 0) { partes.push(actual); actual = ""; } else actual += c;
    }
    partes.push(actual);
    for (const p of partes) {
      const t = p.trim();
      if (!t || /^(CONSTRAINT|PRIMARY|UNIQUE|FOREIGN|CHECK)\b/i.test(t)) continue;
      columnas.add(t.split(/\s+/)[0].replace(/"/g, ""));
    }
    tablas.set(m[1].toLowerCase(), columnas);
  }
  return tablas;
}

describe("I5 · el esquema del kit tiene las mismas columnas que el DDL de Certify de este repositorio", () => {
  const ddlDir = join(RAIZ, "db_scripts", "inji_certify", "ddl");
  const hayDdl = existsSync(ddlDir);
  const kit = columnasPorTabla(readFileSync(join(KIT_ORIGEN, "sql", "00-schema.sql"), "utf8"));
  const oficial = new Map();
  if (hayDdl) for (const f of readdirSync(ddlDir).filter((x) => x.endsWith(".sql"))) {
    for (const [t, cols] of columnasPorTabla(readFileSync(join(ddlDir, f), "utf8"))) oficial.set(t, cols);
  }

  test("se encontró el DDL oficial y el del kit (el analizador no devuelve vacío)", { skip: !hayDdl && "no está db_scripts/ (copia suelta del kit)" }, () => {
    assert.ok(oficial.size >= 10, `tablas del DDL oficial: ${oficial.size}`);
    assert.ok(kit.size >= 10, `tablas del kit: ${kit.size}`);
  });

  test("status_list_credential usa capacity_in_kb (la columna que lee StatusListCredential.java)", () => {
    const cols = kit.get("status_list_credential");
    assert.ok(cols?.has("capacity_in_kb"), `columnas del kit: ${[...(cols ?? [])].join(", ")}`);
    assert.ok(!cols.has("capacity"), "queda la columna vieja `capacity`");
  });

  test("el fuente de Certify mapea esa columna", () => {
    const ruta = join(RAIZ, "certify-service", "src", "main", "java", "io", "mosip", "certify", "entity", "StatusListCredential.java");
    if (!existsSync(ruta)) return; // copia suelta del kit
    assert.match(readFileSync(ruta, "utf8"), /@Column\(name = "capacity_in_kb"\)/);
  });

  test("cada tabla del DDL oficial existe en el kit con exactamente las mismas columnas", { skip: !hayDdl && "no está db_scripts/" }, () => {
    const faltan = [];
    for (const [tabla, cols] of oficial) {
      const k = kit.get(tabla);
      if (!k) { faltan.push(`tabla ${tabla}: falta en el kit`); continue; }
      const sin = [...cols].filter((c) => !k.has(c)), sobra = [...k].filter((c) => !cols.has(c));
      if (sin.length || sobra.length) faltan.push(`${tabla}: faltan [${sin}] sobran [${sobra}]`);
    }
    assert.deepEqual(faltan, []);
  });
});
