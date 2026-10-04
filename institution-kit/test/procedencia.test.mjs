// T6 · D4: el diagnóstico vendorizado es una copia SIN modificar con procedencia, y se refresca con
// scripts/sync-diagnostico.sh (que falla ante cambios locales).
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, cpSync, rmSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { prepararEntorno } from "./helpers/entorno.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const KIT = join(AQUI, "..");
const FICHEROS = ["cli.mjs", "motor.mjs", "red.mjs", "jsonld.mjs"];
const sha = (ruta) => createHash("sha256").update(readFileSync(ruta)).digest("hex");

// Filas «| `fichero` | `origen` | `sha` | fecha |» de la tabla entre marcadores.
function tabla(carpetaKit) {
  const t = readFileSync(join(carpetaKit, "diagnostico", "PROCEDENCIA.md"), "utf8");
  const bloque = t.split("<!-- sync-diagnostico:inicio -->")[1].split("<!-- sync-diagnostico:fin -->")[0];
  const filas = {};
  for (const l of bloque.split("\n")) {
    const m = l.match(/^\| `([^`]+)` \| `([^`]+)` \| `([0-9a-f]{64})` \| (.+) \|$/);
    if (m) filas[m[1]] = { origen: m[2], sha: m[3], fecha: m[4] };
  }
  return { filas, texto: t };
}

describe("PROCEDENCIA.md: las huellas coinciden con los ficheros vendorizados", () => {
  const { filas, texto } = tabla(KIT);

  test("los cuatro ficheros están registrados, con su ruta de origen y una fecha", () => {
    assert.deepEqual(Object.keys(filas).sort(), [...FICHEROS].sort());
    for (const f of FICHEROS) {
      assert.equal(filas[f].origen, `inji-vc/stack/diagnostico/${f}`);
      assert.match(filas[f].fecha, /\d/);
    }
  });

  for (const f of FICHEROS) {
    test(`diagnostico/${f}: el SHA-256 de PROCEDENCIA.md es el del fichero (copia sin modificar)`, () => {
      assert.equal(sha(join(KIT, "diagnostico", f)), filas[f].sha);
    });
  }

  test("en diagnostico/ no hay más fuente que los cuatro vendorizados (lo propio del kit va en scripts/lib)", () => {
    assert.deepEqual(readdirSync(join(KIT, "diagnostico")).filter((f) => f.endsWith(".mjs")).sort(), [...FICHEROS].sort());
  });

  test("anota el commit del origen o que no hay git, y cita el script de sincronización", () => {
    assert.match(texto, /Commit del origen en la última sincronización: (\w{40}|sin git)/);
    assert.match(texto, /scripts\/sync-diagnostico\.sh/);
  });

  test("si el origen del repositorio vecino está al lado, no ha cambiado sin sincronizar (informativo: solo falla si difiere un fichero)", (t) => {
    const origen = join(KIT, "..", "..", "inji-vc", "stack", "diagnostico");
    if (!existsSync(origen)) return t.skip("no hay inji-vc al lado (CI del kit)");
    // Solo se avisa por la salida de la prueba: el origen evoluciona por su cuenta y refrescar es decisión de quien sincroniza.
    const distintos = FICHEROS.filter((f) => existsSync(join(origen, f)) && sha(join(origen, f)) !== filas[f].sha);
    if (distintos.length) t.diagnostic(`el origen difiere de la copia en ${distintos.join(", ")}: ejecute scripts/sync-diagnostico.sh`);
  });
});

describe("scripts/sync-diagnostico.sh", () => {
  // Un kit temporal (sin generar) y una carpeta de «origen» que es copia de los vendorizados.
  function montar() {
    const e = prepararEntorno({ generar: false });
    const origen = mkdtempSync(join(tmpdir(), "origen-diag-"));
    for (const f of FICHEROS) cpSync(join(e.kit, "diagnostico", f), join(origen, f));
    const sync = (extra = {}) => e.ejecutar('bash scripts/sync-diagnostico.sh', { DIAGNOSTICO_ORIGEN: origen, ...extra });
    return { e, origen, sync, limpiar: () => { e.limpiar(); rmSync(origen, { recursive: true, force: true }); } };
  }
  const huellasDe = (kit) => Object.fromEntries(FICHEROS.map((f) => [f, sha(join(kit, "diagnostico", f))]));

  test("sobre una copia al día no cambia nada (idempotente: ni ficheros ni fechas)", () => {
    const m = montar();
    try {
      const antes = readFileSync(join(m.e.kit, "diagnostico", "PROCEDENCIA.md"), "utf8");
      const r = m.sync();
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /Diagnóstico sincronizado desde /);
      assert.equal(readFileSync(join(m.e.kit, "diagnostico", "PROCEDENCIA.md"), "utf8"), antes);
    } finally { m.limpiar(); }
  });

  test("si el origen cambió: copia el fichero nuevo y regenera su SHA-256 (la tabla vuelve a coincidir)", () => {
    const m = montar();
    try {
      writeFileSync(join(m.origen, "motor.mjs"), readFileSync(join(m.origen, "motor.mjs"), "utf8") + "\n// cambio en el origen\n");
      const r = m.sync();
      assert.equal(r.status, 0, r.stderr);
      const { filas } = tabla(m.e.kit);
      const h = huellasDe(m.e.kit);
      assert.equal(h["motor.mjs"], sha(join(m.origen, "motor.mjs")));
      for (const f of FICHEROS) assert.equal(filas[f].sha, h[f], f);
      assert.notEqual(filas["motor.mjs"].sha, sha(join(KIT, "diagnostico", "motor.mjs")));
      // El texto fuera de los marcadores se conserva.
      assert.match(readFileSync(join(m.e.kit, "diagnostico", "PROCEDENCIA.md"), "utf8"), /Procedencia de `diagnostico\/`/);
      assert.match(readFileSync(join(m.e.kit, "diagnostico", "PROCEDENCIA.md"), "utf8"), /test\/fixtures\/contextos\//);
    } finally { m.limpiar(); }
  });

  test("con cambios locales en un vendorizado FALLA, no toca nada y dice cuál", () => {
    const m = montar();
    try {
      const ruta = join(m.e.kit, "diagnostico", "red.mjs");
      writeFileSync(ruta, readFileSync(ruta, "utf8") + "\n// parche local\n");
      writeFileSync(join(m.origen, "motor.mjs"), readFileSync(join(m.origen, "motor.mjs"), "utf8") + "\n// nuevo\n");
      const antes = huellasDe(m.e.kit);
      const procedencia = readFileSync(join(m.e.kit, "diagnostico", "PROCEDENCIA.md"), "utf8");
      const r = m.sync();
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /diagnostico\/red\.mjs tiene cambios locales/);
      assert.deepEqual(huellasDe(m.e.kit), antes, "ningún fichero cambió (ni siquiera motor.mjs, que sí cambió en el origen)");
      assert.equal(readFileSync(join(m.e.kit, "diagnostico", "PROCEDENCIA.md"), "utf8"), procedencia);
    } finally { m.limpiar(); }
  });

  test("SYNC_FORZAR=1 descarta el cambio local y deja la copia igual al origen", () => {
    const m = montar();
    try {
      const ruta = join(m.e.kit, "diagnostico", "cli.mjs");
      writeFileSync(ruta, "// roto\n");
      const r = m.sync({ SYNC_FORZAR: "1" });
      assert.equal(r.status, 0, r.stderr);
      assert.equal(sha(ruta), sha(join(m.origen, "cli.mjs")));
      assert.equal(tabla(m.e.kit).filas["cli.mjs"].sha, sha(ruta));
    } finally { m.limpiar(); }
  });

  test("un cambio local que coincide con el origen (ya sincronizado a mano) no es un error", () => {
    const m = montar();
    try {
      const nuevo = readFileSync(join(m.origen, "red.mjs"), "utf8") + "\n// igual en los dos\n";
      writeFileSync(join(m.origen, "red.mjs"), nuevo);
      writeFileSync(join(m.e.kit, "diagnostico", "red.mjs"), nuevo);
      const r = m.sync();
      assert.equal(r.status, 0, r.stderr);
      assert.equal(tabla(m.e.kit).filas["red.mjs"].sha, sha(join(m.origen, "red.mjs")));
    } finally { m.limpiar(); }
  });

  test("al origen le falta un fichero -> FALLA sin copiar ninguno", () => {
    const m = montar();
    try {
      rmSync(join(m.origen, "red.mjs"));
      writeFileSync(join(m.origen, "cli.mjs"), "// distinto\n");
      const antes = huellasDe(m.e.kit);
      const r = m.sync();
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /el origen no tiene red\.mjs/);
      assert.deepEqual(huellasDe(m.e.kit), antes);
    } finally { m.limpiar(); }
  });

  test("origen inexistente -> FALLA con la variable a usar", () => {
    const m = montar();
    try {
      const r = m.sync({ DIAGNOSTICO_ORIGEN: join(m.origen, "no-existe") });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /no existe el origen del diagnóstico.*DIAGNOSTICO_ORIGEN/);
    } finally { m.limpiar(); }
  });

  test("sin DIAGNOSTICO_ORIGEN usa ../../inji-vc/stack/diagnostico relativo al kit", () => {
    const t = readFileSync(join(KIT, "scripts", "sync-diagnostico.sh"), "utf8");
    assert.match(t, /ORIGEN_RELATIVO="\.\.\/\.\.\/inji-vc\/stack\/diagnostico"/);
    assert.match(t, /DIAGNOSTICO_ORIGEN:-\$\{KIT_DIR\}\/\$\{ORIGEN_RELATIVO\}/);
    // En el kit temporal (sin inji-vc al lado) y sin la variable, falla con mensaje, no con un traspié de bash.
    const m = montar();
    try {
      const r = m.e.ejecutar("bash scripts/sync-diagnostico.sh");
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /no existe el origen del diagnóstico/);
    } finally { m.limpiar(); }
  });

  test("PROCEDENCIA.md sin marcadores -> FALLA y no la reescribe", () => {
    const m = montar();
    try {
      const ruta = join(m.e.kit, "diagnostico", "PROCEDENCIA.md");
      writeFileSync(ruta, "# sin marcadores\n");
      const r = m.sync();
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /marcadores/);
      assert.equal(readFileSync(ruta, "utf8"), "# sin marcadores\n");
    } finally { m.limpiar(); }
  });
});
