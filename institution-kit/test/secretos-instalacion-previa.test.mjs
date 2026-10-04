// T8 · K2 (alta), K3 (media) y T7-3: las contraseñas NUNCA se regeneran sobre una instalación existente.
//   - Instalación nueva (sin generated/.env.runtime ni contenedor/volumen de este kit): se generan (64 hex).
//   - Instalación previa con contraseñas propias o generadas: se reutilizan las de .env.runtime.
//   - Instalación previa con las de defecto (postgres/local): install.sh SE DETIENE y explica cómo rotarlas a mano.
//   - KIT_CONSERVAR_SECRETOS_POR_DEFECTO desaparece.
//   - Se valida antes de generar secretos: un .env inválido no deja un .env.runtime con contraseñas nuevas.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, symlinkSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { prepararEntorno, KIT_ORIGEN } from "./helpers/entorno.mjs";

const SIN = { POSTGRES_PASSWORD: undefined, KEYSTORE_PASSWORD: undefined };
const HEX64 = /^[0-9a-f]{64}$/;
const valor = (t, k) => t.match(new RegExp(`^${k}=(.*)$`, "m"))?.[1];

// Un `.env.runtime` como el del kit anterior (todo el .env, con las contraseñas de defecto).
const RUNTIME_ANTERIOR = "TLS_MODE=domain\nPOSTGRES_USER=postgres\nPOSTGRES_PASSWORD=postgres\nPOSTGRES_DB=inji_certify\nKEYSTORE_PASSWORD=local\n";
function conRuntime(e, texto) {
  mkdirSync(e.generated, { recursive: true });
  writeFileSync(e.rutas.runtime, texto);
  chmodSync(e.rutas.runtime, 0o600);
}
// docker falso: registra las llamadas; `ps -a` (contenedor de la base) o `volume ls` devuelven un id si `lista`.
function dockerFalso(e, { contenedor = "", volumen = "" } = {}) {
  const bin = join(e.raiz, "bin-docker");
  mkdirSync(bin, { recursive: true });
  const registro = join(e.raiz, "docker.log");
  writeFileSync(join(bin, "docker"), `#!/bin/sh
echo "$@" >> "${registro}"
case "$1" in
  ps) echo "${contenedor}" ;;
  volume) echo "${volumen}" ;;
  compose) exit 0 ;;
esac
exit 0
`);
  chmodSync(join(bin, "docker"), 0o755);
  return { path: `${bin}:${process.env.PATH}`, registro: () => (existsSync(registro) ? readFileSync(registro, "utf8") : "") };
}
const gen = (e, extra = {}) => e.ejecutar('bash "$PWD/scripts/generate-config.sh"', extra);

describe("K2 · instalación nueva: se generan; instalación previa: nunca se regeneran", () => {
  test("nueva (sin .env.runtime ni docker): genera 64 hex y avisa", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const r = gen(e);
      assert.equal(r.status, 0, r.stderr);
      assert.match(valor(e.leer("runtime"), "POSTGRES_PASSWORD"), HEX64);
      assert.match(r.stderr, /AVISO: se generaron contraseñas/);
    } finally { e.limpiar(); }
  });

  test(".env.runtime del kit anterior con postgres/local y .env por defecto: SE DETIENE, no toca .env.runtime y no genera nada", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      conRuntime(e, RUNTIME_ANTERIOR);
      const r = gen(e);
      assert.notEqual(r.status, 0, "debe detenerse");
      assert.match(r.stderr, /ERROR: .*instalación (previa|existente)/i);
      assert.match(r.stderr, /postgres.*local|POSTGRES_PASSWORD.*KEYSTORE_PASSWORD/s);
      assert.equal(readFileSync(e.rutas.runtime, "utf8"), RUNTIME_ANTERIOR, ".env.runtime intacto");
      for (const f of ["propiedadesDefault", "caddyfile", "sql", "composeArgs"]) assert.equal(e.existe(f), false, `no generó ${f}`);
    } finally { e.limpiar(); }
  });

  test("el mensaje explica cómo rotarlas a mano (Postgres: ALTER USER; keystore: keytool) y qué poner en el .env", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      conRuntime(e, RUNTIME_ANTERIOR);
      const m = gen(e).stderr;
      assert.match(m, /ALTER USER/);
      assert.match(m, /--entrypoint keytool[\s\S]*-storepasswd/);
      assert.match(m, /POSTGRES_PASSWORD/);
      assert.match(m, /KEYSTORE_PASSWORD/);
      assert.match(m, /openssl rand -hex 32/);
      assert.match(m, /02-GUIA-DE-INSTALACION/);
      assert.match(m, /no (genera|regenera)/i);
    } finally { e.limpiar(); }
  });

  test("solo la de Postgres por defecto (la del keystore ya es propia): se detiene nombrando solo esa", () => {
    const e = prepararEntorno({ extra: { POSTGRES_PASSWORD: undefined, KEYSTORE_PASSWORD: "keystore-propio-1" }, generar: false });
    try {
      conRuntime(e, "POSTGRES_PASSWORD=postgres\nKEYSTORE_PASSWORD=keystore-propio-1\n");
      const r = gen(e);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /POSTGRES_PASSWORD/);
      assert.doesNotMatch(r.stderr.split("\n").filter((l) => /^\s*-\s/.test(l)).join("\n"), /KEYSTORE_PASSWORD/);
    } finally { e.limpiar(); }
  });

  test("install.sh también se detiene (antes de construir ni levantar nada)", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      conRuntime(e, RUNTIME_ANTERIOR);
      const d = dockerFalso(e);
      const bin = join(e.raiz, "bin");
      mkdirSync(bin);
      for (const c of ["bash", "dirname", "env", "cat", "cp", "chmod", "stat", "grep", "tr", "cut", "head", "mkdir", "mktemp", "mv", "rm", "id", "uname", "ls", "sed", "od", "envsubst", "openssl", "jq", "curl", "sleep", "awk"]) {
        try { symlinkSync(execFileSync("sh", ["-c", `command -v ${c}`], { encoding: "utf8" }).trim(), join(bin, c)); } catch { /* opcional */ }
      }
      symlinkSync(join(e.raiz, "bin-docker", "docker"), join(bin, "docker"));
      const r = e.ejecutar('bash "$PWD/install.sh"', { PATH: bin });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /instalación (previa|existente)/i);
      const llamadas = d.registro();
      assert.doesNotMatch(llamadas, /\bbuild\b|\bup\b/, "no construyó ni levantó nada");
      assert.equal(readFileSync(e.rutas.runtime, "utf8"), RUNTIME_ANTERIOR);
    } finally { e.limpiar(); }
  });

  test(".env.runtime con contraseñas generadas antes (hex) y .env por defecto: se REUTILIZAN, no se regeneran ni se detiene", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const pg = "a".repeat(64), ks = "b".repeat(64);
      conRuntime(e, `POSTGRES_PASSWORD=${pg}\nKEYSTORE_PASSWORD=${ks}\n`);
      const r = gen(e);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(valor(e.leer("runtime"), "POSTGRES_PASSWORD"), pg);
      assert.equal(valor(e.leer("runtime"), "KEYSTORE_PASSWORD"), ks);
      assert.doesNotMatch(r.stderr, /se generaron contraseñas/);
    } finally { e.limpiar(); }
  });

  test("valores entre comillas en un .env.runtime viejo se leen sin las comillas", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const pg = "c".repeat(64), ks = "d".repeat(64);
      conRuntime(e, `POSTGRES_PASSWORD="${pg}"\nKEYSTORE_PASSWORD='${ks}'\n`);
      const r = gen(e);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(valor(e.leer("runtime"), "POSTGRES_PASSWORD"), pg);
      assert.equal(valor(e.leer("runtime"), "KEYSTORE_PASSWORD"), ks);
    } finally { e.limpiar(); }
  });

  test("contraseñas explícitas en el .env sobre una instalación previa: se respetan (es la forma de rotarlas)", () => {
    const e = prepararEntorno({ extra: { POSTGRES_PASSWORD: "rotada-por-mi-1", KEYSTORE_PASSWORD: "rotada-por-mi-2" }, generar: false });
    try {
      conRuntime(e, RUNTIME_ANTERIOR);
      const r = gen(e);
      assert.equal(r.status, 0, r.stderr);
      assert.equal(valor(e.leer("runtime"), "POSTGRES_PASSWORD"), "rotada-por-mi-1");
      assert.equal(valor(e.leer("runtime"), "KEYSTORE_PASSWORD"), "rotada-por-mi-2");
    } finally { e.limpiar(); }
  });

  test("sin .env.runtime pero con un contenedor de la base de este kit (docker ps -a): se detiene", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const d = dockerFalso(e, { contenedor: "3f2a1b9c8d7e" });
      const r = gen(e, { PATH: d.path });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /instalación (previa|existente)/i);
      assert.match(d.registro(), /ps -a .*com\.docker\.compose\.service=database/);
      assert.equal(e.existe("runtime"), false, "no escribió contraseñas nuevas");
    } finally { e.limpiar(); }
  });

  test("sin .env.runtime pero con el volumen del keystore o de datos de este kit (docker volume ls): se detiene", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const d = dockerFalso(e, { volumen: "institution-kit_pgdata" });
      const r = gen(e, { PATH: d.path });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /instalación (previa|existente)/i);
      assert.match(d.registro(), /volume ls .*com\.docker\.compose\.volume=/);
      assert.equal(e.existe("runtime"), false);
    } finally { e.limpiar(); }
  });

  test("docker presente pero sin contenedor ni volumen del kit: instalación nueva, genera", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const d = dockerFalso(e);
      const r = gen(e, { PATH: d.path });
      assert.equal(r.status, 0, r.stderr);
      assert.match(valor(e.leer("runtime"), "KEYSTORE_PASSWORD"), HEX64);
    } finally { e.limpiar(); }
  });
});

describe("K3 · KIT_CONSERVAR_SECRETOS_POR_DEFECTO desaparece", () => {
  test("con =1 y .env.runtime viejo con postgres/local: ya NO deja postgres/local; se detiene", () => {
    const e = prepararEntorno({ extra: { ...SIN, KIT_CONSERVAR_SECRETOS_POR_DEFECTO: "1" }, generar: false });
    try {
      conRuntime(e, RUNTIME_ANTERIOR);
      const r = gen(e);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /KIT_CONSERVAR_SECRETOS_POR_DEFECTO ya no existe/);
      assert.equal(readFileSync(e.rutas.runtime, "utf8"), RUNTIME_ANTERIOR);
    } finally { e.limpiar(); }
  });

  for (const v of ["0", "false", "no", "1"]) {
    test(`con =${v} en una instalación NUEVA no deja las contraseñas por defecto (se genera) y avisa de que la variable ya no existe`, () => {
      const e = prepararEntorno({ extra: { ...SIN, KIT_CONSERVAR_SECRETOS_POR_DEFECTO: v }, generar: false });
      try {
        const r = gen(e);
        assert.equal(r.status, 0, r.stderr);
        assert.match(valor(e.leer("runtime"), "POSTGRES_PASSWORD"), HEX64);
        assert.match(r.stderr, /KIT_CONSERVAR_SECRETOS_POR_DEFECTO ya no existe/);
      } finally { e.limpiar(); }
    });
  }

  test("el código ya no lee la variable (solo la menciona para avisar)", () => {
    const t = readFileSync(join(KIT_ORIGEN, "scripts/lib/common.sh"), "utf8");
    const usos = t.split("\n").filter((l) => l.includes("KIT_CONSERVAR_SECRETOS_POR_DEFECTO") && !l.trim().startsWith("#"));
    // El `if` que avisa, el texto del aviso y la línea del mensaje de parada: ninguno cambia las contraseñas.
    assert.equal(usos.length, 3, usos.join("\n"));
    assert.ok(usos.every((l) => /\[\[ -n|echo "AVISO|Tampoco existe ya/.test(l)), usos.join("\n"));
    assert.doesNotMatch(t, /printf -v "\$\{var\}" '%s' "\$\{defecto\}"/);
  });
});

describe("T7-3 · se valida antes de generar secretos", () => {
  test(".env inválido (sin LOGO_PATH) en instalación nueva con contraseñas por defecto: no queda .env.runtime ni nada en generated/", () => {
    const e = prepararEntorno({ extra: { ...SIN, LOGO_PATH: undefined }, generar: false });
    try {
      const r = gen(e);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /LOGO_PATH es obligatorio/);
      assert.equal(e.existe("runtime"), false, ".env.runtime no debe existir");
      assert.deepEqual(existsSync(e.generated) ? readdirSync(e.generated) : [], []);
      assert.doesNotMatch(r.stderr, /se generaron contraseñas/);
    } finally { e.limpiar(); }
  });

  test("tras corregir el .env, la segunda ejecución genera una sola vez y no avisa dos veces", () => {
    const e = prepararEntorno({ extra: { ...SIN, LOGO_PATH: undefined }, generar: false });
    try {
      assert.notEqual(gen(e).status, 0);
      writeFileSync(join(e.kit, ".env"), readFileSync(join(e.kit, ".env"), "utf8") + `LOGO_PATH="${e.logoOrigen}"\n`);
      const b = gen(e);
      assert.equal(b.status, 0, b.stderr);
      assert.equal((b.stderr.match(/se generaron contraseñas/g) ?? []).length, 1);
      const c = gen(e);
      assert.doesNotMatch(c.stderr, /se generaron contraseñas/);
    } finally { e.limpiar(); }
  });

  test(".env.runtime que escribe la generación lleva la URL y el DID ya derivados (no vacíos)", () => {
    const e = prepararEntorno({ extra: SIN, generar: false });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/generate-properties.sh"');
      assert.equal(r.status, 0, r.stderr);
      const t = e.leer("runtime");
      assert.equal(valor(t, "CERTIFY_PUBLIC_URL"), "https://emisor.prueba.invalid");
      assert.equal(valor(t, "DID_URL"), "did:web:emisor.prueba.invalid");
    } finally { e.limpiar(); }
  });
});
