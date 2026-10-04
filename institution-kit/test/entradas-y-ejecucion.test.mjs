// T8 · K12 / K15 (baja) y T7-4, T7-5, T7-6: entradas que se aceptaban o rechazaban mal, y cómo se ejecuta Node.
//   - run_node (sin Node local) montaba el kit entero en lectura-escritura: ahora solo scripts/ (ro) y lo que escribe.
//   - TRUSTED_PROXIES=0.0.0.0/0 (confía en cualquier X-Forwarded-For) se rechaza.
//   - http:// en CERTIFY_PUBLIC_URL solo con KIT_PERMITIR_HTTP=1.
//   - CADDY_HTTP_PORT con ceros a la izquierda; .env con CRLF o valores con espacios sin comillas.
//   - T7-4: INSTITUTION_ID con guion dice INSTITUTION_ID, no «CREDENTIAL_TYPE».
//   - T7-5: generate-logo.sh conserva los logos de otras claves (el comentario decía lo contrario).
//   - T7-6: en modo proxy, un FALLA de la comprobación 1 sugiere «¿su proxy ya reenvía a este servidor?».
//   - `timeout` en macOS: kit_timeout portable.  - Las claves TLS de prueba, con allowlist de escáner de secretos.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, symlinkSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { prepararEntorno, KIT_ORIGEN } from "./helpers/entorno.mjs";

const proxy = (extra = {}) => prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid", CADDY_ACME_EMAIL: undefined, ...extra } });

describe("K12 · run_node monta solo lo necesario (sin Node local)", () => {
  const orden = (e, script) => {
    const r = e.ejecutar(`bash "$PWD/scripts/${script}"`, { KIT_FORCE_DOCKER: "1", KIT_DRY_RUN: "1" });
    assert.equal(r.status, 0, r.stderr);
    const linea = r.stdout.split("\n").find((l) => l.startsWith("docker run"));
    assert.ok(linea, r.stdout);
    return linea;
  };
  test("generate-context: scripts/ de solo lectura y SOLO generated/contextos; ni el kit entero, ni .env, ni .env.runtime", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const l = orden(e, "generate-context.sh");
      assert.match(l, /-v \S+\/scripts:\/kit\/scripts:ro\b/);
      assert.match(l, /-v \S+\/generated\/contextos:\/kit\/generated\/contextos\b/);
      assert.doesNotMatch(l, /-v \S+\/institution-kit:\/kit\b/, "no se monta el kit entero");
      assert.doesNotMatch(l, /\.env/);
      assert.doesNotMatch(l, /-v \S+\/generated:\/kit\/generated\b/, "no se monta generated/ entera (lleva .env.runtime)");
      assert.equal((l.match(/ -v /g) ?? []).length, 2);
      assert.match(l, / -w \/kit /);
      assert.match(l, / node:22-alpine node \/kit\/scripts\/generate-context\.mjs generated$/);
    } finally { e.limpiar(); }
  });
  test("generate-credential-sql: scripts/ ro y solo los DOS ficheros que escribe", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const l = orden(e, "generate-credential-sql.sh");
      assert.match(l, /-v \S+\/scripts:\/kit\/scripts:ro\b/);
      assert.match(l, /generated\/credential_config\.sql:\/kit\/generated\/credential_config\.sql\b/);
      assert.match(l, /generated\/credencial-muestra\.json:\/kit\/generated\/credencial-muestra\.json\b/);
      assert.equal((l.match(/ -v /g) ?? []).length, 3);
      assert.doesNotMatch(l, /\.env\b|\.env\.runtime/);
    } finally { e.limpiar(); }
  });
  test("con --comprobar (DRY_RUN de apply-credential) el contexto se monta de solo lectura", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/generate-context.sh"', { KIT_FORCE_DOCKER: "1", KIT_DRY_RUN: "1", KIT_CONTEXTO_SOLO_COMPROBAR: "1" });
      assert.match(r.stdout, /generated\/contextos:\/kit\/generated\/contextos:ro\b/);
    } finally { e.limpiar(); }
  });
  test("un programa que run_node no conoce se rechaza (no se monta nada por defecto)", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const r = e.ejecutar("source scripts/lib/common.sh; KIT_FORCE_DOCKER=1 KIT_DRY_RUN=1 run_node otro-programa.mjs");
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /run_node: programa desconocido/);
    } finally { e.limpiar(); }
  });
  test("las variables que lee el programa se reenvían (incluida KIT_FORZAR_CONTEXTO) y el usuario no es root", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const l = orden(e, "generate-context.sh");
      for (const v of ["CREDENTIAL_CONFIG_KEY_ID", "CREDENTIAL_ATTRIBUTES", "CERTIFY_PUBLIC_URL", "KIT_FORZAR_CONTEXTO"]) assert.match(l, new RegExp(`-e ${v}\\b`));
      assert.match(l, /--user [1-9]\d*:\d+/);
    } finally { e.limpiar(); }
  });
});

describe("K15 · TRUSTED_PROXIES demasiado amplio", () => {
  for (const tp of ["0.0.0.0/0", "::/0", "10.0.0.0/8 0.0.0.0/0", "0.0.0.0", "::"]) {
    test(`TRUSTED_PROXIES=${tp} se rechaza con un aviso que explica por qué, y no genera nada`, () => {
      const e = proxy({ TRUSTED_PROXIES: tp });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /TRUSTED_PROXIES.*(cualquier|todo)/s);
        assert.match(e.salida.stderr, /X-Forwarded-For/);
        assert.equal(e.existe("caddyfile"), false);
      } finally { e.limpiar(); }
    });
  }
  for (const tp of ["private_ranges", "10.0.0.0/8", "192.168.1.5", "10.1.2.3 fc00::/7", "203.0.113.0/24"]) {
    test(`TRUSTED_PROXIES=${tp} se acepta`, () => {
      const e = proxy({ TRUSTED_PROXIES: tp });
      try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
    });
  }
});

describe("K15 · http:// solo con KIT_PERMITIR_HTTP=1", () => {
  for (const u of ["http://localhost:8080", "http://127.0.0.1", "http://localhost"]) {
    test(`${u} sin KIT_PERMITIR_HTTP: se rechaza al principio (el motor de verificación exige https) y no se construye nada`, () => {
      const e = proxy({ CERTIFY_PUBLIC_URL: u });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /KIT_PERMITIR_HTTP=1/);
        assert.match(e.salida.stderr, /https/);
        assert.equal(e.existe("caddyfile"), false);
      } finally { e.limpiar(); }
    });
    test(`${u} con KIT_PERMITIR_HTTP=1: se acepta (pruebas locales) y avisa de que verify-install.sh no podrá pasar`, () => {
      const e = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: u, CADDY_ACME_EMAIL: undefined, KIT_PERMITIR_HTTP: "1" } });
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        assert.match(e.salida.stderr, /AVISO: .*http/i);
      } finally { e.limpiar(); }
    });
  }
  test("KIT_PERMITIR_HTTP con otro valor que 1 no vale; y no abre http para un dominio público", () => {
    const a = proxy({ CERTIFY_PUBLIC_URL: "http://localhost:8080", KIT_PERMITIR_HTTP: "0" });
    const b = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "http://certify.prueba.invalid", CADDY_ACME_EMAIL: undefined, KIT_PERMITIR_HTTP: "1" } });
    try {
      assert.notEqual(a.salida.status, 0);
      assert.notEqual(b.salida.status, 0);
    } finally { a.limpiar(); b.limpiar(); }
  });
});

describe("K15 · CADDY_HTTP_PORT y el formato del .env", () => {
  for (const p of ["08", "0080", "00", "0"]) {
    test(`CADDY_HTTP_PORT=${p} se rechaza (ceros a la izquierda: «08» publicaba el puerto 8)`, () => {
      const e = proxy({ CADDY_HTTP_PORT: p });
      try { assert.notEqual(e.salida.status, 0); assert.match(e.salida.stderr, /CADDY_HTTP_PORT/); } finally { e.limpiar(); }
    });
  }
  test("CADDY_HTTP_PORT=8080 y 65535 se aceptan", () => {
    for (const p of ["8080", "65535", "9090"]) {
      const e = proxy({ CADDY_HTTP_PORT: p });
      try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
    }
  });

  test(".env con finales de línea de Windows (CRLF): error que lo dice y cómo arreglarlo (antes: «actual: domain\\r»)", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const ruta = join(e.kit, ".env");
      writeFileSync(ruta, readFileSync(ruta, "utf8").replaceAll("\n", "\r\n"));
      const r = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /CRLF|Windows/);
      assert.match(r.stderr, /\\r|dos2unix/);
    } finally { e.limpiar(); }
  });

  test(".env con un valor con espacios sin comillas: error claro en español (antes: «.env: line 5: Nacional: command not found»)", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const ruta = join(e.kit, ".env");
      writeFileSync(ruta, readFileSync(ruta, "utf8") + "INSTITUTION_NOTA=Instituto Nacional de Prueba\n");
      const r = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /comillas/);
      assert.match(r.stderr, /\.env/);
      assert.equal(e.existe("propiedadesDefault"), false);
    } finally { e.limpiar(); }
  });

  test("un .env correcto no cambia: se sigue leyendo igual", () => {
    const e = prepararEntorno({});
    try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
  });
});

describe("T7-4 · INSTITUTION_ID con guion", () => {
  for (const id of ["mi-institucion", "mi institucion", "inst.ituto", "1inst", "ñandú"]) {
    test(`INSTITUTION_ID=${id}: el error nombra INSTITUTION_ID y su regla, no CREDENTIAL_TYPE`, () => {
      const e = prepararEntorno({ extra: { INSTITUTION_ID: id } });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /INSTITUTION_ID/);
        assert.match(e.salida.stderr, /letras sin acento, dígitos y «_»/);
        assert.doesNotMatch(e.salida.stderr, /en CREDENTIAL_TYPE/);
      } finally { e.limpiar(); }
    });
  }
  test("con CREDENTIAL_TYPE explícito, INSTITUTION_ID con guion NO molesta (el tipo no sale de él)", () => {
    const e = prepararEntorno({ extra: { INSTITUTION_ID: "mi-institucion", CREDENTIAL_TYPE: "VerifiableCredential,MiLicencia" } });
    try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
  });
  test("un CREDENTIAL_TYPE inválido sigue diciendo CREDENTIAL_TYPE", () => {
    const e = prepararEntorno({ extra: { CREDENTIAL_TYPE: "VerifiableCredential,mi-tipo" } });
    try { assert.match(e.salida.stderr, /en CREDENTIAL_TYPE/); } finally { e.limpiar(); }
  });
});

describe("T7-5 · generate-logo.sh conserva los logos de otras claves", () => {
  test("dos claves seguidas dejan los dos PNG (las credenciales ya emitidas referencian el logo viejo)", () => {
    const e = prepararEntorno({});
    try {
      assert.ok(existsSync(join(e.generated, "logos", "PruebaLicencia.png")));
      writeFileSync(join(e.kit, ".env"), readFileSync(join(e.kit, ".env"), "utf8") + 'CREDENTIAL_CONFIG_KEY_ID="PruebaLicenciaV2"\n');
      const r = e.ejecutar('bash "$PWD/scripts/generate-logo.sh"');
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readdirSync(join(e.generated, "logos")).sort(), ["PruebaLicencia.png", "PruebaLicenciaV2.png"]);
    } finally { e.limpiar(); }
  });
  test("el comentario ya no dice que un logo viejo «no se sirve»", () => {
    const t = readFileSync(join(KIT_ORIGEN, "scripts", "generate-logo.sh"), "utf8");
    assert.doesNotMatch(t, /no se sirve/);
    assert.match(t, /se conservan/i);
  });
});

describe("T7-6 · verify-install.sh sugiere mirar el proxy / el certificado cuando la comprobación 1 falla", () => {
  const verif = (e, extra = {}) => {
    const bin = join(e.raiz, "bin"); mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "docker"), '#!/bin/sh\ncase "$*" in *actuator/health*) echo \'{"status":"UP"}\';; esac\nexit 0\n', { mode: 0o755 });
    writeFileSync(join(bin, "node"), '#!/bin/sh\necho "  1. FALLA     La metadata del emisor responde: simulado"\nexit 1\n', { mode: 0o755 });
    return e.ejecutar("bash scripts/verify-install.sh", { PATH: `${bin}:${process.env.PATH}`, KIT_NODE: "local", VERIFY_HEALTH_INTENTOS: "1", VERIFY_HEALTH_PAUSA: "0", ...extra });
  };
  test("proxy: «¿su proxy ya reenvía a este servidor?» con la URL y el puerto", () => {
    const e = proxy({});
    try {
      const r = verif(e);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /¿su proxy ya reenvía a este servidor\?/i);
      assert.match(r.stderr, /https:\/\/certify\.prueba\.invalid/);
      assert.match(r.stderr, /8080/);
    } finally { e.limpiar(); }
  });
  test("domain: sugiere esperar al certificado de Let's Encrypt y repetir", () => {
    const e = prepararEntorno({});
    try {
      const r = verif(e);
      assert.match(r.stderr, /Let's Encrypt|certificado/);
      assert.match(r.stderr, /verify-install\.sh/);
      assert.doesNotMatch(r.stderr, /su proxy/);
    } finally { e.limpiar(); }
  });
  test("si la verificación pasa no imprime ninguna sugerencia", () => {
    const e = proxy({});
    try {
      const bin = join(e.raiz, "bin"); mkdirSync(bin, { recursive: true });
      writeFileSync(join(bin, "docker"), '#!/bin/sh\ncase "$*" in *actuator/health*) echo \'{"status":"UP"}\';; esac\nexit 0\n', { mode: 0o755 });
      writeFileSync(join(bin, "node"), '#!/bin/sh\necho "Resultado: la instalación pasa la verificación."\nexit 0\n', { mode: 0o755 });
      const r = e.ejecutar("bash scripts/verify-install.sh", { PATH: `${bin}:${process.env.PATH}`, KIT_NODE: "local", VERIFY_HEALTH_INTENTOS: "1", VERIFY_HEALTH_PAUSA: "0" });
      assert.equal(r.status, 0, r.stderr);
      assert.doesNotMatch(r.stderr, /su proxy|Let's Encrypt/);
    } finally { e.limpiar(); }
  });
});

describe("K15 · kit_timeout (macOS no trae `timeout`)", () => {
  // PATH solo con lo necesario para el respaldo de kit_timeout, y SIN timeout ni gtimeout.
  const sinTimeout = (e) => {
    const bin = join(e.raiz, "bin-sin-timeout"); mkdirSync(bin, { recursive: true });
    for (const c of ["bash", "sleep", "mktemp", "rm", "cat", "env", "dirname", "true", "false", "echo", "kill"]) {
      try { symlinkSync(execFileSync("sh", ["-c", `command -v ${c}`], { encoding: "utf8" }).trim(), join(bin, c)); } catch { /* builtin */ }
    }
    return bin;
  };
  const corre = (e, orden) => e.ejecutar(`source scripts/lib/common.sh; ${orden}`, { PATH: sinTimeout(e), TMPDIR: e.raiz });
  test("sin `timeout` ni `gtimeout` en el PATH, la orden que termina a tiempo devuelve su código", () => {
    const e = prepararEntorno({ generar: false });
    try {
      assert.equal(spawnSync("sh", ["-c", `PATH="${sinTimeout(e)}"; command -v timeout`]).status, 1, "el PATH de prueba no tiene timeout");
      assert.equal(corre(e, "kit_timeout 5 true").status, 0);
      assert.equal(corre(e, "kit_timeout 5 false").status, 1);
    } finally { e.limpiar(); }
  });
  test("una orden que no termina se corta a los segundos pedidos y devuelve 124", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const t0 = Date.now();
      const r = corre(e, "kit_timeout 1 sleep 30");
      assert.equal(r.status, 124, r.stderr);
      assert.ok(Date.now() - t0 < 10_000, "no esperó los 30 s");
    } finally { e.limpiar(); }
  });
  test("install.sh ya no usa `timeout` a secas", () => {
    const t = readFileSync(join(KIT_ORIGEN, "install.sh"), "utf8").split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
    assert.doesNotMatch(t, /(^|\s)timeout\s+\d/m);
    assert.match(t, /kit_timeout 30/);
  });
});

describe("K15 · claves TLS de prueba en el repositorio", () => {
  test("hay una allowlist de escáner de secretos (gitleaks) que las nombra y dice por qué", () => {
    const ruta = join(KIT_ORIGEN, "..", ".gitleaks.toml");
    assert.ok(existsSync(ruta), ".gitleaks.toml en la raíz del repositorio");
    const t = readFileSync(ruta, "utf8");
    assert.match(t, /institution-kit\/test\/fixtures\/tls/);
    assert.match(t, /autofirmad/i);
    assert.match(t, /no protegen nada|de mentira/i);
  });
  test("las claves de test/fixtures/tls son las de la procedencia documentada (autofirmadas, de mentira)", () => {
    const p = readFileSync(join(KIT_ORIGEN, "test", "helpers", "PROCEDENCIA.md"), "utf8");
    assert.match(p, /autofirmados, de mentira/);
    assert.deepEqual(readdirSync(join(KIT_ORIGEN, "test", "fixtures", "tls")).sort(), ["desconocido.key", "desconocido.pem", "localhost.key", "localhost.pem"]);
  });
});
