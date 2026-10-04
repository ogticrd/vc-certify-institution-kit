// T8 · K13 (media) y T7-2:
//  - Los tres servicios reinician solos (`restart: unless-stopped`): tras reiniciar el servidor o un OOM de Java, el
//    emisor no queda caído hasta que alguien ejecute `docker compose up -d`.
//  - Certify tiene healthcheck (el `wget` interno a /v1/certify/actuator/health: la imagen instala wget, ver el
//    Dockerfile) y Caddy espera a que esté sano (`depends_on: condition: service_healthy`).
//  - Postgres con volumen con NOMBRE (pgdata): la imagen declara su volumen anónimo y `docker compose down` + `up`
//    creaba otro VACÍO (T7-2). Una instalación anterior (volumen anónimo) NO se pasa a ciegas: install.sh se detiene
//    y explica la migración, porque actualizar sin migrar crearía una base nueva y vacía.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, chmodSync, existsSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { prepararEntorno, KIT_ORIGEN } from "./helpers/entorno.mjs";

const hayCompose = (() => { try { execFileSync("docker", ["compose", "version"], { stdio: "ignore" }); return true; } catch { return false; } })();
const yml = () => readFileSync(join(KIT_ORIGEN, "docker-compose.yml"), "utf8");
const servicio = (texto, nombre) => {
  const m = texto.match(new RegExp(`^  ${nombre}:\\n((?:    .*\\n|\\n)*)`, "m"));
  assert.ok(m, `no hay servicio ${nombre}`);
  return m[1];
};

describe("K13 · reinicio automático y healthchecks (texto del compose)", () => {
  for (const s of ["database", "certify", "caddy"]) {
    test(`${s}: restart: unless-stopped`, () => assert.match(servicio(yml(), s), /^    restart: unless-stopped$/m));
  }
  test("Certify tiene healthcheck con wget al health interno y un arranque largo (Spring tarda)", () => {
    const c = servicio(yml(), "certify");
    assert.match(c, /healthcheck:/);
    assert.match(c, /wget .*http:\/\/localhost:8090\/v1\/certify\/actuator\/health/);
    assert.match(c, /start_period: \d+s/);
    assert.ok(Number(c.match(/start_period: (\d+)s/)[1]) >= 60, "start_period largo");
  });
  test("Caddy espera a que Certify esté sano", () => {
    assert.match(servicio(yml(), "caddy"), /depends_on:\n      certify:\n        condition: service_healthy/);
  });
  test("Certify sigue esperando a la base sana", () => {
    assert.match(servicio(yml(), "certify"), /depends_on:\n      database:\n        condition: service_healthy/);
  });
  test("wget existe en la imagen de Certify (el healthcheck lo necesita) y en la de Caddy (alpine/busybox)", () => {
    const d = readFileSync(join(KIT_ORIGEN, "Dockerfile"), "utf8");
    assert.match(d, /apt-get install -y --no-install-recommends unzip wget/);
  });
});

describe("T7-2 · volumen con nombre para los datos de Postgres (texto del compose)", () => {
  test("la base monta pgdata en /var/lib/postgresql/data y pgdata está declarado", () => {
    assert.match(servicio(yml(), "database"), /^      - pgdata:\/var\/lib\/postgresql\/data$/m);
    assert.match(yml(), /^volumes:\n(?:  .*\n)*  pgdata:$/m);
  });
});

describe("K13/T7-2 · lo que resuelve `docker compose config` de verdad (sin daemon)", () => {
  for (const modo of ["domain", "ip", "proxy"]) {
    test(`${modo}: restart, healthcheck, depends_on y volumen`, { skip: !hayCompose && "docker compose no está instalado" }, () => {
      const extra = modo === "proxy" ? { CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid", CADDY_ACME_EMAIL: undefined } : {};
      const e = prepararEntorno({ modo, extra });
      try {
        const r = e.ejecutar("docker compose $(cat generated/compose-args) config --format json", { HOME: process.env.HOME });
        assert.equal(r.status, 0, r.stderr);
        const cfg = JSON.parse(r.stdout);
        for (const s of ["database", "certify", "caddy"]) assert.equal(cfg.services[s].restart, "unless-stopped", s);
        assert.match(cfg.services.certify.healthcheck.test.join(" "), /actuator\/health/);
        assert.equal(cfg.services.caddy.depends_on.certify.condition, "service_healthy");
        assert.equal(cfg.services.certify.depends_on.database.condition, "service_healthy");
        assert.ok(cfg.volumes.pgdata, "volumen pgdata");
        assert.ok(cfg.services.database.volumes.some((v) => v.type === "volume" && v.source === "pgdata" && v.target === "/var/lib/postgresql/data"));
      } finally { e.limpiar(); }
    });
  }
});

// docker falso: `ps -a` devuelve un contenedor de la base; `inspect` devuelve el nombre del volumen montado en los datos.
function dockerConBase(e, { montaje }) {
  const bin = join(e.raiz, "bin-docker");
  mkdirSync(bin, { recursive: true });
  const registro = join(e.raiz, "docker.log");
  writeFileSync(join(bin, "docker"), `#!/bin/sh
echo "$@" >> "${registro}"
case "$1" in
  ps) echo "abc123def456" ;;
  volume) echo "" ;;
  inspect) echo "${montaje}" ;;
esac
exit 0
`);
  chmodSync(join(bin, "docker"), 0o755);
  return { path: `${bin}:${process.env.PATH}`, registro: () => (existsSync(registro) ? readFileSync(registro, "utf8") : "") };
}
const ANONIMO = "9f2c" + "a1b3".repeat(15);

describe("T7-2 · una base que vive en un volumen anónimo no se pierde al actualizar", () => {
  test("verificar_volumen_postgres: con un volumen ANÓNIMO se detiene y explica cada paso de la migración", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const d = dockerConBase(e, { montaje: ANONIMO });
      const r = e.ejecutar("source scripts/lib/common.sh; verificar_volumen_postgres", { PATH: d.path });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /volumen ANÓNIMO/);
      assert.ok(r.stderr.includes(ANONIMO), "nombra el volumen a copiar");
      assert.match(r.stderr, /pg_dumpall/);
      assert.match(r.stderr, /stop database/);
      assert.match(r.stderr, /up --no-start database/);
      assert.match(r.stderr, new RegExp(`-v ${ANONIMO}:/desde:ro -v [a-z0-9_-]+_pgdata:/hacia`));
      assert.match(r.stderr, /vacía|vacio|vacía/i);
      assert.match(d.registro(), /inspect/);
    } finally { e.limpiar(); }
  });

  test("con un volumen ya con nombre (…_pgdata) no hace nada", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const d = dockerConBase(e, { montaje: "institution-kit_pgdata" });
      const r = e.ejecutar("source scripts/lib/common.sh; verificar_volumen_postgres", { PATH: d.path });
      assert.equal(r.status, 0, r.stderr);
    } finally { e.limpiar(); }
  });

  test("sin contenedor de la base (instalación nueva) o sin docker: no hace nada", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const r = e.ejecutar("source scripts/lib/common.sh; verificar_volumen_postgres");
      assert.equal(r.status, 0, r.stderr);
    } finally { e.limpiar(); }
  });

  test("install.sh la llama antes de construir o levantar nada", () => {
    const t = readFileSync(join(KIT_ORIGEN, "install.sh"), "utf8");
    const iGuarda = t.indexOf("verificar_volumen_postgres");
    assert.ok(iGuarda !== -1);
    assert.ok(iGuarda < t.indexOf('"${KIT_COMPOSE[@]}" build'));
    assert.ok(iGuarda < t.indexOf('"${KIT_COMPOSE[@]}" up'));
  });
});

describe("T7-2 · install.sh: el mensaje del modo ip y el `up`", () => {
  const sinComentarios = (t) => t.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
  test("el modo ip ya no recomienda `docker compose down`: pide parar y quitar solo Caddy y su volumen", () => {
    const t = sinComentarios(readFileSync(join(KIT_ORIGEN, "install.sh"), "utf8"));
    assert.doesNotMatch(t, /docker compose down/);
    assert.match(t, /rm -sf caddy/);
    assert.match(t, /volume rm/);
    assert.match(t, /caddy_data/);
  });
  test("`up -d` con un servicio que no llega a estar sano da un mensaje con la orden de los logs, no solo el error de compose", () => {
    const t = readFileSync(join(KIT_ORIGEN, "install.sh"), "utf8");
    assert.match(t, /"\$\{KIT_COMPOSE\[@\]\}" up -d \|\| \{/);
    assert.match(t, /logs certify/);
  });
});
