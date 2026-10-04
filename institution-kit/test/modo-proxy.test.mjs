// T5 · Modo proxy (R6, D5). Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, writeFileSync, mkdirSync, chmodSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { prepararEntorno, KIT_ORIGEN } from "./helpers/entorno.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const URL_PROXY = "https://certify.prueba.invalid";
// En proxy no hay ACME: CADDY_ACME_EMAIL no hace falta (undefined lo quita del .env).
const proxy = (extra = {}, opciones = {}) =>
  prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: URL_PROXY, CADDY_ACME_EMAIL: undefined, ...extra }, ...opciones });
const vivo = (t) => t.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n"); // sin comentarios
const hayCompose = (() => {
  try { execFileSync("docker", ["compose", "version"], { stdio: "ignore" }); return true; } catch { return false; }
})();
const sinCompose = !hayCompose && "docker compose no está instalado";

describe("TLS_MODE=proxy · CERTIFY_PUBLIC_URL obligatorio (R6)", () => {
  test("sin CERTIFY_PUBLIC_URL: error claro y no genera nada", () => {
    const e = proxy({ CERTIFY_PUBLIC_URL: undefined });
    try {
      assert.notEqual(e.salida.status, 0);
      assert.match(e.salida.stderr, /CERTIFY_PUBLIC_URL es obligatorio con TLS_MODE=proxy/);
      assert.match(e.salida.stderr, /https:\/\/.*sin barra final/);
      for (const f of ["caddyfile", "propiedadesDefault", "sql"]) assert.equal(e.existe(f), false, f);
    } finally { e.limpiar(); }
  });

  test("CERTIFY_PUBLIC_URL vacío: el mismo error", () => {
    const e = proxy({ CERTIFY_PUBLIC_URL: "" });
    try {
      assert.notEqual(e.salida.status, 0);
      assert.match(e.salida.stderr, /CERTIFY_PUBLIC_URL es obligatorio con TLS_MODE=proxy/);
    } finally { e.limpiar(); }
  });

  for (const [nombre, v, patron] of [
    ["con barra final", "https://certify.prueba.invalid/", /no debe terminar en «\/»/],
    ["con ruta", "https://certify.prueba.invalid/v1", /https:\/\/<dominio público> sin ruta/],
    ["con http (no localhost)", "http://certify.prueba.invalid", /https:\/\/<dominio público>/],
    ["sin esquema", "certify.prueba.invalid", /https:\/\/<dominio público>/],
    ["con espacios", "https://certify prueba.invalid", /https:\/\/<dominio público>/],
    ["con usuario (@)", "https://usuario@certify.prueba.invalid", /https:\/\/<dominio público>/],
    ["con puerto no numérico", "https://certify.prueba.invalid:abc", /https:\/\/<dominio público>/],
    ["con consulta", "https://certify.prueba.invalid?x=1", /https:\/\/<dominio público>/],
    ["con salto de línea", "https://certify.prueba.invalid\nspring.x=1", /https:\/\/<dominio público>/],
  ]) {
    test(`CERTIFY_PUBLIC_URL ${nombre} se rechaza`, () => {
      const e = proxy({ CERTIFY_PUBLIC_URL: v });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, patron);
        assert.equal(e.existe("caddyfile"), false);
      } finally { e.limpiar(); }
    });
  }

  for (const v of ["https://certify.prueba.invalid", "https://certify.prueba.invalid:8443", "http://localhost:8080", "http://127.0.0.1"]) {
    test(`CERTIFY_PUBLIC_URL=${v} se acepta`, () => {
      const e = proxy({ CERTIFY_PUBLIC_URL: v });
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        assert.match(e.leer("runtime"), new RegExp(`^CERTIFY_PUBLIC_URL=${v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"));
      } finally { e.limpiar(); }
    });
  }

  test("el DID y las URL del emisor salen de CERTIFY_PUBLIC_URL; con puerto, el DID lo codifica como %3A", () => {
    const e = proxy();
    const e2 = proxy({ CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid:8443" });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("runtime"), /^DID_URL=did:web:certify\.prueba\.invalid$/m);
      assert.match(e.leer("propiedadesDefault"), /^mosip\.certify\.domain\.url=https:\/\/certify\.prueba\.invalid$/m);
      assert.match(e.leer("sql"), /did:web:certify\.prueba\.invalid/);
      assert.match(e2.leer("runtime"), /^DID_URL=did:web:certify\.prueba\.invalid%3A8443$/m);
    } finally { e.limpiar(); e2.limpiar(); }
  });

  test("en proxy no hace falta CADDY_ACME_EMAIL; en domain e ip sigue siendo obligatorio", () => {
    const p = proxy();
    const d = prepararEntorno({ modo: "domain", extra: { CADDY_ACME_EMAIL: undefined } });
    const i = prepararEntorno({ modo: "ip", extra: { CADDY_ACME_EMAIL: undefined } });
    try {
      assert.equal(p.salida.status, 0, p.salida.stderr);
      for (const x of [d, i]) {
        assert.notEqual(x.salida.status, 0);
        assert.match(x.salida.stderr, /CADDY_ACME_EMAIL/);
      }
    } finally { p.limpiar(); d.limpiar(); i.limpiar(); }
  });
});

describe("TLS_MODE=proxy · Caddyfile", () => {
  const e = proxy();
  const c = () => e.leer("caddyfile");
  const v = () => vivo(c());

  test("genera sin error", () => assert.equal(e.salida.status, 0, e.salida.stderr));

  test("sitio :80, sin tls, sin ACME, sin email, sin nombre de dominio", () => {
    assert.match(v(), /^:80 \{\n\timport certify_comun\n\}$/m);
    assert.doesNotMatch(v(), /\btls\b/);
    assert.doesNotMatch(v(), /\bemail\b/);
    assert.doesNotMatch(v(), /acme/i);
    assert.doesNotMatch(v(), /:443/);
    assert.doesNotMatch(v(), /certify\.prueba\.invalid/);
    assert.match(v(), /^\tauto_https off$/m);
  });

  test("confía en el proxy: trusted_proxies static private_ranges y lectura estricta de X-Forwarded-For", () => {
    assert.match(v(), /servers \{\n\t\ttrusted_proxies static private_ranges\n\t\ttrusted_proxies_strict\n\t\}/);
  });

  test("health del actuator con client_ip private_ranges (nunca remote_ip)", () => {
    assert.match(v(), /@interno client_ip private_ranges/);
    assert.doesNotMatch(v(), /remote_ip/);
    assert.match(v(), /handle \/v1\/certify\/actuator\*/);
  });

  test("el bloque global va primero, el fragmento se define antes de importarse y las llaves cuadran", () => {
    const t = v();
    assert.ok(t.indexOf("trusted_proxies") < t.indexOf("(certify_comun)"));
    assert.ok(t.indexOf("(certify_comun)") < t.indexOf("import certify_comun"));
    assert.equal(t.trim().startsWith("{"), true, "el bloque de opciones globales es lo primero");
    assert.equal((t.match(/\{/g) ?? []).length, (t.match(/\}/g) ?? []).length);
    assert.doesNotMatch(c(), /\$[A-Z_]+/, "variable sin sustituir");
  });

  test("lleva las mismas rutas comunes que domain e ip (did.json, contextos, logos, actuator 404, proxy a Certify)", () => {
    const d = prepararEntorno({ modo: "domain" });
    try {
      const rutas = (t) => (t.match(/^\t(?:handle|handle_path|route) \S+/gm) ?? []).sort();
      assert.deepEqual(rutas(c()), rutas(d.leer("caddyfile")));
      const fragmento = (t) => t.slice(t.indexOf("(certify_comun) {"), t.indexOf("\n}\n", t.indexOf("(certify_comun) {")) + 3);
      assert.equal(fragmento(c()), fragmento(d.leer("caddyfile")), "UNA sola copia de la lógica de rutas");
    } finally { d.limpiar(); }
  });

  test("TRUSTED_PROXIES propio: se escribe tal cual", () => {
    const x = proxy({ TRUSTED_PROXIES: "10.1.2.3 192.0.2.0/24 2001:db8::/32" });
    try {
      assert.equal(x.salida.status, 0, x.salida.stderr);
      assert.match(vivo(x.leer("caddyfile")), /^\t\ttrusted_proxies static 10\.1\.2\.3 192\.0\.2\.0\/24 2001:db8::\/32$/m);
    } finally { x.limpiar(); }
  });

  for (const malo of ["private_ranges }\n respond 200 {", "10.0.0.1; respond", "todos", "0.0.0.0/0 }", "$(id)"]) {
    test(`TRUSTED_PROXIES=${JSON.stringify(malo)} se rechaza (va al Caddyfile)`, () => {
      const x = proxy({ TRUSTED_PROXIES: malo });
      try {
        assert.notEqual(x.salida.status, 0);
        assert.match(x.salida.stderr, /TRUSTED_PROXIES solo admite/);
        assert.equal(x.existe("caddyfile"), false);
      } finally { x.limpiar(); }
    });
  }

  test("domain e ip no llevan trusted_proxies ni auto_https off", () => {
    for (const modo of ["domain", "ip"]) {
      const x = prepararEntorno({ modo });
      try {
        assert.doesNotMatch(vivo(x.leer("caddyfile")), /trusted_proxies|auto_https/, modo);
      } finally { x.limpiar(); }
    }
  });

  test("caddy validate (se omite si no hay binario `caddy`)", { skip: (() => { try { execFileSync("caddy", ["version"], { stdio: "ignore" }); return false; } catch { return "no hay binario caddy en esta máquina"; } })() }, () => {
    execFileSync("caddy", ["validate", "--config", e.rutas.caddyfile, "--adapter", "caddyfile"], { stdio: "pipe" });
  });

  test("limpieza", () => e.limpiar());
});

describe("CADDY_HTTP_PORT", () => {
  test("por defecto 8080; el valor llega a .env.runtime", () => {
    const e = proxy();
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("runtime"), /^CADDY_HTTP_PORT=8080$/m);
    } finally { e.limpiar(); }
  });

  test("propio: 9090", () => {
    const e = proxy({ CADDY_HTTP_PORT: "9090" });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("runtime"), /^CADDY_HTTP_PORT=9090$/m);
    } finally { e.limpiar(); }
  });

  for (const malo of ["0", "65536", "abc", "80 80", "8080:80", "-1", "08080x"]) {
    test(`CADDY_HTTP_PORT=${JSON.stringify(malo)} se rechaza`, () => {
      const e = proxy({ CADDY_HTTP_PORT: malo });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /CADDY_HTTP_PORT debe ser un puerto entre 1 y 65535/);
        assert.equal(e.existe("caddyfile"), false);
      } finally { e.limpiar(); }
    });
  }

  test("en domain e ip no se valida (no se usa)", () => {
    const e = prepararEntorno({ modo: "domain", extra: { CADDY_HTTP_PORT: "abc" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
    } finally { e.limpiar(); }
  });
});

describe("compose por modo: ficheros superpuestos (D5)", () => {
  const leerKit = (ruta) => readFileSync(join(KIT_ORIGEN, ruta), "utf8");

  test("el docker-compose.yml base no publica ningún puerto de Caddy", () => {
    const caddy = leerKit("docker-compose.yml").split(/^  caddy:/m)[1].split(/^networks:/m)[0];
    assert.doesNotMatch(vivo(caddy), /^\s+ports:/m);
    assert.doesNotMatch(vivo(caddy), /"?(80|443|8080)"?:\d+/);
  });

  test("docker-compose.tls.yml publica 80 y 443; docker-compose.proxy.yml solo CADDY_HTTP_PORT → 80", () => {
    const tls = vivo(leerKit("docker-compose.tls.yml"));
    assert.match(tls, /- "80:80"/);
    assert.match(tls, /- "443:443"/);
    const px = vivo(leerKit("docker-compose.proxy.yml"));
    assert.match(px, /- "\$\{CADDY_HTTP_PORT:-8080\}:80"/);
    assert.doesNotMatch(px, /443/);
    assert.doesNotMatch(px, /"80:80"/);
    assert.equal((px.match(/^\s+- "/gm) ?? []).length, 1, "un solo puerto publicado");
  });

  for (const [modo, esperado] of [
    ["domain", "-f docker-compose.yml -f docker-compose.tls.yml --env-file generated/.env.runtime"],
    ["ip", "-f docker-compose.yml -f docker-compose.tls.yml --env-file generated/.env.runtime"],
    ["proxy", "-f docker-compose.yml -f docker-compose.proxy.yml --env-file generated/.env.runtime"],
  ]) {
    test(`generated/compose-args (${modo}) deja escrita la orden exacta`, () => {
      const e = modo === "proxy" ? proxy() : prepararEntorno({ modo });
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        assert.equal(e.leer("composeArgs"), `${esperado}\n`);
      } finally { e.limpiar(); }
    });
  }

  const puertos = (e, fichero = null) => {
    const orden = fichero ?? "docker compose $(cat generated/compose-args)";
    const r = e.ejecutar(`${orden} config --format json`, { HOME: process.env.HOME });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout).services.caddy.ports.map((p) => `${p.published}:${p.target}`).sort();
  };

  test("docker compose config (sin daemon): proxy publica SOLO 8080:80; no hay 443 ni 80", { skip: sinCompose }, () => {
    const e = proxy();
    try {
      assert.deepEqual(puertos(e), ["8080:80"]);
    } finally { e.limpiar(); }
  });

  test("docker compose config: CADDY_HTTP_PORT=9090 → 9090:80", { skip: sinCompose }, () => {
    const e = proxy({ CADDY_HTTP_PORT: "9090" });
    try {
      assert.deepEqual(puertos(e), ["9090:80"]);
    } finally { e.limpiar(); }
  });

  for (const modo of ["domain", "ip"]) {
    test(`docker compose config: ${modo} publica 80:80 y 443:443, igual que el compose anterior a T5 (fixture)`, { skip: sinCompose }, () => {
      const e = prepararEntorno({ modo });
      try {
        const nuevo = puertos(e);
        const antes = puertos(e, `docker compose -f ${join(AQUI, "fixtures", "linea-base-t3", "docker-compose.yml")}`);
        assert.deepEqual(nuevo, ["443:443", "80:80"]);
        assert.deepEqual(nuevo, antes);
      } finally { e.limpiar(); }
    });
  }

  test("docker compose config: el resto del compose (servicios, volúmenes, redes) no cambia entre modos", { skip: sinCompose }, () => {
    const e = proxy();
    const d = prepararEntorno({ modo: "domain" });
    try {
      const cfg = (x) => {
        const r = x.ejecutar("docker compose $(cat generated/compose-args) config --format json", { HOME: process.env.HOME });
        const j = JSON.parse(r.stdout);
        for (const s of Object.values(j.services)) delete s.ports;
        delete j.name;
        // Las rutas absolutas de los montajes dependen del directorio temporal de cada entorno.
        return JSON.stringify(j).replaceAll(x.kit, "<kit>").replaceAll(x.raiz, "<raiz>");
      };
      // Las contraseñas generadas difieren entre entornos: se igualan antes de comparar.
      const norm = (t, x) => t.replaceAll(/[0-9a-f]{64}/g, "<hex>");
      assert.equal(norm(cfg(e), e), norm(cfg(d), d));
    } finally { e.limpiar(); d.limpiar(); }
  });
});

describe("domain e ip: sin cambios de comportamiento frente a la línea base de T3 (fixtures)", () => {
  // Los fixtures son el Caddyfile que generaba el kit en el commit 743540e (fin de T3), con el mismo
  // .env de prueba. T8 (K8) cambió A PROPÓSITO el fragmento de rutas `(certify_comun)` (lista blanca en vez de
  // `handle /v1/certify/*`, 404 final: ver caddy-lista-blanca.test.mjs), así que ya no se compara el fragmento
  // entero. Lo que sigue sin cambiar frente a la línea base, y se compara, es TODO lo de fuera del fragmento
  // (bloque global con el correo, bloque del sitio con su `import`). T5 solo cambió `remote_ip`→`client_ip`
  // (en el fragmento).
  const sinFragmento = (c) => c.replace(/^\(certify_comun\) \{\n[\s\S]*?\n\}\n/m, "");
  for (const modo of ["domain", "ip"]) {
    test(`Caddyfile ${modo}: lo de fuera del fragmento de rutas es idéntico a la línea base de T3`, () => {
      const e = prepararEntorno({ modo });
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        const antes = vivo(sinFragmento(readFileSync(join(AQUI, "fixtures", "linea-base-t3", `Caddyfile.${modo}`), "utf8")));
        const ahora = vivo(sinFragmento(e.leer("caddyfile")));
        assert.equal(ahora, antes);
        assert.ok(ahora.length > 20, "algo se comparó");
        assert.equal((vivo(e.leer("caddyfile")).match(/client_ip/g) ?? []).length, 1);
      } finally { e.limpiar(); }
    });
  }

  test("domain: el sitio sigue siendo el dominio y lleva email (ACME); ip, el hostname sslip.io", () => {
    const d = prepararEntorno({ modo: "domain" });
    const i = prepararEntorno({ modo: "ip" });
    try {
      assert.match(vivo(d.leer("caddyfile")), /^\{\n\temail infra@prueba\.invalid\n\}/);
      assert.match(vivo(d.leer("caddyfile")), /^emisor\.prueba\.invalid \{\n\timport certify_comun\n\}/m);
      assert.match(vivo(i.leer("caddyfile")), /^203-0-113-10\.sslip\.io \{\n\timport certify_comun\n\}/m);
    } finally { d.limpiar(); i.limpiar(); }
  });

  test("las properties de domain, ip y proxy solo difieren en la URL pública y el DID", () => {
    const d = prepararEntorno({ modo: "domain", extra: { POSTGRES_PASSWORD: "p", KEYSTORE_PASSWORD: "k" } });
    const x = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "https://emisor.prueba.invalid", CADDY_ACME_EMAIL: undefined, POSTGRES_PASSWORD: "p", KEYSTORE_PASSWORD: "k" } });
    try {
      // Mismo host público → mismas properties en domain y en proxy.
      assert.equal(d.leer("propiedadesDefault"), x.leer("propiedadesDefault"));
      assert.equal(d.leer("propiedadesInstitucion"), x.leer("propiedadesInstitucion"));
      assert.equal(d.leer("sql"), x.leer("sql"));
    } finally { d.limpiar(); x.limpiar(); }
  });
});

describe("install.sh en modo proxy (docker y curl falsos: sin daemon ni red)", () => {
  test("todo `docker compose` usa generated/compose-args; sin ACME ni logs de Caddy; el mensaje habla del proxy", () => {
    const e = proxy({ RESTAPI_PLUGIN_JAR: undefined }, { generar: false });
    try {
      const plugin = join(e.raiz, "plugin.jar"); writeFileSync(plugin, "x");
      const jarDir = join(e.raiz, "certify-service", "loader_path", "certify"); mkdirSync(jarDir, { recursive: true });
      writeFileSync(join(jarDir, "restapi-dataprovider-plugin-0.0.0.jar"), "x");
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      const registro = join(e.raiz, "docker.log");
      writeFileSync(join(bin, "docker"), `#!/bin/sh
echo "docker $*" >> "${registro}"
case "$*" in
  *"exec -T caddy wget"*actuator/health*) echo '{"status":"UP"}';;
  *"exec -T caddy wget"*did.json*) cat "${join(AQUI, "fixtures", "did-certify.json")}";;
esac
exit 0
`);
      writeFileSync(join(bin, "curl"), `#!/bin/sh
case "$*" in
  *did.json*) cat "${join(e.generated, "did", "did.json")}";;
  *openid-credential-issuer*) echo '{"credential_endpoint":"https://certify.prueba.invalid/v1/certify/issuance/credential"}';;
esac
`);
      // `node` falso SOLO para el programa de verificación (T6: install.sh llama a verify-install.sh, que
      // diagnosticaría https://certify.prueba.invalid de verdad); lo demás va al node real.
      writeFileSync(join(bin, "node"), `#!/bin/sh
case "$*" in
  *verificar-instalacion.mjs*) echo "Resumen: simulado"; exit 0;;
esac
exec "${process.execPath}" "$@"
`);
      chmodSync(join(bin, "docker"), 0o755); chmodSync(join(bin, "curl"), 0o755); chmodSync(join(bin, "node"), 0o755);
      const r = e.ejecutar('bash install.sh', { PATH: `${bin}:${process.env.PATH}` });
      assert.equal(r.status, 0, r.stdout + r.stderr);
      const llamadas = readFileSync(registro, "utf8").trim().split("\n").filter((l) => !l.startsWith("docker compose version"));
      assert.ok(llamadas.length >= 4);
      for (const l of llamadas) {
        assert.match(l, /^docker compose -f docker-compose\.yml -f docker-compose\.proxy\.yml --env-file generated\/\.env\.runtime /, l);
      }
      assert.ok(llamadas.some((l) => / build$/.test(l)) && llamadas.some((l) => / up -d$/.test(l)));
      assert.ok(!llamadas.some((l) => / logs /.test(l)), "en proxy no hay logs de ACME que monitorear");
      assert.doesNotMatch(r.stdout, /Let's Encrypt|ACME/);
      assert.match(r.stdout, /Modo proxy: Caddy escucha solo HTTP en el puerto 8080/);
      assert.match(r.stdout, /X-Forwarded-For/);
    } finally { e.limpiar(); }
  });
});
