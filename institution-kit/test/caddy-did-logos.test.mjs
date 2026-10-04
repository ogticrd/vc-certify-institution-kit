// T3 · R5 (did.json corregido), R9 (actuator), R10 (logo propio). Sin Docker ni red: se prueban los
// ficheros que generan los scripts. Si existe el binario `caddy`, además se valida el Caddyfile con él.
//
//   fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, readdirSync, readdirSync as ls, statSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { prepararEntorno, valoresSql, literal, KIT_ORIGEN, PNG_1X1 } from "./helpers/entorno.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const DID_CERTIFY = JSON.parse(readFileSync(join(AQUI, "fixtures", "did-certify.json"), "utf8"));
const CADDY = spawnSync("caddy", ["version"], { encoding: "utf8" }).status === 0;
const HOSTS = { domain: "emisor.prueba.invalid", ip: "203-0-113-10.sslip.io" };

// Llaves equilibradas (ignorando comentarios y cadenas): un Caddyfile con una llave de más o de menos
// no arranca, y es el error más fácil de cometer al editar la plantilla.
function llavesEquilibradas(texto) {
  let prof = 0;
  for (const linea of texto.split("\n")) {
    const l = linea.replace(/"[^"]*"/g, '""').replace(/#.*$/, "");
    for (const c of l) {
      if (c === "{") prof++;
      if (c === "}") prof--;
      if (prof < 0) return false;
    }
  }
  return prof === 0;
}

// Texto del bloque `tras` { … } (con las llaves equilibradas), para acotar aserciones a un manejador.
function bloque(texto, cabecera) {
  const i = texto.indexOf(cabecera);
  assert.notEqual(i, -1, `no hay «${cabecera}»`);
  const ini = texto.indexOf("{", i);
  let prof = 0;
  for (let j = ini; j < texto.length; j++) {
    if (texto[j] === "{") prof++;
    if (texto[j] === "}" && --prof === 0) return texto.slice(ini, j + 1);
  }
  throw new Error(`bloque sin cerrar: ${cabecera}`);
}

for (const modo of ["domain", "ip"]) {
  describe(`Caddy, did.json, contextos, logos y actuator · TLS_MODE=${modo}`, () => {
    let e, c;
    const host = HOSTS[modo];
    before(() => { e = prepararEntorno({ modo }); c = e.leer("caddyfile"); });
    after(() => e.limpiar());

    test("la generación termina bien y el Caddyfile está bien formado", () => {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.ok(llavesEquilibradas(c), "llaves desequilibradas");
      assert.doesNotMatch(c, /\$\{?[A-Z_]+\}?/, "variable sin sustituir");
      // El bloque global va primero, el sitio usa el fragmento y el fragmento se define una sola vez.
      assert.match(c, /^\{\n\temail infra@prueba\.invalid\n\}/);
      assert.match(c, new RegExp(`^${host.replaceAll(".", "\\.")} \\{\\n(.*\\n)*?\\timport certify_comun\\n\\}`, "m"));
      assert.equal(c.match(/^\(certify_comun\) \{$/gm).length, 1);
      // Caddy exige definir el fragmento antes de importarlo.
      assert.ok(c.search(/^\(certify_comun\) \{$/m) < c.search(/^\timport certify_comun$/m));
    });

    test("R5: did.json se sirve del fichero corregido si existe y, si no, cae a Certify", () => {
      const did = bloque(c, "handle /.well-known/did.json");
      assert.match(did, /@corregido file \{\n\t\t\troot \/srv\/did\n\t\t\ttry_files \/did\.json\n\t\t\}/);
      const corregido = bloque(did, "handle @corregido");
      assert.match(corregido, /root \* \/srv\/did/);
      assert.match(corregido, /rewrite \* \/did\.json/);
      assert.match(corregido, /header Cache-Control "no-cache"/);
      assert.match(corregido, /header Content-Type "application\/json"/);
      assert.match(corregido, /\bfile_server\b/);
      // Respaldo: el `handle` SIN matcher, después del fichero, reescribe al DID de Certify.
      const resto = did.slice(did.indexOf(corregido) + corregido.length);
      assert.match(resto, /handle \{\n\t\t\trewrite \* \/v1\/certify\/\.well-known\/did\.json\n\t\t\treverse_proxy certify:8090\n\t\t\}/);
    });

    test("R1: /contextos/* se sirve desde /srv/contextos con no-cache y application/ld+json", () => {
      const b = bloque(c, "handle_path /contextos/*");
      assert.match(b, /root \* \/srv\/contextos/);
      assert.match(b, /header Cache-Control "no-cache"/);
      assert.match(b, /header Content-Type "application\/ld\+json"/);
      assert.match(b, /\bfile_server\b/);
      assert.doesNotMatch(b, /\bbrowse\b/, "sin listado de directorio");
    });

    test("R10: /logos/* se sirve desde /srv/logos con no-cache e image/png", () => {
      const b = bloque(c, "handle_path /logos/*");
      assert.match(b, /root \* \/srv\/logos/);
      assert.match(b, /header Cache-Control "no-cache"/);
      assert.match(b, /header Content-Type "image\/png"/);
      assert.match(b, /\bfile_server\b/);
      assert.doesNotMatch(b, /\bbrowse\b/);
    });

    test("R9/D8: el actuator es 404, salvo health desde rangos privados", () => {
      const salud = bloque(c, "handle /v1/certify/actuator/health");
      assert.match(salud, /@interno remote_ip private_ranges/);
      // Desde la red privada, proxy a Certify; desde cualquier otra, 404.
      assert.match(bloque(salud, "handle @interno"), /^\{\n\t\t\treverse_proxy certify:8090\n\t\t\}$/);
      assert.match(salud, /handle \{\n\t\t\trespond 404\n\t\t\}/);
      assert.match(bloque(c, "handle /v1/certify/actuator*"), /^\{\n\t\trespond 404\n\t\}$/);
      // La regla específica (health) va antes que el comodín, y ambas antes del proxy general de Certify.
      const iSalud = c.indexOf("handle /v1/certify/actuator/health");
      const iComodin = c.indexOf("handle /v1/certify/actuator*");
      const iGeneral = c.indexOf("handle /v1/certify/* {");
      assert.ok(iSalud < iComodin && iComodin < iGeneral);
      // El único matcher de IP es el de rangos privados.
      assert.doesNotMatch(c, /remote_ip (?!private_ranges)/);
    });

    test("la metadata del emisor y el resto de /v1/certify/* siguen yendo a Certify", () => {
      assert.match(c, /route \/\.well-known\/openid-credential-issuer \{\n\t\trewrite \* \/v1\/certify\/\.well-known\/openid-credential-issuer\n\t\treverse_proxy certify:8090\n\t\}/);
      assert.match(c, /handle \/v1\/certify\/\* \{\n\t\treverse_proxy certify:8090\n\t\}/);
    });

    test("no-cache en las tres rutas que sirven ficheros", () => {
      assert.equal((c.match(/header Cache-Control "no-cache"/g) || []).length, 3);
    });

    test("compose: Caddy monta las carpetas de did, contextos y logos en solo lectura, y no generated/ entera", () => {
      const y = readFileSync(e.rutas.compose, "utf8");
      const delCaddy = y.slice(y.search(/^  caddy:$/m), y.search(/^networks:$/m));
      const montajes = delCaddy.split("\n").filter((l) => /^      - \.\//.test(l)).map((l) => l.trim().slice(2));
      for (const m of ["did", "contextos", "logos"]) {
        assert.ok(montajes.includes(`./generated/${m}:/srv/${m}:ro`), `falta el montaje de ${m}: ${montajes}`);
      }
      // Todo montaje de generated/ en Caddy es de solo lectura y de una de esas carpetas (o del Caddyfile).
      for (const m of montajes) assert.match(m, /^\.\/generated\/(did|contextos|logos|caddy\/Caddyfile):[^:]+:ro$/, m);
    });

    test("las carpetas que compose monta existen tras generar (si no, Docker las crearía como root)", () => {
      for (const m of ["did", "contextos", "logos"]) {
        assert.ok(existsSync(join(e.generated, m)) && statSync(join(e.generated, m)).isDirectory(), m);
      }
      assert.deepEqual(ls(join(e.generated, "did")), [], "did/ vacía hasta que generate-did.sh corra con Certify UP");
    });

    test("R10: el logo se copia a generated/logos/<clave>.png y display.logo.url apunta a él", () => {
      assert.deepEqual(readFileSync(e.rutas.logo), PNG_1X1);
      const display = JSON.parse(literal(valoresSql(e.leer("sql")).display));
      assert.equal(display[0].logo.url, `https://${host}/logos/PruebaLicencia.png`);
      assert.doesNotMatch(e.leer("sql"), /mosip\.github\.io|agro-vertias/);
    });

    test("caddy validate sobre el Caddyfile generado", { skip: !CADDY && "no hay binario caddy en esta máquina" }, () => {
      const r = spawnSync("caddy", ["validate", "--adapter", "caddyfile", "--config", e.rutas.caddyfile], { encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
    });
  });
}

describe("el logo de terceros ya no existe en el kit (R10)", () => {
  test("ningún script, plantilla, compose ni .env.example lo menciona", () => {
    const rutas = [];
    const recorre = (d) => {
      for (const n of readdirSync(d)) {
        if (["test", "docs", "generated", "diagnostico", ".git"].includes(n)) continue;
        const p = join(d, n);
        statSync(p).isDirectory() ? recorre(p) : rutas.push(p);
      }
    };
    recorre(KIT_ORIGEN);
    for (const p of rutas) {
      if (/\.(png|jar|zip)$/.test(p)) continue;
      assert.doesNotMatch(readFileSync(p, "utf8"), /agro-vertias|mosip\.github\.io\/inji-config\/logos/, p);
    }
  });
});

describe("LOGO_PATH obligatorio y PNG (R10)", () => {
  const falla = (extra, patron, { runtime = false, antes } = {}) => {
    const e = prepararEntorno({ runtime, extra });
    try {
      antes?.(e);
      const paso = runtime ? e.pasos.runtime : e.pasos.generar;
      assert.notEqual(paso.status, 0, "debía fallar");
      assert.match(paso.stderr, patron);
      assert.equal(e.existe("sql"), false, "no se genera nada si el logo no vale");
      assert.equal(e.existe("logo"), false);
    } finally { e.limpiar(); }
  };

  test("sin LOGO_PATH: error claro (generate-config.sh)", () => {
    falla({ LOGO_PATH: undefined }, /LOGO_PATH es obligatorio.*PNG/);
  });

  test("sin LOGO_PATH: también falla la validación de install.sh", () => {
    falla({ LOGO_PATH: undefined }, /LOGO_PATH es obligatorio/, { runtime: true });
  });

  test("LOGO_PATH vacío: error claro", () => {
    falla({ LOGO_PATH: "" }, /LOGO_PATH es obligatorio/);
  });

  test("LOGO_PATH que no existe: error con la ruta", () => {
    falla({ LOGO_PATH: "/no/existe/logo.png" }, /LOGO_PATH no apunta a un fichero legible: \/no\/existe\/logo\.png/);
  });

  test("LOGO_PATH que es un directorio: error", () => {
    falla({ LOGO_PATH: "/tmp" }, /no apunta a un fichero legible/);
  });

  for (const [nombre, bytes] of [
    ["un texto", Buffer.from("esto no es un png\n")],
    ["un JPEG", Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46, 0x49, 0x46])],
    ["un SVG", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>')],
    ["un fichero vacío", Buffer.alloc(0)],
    ["solo los 4 primeros bytes de la firma PNG", Buffer.from([0x89, 0x50, 0x4e, 0x47])],
    ["un PNG con la firma corrompida (fin de línea CRLF cambiado)", Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0a, 0x0d, 0x1a, 0x0a, 0, 0])],
  ]) {
    test(`LOGO_PATH que es ${nombre}: error «no es un PNG»`, () => {
      const e = prepararEntorno({ runtime: false, generar: false });
      try {
        const falso = join(e.raiz, "falso.png"); // con extensión .png a propósito: se comprueba el contenido
        writeFileSync(falso, bytes);
        const envPath = join(e.kit, ".env");
        writeFileSync(envPath, readFileSync(envPath, "utf8").replace(/^LOGO_PATH=.*$/m, `LOGO_PATH="${falso}"`));
        const r = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
        assert.notEqual(r.status, 0);
        assert.match(r.stderr, /LOGO_PATH no es un PNG/);
        assert.equal(existsSync(e.rutas.logo), false, "el fichero falso no se copia a logos/");
        assert.equal(e.existe("sql"), false);
      } finally { e.limpiar(); }
    });
  }

  test("CREDENTIAL_LOGO_URL en el .env: se rechaza con el motivo (el logo de terceros desaparece)", () => {
    falla({ CREDENTIAL_LOGO_URL: "https://otro.invalid/logo.png" }, /CREDENTIAL_LOGO_URL ya no existe.*LOGO_PATH/);
  });

  test("una ruta relativa se resuelve desde el directorio del kit", () => {
    const e = prepararEntorno({ runtime: false, generar: false });
    try {
      writeFileSync(join(e.kit, "mi-logo.png"), PNG_1X1);
      const envPath = join(e.kit, ".env");
      writeFileSync(envPath, readFileSync(envPath, "utf8").replace(/^LOGO_PATH=.*$/m, 'LOGO_PATH="mi-logo.png"'));
      const r = e.ejecutar('bash "$PWD/scripts/generate-config.sh"');
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(readFileSync(e.rutas.logo), PNG_1X1);
    } finally { e.limpiar(); }
  });

  test("PNG válido: se copia byte a byte, con permisos de lectura, y la salida da la URL pública", () => {
    const e = prepararEntorno();
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.deepEqual(readFileSync(e.rutas.logo), PNG_1X1);
      assert.equal(statSync(e.rutas.logo).mode & 0o444, 0o444);
      assert.match(e.salida.stdout, /URL pública: https:\/\/emisor\.prueba\.invalid\/logos\/PruebaLicencia\.png/);
      // El original no se toca.
      assert.deepEqual(readFileSync(e.logoOrigen), PNG_1X1);
    } finally { e.limpiar(); }
  });

  test("la clave de la credencial es el nombre del fichero: una clave con «/» no puede escribir fuera de logos/", () => {
    const e = prepararEntorno({ runtime: false, extra: { CREDENTIAL_CONFIG_KEY_ID: "../escape" } });
    try {
      assert.notEqual(e.pasos.generar.status, 0);
      assert.match(e.pasos.generar.stderr, /CREDENTIAL_CONFIG_KEY_ID inválido/);
      assert.equal(existsSync(join(e.raiz, "institution-kit", "escape.png")), false);
      assert.equal(existsSync(join(e.generated, "escape.png")), false);
    } finally { e.limpiar(); }
  });
});

describe("generate-did.sh (R5)", () => {
  const conDid = (doc, cuerpo, { modo = "domain", antes } = {}) => {
    const e = prepararEntorno({ modo, runtime: false, generar: false });
    try {
      const origen = join(e.raiz, "did-origen.json");
      writeFileSync(origen, typeof doc === "string" ? doc : JSON.stringify(doc, null, 2));
      antes?.(e);
      const r = e.ejecutar('bash "$PWD/scripts/generate-did.sh"', { DID_ORIGEN: origen });
      cuerpo(e, r, origen);
    } finally { e.limpiar(); }
  };
  const salida = (e) => join(e.generated, "did", "did.json");
  const leerDid = (e) => JSON.parse(readFileSync(salida(e), "utf8"));

  test("el did.json de muestra de Certify tiene el defecto: assertionMethod es el DID pelado", () => {
    assert.deepEqual(DID_CERTIFY.assertionMethod, [DID_CERTIFY.id]);
    assert.deepEqual(DID_CERTIFY.authentication, [DID_CERTIFY.id]);
  });

  test("sustituye el DID pelado por el id del método de verificación y conserva lo demás", () => {
    conDid(DID_CERTIFY, (e, r) => {
      assert.equal(r.status, 0, r.stderr);
      const d = leerDid(e);
      const idMetodo = "did:web:emisor.prueba.invalid#key-0";
      assert.deepEqual(d.assertionMethod, [idMetodo]);
      assert.deepEqual(d.authentication, [idMetodo]);
      // Cada referencia resuelve a un verificationMethod del propio documento.
      for (const ref of d.assertionMethod) assert.ok(d.verificationMethod.some((m) => m.id === ref));
      assert.ok(!d.assertionMethod.includes(d.id), "ya no es el DID pelado");
      // Lo demás, intacto (clave, controlador, contexto, servicios).
      const { assertionMethod: _a, authentication: _b, ...resto } = d;
      const { assertionMethod: _c, authentication: _d, ...restoOrigen } = DID_CERTIFY;
      assert.deepEqual(resto, restoOrigen);
      assert.match(r.stdout, /DID corregido en .*generated\/did\/did\.json/);
      assert.match(r.stdout, /assertionMethod : \["did:web:emisor\.prueba\.invalid#key-0"\]/);
      assert.equal(r.stderr, "", "sin avisos cuando el id coincide con DID_URL");
    });
  });

  test("con varias claves, assertionMethod y authentication listan todas, en el orden del documento", () => {
    const doc = structuredClone(DID_CERTIFY);
    doc.verificationMethod.push({ ...doc.verificationMethod[0], id: "did:web:emisor.prueba.invalid#key-1", publicKeyMultibase: "z6MkotraClaveDePrueba" });
    conDid(doc, (e, r) => {
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(leerDid(e).assertionMethod, ["did:web:emisor.prueba.invalid#key-0", "did:web:emisor.prueba.invalid#key-1"]);
    });
  });

  test("es idempotente y no deja temporales; el fichero es legible por Caddy", () => {
    conDid(DID_CERTIFY, (e, r) => {
      assert.equal(r.status, 0, r.stderr);
      const primero = readFileSync(salida(e), "utf8");
      const r2 = e.ejecutar('bash "$PWD/scripts/generate-did.sh"', { DID_ORIGEN: join(e.raiz, "did-origen.json") });
      assert.equal(r2.status, 0, r2.stderr);
      assert.equal(readFileSync(salida(e), "utf8"), primero);
      assert.deepEqual(ls(join(e.generated, "did"), { encoding: "utf8" }).filter((n) => n !== "did.json"), [], "sin .did.json.XXXX");
      assert.equal(statSync(salida(e)).mode & 0o644, 0o644);
    });
  });

  test("también con TLS_MODE=ip (el DID lleva el hostname sslip.io)", () => {
    const doc = JSON.parse(JSON.stringify(DID_CERTIFY).replaceAll("emisor.prueba.invalid", HOSTS.ip));
    conDid(doc, (e, r) => {
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(leerDid(e).assertionMethod, [`did:web:${HOSTS.ip}#key-0`]);
      assert.equal(r.stderr, "");
    }, { modo: "ip" });
  });

  test("avisa (sin fallar) si el id del DID no coincide con DID_URL", () => {
    const doc = JSON.parse(JSON.stringify(DID_CERTIFY).replaceAll("emisor.prueba.invalid", "otro.invalid"));
    conDid(doc, (e, r) => {
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stderr, /AVISO: el id del DID \(did:web:otro\.invalid\) no coincide con DID_URL \(did:web:emisor\.prueba\.invalid\)/);
    });
  });

  for (const [nombre, doc] of [
    ["sin verificationMethod", (() => { const d = structuredClone(DID_CERTIFY); delete d.verificationMethod; return d; })()],
    ["con verificationMethod vacío", { ...DID_CERTIFY, verificationMethod: [] }],
    ["con un método sin id", { ...DID_CERTIFY, verificationMethod: [{ type: "Ed25519VerificationKey2020" }] }],
    ["sin id propio", (() => { const d = structuredClone(DID_CERTIFY); delete d.id; return d; })()],
    ["que no es un objeto", [DID_CERTIFY]],
    ["que no es JSON", "<html>502 Bad Gateway</html>"],
    ["vacío", ""],
  ]) {
    test(`origen ${nombre}: falla y no escribe nada`, () => {
      conDid(doc, (e, r) => {
        assert.notEqual(r.status, 0);
        assert.match(r.stderr, /ERROR: .*(DID|Certify)/);
        assert.equal(existsSync(salida(e)), false);
        assert.deepEqual(ls(join(e.generated, "did")), [], "ni temporales");
      });
    });
  }

  test("si falla, NO sobreescribe un did.json anterior", () => {
    conDid({ ...DID_CERTIFY, verificationMethod: [] }, (e, r) => {
      assert.notEqual(r.status, 0);
      assert.equal(readFileSync(salida(e), "utf8"), "VIEJO\n");
    }, { antes: (e) => { mkdirSync(join(e.generated, "did"), { recursive: true }); writeFileSync(join(e.generated, "did", "did.json"), "VIEJO\n"); } });
  });

  test("DID_ORIGEN que no existe: falla con la ruta", () => {
    const e = prepararEntorno({ runtime: false, generar: false });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/generate-did.sh"', { DID_ORIGEN: "/no/existe/did.json" });
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /DID_ORIGEN no es un fichero: \/no\/existe\/did\.json/);
    } finally { e.limpiar(); }
  });

  describe("sin DID_ORIGEN: lo pide a Certify por la red interna (docker compose exec en el contenedor de Caddy)", () => {
    const dockerFalso = (e, cuerpoSh) => {
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$@" >> "${join(e.raiz, "docker-args")}"\n${cuerpoSh}\n`);
      chmodSync(join(bin, "docker"), 0o755);
      return bin;
    };

    test("la orden es `docker compose exec -T caddy wget -qO- http://certify:8090/v1/certify/.well-known/did.json`, no la URL pública", () => {
      const e = prepararEntorno({ runtime: false, generar: false });
      try {
        const bin = dockerFalso(e, `cat "${join(AQUI, "fixtures", "did-certify.json")}"`);
        const r = e.ejecutar('bash "$PWD/scripts/generate-did.sh"', { PATH: `${bin}:${process.env.PATH}` });
        assert.equal(r.status, 0, r.stderr);
        const args = readFileSync(join(e.raiz, "docker-args"), "utf8").trim();
        assert.equal(args, "compose exec -T caddy wget -qO- http://certify:8090/v1/certify/.well-known/did.json");
        assert.doesNotMatch(args, /emisor\.prueba\.invalid/);
        assert.deepEqual(leerDid(e).assertionMethod, ["did:web:emisor.prueba.invalid#key-0"]);
      } finally { e.limpiar(); }
    });

    test("si Certify no responde (docker falla): error en español y no escribe nada", () => {
      const e = prepararEntorno({ runtime: false, generar: false });
      try {
        const bin = dockerFalso(e, "exit 1");
        const r = e.ejecutar('bash "$PWD/scripts/generate-did.sh"', { PATH: `${bin}:${process.env.PATH}` });
        assert.notEqual(r.status, 0);
        assert.match(r.stderr, /no se pudo leer el DID de Certify/);
        assert.equal(existsSync(salida(e)), false);
      } finally { e.limpiar(); }
    });

    test("si Certify devuelve vacío: error y no escribe nada", () => {
      const e = prepararEntorno({ runtime: false, generar: false });
      try {
        const bin = dockerFalso(e, "true");
        const r = e.ejecutar('bash "$PWD/scripts/generate-did.sh"', { PATH: `${bin}:${process.env.PATH}` });
        assert.notEqual(r.status, 0);
        assert.match(r.stderr, /DID vacío/);
        assert.equal(existsSync(salida(e)), false);
      } finally { e.limpiar(); }
    });
  });

  test("tiene nota de procedencia con la ruta del original y la fecha", () => {
    const t = readFileSync(join(KIT_ORIGEN, "scripts", "generate-did.sh"), "utf8");
    assert.match(t, /PROCEDENCIA.*inji-vc\/stack\/bin\/generar-did\.sh.*4-oct-2026/s);
  });
});

describe("el orden de install.sh (R5): el DID se corrige con Certify ya en marcha", () => {
  const install = readFileSync(join(KIT_ORIGEN, "install.sh"), "utf8");
  const config = readFileSync(join(KIT_ORIGEN, "scripts", "generate-config.sh"), "utf8");

  test("generate-did.sh va después de verify-health.sh y antes del resumen final", () => {
    const iSalud = install.indexOf("scripts/verify-health.sh");
    const iDid = install.indexOf("scripts/generate-did.sh");
    const iFinal = install.indexOf("Instalación completada");
    assert.ok(iSalud !== -1 && iDid !== -1 && iFinal !== -1);
    assert.ok(iSalud < iDid && iDid < iFinal);
    assert.ok(install.indexOf("docker compose up") < iSalud);
  });

  test("generate-config.sh NO lo ejecuta (no hay Certify todavía) pero sí crea la carpeta vacía que Caddy monta", () => {
    const sinComentarios = config.split("\n").filter((l) => !l.trim().startsWith("#")).join("\n");
    assert.doesNotMatch(sinComentarios, /generate-did\.sh/);
    assert.match(config, /mkdir -p .*generated\/did/);
  });

  test("verify-health.sh pregunta el health por la red interna: el actuator ya no es público", () => {
    const t = readFileSync(join(KIT_ORIGEN, "scripts", "verify-health.sh"), "utf8");
    assert.match(t, /docker compose exec -T caddy wget -qO- http:\/\/certify:8090\/v1\/certify\/actuator\/health/);
    assert.doesNotMatch(t, /curl[^\n]*actuator\/health/);
  });
});
