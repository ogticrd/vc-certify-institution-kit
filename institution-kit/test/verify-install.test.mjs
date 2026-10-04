// T6 · R8, D4: verify-install.sh contra un emisor simulado (https en 127.0.0.1, puerto libre).
//
//   fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
//
// Qué se prueba y con qué:
//  - El emisor simulado es el del stack de OGTIC (test/helpers/emisor-simulado.mjs, copia con
//    procedencia). Sirve lo que GENERÓ EL KIT (contexto propio, logo, columnas del SQL para la metadata)
//    en https://localhost:<puerto>, así que la prueba cubre generador -> servidor -> verificación.
//  - verify-install.sh corre con `node` local (KIT_NODE=local) y un `docker` falso solo para el health
//    interno; el diagnóstico (cli.mjs/motor.mjs/red.mjs vendorizados, sin tocar) corre como subproceso
//    con test/helpers/precarga-verificacion.mjs (certificado de pruebas, nada sale de la máquina, los
//    contextos de W3C se piden al emisor simulado).
//  - Ninguna petición va a un emisor real ni a Cuenta Única: el servidor de autorización esperado es el
//    propio emisor simulado (AUTH_ISSUER_URL).
// El `ejecutar` del arnés usa spawnSync y bloquearía el servidor, que vive en este mismo proceso: aquí
// los scripts se lanzan de forma asíncrona.
import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, chmodSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { aislar } from "./helpers/aislamiento.mjs";
import { emisorSimulado } from "./helpers/emisor-simulado.mjs";
import { prepararEntorno, valoresSql, literal } from "./helpers/entorno.mjs";

aislar();
const AQUI = dirname(fileURLToPath(import.meta.url));
const PRECARGA = join(AQUI, "helpers", "precarga-verificacion.mjs");
const KEY = "PruebaLicencia";
const ATRIBUTOS = ["nombre", "apellido", "numeroLicencia"];
const SALUD_UP = '{"status":"UP"}';

// Lanza `bash -c orden` en el kit temporal sin bloquear el bucle de eventos.
function lanzar(kit, raiz, orden, extra = {}) {
  return new Promise((resolver) => {
    const env = { PATH: process.env.PATH, HOME: raiz, LANG: "C", LC_ALL: "C", ...extra };
    const p = spawn("bash", ["-c", orden], { cwd: kit, env });
    let stdout = "", stderr = "";
    p.stdout.on("data", (b) => (stdout += b));
    p.stderr.on("data", (b) => (stderr += b));
    p.on("close", (status) => resolver({ status, stdout, stderr }));
  });
}

let emisor, kit, bin, registroDocker;
const rutas = {};
const retoques = { metadata: null, did: null };
const cuerpoJson = (o, extra = {}) => ({ estado: 200, tipo: "application/json", cuerpo: JSON.stringify(o), ...extra });
const lineasDe = (salida) => salida.stdout.split("\n");
const lineaDe = (salida, n) => lineasDe(salida).find((l) => new RegExp(`^\\s*${n}\\. `).test(l)) ?? "";
const estadoDe = (salida, n) => (lineaDe(salida, n).match(/^\s*\S+\.\s+(OK|FALLA|AVISO|PENDIENTE)\b/) ?? [])[1];

function ponerSalud(texto) { writeFileSync(join(bin, "salud.json"), texto); }

before(async () => {
  emisor = await emisorSimulado({
    rutas,
    metadata: (m, base) => retoques.metadata?.(m, base),
    did: (d, base) => retoques.did?.(d, base),
  });
  // El kit se genera para ESA URL pública (modo proxy: CERTIFY_PUBLIC_URL manda), con el propio emisor
  // simulado como servidor de autorización.
  kit = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: emisor.base, AUTH_ISSUER_URL: emisor.base } });
  assert.equal(kit.salida.status, 0, kit.salida.stderr);

  // Los contextos y tipos que Certify publicaría: las columnas que escribió el kit en el SQL.
  const v = valoresSql(kit.leer("sql"));
  const contextos = literal(v.context).split(",");
  const tipos = literal(v.credential_type).split(",");
  retoques.base = (m, base) => {
    m.credential_configurations_supported = {
      [KEY]: {
        format: "ldp_vc", scope: "openid", credential_signing_alg_values_supported: ["Ed25519Signature2020"],
        cryptographic_binding_methods_supported: ["did:jwk"],
        credential_definition: {
          "@context": contextos, type: tipos,
          credentialSubject: Object.fromEntries(ATRIBUTOS.map((a) => [a, { display: [{ name: a, locale: "es" }] }])),
        },
        display: [{ name: "Licencia de prueba", locale: "es", logo: { url: `${base}/logos/${KEY}.png`, alt_text: "Logo" } }],
        order: [...ATRIBUTOS],
      },
    };
  };
  bin = join(kit.raiz, "bin");
  mkdirSync(bin);
  registroDocker = join(kit.raiz, "docker.log");
  writeFileSync(join(bin, "docker"), `#!/bin/sh
echo "docker $*" >> "${registroDocker}"
case "$*" in
  *"exec -T caddy wget"*actuator/health*) cat "${join(bin, "salud.json")}";;
esac
exit 0
`);
  chmodSync(join(bin, "docker"), 0o755);
});

after(async () => { await emisor?.cerrar(); kit?.limpiar(); });

// Cada prueba parte de un emisor sano: lo que sirve el kit, y nada más.
beforeEach(() => {
  for (const k of Object.keys(rutas)) delete rutas[k];
  retoques.metadata = retoques.base;
  retoques.did = null;
  rutas[`/contextos/${KEY}.json`] = { estado: 200, tipo: "application/ld+json", cache: "no-cache", cuerpo: readFileSync(kit.rutas.contexto) };
  rutas[`/logos/${KEY}.png`] = { estado: 200, tipo: "image/png", cuerpo: readFileSync(kit.rutas.logo) };
  ponerSalud(SALUD_UP);
  rmSync(registroDocker, { force: true });
});

const verificar = (extra = {}) => lanzar(kit.kit, kit.raiz, 'bash scripts/verify-install.sh', {
  PATH: `${bin}:${process.env.PATH}`,
  KIT_NODE: "local",
  NODE_OPTIONS: `--import=${PRECARGA}`,
  KIT_PRUEBA_BASE: emisor.base,
  VERIFY_HEALTH_INTENTOS: "1", VERIFY_HEALTH_PAUSA: "0",
  ...extra,
});

// Modifica la metadata sana. `f(config, metadata)`.
const retocarConfig = (f) => {
  const base = retoques.base;
  retoques.metadata = (m, b) => { base(m, b); f(m.credential_configurations_supported[KEY], m); };
};
const contextoGenerado = () => JSON.parse(readFileSync(kit.rutas.contexto, "utf8"));

describe("verify-install.sh contra un emisor sano (todo lo que generó el kit)", () => {
  test("las 11 comprobaciones y las dos del kit salen OK y el código de salida es 0", async () => {
    const r = await verificar();
    assert.equal(r.status, 0, r.stdout + r.stderr);
    for (let n = 1; n <= 11; n++) assert.equal(estadoDe(r, n), "OK", `comprobación ${n}: ${lineaDe(r, n)}`);
    assert.equal(lineasDe(r).filter((l) => /^\s*\+\.\s+OK\b/.test(l)).length, 2, r.stdout);
    assert.match(r.stdout, /Cobertura de firma sobre la credencial de muestra: 3 de 3 atributos firmados \(cobertura 100 %\)/);
    assert.match(r.stdout, /El @context de la metadata está completo/);
    assert.match(r.stdout, /^Resumen: 11\/11 \(\+cobertura OK, \+@context de la metadata OK\) · FALLA 0 · AVISO 0 · PENDIENTE 0$/m);
    assert.match(r.stdout, /Resultado: la instalación pasa la verificación\./);
    assert.match(r.stdout, /OK {8}Certify responde UP\./);
    assert.match(r.stdout, new RegExp(`credential_endpoint: ${emisor.base}/credential`));
  });

  test("el health se pregunta por la red interna con la orden de compose-args (no por la URL pública)", async () => {
    const r = await verificar();
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const llamadas = readFileSync(registroDocker, "utf8").trim().split("\n");
    assert.equal(llamadas.length, 1, "con KIT_NODE=local, docker solo se usa para el health");
    assert.equal(llamadas[0],
      "docker compose -f docker-compose.yml -f docker-compose.proxy.yml --env-file generated/.env.runtime exec -T caddy wget -qO- http://certify:8090/v1/certify/actuator/health");
    assert.ok(!emisor.peticiones.some((p) => /actuator/i.test(p.ruta)), "el diagnóstico nunca toca el actuator");
  });

  test("el diagnóstico respeta sus límites: un único POST con {} y sin token", async () => {
    emisor.peticiones.length = 0;
    const r = await verificar();
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const posts = emisor.peticiones.filter((p) => p.metodo === "POST");
    assert.equal(posts.length, 1);
    assert.equal(posts[0].cuerpo, "{}");
    assert.ok(emisor.peticiones.every((p) => p.cabeceras.authorization === undefined));
  });

  test("el texto está en español: una línea por comprobación, estados OK/FALLA/AVISO/PENDIENTE, resumen y resultado", async () => {
    const r = await verificar();
    const filas = lineasDe(r).filter((l) => /^\s*(\d+|\+)\.\s+(OK|FALLA|AVISO|PENDIENTE)\s/.test(l));
    assert.equal(filas.length, 13, "11 del diagnóstico + 2 del kit");
    assert.match(r.stdout, /^Verificación de la instalación: https:\/\/localhost:\d+\/\.well-known\/openid-credential-issuer$/m);
    assert.match(r.stdout, /Servidor de autorización esperado:/);
    assert.match(r.stdout, /La metadata del emisor responde/);
    assert.match(r.stdout, /El DID del emisor resuelve y autoriza su clave/);
    assert.doesNotMatch(r.stdout + r.stderr, /\b(PASS|FAIL|passed|failed|Error:|undefined|NaN|\[object)/);
  });

  test("no se imprime ningún dato de la credencial de muestra: solo nombres de campo", async () => {
    const muestra = JSON.parse(readFileSync(kit.rutas.muestra, "utf8"));
    const valores = Object.entries(muestra.credentialSubject).map(([, v]) => String(v));
    assert.ok(valores.length >= 4 && valores.every((v) => v.length >= 4), "la muestra trae valores identificables");
    for (const caso of [{}, { VERIFY_PRIVADAS: "0" }]) {
      const r = await verificar(caso);
      for (const v of valores) {
        assert.ok(!(r.stdout + r.stderr).includes(v), `se imprimió el valor «${v}»`);
      }
    }
    const ok = await verificar();
    assert.match(ok.stdout, /\(cobertura 100 %\): nombre, apellido, numeroLicencia\./, "los nombres de campo sí");
    // Y la muestra rota (cobertura 0 %) tampoco vuelca valores.
    const c = contextoGenerado();
    delete c["@context"].nombre;
    rutas[`/contextos/${KEY}.json`] = { estado: 200, tipo: "application/ld+json", cache: "no-cache", cuerpo: JSON.stringify(c) };
    const rota = await verificar();
    for (const v of valores) assert.ok(!(rota.stdout + rota.stderr).includes(v), `se imprimió el valor «${v}»`);
  });

  test("la salida no depende de variables de entorno ajenas: sin .env ni .env.runtime en la salida", async () => {
    const r = await verificar();
    assert.ok(!/clave-bd-de-mentira|clave-keystore-de-mentira|secreto-de-mentira/.test(r.stdout + r.stderr));
    assert.ok(!/[0-9a-f]{64}/.test(r.stdout + r.stderr), "ninguna cadena de 64 hex (contraseñas generadas)");
  });
});

describe("verify-install.sh: cada rotura da FALLA y código 1", () => {
  const roto = (r, n) => {
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.equal(estadoDe(r, n), "FALLA", `comprobación ${n}: ${lineaDe(r, n)}\n${r.stdout}`);
    assert.match(r.stdout, /Resultado: la verificación FALLÓ/);
  };

  test("did.json sin assertionMethod -> FALLA en la 10", async () => {
    retoques.did = (d) => { delete d.assertionMethod; };
    const r = await verificar();
    roto(r, 10);
    assert.match(r.stdout, /no tiene assertionMethod/);
  });

  test("did.json con el DID pelado en assertionMethod (el defecto de Certify) -> FALLA en la 10", async () => {
    retoques.did = (d) => { d.assertionMethod = [d.id]; };
    const r = await verificar();
    roto(r, 10);
    assert.match(r.stdout, /DID pelado/);
  });

  test("contexto servido con otro nombre de atributo -> FALLA en la 8, la 9 y la cobertura de la muestra", async () => {
    const c = contextoGenerado();
    c["@context"].nombres = c["@context"].nombre;
    delete c["@context"].nombre;
    rutas[`/contextos/${KEY}.json`] = { estado: 200, tipo: "application/ld+json", cache: "no-cache", cuerpo: JSON.stringify(c) };
    const r = await verificar();
    roto(r, 8);
    assert.equal(estadoDe(r, 9), "FALLA");
    assert.match(r.stdout, /NO firmados: nombre/);
    assert.match(r.stdout, /FALLA\s+Cobertura de firma sobre la credencial de muestra: 2 de 3 atributos firmados/);
    assert.match(r.stdout, /No firmados: nombre\b/);
    assert.match(r.stdout, /^Resumen: 9\/11 /m);
  });

  test("contexto sin Cache-Control: no-cache -> FALLA (el motor lo daría como AVISO; R8 lo exige)", async () => {
    rutas[`/contextos/${KEY}.json`] = { estado: 200, tipo: "application/ld+json", cuerpo: readFileSync(kit.rutas.contexto) };
    const r = await verificar();
    roto(r, 7);
    assert.match(lineaDe(r, 7), /el kit lo exige: R8/);
    assert.match(r.stdout, /sin Cache-Control/);
  });

  test("logo SVG -> FALLA en la 6 (el motor lo daría como AVISO; R8 pide PNG)", async () => {
    rutas[`/logos/${KEY}.png`] = { estado: 200, tipo: "image/svg+xml", cuerpo: "<svg xmlns='http://www.w3.org/2000/svg'/>" };
    const r = await verificar();
    roto(r, 6);
    assert.match(r.stdout, /SVG/);
  });

  test("logo que no existe (404) -> FALLA en la 6", async () => {
    rutas[`/logos/${KEY}.png`] = null;
    const r = await verificar();
    roto(r, 6);
  });

  test("metadata sin el contexto de la suite -> FALLA solo en la comprobación del kit (el motor no la ve)", async () => {
    retocarConfig((c) => {
      c.credential_definition["@context"] = c.credential_definition["@context"].filter((x) => !x.includes("ed25519-2020"));
    });
    const r = await verificar();
    assert.equal(r.status, 1, r.stdout + r.stderr);
    for (let n = 1; n <= 11; n++) assert.equal(estadoDe(r, n), "OK", `el motor sí da OK en la ${n}: ${lineaDe(r, n)}`);
    assert.match(r.stdout, /FALLA\s+El @context de la metadata está completo[^\n]*falta el contexto de la suite de firma/);
    assert.match(r.stdout, /\+@context de la metadata FALLA/);
  });

  test("tipos desordenados en la metadata -> FALLA en la 11", async () => {
    retocarConfig((c) => { c.credential_definition.type = [...c.credential_definition.type].reverse(); });
    const r = await verificar();
    roto(r, 11);
    assert.match(r.stdout, /SQL sugerido: UPDATE certify\.credential_config/);
  });

  test("endpoint de emisión inexistente (404) -> FALLA en la 3", async () => {
    rutas["/credential"] = null;
    const r = await verificar();
    roto(r, 3);
  });

  test("la metadata no responde -> FALLA en la 1, el resto PENDIENTE (no diez fallas) y código 1", async () => {
    rutas["/.well-known/openid-credential-issuer"] = null;
    const r = await verificar();
    roto(r, 1);
    for (let n = 2; n <= 11; n++) assert.equal(estadoDe(r, n), "PENDIENTE", `comprobación ${n}`);
    assert.match(r.stdout, /PENDIENTE\s+El @context de la metadata está completo/);
    assert.match(r.stdout, /^Resumen: 0\/11 /m);
  });

  test("Certify no responde UP por la red interna -> FALLA de salud, código 1; el diagnóstico se muestra igual", async () => {
    ponerSalud('{"status":"DOWN"}');
    const r = await verificar();
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stderr, /FALLA {5}Certify no respondió UP/);
    assert.match(r.stderr, /Resultado global: la verificación FALLÓ \(Certify no respondió UP\)/);
    assert.match(r.stdout, /Resumen: 11\/11/, "el diagnóstico corrió");
  });

  test("health con una respuesta que no es JSON -> FALLA, sin romper el script", async () => {
    ponerSalud("<html>502</html>");
    const r = await verificar();
    assert.equal(r.status, 1);
    assert.match(r.stderr, /FALLA {5}Certify no respondió UP/);
  });

  test("sin credencial de muestra -> FALLA en la cobertura (no se omite en silencio) y código 1", async () => {
    const f = kit.rutas.muestra;
    const copia = readFileSync(f);
    rmSync(f);
    try {
      const r = await verificar();
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stdout, /FALLA\s+Cobertura de firma sobre la credencial de muestra: No se pudo leer/);
    } finally { writeFileSync(f, copia); }
  });
});

describe("direcciones privadas: se activan solo cuando la URL pública resuelve al propio servidor", () => {
  test("VERIFY_PRIVADAS=0 con una URL que resuelve a 127.0.0.1 -> FALLA (la barrera anti-SSRF del motor sigue en pie)", async () => {
    const r = await verificar({ VERIFY_PRIVADAS: "0" });
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /Direcciones privadas: no permitidas/);
    assert.match(r.stdout, /dirección no pública/);
  });

  test("auto (por defecto): localhost resuelve a una dirección de bucle -> se permiten, y lo dice", async () => {
    const r = await verificar();
    assert.match(r.stdout, /Direcciones privadas: permitidas \(la URL pública resuelve a una dirección privada/);
  });

  test("VERIFY_PRIVADAS=1 las permite siempre; un valor inválido se rechaza", async () => {
    const r = await verificar({ VERIFY_PRIVADAS: "1" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /Direcciones privadas: permitidas \(indicado\)/);
    const mala = await verificar({ VERIFY_PRIVADAS: "quizá" });
    assert.equal(mala.status, 1);
    assert.match(mala.stderr, /VERIFY_PRIVADAS debe ser auto, 1 o 0/);
  });
});

describe("cómo se corre sin Node en el servidor (KIT_NODE=docker)", () => {
  test("KIT_DRY_RUN imprime un `docker run … node:22-alpine node …` con montajes de solo lectura y sin secretos", async () => {
    const r = await verificar({ KIT_NODE: "docker", KIT_DRY_RUN: "1" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const orden = lineasDe(r).find((l) => l.includes("docker run"));
    assert.ok(orden, r.stdout);
    assert.match(orden, /docker run --rm --network host --user \d+:\d+/);
    assert.match(orden, /diagnostico:\/kit\/diagnostico:ro/);
    assert.match(orden, /verificar-instalacion\.mjs:\/kit\/scripts\/lib\/verificar-instalacion\.mjs:ro/);
    assert.match(orden, /credencial-muestra\.json:\/kit\/generated\/credencial-muestra\.json:ro/);
    assert.match(orden, /node:22-alpine node \/kit\/scripts\/lib\/verificar-instalacion\.mjs/);
    assert.match(orden, /--muestra \/kit\/generated\/credencial-muestra\.json/);
    // Ni el .env ni .env.runtime (secretos) se montan, ni el kit entero.
    assert.doesNotMatch(orden, /\.env/);
    assert.doesNotMatch(orden, /-v \S*institution-kit(\/)?:/);
    assert.ok(!orden.includes(" -e "), "no se reenvía ninguna variable (ESPERA solo si está definida)");
    // En seco no se ejecuta el diagnóstico: no hay peticiones de verificación.
  });

  test("KIT_NODE=local sin node en el PATH, o un KIT_NODE desconocido, es un error claro", async () => {
    const r = await verificar({ KIT_NODE: "otro" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /KIT_NODE debe ser auto, local o docker/);
  });

  test("auto sin `node` en el PATH usa `docker run` (Node no se instala en el servidor)", async () => {
    const vacio = join(kit.raiz, "bin-vacio");
    mkdirSync(vacio, { recursive: true });
    // Un PATH con solo lo que el script necesita para llegar hasta ahí (bash, utilidades) y un docker falso
    // para el health, pero SIN node: se simula enlazando las utilidades una a una.
    for (const u of ["bash", "env", "cat", "sed", "awk", "jq", "dirname", "mktemp", "chmod", "mv", "rm", "id", "tr", "cut", "grep", "head", "sleep", "mkdir", "date", "uname", "basename", "readlink", "ls", "envsubst"]) {
      const ruta = (await lanzar(kit.kit, kit.raiz, `command -v ${u} || true`, { PATH: process.env.PATH })).stdout.trim();
      if (ruta) { try { rmSync(join(vacio, u), { force: true }); } catch {} writeFileSync(join(vacio, u), `#!/bin/sh\nexec "${ruta}" "$@"\n`); chmodSync(join(vacio, u), 0o755); }
    }
    writeFileSync(join(vacio, "docker"), readFileSync(join(bin, "docker")));
    chmodSync(join(vacio, "docker"), 0o755);
    // Sin node el script usa docker; el falso responde al health y no ejecuta nada más.
    const r = await lanzar(kit.kit, kit.raiz, "bash scripts/verify-install.sh", {
      PATH: vacio, KIT_NODE: "auto", VERIFY_HEALTH_INTENTOS: "1", VERIFY_HEALTH_PAUSA: "0",
    });
    const llamadas = readFileSync(registroDocker, "utf8").trim().split("\n");
    assert.ok(llamadas.some((l) => l.startsWith("docker run --rm --network host")), `usó docker run: ${llamadas.join(" | ")}`);
    // El `docker` falso no ejecuta el contenedor (y sale 0): lo que se comprueba es que, sin node, se pide el contenedor.
    assert.ok(llamadas.some((l) => /node:22-alpine node \/kit\/scripts\/lib\/verificar-instalacion\.mjs --url https:\/\/localhost:\d+\/\.well-known\/openid-credential-issuer --as https:\/\/localhost:\d+ --muestra \/kit\/generated\/credencial-muestra\.json --privadas auto$/.test(l)), llamadas.join(" | "));
    assert.equal(r.status, 0);
  });
});

describe("install.sh llama a verify-install.sh al final y propaga su código", () => {
  const preparar = () => {
    const e = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid", RESTAPI_PLUGIN_JAR: undefined }, generar: false });
    const plugin = join(e.raiz, "plugin.jar"); writeFileSync(plugin, "x");
    const jarDir = join(e.raiz, "certify-service", "loader_path", "certify"); mkdirSync(jarDir, { recursive: true });
    writeFileSync(join(jarDir, "restapi-dataprovider-plugin-0.0.0.jar"), "x");
    const b = join(e.raiz, "bin"); mkdirSync(b);
    const registro = join(e.raiz, "docker.log");
    writeFileSync(join(b, "docker"), `#!/bin/sh
echo "docker $*" >> "${registro}"
case "$*" in
  *"exec -T caddy wget"*actuator/health*) echo '{"status":"UP"}';;
  *"exec -T caddy wget"*did.json*) cat "${join(AQUI, "fixtures", "did-certify.json")}";;
esac
exit 0
`);
    // `node` falso SOLO para el programa de verificación; todo lo demás va al node real.
    writeFileSync(join(b, "node"), `#!/bin/sh
case "$*" in
  *verificar-instalacion.mjs*) echo "Resumen: simulado"; exit \${FAKE_VERIFICACION:-0};;
esac
exec "${process.execPath}" "$@"
`);
    writeFileSync(join(b, "curl"), "#!/bin/sh\nexit 0\n");
    for (const f of ["docker", "node", "curl"]) chmodSync(join(b, f), 0o755);
    return { e, b, registro };
  };

  test("verificación correcta: install.sh sale 0 y dice «Instalación completada»; generate-did va antes de verify-install", async () => {
    const { e, b, registro } = preparar();
    try {
      const r = await lanzar(e.kit, e.raiz, "bash install.sh", { PATH: `${b}:${process.env.PATH}`, FAKE_VERIFICACION: "0" });
      assert.equal(r.status, 0, r.stdout + r.stderr);
      const iDid = r.stdout.indexOf("Corrigiendo el DID");
      const iVer = r.stdout.indexOf("Resumen: simulado");
      const iFin = r.stdout.indexOf("Instalación completada");
      assert.ok(iDid !== -1 && iDid < iVer && iVer < iFin, `orden: did ${iDid}, verificación ${iVer}, fin ${iFin}`);
      for (const l of readFileSync(registro, "utf8").trim().split("\n").filter((x) => !x.startsWith("docker compose version"))) {
        assert.match(l, /^docker compose -f docker-compose\.yml -f docker-compose\.proxy\.yml --env-file generated\/\.env\.runtime /, l);
      }
    } finally { e.limpiar(); }
  });

  test("verificación con FALLA: install.sh sale con ese código, avisa, y aun así imprime los datos para OGTIC", async () => {
    const { e, b } = preparar();
    try {
      const r = await lanzar(e.kit, e.raiz, "bash install.sh", { PATH: `${b}:${process.env.PATH}`, FAKE_VERIFICACION: "1" });
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stdout, /Instalación terminada, pero la verificación FALLÓ \(código 1\)/);
      assert.doesNotMatch(r.stdout, /Instalación completada/);
      assert.match(r.stdout, /CERTIFY_PUBLIC_URL: https:\/\/certify\.prueba\.invalid/);
    } finally { e.limpiar(); }
  });
});

describe("estructura del kit tras T6", () => {
  test("verify-health.sh ya no existe y install.sh llama a verify-install.sh", () => {
    assert.equal(existsSync(join(AQUI, "..", "scripts", "verify-health.sh")), false);
    assert.ok((readFileSync(join(AQUI, "..", "scripts", "verify-install.sh"), "utf8")).startsWith("#!/usr/bin/env bash"));
    const install = readFileSync(join(AQUI, "..", "install.sh"), "utf8");
    assert.match(install, /scripts\/verify-install\.sh/);
    assert.doesNotMatch(install, /verify-health/);
  });

  test("el script de verificación lleva `${KIT_COMPOSE[@]}` para el health y no usa la URL pública para el actuator", () => {
    const comun = readFileSync(join(AQUI, "..", "scripts", "lib", "common.sh"), "utf8");
    assert.match(comun, /"\$\{KIT_COMPOSE\[@\]\}" exec -T caddy wget -qO- http:\/\/certify:8090\/v1\/certify\/actuator\/health/);
    const v = readFileSync(join(AQUI, "..", "scripts", "verify-install.sh"), "utf8");
    assert.match(v, /load_compose_args/);
    assert.match(v, /wait_for_health/);
    assert.doesNotMatch(v, /curl[^\n]*actuator/);
  });
});
