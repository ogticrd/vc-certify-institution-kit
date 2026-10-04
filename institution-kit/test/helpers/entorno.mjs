// Ejecutar (Node 22, sin dependencias; desde la raíz del repo):
//   fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
// (Node 22 no expande un directorio: `node --test institution-kit/test/` falla con MODULE_NOT_FOUND;
//  hay que pasar el glob entre comillas.)
//
// Arnés de pruebas de los generadores del kit.
//
// Copia `institution-kit/` a un directorio temporal (sin .git, sin generated/, sin
// el .env real de quien corra las pruebas, sin test/), escribe un .env de prueba y
// ejecuta los generadores con bash desde allí. No usa Docker ni red.
//
// Estructura del temporal:  <raiz>/institution-kit/...   (así `..` = <raiz>, como en el
// fork, y nada se escribe fuera de <raiz>).
//
// Nota sobre `.env.runtime`: lo escribe `install.sh` (función `write_runtime_env`), no
// `generate-config.sh`. `install.sh` exige docker/curl/jq y construye la imagen, así que
// aquí se reproduce SOLO su tramo de configuración (load_env ... write_runtime_env) con
// las mismas funciones de `scripts/lib/common.sh`. Ver registro T1.
import { spawnSync } from "node:child_process";
import {
  cpSync, mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { fileURLToPath } from "node:url";

const AQUI = dirname(fileURLToPath(import.meta.url));
export const KIT_ORIGEN = join(AQUI, "..", "..");

// Fuera del temporal: lo que no debe copiarse (el .env real nunca se lee ni se copia).
const EXCLUIDOS = new Set([".git", "generated", ".env", "test", "node_modules", "caddy_data"]);

export const ENV_BASE = {
  TLS_MODE: "domain",
  CERTIFY_PUBLIC_HOST: "emisor.prueba.invalid",
  SERVER_PUBLIC_IP: "203.0.113.10",
  IP_DNS_PROVIDER: "sslip.io",
  CADDY_ACME_EMAIL: "infra@prueba.invalid",
  INSTITUTION_ID: "prueba",
  INSTITUTION_DISPLAY_NAME: "Institucion de Prueba",
  RESTAPI_BASE_URL: "https://api.prueba.invalid/datos",
  OAUTH_CLIENT_ID: "cliente-de-mentira",
  OAUTH_CLIENT_SECRET: "secreto-de-mentira",
  CREDENTIAL_CONFIG_KEY_ID: "PruebaLicencia",
  CREDENTIAL_ATTRIBUTES: "nombre,apellido,numeroLicencia",
  CREDENTIAL_SCOPE: "openid offline_access profile email",
  // Variable de logo de HOY; T3 la cambiará por LOGO_PATH.
  CREDENTIAL_LOGO_URL: "https://emisor.prueba.invalid/logo-de-prueba.png",
  POSTGRES_USER: "postgres",
  POSTGRES_PASSWORD: "clave-bd-de-mentira",
  POSTGRES_DB: "inji_certify",
};

// Un valor `undefined` en `extra` elimina la variable del .env (para probar .env incompleto).
export function escribirEnv(ruta, { modo = "domain", extra = {} } = {}) {
  const vars = { ...ENV_BASE, TLS_MODE: modo, ...extra };
  const lineas = Object.entries(vars)
    .filter(([, v]) => v !== undefined)
    .map(([k, v]) => `${k}="${String(v).replace(/(["\\$`])/g, "\\$1")}"`);
  writeFileSync(ruta, lineas.join("\n") + "\n");
}

// Tramo de install.sh (líneas "load_env ... export_env_for_templates") sin docker ni build.
const TRAMO_INSTALL = [
  'source "$PWD/scripts/lib/common.sh"',
  "load_env", "apply_defaults", "derive_public_url", "derive_did_url", "validate_env",
  "write_runtime_env", "export_env_for_templates",
].join("; ");

function bash(cwd, orden, env) {
  const r = spawnSync("bash", ["-c", orden], { cwd, encoding: "utf8", env });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

/**
 * Prepara un entorno temporal y ejecuta la generación.
 * @param {object} o
 * @param {"domain"|"ip"|string} o.modo       valor de TLS_MODE
 * @param {object} o.extra                    variables del .env que se suman/sustituyen
 * @param {boolean} o.runtime                 reproducir el tramo de install.sh que escribe .env.runtime (por defecto sí)
 * @param {boolean} o.generar                 ejecutar generate-config.sh (por defecto sí)
 * @param {string|null} o.envTexto            si se da, se escribe tal cual como .env (en vez de ENV_BASE)
 */
export function prepararEntorno({ modo = "domain", extra = {}, runtime = true, generar = true, envTexto = null } = {}) {
  const raiz = mkdtempSync(join(tmpdir(), "kit-prueba-"));
  const kit = join(raiz, "institution-kit");
  cpSync(KIT_ORIGEN, kit, {
    recursive: true,
    filter: (src) => !EXCLUIDOS.has(basename(src)),
  });
  if (envTexto !== null) writeFileSync(join(kit, ".env"), envTexto);
  else escribirEnv(join(kit, ".env"), { modo, extra });

  // Entorno limpio: ni el de quien ejecuta las pruebas ni variables heredadas del kit.
  const env = {
    PATH: process.env.PATH, HOME: raiz, LANG: "C", LC_ALL: "C",
  };

  const pasos = {};
  if (runtime) pasos.runtime = bash(kit, TRAMO_INSTALL, env);
  if (generar && (!runtime || pasos.runtime.status === 0)) {
    pasos.generar = bash(kit, 'bash "$PWD/scripts/generate-config.sh"', env);
  }
  const gen = join(kit, "generated");
  const rutas = {
    runtime: join(gen, ".env.runtime"),
    propiedadesDefault: join(gen, "config", "certify-default.properties"),
    propiedadesInstitucion: join(gen, "config", "certify-institution.properties"),
    caddyfile: join(gen, "caddy", "Caddyfile"),
    sql: join(gen, "credential_config.sql"),
    muestra: join(gen, "credencial-muestra.json"),
    contexto: join(gen, "contextos", `${extra.CREDENTIAL_CONFIG_KEY_ID ?? ENV_BASE.CREDENTIAL_CONFIG_KEY_ID}.json`),
  };
  // Ejecuta una orden bash en el kit temporal con el mismo entorno limpio (más `adicional`).
  const ejecutar = (orden, adicional = {}) => bash(kit, orden, { ...env, ...adicional });
  return {
    raiz, kit, generated: gen, rutas, pasos, ejecutar,
    salida: (pasos.generar ?? pasos.runtime ?? { stdout: "", stderr: "", status: null }),
    existe: (clave) => existsSync(rutas[clave]),
    leer: (clave) => readFileSync(rutas[clave], "utf8"),
    modo: (clave) => statSync(rutas[clave]).mode & 0o777,
    limpiar: () => rmSync(raiz, { recursive: true, force: true }),
  };
}

// --- Utilidades de lectura del SQL generado -------------------------------------------

// Valor de la columna `columna` del INSERT: se localiza por posición en la lista de columnas
// y de valores del SQL generado (un literal por línea, como lo escribe el script).
export function valoresSql(sql) {
  const cols = sql.match(/INSERT INTO certify\.credential_config \(([\s\S]*?)\) VALUES \(/)[1]
    .split(",").map((c) => c.trim());
  const cuerpo = sql.match(/\) VALUES \(\n([\s\S]*?)\n\)\nON CONFLICT/)[1].split("\n").map((l) => l.trim().replace(/,$/, ""));
  if (cols.length !== cuerpo.length) throw new Error(`columnas ${cols.length} != valores ${cuerpo.length}`);
  return Object.fromEntries(cols.map((c, i) => [c, cuerpo[i]]));
}

export const literal = (v) => v.replace(/^'/, "").replace(/'(::\w+)?$/, "").replace(/''/g, "'");

// Plantilla Velocity de la credencial (vc_template va en base64) como objeto.
export function plantillaDesdeSql(sql) {
  const b64 = literal(valoresSql(sql).vc_template);
  return JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
}
