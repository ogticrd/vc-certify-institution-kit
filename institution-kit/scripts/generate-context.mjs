// Genera el contexto JSON-LD propio de la credencial: generated/contextos/<key>.json (+ <key>.sha256)
//
// Entrada (variables de entorno): CREDENTIAL_CONFIG_KEY_ID, CREDENTIAL_ATTRIBUTES,
// CERTIFY_PUBLIC_URL (y CREDENTIAL_TYPE / INSTITUTION_ID para el tipo propio), KIT_FORZAR_CONTEXTO.
// Salida: <salida>/contextos/<key>.json y <salida>/contextos/<key>.sha256 (formato de `sha256sum`);
// `salida` es el primer argumento (por defecto `generated`, relativo al directorio actual, que
// `run_node` fija en la raíz del kit). Con `--comprobar` no escribe nada: solo dice si habría que
// publicar un contexto distinto del que ya está (lo usa apply-credential.sh con DRY_RUN=1).
//
// Por qué existe: sin un contexto que defina cada atributo, la canonicalización RDF de la firma
// los descarta y la firma no cubre ningún dato (R1). Ver scripts/lib/credencial.mjs.
//
// INMUTABLE (K5, T7-1): «contexto nuevo = clave nueva». Caddy sirve generated/contextos/ tal cual y las
// credenciales ya emitidas se firmaron con ESE contexto: si el publicado cambia (otros atributos, otro tipo,
// otra URL pública), dejan de verificar —la firma ya no cubre sus atributos— sin que nadie lo note. Por eso, si
// ya hay un contexto para esta clave con otro contenido, NO se sobrescribe: falla, salvo KIT_FORZAR_CONTEXTO=1.
// «Mismo contenido» es el mismo JSON (el orden de los atributos no importa: los términos son los mismos).
import { mkdirSync, writeFileSync, readFileSync, existsSync, renameSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { leerEntrada, construirContexto, ErrorEntrada } from "./lib/credencial.mjs";

const huella = (b) => createHash("sha256").update(b).digest("hex");
// JSON con las claves ordenadas, para comparar «el mismo contexto» sin depender del orden de los términos.
const canonico = (v) => JSON.stringify(v, (_, x) => (x && typeof x === "object" && !Array.isArray(x)
  ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, x[k]])) : x));
const escribirAtomico = (ruta, texto) => { const tmp = `${ruta}.tmp-${process.pid}`; writeFileSync(tmp, texto); renameSync(tmp, ruta); };

try {
  const entrada = leerEntrada(process.env);
  const args = process.argv.slice(2);
  const soloComprobar = args.includes("--comprobar");
  const salida = args.find((a) => !a.startsWith("--")) || "generated";
  const dir = join(salida, "contextos");
  const ruta = join(dir, `${entrada.clave}.json`);
  const rutaHuella = join(dir, `${entrada.clave}.sha256`);

  const texto = JSON.stringify(construirContexto(entrada), null, 2) + "\n";
  const nueva = huella(texto);

  // Lo ya publicado: el fichero (su huella real) o, si falta, la huella que quedó anotada.
  let previa = null;
  let mismoContenido = false;
  if (existsSync(ruta)) {
    const bytes = readFileSync(ruta);
    previa = huella(bytes);
    if (previa === nueva) mismoContenido = true;
    else {
      try { mismoContenido = canonico(JSON.parse(bytes.toString("utf8"))) === canonico(JSON.parse(texto)); } catch { mismoContenido = false; }
    }
  } else if (existsSync(rutaHuella)) {
    previa = readFileSync(rutaHuella, "utf8").trim().split(/\s+/)[0] || null;
    mismoContenido = previa === nueva;
  }

  if (previa !== null && !mismoContenido) {
    const forzar = process.env.KIT_FORZAR_CONTEXTO === "1";
    if (!forzar) {
      console.error(`ERROR: el contexto de la credencial «${entrada.clave}» ya está publicado con OTRO contenido `
        + `(huella ${previa.slice(0, 12)}… y el del .env actual daría ${nueva.slice(0, 12)}…).\n`
        + `CONTEXTO NUEVO = CLAVE NUEVA. Las credenciales ya emitidas se firmaron con el contexto publicado; si cambia `
        + `(otros atributos, otro tipo, INSTITUTION_ID o URL pública), dejan de verificar sin que nadie lo note, y Caddy `
        + `serviría el nuevo en cuanto se generara.\n`
        + `Para cambiarlo de verdad:\n`
        + `  1. ponga una CREDENTIAL_CONFIG_KEY_ID NUEVA en el .env (el contexto viejo se queda publicado, intacto);\n`
        + `  2. ponga la configuración vieja en «inactive»: UPDATE certify.credential_config SET status = 'inactive' WHERE credential_config_key_id = '${entrada.clave}';\n`
        + `  3. ejecute scripts/apply-credential.sh.\n`
        + `Solo si de verdad quiere sobrescribirlo (INVALIDA lo ya emitido con esta clave): KIT_FORZAR_CONTEXTO=1.`);
      process.exit(1);
    }
    console.error(`AVISO: KIT_FORZAR_CONTEXTO=1: se sobrescribe el contexto «${entrada.clave}» (huella ${previa.slice(0, 12)}… → ${nueva.slice(0, 12)}…). `
      + `Esto INVALIDA las credenciales ya emitidas con esta clave: dejarán de verificar. Use una CREDENTIAL_CONFIG_KEY_ID nueva si puede.`);
  }

  if (soloComprobar) {
    console.log(`  -> ${ruta}: --comprobar, no se escribió nada (${previa === null ? "todavía no hay contexto publicado para esta clave" : "el publicado coincide con el del .env"})`);
  } else {
    mkdirSync(dir, { recursive: true });
    if (previa === null || !mismoContenido) escribirAtomico(ruta, texto);
    const publicado = huella(readFileSync(ruta));
    const lineaHuella = `${publicado}  ${entrada.clave}.json\n`;
    if (!existsSync(rutaHuella) || readFileSync(rutaHuella, "utf8") !== lineaHuella) escribirAtomico(rutaHuella, lineaHuella);
    console.log(`  -> ${ruta}  (${entrada.atributos.length} atributos; se sirve en ${entrada.urlContexto}; huella ${publicado.slice(0, 12)}…)`);
  }
} catch (e) {
  if (!(e instanceof ErrorEntrada)) throw e;
  console.error(`ERROR: ${e.message}`);
  process.exit(1);
}
