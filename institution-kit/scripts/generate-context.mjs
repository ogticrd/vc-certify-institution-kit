// Genera el contexto JSON-LD propio de la credencial: generated/contextos/<key>.json
//
// Entrada (variables de entorno): CREDENTIAL_CONFIG_KEY_ID, CREDENTIAL_ATTRIBUTES,
// CERTIFY_PUBLIC_URL (y CREDENTIAL_TYPE / INSTITUTION_ID para el tipo propio).
// Salida: <salida>/contextos/<key>.json; `salida` es el primer argumento (por defecto `generated`,
// relativo al directorio actual, que `run_node` fija en la raíz del kit).
//
// Por qué existe: sin un contexto que defina cada atributo, la canonicalización RDF de la firma
// los descarta y la firma no cubre ningún dato (R1). Ver scripts/lib/credencial.mjs.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { leerEntrada, construirContexto, ErrorEntrada } from "./lib/credencial.mjs";

try {
  const entrada = leerEntrada(process.env);
  const salida = process.argv[2] || "generated";
  const dir = join(salida, "contextos");
  mkdirSync(dir, { recursive: true });
  const ruta = join(dir, `${entrada.clave}.json`);
  writeFileSync(ruta, JSON.stringify(construirContexto(entrada), null, 2) + "\n");
  console.log(`  -> ${ruta}  (${entrada.atributos.length} atributos; se sirve en ${entrada.urlContexto})`);
} catch (e) {
  if (!(e instanceof ErrorEntrada)) throw e;
  console.error(`ERROR: ${e.message}`);
  process.exit(1);
}
