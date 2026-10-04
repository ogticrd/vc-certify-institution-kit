// Genera el SQL de credential_config y la credencial de muestra.
//
// Entrada: las variables de entorno que lee scripts/lib/credencial.mjs (leerEntrada).
// Salida: <salida>/credential_config.sql y <salida>/credencial-muestra.json
// La muestra es la credencial que saldría de la plantilla con valores ficticios y sin firma;
// sirve para comprobar que la firma cubre todos los atributos (verify-install.sh, T6).
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { leerEntrada, construirSql, construirMuestra, ErrorEntrada } from "./lib/credencial.mjs";

try {
  const entrada = leerEntrada(process.env, { paraSql: true });
  const salida = process.argv[2] || "generated";
  mkdirSync(salida, { recursive: true });
  writeFileSync(join(salida, "credential_config.sql"), construirSql(entrada));
  writeFileSync(join(salida, "credencial-muestra.json"), JSON.stringify(construirMuestra(entrada), null, 2) + "\n");
  console.log(`SQL de credencial generado en ${join(salida, "credential_config.sql")}`);
  console.log(`  tipos: ${entrada.tipos.join(",")}`);
  console.log(`  credencial de muestra: ${join(salida, "credencial-muestra.json")}`);
} catch (e) {
  if (!(e instanceof ErrorEntrada)) throw e;
  console.error(`ERROR: ${e.message}`);
  process.exit(1);
}
