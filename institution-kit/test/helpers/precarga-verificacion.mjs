// Se precarga con NODE_OPTIONS=--import=<este fichero> al ejecutar verify-install.sh en las pruebas
// (el diagnóstico corre como subproceso: cli.mjs, motor.mjs y red.mjs son los vendorizados, sin tocar,
// así que la red de la prueba se pone desde fuera, en el proceso, como hace test/helpers/aislamiento.mjs
// en el stack de OGTIC).
//
//  - aislar(): confía en el certificado de pruebas (autofirmado) y hace que cualquier host que no sea
//    localhost falle en voz alta en vez de salir a internet.
//  - Los contextos de W3C (www.w3.org, w3id.org) se redirigen a /ajenos/<host>/<ruta> del emisor
//    simulado (KIT_PRUEBA_BASE), que los sirve de test/fixtures/contextos/. El motor sigue viendo la
//    URL pública.
import https from "node:https";
import { aislar } from "./aislamiento.mjs";

aislar();
const base = process.env.KIT_PRUEBA_BASE;
const peticion = https.request;
https.request = (url, opciones, cb) => {
  const u = new URL(url);
  if (base && (u.hostname === "www.w3.org" || u.hostname === "w3id.org")) url = new URL(`${base}/ajenos/${u.hostname}${u.pathname}`);
  return peticion(url, opciones, cb);
};
