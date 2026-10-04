// Aislamiento de las pruebas: NADA sale de esta máquina.
//
// red.mjs solo habla https y valida contra los certificados del sistema, así que
// los servidores locales de prueba necesitan dos cosas: un certificado en el que
// confíe (test/fixtures/tls/localhost.pem, autofirmado y de mentira) y un DNS que
// no pregunte por nombres inventados. Las dos cosas se ponen aquí, en el proceso
// de la prueba, sin tocar el código de producción ni el almacén de certificados
// del sistema.
//
// Además es una red de seguridad: si un cambio futuro hiciera que una prueba
// intentara conectar con un host que no es localhost, falla en voz alta en vez de
// salir a internet.
import https from "node:https";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const AQUI = dirname(fileURLToPath(import.meta.url));
export const CERT = readFileSync(join(AQUI, "../fixtures/tls/localhost.pem"));
export const CLAVE = readFileSync(join(AQUI, "../fixtures/tls/localhost.key"));
// test/fixtures/tls/: certificados autofirmados SOLO PARA PRUEBAS (openssl, 100 años). localhost.* es el
// de los servidores locales; desconocido.* es otro en el que nadie confía, para probar el rechazo de TLS.
export const CERT_DESCONOCIDO = readFileSync(join(AQUI, "../fixtures/tls/desconocido.pem"));
export const CLAVE_DESCONOCIDA = readFileSync(join(AQUI, "../fixtures/tls/desconocido.key"));

const LOCALES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
const esLocal = (h) => LOCALES.has(String(h).toLowerCase());

// DNS de mentira: nombre -> direcciones. Todo lo que no es localhost y no está
// aquí devuelve NXDOMAIN, sin preguntar a nadie.
export const dnsFalso = new Map();
// Para las dos consultas de dns.promises.resolve que hace clasificar() en red.mjs.
export const resolveFalso = { A: null, AAAA: null }; // null = NXDOMAIN; {codigo} = error con ese código; [..] = respuesta

let instalado = false;
export function aislar() {
  if (instalado) return;
  instalado = true;
  const request = https.request.bind(https);
  const lookup = dns.lookup.bind(dns);
  const resolve = dns.promises.resolve.bind(dns.promises);

  https.request = (url, opciones, cb) => {
    const host = new URL(url).hostname;
    if (!esLocal(host) && !dnsFalso.has(host) && !host.endsWith(".invalid") && !host.endsWith(".test"))
      throw new Error(`LA PRUEBA INTENTÓ SALIR A ${host}: las pruebas no pueden hacer peticiones a servidores reales`);
    return request(url, { ...opciones, ca: CERT }, cb);
  };
  dns.lookup = (host, opciones, cb) => {
    if (typeof opciones === "function") { cb = opciones; opciones = {}; }
    if (esLocal(host)) return lookup(host, opciones, cb);
    process.nextTick(() => {
      const dirs = dnsFalso.get(host.toLowerCase());
      if (!dirs) return cb(Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: "ENOTFOUND", hostname: host }));
      const lista = dirs.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
      if (opciones?.all) cb(null, lista); else cb(null, lista[0].address, lista[0].family);
    });
  };
  dns.promises.resolve = async (host, tipo = "A") => {
    if (esLocal(host)) return resolve(host, tipo);
    const r = resolveFalso[tipo];
    if (Array.isArray(r)) return r;
    if (r?.codigo) throw Object.assign(new Error(`query ${tipo} ${r.codigo}`), { code: r.codigo });
    throw Object.assign(new Error(`query ${tipo} ENOTFOUND ${host}`), { code: "ENOTFOUND" });
  };
}

// Un servidor https local en un puerto libre. `manejador(req, res, cuerpo)`.
export async function servidorHttps(manejador, { alRecibir, desconocido = false } = {}) {
  aislar();
  const peticiones = [];
  const servidor = https.createServer(desconocido ? { key: CLAVE_DESCONOCIDA, cert: CERT_DESCONOCIDO } : { key: CLAVE, cert: CERT }, async (req, res) => {
    const trozos = [];
    for await (const t of req) trozos.push(t);
    const cuerpo = Buffer.concat(trozos).toString("utf8");
    peticiones.push({ metodo: req.method, ruta: req.url, cabeceras: req.headers, cuerpo });
    alRecibir?.(req);
    try { await manejador(req, res, cuerpo); } catch (e) { res.writeHead(500); res.end(String(e)); }
  });
  await new Promise((ok) => servidor.listen(0, "127.0.0.1", ok));
  const puerto = servidor.address().port;
  const sockets = new Set();
  servidor.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });
  return {
    servidor, puerto, peticiones,
    base: `https://localhost:${puerto}`,
    ip: `https://127.0.0.1:${puerto}`,
    cerrar: () => new Promise((ok) => { for (const s of sockets) s.destroy(); servidor.close(ok); }),
  };
}
