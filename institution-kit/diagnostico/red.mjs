// Las peticiones del diagnóstico hacia fuera, con las barreras puestas.
//
// POR QUE NO SE USA fetch. El registro de emisores lo escribimos nosotros, pero
// la METADATA la escribe cada institución, y de ella salen casi todas las URLs
// que se piden: credential_issuer, credential_endpoint, los @context, los logos,
// el servidor de autorización. Una metadata con `"logo": {"url":
// "http://certify-nginx/mimoto-issuers-config.json"}` haría que este servicio
// pidiera, desde dentro de la VM, el fichero con el secreto de Cuenta Única. Eso
// es SSRF, y no hace falta mala fe: basta un error de copia.
//
// Las barreras, todas aquí para que ninguna comprobación se las salte:
//   - Solo https. Nada de http, file, data, ni esquemas raros.
//   - La dirección se valida EN EL MOMENTO DE CONECTAR, con un `lookup` propio:
//     una IP privada, de bucle, de enlace local (el servidor de metadatos de GCE
//     es 169.254.169.254) o de CGNAT se rechaza. Validar antes y conectar después
//     dejaría abierta la trampa del DNS que cambia entre medias.
//   - La excepción son los nombres de HOSTS_INTERNOS, que en la VM resuelven a
//     Caddy por la red de Docker (una máquina de GCE no alcanza su propia IP
//     externa). Caddy es la cara pública: por ahí no se llega a nada que no se
//     vea también desde internet.
//   - Tiempo de espera corto, tamaño máximo de respuesta, y como mucho tres
//     redirecciones, cada una validada como la primera. Un POST nunca se redirige.
//   - Dos opciones por petición, SOLO para endurecer (nunca relajan nada de lo
//     de arriba): `sinRedirecciones` devuelve la respuesta 3xx tal cual en vez de
//     seguirla, y `espera` baja el tiempo máximo de ESA petición (no puede subir
//     el de la instancia). Las usa la comprobación 12, que pide la lista de estado
//     como la app: sin redirecciones y con 5 s.
import https from "node:https";
import dns from "node:dns";
import net from "node:net";

// SOLO ASCII. Con una «ó» aquí, Node manda el byte 0xF3 suelto (latin1, UTF-8
// inválido) y el WAF de Cloudflare delante de Cuenta Única responde 403 a todo:
// medido el 29-sep, con curl y la misma cadena en UTF-8 daba 200.
const UA = "soyyord-diagnostico/1.0 (OGTIC; diagnostico de emisores)";

// Rangos que nunca se consultan. IPv4 como [red, bits].
const PRIVADAS_V4 = [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
  ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["224.0.0.0", 3]];
const aNum = (ip) => ip.split(".").reduce((n, x) => (n << 8n) + BigInt(Number(x)), 0n);
const privadaV4 = (ip) => { const n = aNum(ip); return PRIVADAS_V4.some(([red, bits]) => (n >> BigInt(32 - bits)) === (aNum(red) >> BigInt(32 - bits))); };

// Una IPv6 (con o sin zona, con o sin cola IPv4 `a.b.c.d`) como ocho grupos de 16 bits, o null si no lo es.
// Hace falta porque la MISMA dirección se escribe de muchas formas: `::ffff:127.0.0.1` y `::ffff:7f00:1` son
// la IPv4 de bucle, y una barrera que solo conoce una forma deja pasar la otra (C14 de la evaluación
// adversarial de la comprobación 12: `https://[::ffff:7f00:1]:<puerto>/` llegaba a un servidor en 127.0.0.1).
function gruposV6(ip) {
  let x = ip.toLowerCase().replace(/%.*$/, "");
  if (!net.isIPv6(x)) return null;
  const cola = x.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (cola) { const n = aNum(cola[2]); x = `${cola[1]}${((n >> 16n) & 0xffffn).toString(16)}:${(n & 0xffffn).toString(16)}`; }
  const [cabeza, resto] = x.split("::");
  const ca = cabeza ? cabeza.split(":") : [], re = resto === undefined ? null : resto ? resto.split(":") : [];
  const grupos = re === null ? ca : [...ca, ...Array(8 - ca.length - re.length).fill("0"), ...re];
  return grupos.length === 8 ? grupos.map((g) => parseInt(g, 16)) : null;
}

export function esPrivada(ip) {
  if (net.isIPv4(ip)) return privadaV4(ip);
  const g = gruposV6(String(ip));
  if (g) {
    const ceros = (n) => g.slice(0, n).every((v) => v === 0);
    if (ceros(5) && g[5] === 0xffff) return privadaV4(`${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`); // IPv4 mapeada: vale lo que valga la IPv4
    if (ceros(6)) return true;                                   // ::/96 (:: y ::1 incluidos): IPv4 «compatible», obsoleta
    if (g[0] === 0x64 && g[1] === 0xff9b) return true;           // NAT64
    return (g[0] & 0xfe00) === 0xfc00 || (g[0] & 0xffc0) === 0xfe80 || (g[0] & 0xffc0) === 0xfec0 || (g[0] >> 8) === 0xff;
  }
  // No es una IP que sepamos leer: las reglas de siempre, sobre el texto.
  const x = String(ip).toLowerCase();
  const mapeada = x.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapeada) return net.isIPv4(mapeada[1]) ? privadaV4(mapeada[1]) : false;
  return x === "::" || x === "::1" || /^f[cd]/.test(x) || /^fe[89abcdef]/.test(x) || /^ff/.test(x) || x.startsWith("64:ff9b:");
}

export class ErrorRed extends Error {
  constructor(codigo, mensaje, host) { super(mensaje); this.codigo = codigo; this.host = host; }
}

export function crearRed({ espera = 8000, hostsInternos = [], permitirPrivadas = false } = {}) {
  const internos = new Set(hostsInternos.map((h) => h.toLowerCase()).filter(Boolean));

  const lookup = (host, opciones, cb) => {
    dns.lookup(host, { all: true, family: opciones?.family ?? 0 }, (err, dirs) => {
      if (err) return cb(err);
      if (!permitirPrivadas && !internos.has(host.toLowerCase())) {
        const mala = dirs.find((d) => esPrivada(d.address));
        if (mala) { const e = new Error("dirección no pública"); e.code = "EDIRPRIVADA"; return cb(e); }
      }
      if (opciones?.all) cb(null, dirs); else cb(null, dirs[0].address, dirs[0].family);
    });
  };

  function una(url, { metodo, cuerpo, cabeceras, limite, espera: tope = espera }) {
    return new Promise((resolver, rechazar) => {
      const u = new URL(url);
      const pet = https.request(u, {
        method: metodo, lookup, agent: false, timeout: tope,
        headers: { "User-Agent": UA, Accept: "application/ld+json, application/json;q=0.9, */*;q=0.5",
                   ...(cuerpo ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(cuerpo) } : {}),
                   ...cabeceras },
      }, (res) => {
        const trozos = []; let n = 0, truncado = false;
        res.on("data", (b) => {
          if (n >= limite) { truncado = true; res.destroy(); return; }
          trozos.push(b); n += b.length;
        });
        const fin = () => resolver({ estado: res.statusCode, cabeceras: res.headers,
          cuerpo: Buffer.concat(trozos).subarray(0, limite), truncado, url });
        res.on("end", fin);
        res.on("close", fin);
        res.on("error", (e) => (truncado ? fin() : rechazar(e)));
      });
      // Tope total, no solo de inactividad: un servidor que gotea un byte por
      // segundo no puede tener la evaluación colgada.
      const reloj = setTimeout(() => { const e = new Error("sin respuesta"); e.code = "ESPERA"; pet.destroy(e); }, tope);
      pet.on("timeout", () => { const e = new Error("sin respuesta"); e.code = "ESPERA"; pet.destroy(e); });
      pet.on("error", (e) => { clearTimeout(reloj); rechazar(e); });
      pet.on("close", () => clearTimeout(reloj));
      if (cuerpo) pet.write(cuerpo);
      pet.end();
    });
  }

  // Devuelve {estado, cabeceras, cuerpo(Buffer), url, truncado} o lanza ErrorRed
  // con un código que dice QUÉ falló: dns, espera, tls, conexion, privada...
  async function traer(url, { metodo = "GET", cuerpo = null, cabeceras = {}, limite = 1 << 20, sinRedirecciones = false, espera: esperaPeticion } = {}) {
    // Solo puede BAJAR el tiempo de la instancia: un NaN, un 0 o un valor mayor se ignoran.
    const tope = Number.isFinite(esperaPeticion) && esperaPeticion > 0 ? Math.min(espera, esperaPeticion) : espera;
    let actual = url;
    for (let salto = 0; salto <= 3; salto++) {
      let u;
      try { u = new URL(actual); } catch { throw new ErrorRed("url", `URL no válida: ${String(actual).slice(0, 120)}`, null); }
      if (u.protocol !== "https:") throw new ErrorRed("esquema", `no es https (${u.protocol.replace(":", "")})`, u.hostname);
      if (u.username || u.password) throw new ErrorRed("url", "URL con credenciales", u.hostname);
      // Node NO llama a `lookup` cuando el host ya es una IP literal: la barrera de
      // abajo no se ejecutaría. Se comprueba aquí, y también en cada redirección.
      // (Defecto cazado por test/red.test.mjs el 2-oct-2026.)
      const literal = u.hostname.replace(/^\[|\]$/g, "");
      if (net.isIP(literal) && !permitirPrivadas && !internos.has(u.hostname.toLowerCase()) && esPrivada(literal)) {
        throw new ErrorRed("privada", `${u.hostname} es una dirección no pública: no se consulta`, u.hostname);
      }
      let r;
      try { r = await una(actual, { metodo, cuerpo, cabeceras, limite, espera: tope }); }
      catch (e) { throw await clasificar(e, u.hostname); }
      if (!sinRedirecciones && metodo === "GET" && [301, 302, 303, 307, 308].includes(r.estado) && r.cabeceras.location) {
        actual = new URL(r.cabeceras.location, actual).href;
        continue;
      }
      return r;
    }
    throw new ErrorRed("redirecciones", "demasiadas redirecciones", null);
  }

  return { traer };
}

const TLS = /^(CERT_|ERR_TLS_|UNABLE_TO_|DEPTH_ZERO|SELF_SIGNED|HOSTNAME_MISMATCH|ERR_SSL_|EPROTO)/;

// Traduce el error de Node a lo que le sirve a quien lo tiene que arreglar.
// ENOTFOUND de getaddrinfo mezcla «el nombre no existe» con «existe pero no tiene
// dirección», y son arreglos distintos: se pregunta al DNS para separarlos.
async function clasificar(e, host) {
  const c = e?.code ?? e?.cause?.code ?? "";
  if (c === "EDIRPRIVADA") return new ErrorRed("privada", `${host} resuelve a una dirección no pública: no se consulta`, host);
  if (c === "ESPERA" || c === "ETIMEDOUT") return new ErrorRed("espera", `${host} no respondió a tiempo`, host);
  if (c === "ENOTFOUND") {
    let detalle = "no existe en DNS (NXDOMAIN)", codigo = "nxdomain";
    try { await dns.promises.resolve(host, "A"); detalle = "no se pudo resolver"; codigo = "dns"; }
    catch (x) {
      if (x.code === "ENODATA") {
        try { await dns.promises.resolve(host, "AAAA"); detalle = "no se pudo resolver"; codigo = "dns"; }
        catch { detalle = "existe en DNS pero no tiene dirección (sin registro A ni AAAA)"; codigo = "dns"; }
      } else if (x.code !== "ENOTFOUND") { detalle = `no se pudo resolver (${x.code})`; codigo = "dns"; }
    }
    return new ErrorRed(codigo, `${host} ${detalle}`, host);
  }
  if (c === "EAI_AGAIN") return new ErrorRed("dns", `${host}: fallo temporal de DNS`, host);
  if (TLS.test(c)) return new ErrorRed("tls", `${host}: certificado TLS no válido (${c})`, host);
  if (c === "ECONNREFUSED") return new ErrorRed("conexion", `${host} rechaza la conexión en el puerto HTTPS`, host);
  if (c === "ECONNRESET" || c === "EPIPE") return new ErrorRed("conexion", `${host} cortó la conexión`, host);
  if (c === "EHOSTUNREACH" || c === "ENETUNREACH") return new ErrorRed("conexion", `${host} no es alcanzable`, host);
  return new ErrorRed("otro", `${host}: ${c || e?.message || "error de red"}`, host);
}
