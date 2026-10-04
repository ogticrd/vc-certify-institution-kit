// El motor del diagnóstico: once comprobaciones sobre la metadata de un emisor,
// más la evaluación opcional de una credencial de muestra. Lo usan el servidor
// (página por institución) y la CLI (kit de instituciones), así que no sabe nada
// de HTTP ni de HTML: devuelve datos.
//
// De dónde sale. Automatiza las revisiones que se hicieron a mano con la DGII y
// el MAP (evaluar/revision-emisor-*.md) y reutiliza el enfoque del auditor del
// panel (panel/auditor.mjs): el User-Agent que se identifica, la cabecera de
// bytes para los logos, la regla did:web, el assertionMethod que apunta al DID
// pelado. Lo que cambia es la cobertura: aquí se expande de verdad (jsonld.mjs)
// en vez de clasificar términos a mano.
//
// LÍMITES QUE SE RESPETAN, los mismos del auditor:
//   - Solo GET, y un único POST con cuerpo `{}` y SIN token al credential_endpoint.
//   - Nunca actuator, env, ni rutas administrativas. Nunca tokens.
//   - Los cuerpos ajenos se leen para lo que se comprueba y no se guardan.
//
// CUATRO ESTADOS, no dos. «No evaluable» (pendiente) es lo que evita que un fallo
// raíz aparezca como diez: si la metadata no baja, las otras nueve no «fallan»,
// esperan.
import { createPublicKey, verify as verificarFirma, createHash } from "node:crypto";
import { expandir, aRdf, canonizar, canonizarDocumento } from "./jsonld.mjs";

export const OK = "ok", FALLA = "falla", AVISO = "aviso", PENDIENTE = "pendiente";
export const AS_CUENTA_UNICA = "https://auth.cuentaunica.gob.do";
const V1 = "https://www.w3.org/2018/credentials/v1";
const V2 = "https://www.w3.org/ns/credentials/v2";
const ED2020 = "https://w3id.org/security/suites/ed25519-2020/v1";
const WK = "/.well-known/openid-credential-issuer";
// Contextos que no son de la institución: los publica el W3C o la comunidad y no
// cambian. A ellos no se les da consejo de caché.
const AJENOS = /^https:\/\/(www\.w3\.org|w3id\.org|w3c\.github\.io|w3c-ccg\.github\.io|digitalbazaar\.github\.io)\//;

// --- bibliografía ------------------------------------------------------------
const R = {
  vci: ["OpenID for Verifiable Credential Issuance 1.0", "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html"],
  vciMeta: ["OpenID4VCI 1.0 §12.2 — Metadata del emisor", "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2"],
  vciCred: ["OpenID4VCI 1.0 §8 — Credential Endpoint", "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8"],
  vciDisplay: ["OpenID4VCI 1.0 Apéndice A — display y claims", "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A"],
  rfc8414: ["RFC 8414 — OAuth 2.0 Authorization Server Metadata", "https://www.rfc-editor.org/rfc/rfc8414"],
  oidcDisc: ["OpenID Connect Discovery 1.0", "https://openid.net/specs/openid-connect-discovery-1_0.html"],
  rfc8615: ["RFC 8615 — Well-Known URIs", "https://www.rfc-editor.org/rfc/rfc8615"],
  rfc3629: ["RFC 3629 — UTF-8", "https://www.rfc-editor.org/rfc/rfc3629"],
  rfc9111: ["RFC 9111 §5.2 — Cache-Control", "https://www.rfc-editor.org/rfc/rfc9111#section-5.2"],
  rnImage: ["React Native — Image (formatos admitidos)", "https://reactnative.dev/docs/image"],
  jsonld: ["JSON-LD 1.1", "https://www.w3.org/TR/json-ld11/"],
  jsonldApi: ["JSON-LD 1.1 Processing Algorithms — Expansión", "https://www.w3.org/TR/json-ld11-api/#expansion-algorithm"],
  vc11: ["Verifiable Credentials Data Model 1.1", "https://www.w3.org/TR/vc-data-model/"],
  vc20: ["Verifiable Credentials Data Model 2.0", "https://www.w3.org/TR/vc-data-model-2.0/"],
  vc20ctx: ["VC Data Model 2.0 §4.3 — Contexts", "https://www.w3.org/TR/vc-data-model-2.0/#contexts"],
  didCore: ["DID Core 1.0", "https://www.w3.org/TR/did-core/"],
  didAssert: ["DID Core §5.3.2 — assertionMethod", "https://www.w3.org/TR/did-core/#assertion"],
  didWeb: ["did:web Method Specification", "https://w3c-ccg.github.io/did-method-web/"],
  eddsa: ["Data Integrity EdDSA Cryptosuites v1.0", "https://www.w3.org/TR/vc-di-eddsa/"],
  ed2020: ["Ed25519Signature2020", "https://w3c-ccg.github.io/di-eddsa-2020/"],
  rdfc: ["RDF Dataset Canonicalization (RDFC-1.0 / URDNA2015)", "https://www.w3.org/TR/rdf-canon/"],
  rfc7517: ["RFC 7517 — JSON Web Key (JWK)", "https://www.rfc-editor.org/rfc/rfc7517"],
  rfc8037: ["RFC 8037 — claves OKP (Ed25519) en JOSE", "https://www.rfc-editor.org/rfc/rfc8037"],
};
const refs = (...k) => k.map((x) => ({ titulo: R[x][0], url: R[x][1] }));

// El catálogo: título, porqué y bibliografía de cada comprobación. Lo comparten
// la página y la CLI.
export const CATALOGO = {
  metadata: { n: 1, titulo: "La metadata del emisor responde",
    porque: "Es el punto de entrada: la aplicación lee ahí qué credenciales hay, dónde pedirlas y a qué servidor de autorización mandar a la persona. Si no baja como JSON, nada más funciona.",
    refs: refs("vciMeta", "rfc8615") },
  identificador: { n: 2, titulo: "El identificador del emisor resuelve y publica su metadata",
    porque: "OpenID4VCI exige que la metadata cuelgue del propio `credential_issuer`. Un cliente conforme construye la URL desde ese identificador, y el mismo host suele ser el del DID que verifica la firma.",
    refs: refs("vciMeta", "vci") },
  emision: { n: 3, titulo: "El endpoint de emisión es alcanzable",
    porque: "Es la URL a la que la cartera pide la credencial. Se prueba con un POST vacío y sin token: un emisor sano lo rechaza con 400, 401 o 403. Un 404 o un fallo de DNS significa que la descarga fallará en todos los teléfonos.",
    refs: refs("vciCred") },
  autorizacion: { n: 4, titulo: "El servidor de autorización es Cuenta Única y responde",
    porque: "La persona se identifica en Cuenta Única antes de descargar. La metadata tiene que declararlo en `authorization_servers` y su documento de descubrimiento tiene que responder.",
    refs: refs("rfc8414", "oidcDisc", "vciMeta") },
  codificacion: { n: 5, titulo: "Los textos visibles están bien codificados",
    porque: "Cuando un texto UTF-8 se lee como ISO-8859-1 y se vuelve a escribir en UTF-8, «Dirección» se convierte en «DirecciÃ³n». La aplicación lo muestra tal cual. Suele venir de un fichero .properties o de una conexión a base de datos sin UTF-8.",
    refs: refs("rfc3629", "vciDisplay") },
  logo: { n: 6, titulo: "Cada credencial tiene logo PNG",
    porque: "La tarjeta de la credencial muestra el logo del bloque `display`. El componente de imagen de React Native no pinta SVG: con un SVG, o sin logo, la tarjeta sale sin identidad visual. No impide descargar.",
    refs: refs("vciDisplay", "rnImage") },
  contextos: { n: 7, titulo: "Cada @context se puede descargar",
    porque: "Para verificar la firma, el teléfono descarga cada @context y expande la credencial. Si uno no baja, ninguna credencial verifica. Un contexto publicado no se cambia nunca en su misma URL: los teléfonos guardan copias (hasta 30 días en iPhone). Por eso recomendamos `Cache-Control: no-cache`, que obliga a revalidar sin prohibir la copia.",
    refs: refs("jsonld", "vc20ctx", "rfc9111") },
  cobertura: { n: 8, titulo: "El @context define todos los atributos (la firma los cubre)",
    porque: "La firma se calcula sobre el RDF que resulta de expandir la credencial. Un atributo que el @context no define se DESCARTA en la expansión: se ve en pantalla pero no está firmado, y cualquiera podría cambiarlo. Ningún contexto W3C define `@vocab`, así que no hay red de seguridad. Se comprueba expandiendo un documento sintético con los atributos de la metadata y los contextos reales.",
    refs: refs("jsonldApi", "rdfc", "vc11", "vc20") },
  nombres: { n: 9, titulo: "Los nombres de los atributos coinciden",
    porque: "`credentialSubject`, `order` y el @context tienen que usar exactamente los mismos nombres. Una diferencia de mayúsculas o de guiones basta para que un atributo quede fuera de la firma o no se muestre.",
    refs: refs("vciDisplay", "jsonld") },
  did: { n: 10, titulo: "El DID del emisor resuelve y autoriza su clave",
    porque: "El verificador descarga `https://<host>/.well-known/did.json` (did:web), busca la clave que firmó y comprueba que esté en `assertionMethod`. Si ahí aparece el DID pelado en lugar del id de la clave, un verificador conforme rechaza todas las credenciales aunque la firma sea válida.",
    refs: refs("didCore", "didAssert", "didWeb", "rfc7517") },
  orden: { n: 11, titulo: "Tipos y contextos guardados en el orden que Certify busca",
    porque: "Inji Certify encuentra la plantilla de la credencial con una clave hecha de los tipos y los @context de la petición ORDENADOS alfabéticamente (CredentialUtils.getTemplateName hace Collections.sort), y la compara como texto exacto con las columnas `credential_type` y `context` de `certify.credential_config`. La metadata publica esas columnas tal como están guardadas, así que si ahí no salen ordenadas, la búsqueda falla siempre, al final de todo el flujo, cuando la persona ya inició sesión y sus datos ya se consultaron: «CredentialConfig not found for key: …» (con el código engañoso ERROR_SIGNING_QR_DATA). Ordenar la columna no afecta a la credencial: su @context sale de la plantilla (`vc_template`), donde el de W3C tiene que seguir yendo primero.",
    refs: refs("vciMeta", "vc11") },
};
export const CATALOGO_MUESTRA = {
  m_contexto: { titulo: "El primer @context es el de W3C",
    porque: "El Data Model exige que el primer contexto sea el de W3C, y el verificador de la aplicación lo comprueba («needs to be first in the list of contexts», LdpValidator.kt): si no, rechaza la credencial.",
    refs: refs("vc11", "vc20ctx") },
  m_suite: { titulo: "Incluye el contexto de la suite de firma",
    porque: "El tipo de la prueba (p. ej. Ed25519Signature2020) solo está definido en el contexto de su suite. Sin él, la prueba se queda casi sin cuádruplas y el verificador no puede interpretarla.",
    refs: refs("ed2020", "eddsa") },
  m_cobertura: { titulo: "Todos los atributos de credentialSubject quedan firmados",
    porque: "Se expande la credencial real con sus contextos y se cuentan los atributos que sobreviven. Los que se descartan no están cubiertos por la firma.",
    refs: refs("jsonldApi", "rdfc") },
  m_prueba: { titulo: "La prueba (proof) tiene contenido firmable",
    porque: "Se cuentan las cuádruplas RDF del grafo de la prueba. Una prueba bien definida tiene al menos tipo, fecha, método de verificación y propósito.",
    refs: refs("rdfc", "ed2020") },
  m_emisor: { titulo: "La emitió este emisor",
    porque: "El `issuer` de la credencial tiene que ser el DID del emisor registrado, que es el que el verificador resuelve.",
    refs: refs("didWeb", "vc20") },
  m_firma: { titulo: "La firma es válida",
    porque: "Se hace lo mismo que un verificador: canonicalización URDNA2015 del documento y de las opciones de la prueba, SHA-256 de cada una y verificación Ed25519 con la clave publicada en el DID, comprobando además que esa clave esté autorizada en assertionMethod.",
    refs: refs("ed2020", "eddsa", "rdfc", "didAssert") },
};

const json = (b) => { try { return JSON.parse(Buffer.isBuffer(b) ? b.toString("utf8") : b); } catch { return null; } };
const comoLista = (v) => (v === undefined || v === null ? [] : Array.isArray(v) ? v : [v]);
const sinBarra = (u) => String(u ?? "").replace(/\/+$/, "");
const plural = (n, s, p = s + "s") => `${n} ${n === 1 ? s : p}`;
const cabecera = (r, k) => { const v = r?.cabeceras?.[k]; return Array.isArray(v) ? v.join(", ") : v ?? null; };
const tipoJson = (ct) => /application\/(ld\+)?json/i.test(ct ?? "");

function resultado(id, estado, resumen, accion = null, detalles = []) {
  const c = CATALOGO[id] ?? CATALOGO_MUESTRA[id];
  return { id, n: c.n ?? null, titulo: c.titulo, estado, resumen, accion, detalles: detalles.filter(Boolean), porque: c.porque, refs: c.refs };
}
// Un fallo manda sobre todo; una parte sin evaluar impide decir «resuelto».
const peor = (estados) => estados.includes(FALLA) ? FALLA : estados.includes(AVISO) ? AVISO
  : estados.includes(PENDIENTE) ? PENDIENTE : OK;

// --- detección de doble codificación ------------------------------------------
// Los bytes de continuación UTF-8 (0x80-0xBF) leídos como Windows-1252 dan estos
// caracteres. «Ã» o «Â» seguidos de uno de ellos es la firma inconfundible.
const CP1252 = "€\u0081‚ƒ„…†‡ˆ‰Š‹Œ\u008DŽ\u008F\u0090‘’“”•–—˜™š›œ\u009DžŸ";
const CONT = `[\\u0080-\\u00BF${CP1252}]`;
const MOJIBAKE = new RegExp(`[ÃÂ]${CONT}|â€${CONT}|�`);
function arreglar(s) {
  // Deshace la doble codificación: cada carácter vuelve a su byte de 1252/latin1.
  const bytes = [];
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    const i = CP1252.indexOf(ch);
    if (i >= 0) bytes.push(0x80 + i); else if (cp <= 0xff) bytes.push(cp); else return null;
  }
  const r = Buffer.from(bytes).toString("utf8");
  return r.includes("�") ? null : r;
}

// --- utilidades de claves -----------------------------------------------------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(s) {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error("base58 no válido"); n = n * 58n + BigInt(i); }
  let hex = n.toString(16); if (hex.length % 2) hex = "0" + hex;
  let ceros = 0; for (const c of s) { if (c === "1") ceros++; else break; }
  return Buffer.concat([Buffer.alloc(ceros), n === 0n ? Buffer.alloc(0) : Buffer.from(hex, "hex")]);
}
function multibase(s) {
  if (typeof s !== "string" || !s) throw new Error("multibase vacío");
  if (s[0] === "z") return b58(s.slice(1));
  if (s[0] === "u") return Buffer.from(s.slice(1), "base64url");
  throw new Error(`prefijo multibase «${s[0]}» no soportado`);
}
// La clave Ed25519 cruda (32 bytes) de un método de verificación, si la tiene.
function claveEd25519(vm) {
  if (vm?.publicKeyMultibase) {
    const b = multibase(vm.publicKeyMultibase);
    if (b.length === 34 && b[0] === 0xed && b[1] === 0x01) return b.subarray(2);
    if (b.length === 32) return b;
  }
  if (vm?.publicKeyJwk?.kty === "OKP" && vm.publicKeyJwk.crv === "Ed25519") return Buffer.from(vm.publicKeyJwk.x, "base64url");
  if (vm?.publicKeyBase58) { const b = b58(vm.publicKeyBase58); if (b.length === 32) return b; }
  return null;
}
// Huella comparable de una clave pública, venga como JWK, PEM o multibase.
function huellaClave(x) {
  try {
    const ed = claveEd25519(x);
    if (ed) return "ed:" + ed.toString("base64url");
    let jwk = x.publicKeyJwk ?? (x.kty ? x : null);
    if (!jwk && x.publicKeyPem) jwk = createPublicKey(x.publicKeyPem).export({ format: "jwk" });
    if (!jwk) return null;
    if (jwk.kty === "OKP") return "ed:" + jwk.x;
    if (jwk.kty === "RSA") return "rsa:" + jwk.n;
    if (jwk.kty === "EC") return `ec:${jwk.crv}:${jwk.x}:${jwk.y}`;
  } catch {}
  return null;
}
const PRIVADOS_JWK = ["d", "p", "q", "dp", "dq", "qi", "k"];

// did:web -> URL del documento (did:web Method Specification §3.2.1).
export function urlDidWeb(did) {
  const p = String(did).split(":");
  if (p[0] !== "did" || p[1] !== "web" || !p[2]) return null;
  const host = decodeURIComponent(p[2]);
  const segs = p.slice(3).map(decodeURIComponent);
  return `https://${host}/` + (segs.length ? segs.join("/") + "/did.json" : ".well-known/did.json");
}
function didWebDe(url) {
  // Un credential_issuer que no es una URL («emisor.gob.do») ya lo señala la
  // comprobación 2; aquí no puede tumbar el informe entero con un TypeError.
  let u;
  try { u = new URL(url); } catch { return { raiz: null, conRuta: null }; }
  const host = encodeURIComponent(u.host); // el puerto va como %3A
  const segs = u.pathname.split("/").filter(Boolean).map(encodeURIComponent);
  return { raiz: `did:web:${host}`, conRuta: segs.length ? `did:web:${host}:${segs.join(":")}` : null };
}

// --- el cargador de contextos ---------------------------------------------------
// Los contextos W3C no cambian: se guardan una hora entre evaluaciones. Los de
// la institución se piden en cada evaluación, porque justo de ellos se informa.
const cacheAjenos = new Map();
function crearCargador(red, vistos = new Map()) {
  const cargar = async (url) => {
    if (vistos.has(url)) { const v = vistos.get(url); if (v.doc) return structuredClone(v.doc); throw new Error(v.error); }
    const c = cacheAjenos.get(url);
    if (AJENOS.test(url) && c && Date.now() - c.t < 3600_000) { vistos.set(url, { doc: c.doc, respuesta: c.respuesta }); return structuredClone(c.doc); }
    let r;
    try { r = await red.traer(url); }
    catch (e) { vistos.set(url, { error: e.message, red: e }); throw e; }
    const doc = r.estado === 200 ? json(r.cuerpo) : null;
    const info = { respuesta: { estado: r.estado, tipo: cabecera(r, "content-type"), cache: cabecera(r, "cache-control"), url: r.url } };
    if (!doc) { const error = r.estado === 200 ? "no es JSON" : `responde ${r.estado}`; vistos.set(url, { ...info, error }); throw new Error(`${url} ${error}`); }
    vistos.set(url, { ...info, doc });
    if (AJENOS.test(url)) cacheAjenos.set(url, { t: Date.now(), doc, respuesta: info.respuesta });
    return structuredClone(doc);
  };
  return { cargar, vistos };
}

// Todos los términos que declara un contexto (para sugerir nombres parecidos) y
// sus @vocab (para distinguir «definido» de «caído en el @vocab»).
function terminosDe(ctx, terminos = new Set(), vocabs = new Set()) {
  for (const c of comoLista(ctx)) {
    if (!c || typeof c !== "object") continue;
    for (const [k, v] of Object.entries(c)) {
      if (k === "@vocab" && typeof v === "string") vocabs.add(v);
      else if (!k.startsWith("@")) { terminos.add(k); if (v && typeof v === "object" && v["@context"]) terminosDe(v["@context"], terminos, vocabs); }
    }
  }
  return { terminos, vocabs };
}
const normal = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, "");

// Configuraciones de credencial, en forma draft 13 o 1.0.
function configuraciones(wk) {
  return Object.entries(wk.credential_configurations_supported ?? {}).map(([nombre, c]) => {
    const cd = c.credential_definition ?? {};
    const cs = cd.credentialSubject ?? {};
    // En 1.0 los atributos van en credential_metadata.claims con `path`.
    const claims = comoLista(c.credential_metadata?.claims ?? (Array.isArray(c.claims) ? c.claims : []))
      .map((x) => x?.path?.[0] === "credentialSubject" ? x.path[1] : x?.path?.[0]).filter((x) => typeof x === "string");
    const deCs = Object.keys(cs).length ? Object.keys(cs) : Object.keys(!Array.isArray(c.claims) && c.claims ? c.claims : {});
    return {
      nombre, formato: c.format, cd, contextos: comoLista(cd["@context"]),
      tipos: comoLista(cd.type).filter((t) => t !== "VerifiableCredential"),
      order: comoLista(c.order), deCs: deCs.length ? deCs : claims,
      display: comoLista(c.display ?? c.credential_metadata?.display),
      algoritmos: comoLista(c.credential_signing_alg_values_supported),
      cs,
    };
  });
}

// =============================================================================
// Las once comprobaciones
// =============================================================================
export async function diagnosticar({ metadata_url, as_esperado = AS_CUENTA_UNICA }, { red }) {
  const inicio = Date.now();
  const cs = {};
  const pendienteDe = (id, n, motivo) => resultado(id, PENDIENTE, `Depende de la comprobación ${n}: ${motivo}.`);
  const datos = { credential_issuer: null, did: null };

  // 1. La metadata ---------------------------------------------------------------
  let wk = null;
  {
    let r = null, err = null;
    try { r = await red.traer(metadata_url); } catch (e) { err = e; }
    if (err) cs.metadata = resultado("metadata", FALLA, `No responde: ${err.message}.`,
      "Publique la metadata en esa URL, por HTTPS con un certificado válido.");
    else if (r.estado !== 200) cs.metadata = resultado("metadata", FALLA, `Responde ${r.estado} en ${metadata_url}.`,
      "Publique la metadata en esa ruta, o díganos la URL correcta.");
    else if (!(wk = json(r.cuerpo)) || typeof wk !== "object") { wk = null;
      cs.metadata = resultado("metadata", FALLA, "Responde 200 pero el cuerpo no es JSON.", "Sirva el documento JSON de la metadata.", [`Content-Type: ${cabecera(r, "content-type") ?? "ausente"}`]); }
    else if (!wk.credential_issuer || !wk.credential_configurations_supported) {
      const falta = ["credential_issuer", "credential_configurations_supported"].filter((k) => !wk[k]);
      wk = null;
      cs.metadata = resultado("metadata", FALLA, `Es JSON pero le falta ${falta.join(" y ")}.`, "Complete la metadata según OpenID4VCI §12.2.");
    } else {
      const confs = Object.keys(wk.credential_configurations_supported);
      const detalles = [`URL: ${metadata_url}`, `Content-Type: ${cabecera(r, "content-type") ?? "ausente"}`,
        `Configuraciones: ${confs.join(", ") || "ninguna"}`];
      const bienRuta = metadata_url.replace(/\/+$/, "").endsWith(WK);
      if (!tipoJson(cabecera(r, "content-type"))) detalles.push("El Content-Type no es application/json.");
      cs.metadata = resultado("metadata", confs.length && bienRuta ? OK : AVISO,
        !confs.length ? "Responde, pero no declara ninguna credencial."
          : bienRuta ? `Responde 200 con JSON y ${plural(confs.length, "credencial", "credenciales")}.`
          : "Responde, pero no en una ruta /.well-known/openid-credential-issuer.",
        !confs.length ? "Declare al menos una configuración en credential_configurations_supported."
          : bienRuta ? null : "La aplicación construye la URL como {host}/.well-known/openid-credential-issuer; publíquela ahí.",
        detalles);
    }
  }
  if (!wk) {
    for (const [id, c] of Object.entries(CATALOGO)) if (id !== "metadata") cs[id] = pendienteDe(id, 1, "sin metadata no se puede evaluar");
    return cerrar(cs, { metadata_url, inicio, datos });
  }
  datos.credential_issuer = wk.credential_issuer;
  const confs = configuraciones(wk);

  // 2. credential_issuer -------------------------------------------------------
  let hostEmisorRoto = null;
  {
    const ci = sinBarra(wk.credential_issuer);
    let u = null;
    try { u = new URL(ci); } catch {}
    if (!u || u.protocol !== "https:") cs.identificador = resultado("identificador", FALLA,
      `credential_issuer no es una URL https: «${String(wk.credential_issuer).slice(0, 100)}».`, "Use la URL https del emisor como identificador.");
    else {
      // 1.0 inserta el well-known entre el host y la ruta; los borradores y la
      // aplicación lo añaden al final. Con ruta vacía son la misma URL.
      const candidatas = [...new Set([ci + WK, u.origin + WK + (u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, ""))])];
      const vistos = [];
      let bueno = null, primerError = null;
      for (const url of candidatas) {
        try {
          const r = await red.traer(url);
          const d = r.estado === 200 ? json(r.cuerpo) : null;
          vistos.push(`${url} → ${r.estado}${r.estado === 200 && !d ? " (no es JSON)" : ""}`);
          if (d && sinBarra(d.credential_issuer) === ci) { bueno = url; break; }
          if (d?.credential_issuer) vistos.push(`  sirve otra metadata: credential_issuer = ${d.credential_issuer}`);
        } catch (e) { primerError ??= e; vistos.push(`${url} → ${e.message}`); if (["nxdomain", "dns"].includes(e.codigo)) { hostEmisorRoto = e; break; } }
      }
      if (bueno) cs.identificador = resultado("identificador", OK,
        `${u.host} resuelve y publica su metadata${sinBarra(bueno) === sinBarra(metadata_url) ? " (es la URL registrada)" : ""}.`, null, vistos);
      else if (primerError && ["nxdomain", "dns"].includes(primerError.codigo)) cs.identificador = resultado("identificador", FALLA,
        `${primerError.message}.`,
        `Publique ${u.host} en DNS con la metadata en ${ci + WK}, o cambie credential_issuer (y credential_endpoint y el DID) al host que sí la publica.`, vistos);
      else cs.identificador = resultado("identificador", FALLA,
        primerError ? `${primerError.message}.` : `No publica la metadata en ${candidatas[0]}.`,
        `Sirva la misma metadata en ${ci + WK}.`, vistos);
    }
  }

  // 3. credential_endpoint -------------------------------------------------------
  {
    const ep = wk.credential_endpoint;
    if (!ep) cs.emision = resultado("emision", FALLA, "La metadata no declara credential_endpoint.", "Añada credential_endpoint a la metadata.");
    else {
      try {
        // El ÚNICO POST de todo el diagnóstico: cuerpo vacío, sin token. No puede
        // emitir nada; solo dice si ahí hay un endpoint vivo.
        const r = await red.traer(ep, { metodo: "POST", cuerpo: "{}", limite: 4096 });
        const cuerpo = r.cuerpo.toString("utf8").slice(0, 600);
        const pideAuth = /full authentication is required|unauthorized|invalid[_ ]token|authentication (is )?(required|failed)/i.test(cuerpo);
        const d = json(r.cuerpo);
        const err = d && typeof d === "object" ? [d.error, d.error_description].filter(Boolean).join(": ").slice(0, 140) : "";
        const det = [`POST ${ep} con {} y sin token → ${r.estado}${err ? ` (${err})` : ""}`];
        if ([400, 401, 403].includes(r.estado)) cs.emision = resultado("emision", OK, `Responde ${r.estado} a una petición sin token, como debe.`, null, det);
        else if (r.estado >= 200 && r.estado < 300 && pideAuth) cs.emision = resultado("emision", OK,
          `Responde ${r.estado} pero el cuerpo pide autenticación: el endpoint existe.`, null,
          [...det, "Lo correcto sería 401; no impide integrar."]);
        else if (r.estado === 404 || r.estado === 405) cs.emision = resultado("emision", FALLA,
          `Responde ${r.estado}: no hay un endpoint de emisión en esa URL.`, "Publique el endpoint de emisión en la URL que declara la metadata (o corrija la URL).", det);
        else if (r.estado >= 500) cs.emision = resultado("emision", AVISO, `Responde ${r.estado} (error del servidor) a una petición vacía.`,
          "Debería rechazar con 400 o 401; revisen el registro del servicio.", det);
        else if (r.estado >= 200 && r.estado < 300) cs.emision = resultado("emision", AVISO,
          `Responde ${r.estado} a una petición sin token.`, "Compruebe que el endpoint exige token: debería responder 401.", det);
        else cs.emision = resultado("emision", AVISO, `Responde ${r.estado}, que no es lo esperado.`, "Debería rechazar con 400 o 401.", det);
      } catch (e) {
        cs.emision = resultado("emision", FALLA, `No alcanzable: ${e.message}.`,
          `Publique ${new URL(ep).host} en DNS y con HTTPS, o declare un credential_endpoint que sí sea alcanzable desde internet.`);
      }
    }
  }

  // 4. Servidor de autorización ------------------------------------------------------
  {
    const lista = comoLista(wk.authorization_servers).map(sinBarra);
    const esperado = sinBarra(as_esperado);
    if (!lista.length) cs.autorizacion = resultado("autorizacion", FALLA, "La metadata no declara authorization_servers.",
      `Añada "authorization_servers": ["${esperado}"].`);
    // Pasó de verdad: MAP declaraba https://cuenta.digital.gob.do, que PARECE otro
    // nombre de Cuenta Única y es otro proyecto de Ory con otras claves. Por eso el
    // mensaje dice que los tokens no se cruzan y nombra las propiedades a cambiar:
    // la institución ya tiene cliente, solo tiene que configurarlo.
    else if (!lista.includes(esperado)) cs.autorizacion = resultado("autorizacion", FALLA,
      `Declara ${lista.join(", ")} y no ${esperado}, que es el Cuenta Única de producción. Son servidores distintos, con claves distintas: el emisor rechazaría el token con el que la aplicación pide la credencial.`,
      `Con el cliente que ya tienen, apunten a ${esperado}. En Inji Certify: mosip.certify.authorization.url=${esperado}, mosip.certify.authn.issuer-uri=${esperado} y mosip.certify.authn.jwk-set-uri=${esperado}/.well-known/jwks.json. Después reinicien Certify.`);
    else {
      const det = [];
      let ok = null;
      for (const ruta of ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]) {
        try {
          const r = await red.traer(esperado + ruta);
          const d = r.estado === 200 ? json(r.cuerpo) : null;
          det.push(`${esperado + ruta} → ${r.estado}`);
          if (d?.authorization_endpoint && d?.token_endpoint) { ok = d; break; }
        } catch (e) { det.push(`${esperado + ruta} → ${e.message}`); }
      }
      if (ok && sinBarra(ok.issuer) !== esperado) det.push(`Ojo: su «issuer» es ${ok.issuer}.`);
      cs.autorizacion = ok ? resultado("autorizacion", OK, `Declara ${esperado} y su descubrimiento responde.`, null, det)
        : resultado("autorizacion", FALLA, `${esperado} no publica su documento de descubrimiento.`,
          "Esto es de Cuenta Única, no del emisor: avísenos.", det);
    }
  }

  // 5. Codificación --------------------------------------------------------------
  {
    const textos = [];
    const recoger = (donde, bloques) => { for (const b of comoLista(bloques)) for (const k of ["name", "description"])
      if (typeof b?.[k] === "string") textos.push({ donde: `${donde} (${k}${b.locale ? ", " + b.locale : ""})`, t: b[k] }); };
    recoger("nombre del emisor", wk.display);
    for (const c of confs) {
      recoger(`credencial ${c.nombre}`, c.display);
      for (const [attr, def] of Object.entries(c.cs)) recoger(`atributo ${c.nombre}.${attr}`, def?.display);
      for (const cl of comoLista(c.cd && wk.credential_configurations_supported[c.nombre]?.credential_metadata?.claims))
        recoger(`atributo ${c.nombre}.${comoLista(cl?.path).join(".")}`, cl?.display);
    }
    const malos = textos.filter((x) => MOJIBAKE.test(x.t));
    cs.codificacion = malos.length
      ? resultado("codificacion", FALLA, `${plural(malos.length, "texto")} con doble codificación UTF-8: «${malos[0].t.slice(0, 60)}».`,
          "Lea y sirva esos textos en UTF-8 (suele ser un .properties leído como ISO-8859-1).",
          malos.map((x) => { const bien = arreglar(x.t); return `${x.donde}: «${x.t}»${bien ? ` → debería ser «${bien}»` : ""}`; }))
      : resultado("codificacion", OK, `${plural(textos.length, "texto visible", "textos visibles")}, todos bien codificados.`);
  }

  // 6. Logos ------------------------------------------------------------------------
  {
    const filas = [], estados = [];
    for (const c of confs) {
      const d = c.display.find((x) => x?.logo?.url || x?.logo?.uri);
      const url = d?.logo?.url ?? d?.logo?.uri;
      if (!url) { estados.push(AVISO); filas.push(`${c.nombre}: sin logo`); continue; }
      try {
        const r = await red.traer(url, { limite: 2 << 20 });
        const b = r.cuerpo;
        if (r.estado !== 200) { estados.push(AVISO); filas.push(`${c.nombre}: ${url} → ${r.estado}`); continue; }
        const png = b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47;
        const jpg = b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;
        const svg = /<\?xml|<svg/i.test(b.subarray(0, 256).toString("utf8"));
        const alt = d.logo.alt_text ? "" : " · sin alt_text";
        if (png) { estados.push(OK); filas.push(`${c.nombre}: PNG, ${Math.round(b.length / 1024)} KB${alt}`); }
        else if (jpg) { estados.push(OK); filas.push(`${c.nombre}: JPEG (se pinta; recomendamos PNG)${alt}`); }
        else { estados.push(AVISO); filas.push(`${c.nombre}: ${svg ? "es SVG, no se pinta en la aplicación" : "formato no reconocido"} (${cabecera(r, "content-type") ?? "sin Content-Type"})`); }
      } catch (e) { estados.push(AVISO); filas.push(`${c.nombre}: ${e.message}`); }
    }
    const e = peor(estados.length ? estados : [AVISO]);
    const sin = filas.filter((f) => f.endsWith("sin logo")).length;
    cs.logo = resultado("logo", e,
      e === OK ? `${plural(confs.length, "credencial", "credenciales")} con logo que se puede pintar.`
        : sin === confs.length ? (confs.length === 1 ? "La credencial no tiene logo." : "Ninguna credencial tiene logo.")
        : "Hay logos que faltan o que la aplicación no puede pintar.",
      e === OK ? null : "Añada en display un logo PNG (unos 200×200 px) con su alt_text.", filas);
  }

  // 7. Contextos ---------------------------------------------------------------------
  const { cargar, vistos } = crearCargador(red);
  const contextosRotos = new Set();
  {
    const urls = [...new Set(confs.flatMap((c) => c.contextos).filter((x) => typeof x === "string"))];
    const enLinea = confs.some((c) => c.contextos.some((x) => x && typeof x === "object"));
    const filas = [], estados = [];
    const hostEmisor = (() => { try { return new URL(wk.credential_issuer).host; } catch { return ""; } })();
    for (const url of urls) {
      let error = null;
      try {
        await cargar(url);
        // Que además sea un contexto procesable: se expande uno mínimo con él.
        await expandir({ "@context": url, "@id": "urn:x", "urn:p": "x" }, { cargar });
      } catch (e) { error = vistos.get(url)?.error ?? e.message; }
      const v = vistos.get(url) ?? {};
      const resp = v.respuesta;
      if (error) {
        contextosRotos.add(url); estados.push(FALLA);
        let fila = `${url}: ${error}`;
        // El caso de la DGII: el contexto en .gob.do y todo lo demás en .gov.do.
        try {
          const h = new URL(url).host;
          const otro = h.replace(/\.gob\.do$/, ".gov.do") !== h ? h.replace(/\.gob\.do$/, ".gov.do") : h.replace(/\.gov\.do$/, ".gob.do");
          const base = (x) => x.split(".").slice(-3).join(".");
          if (otro !== h && base(otro) === base(hostEmisor)) fila += ` · ojo: el contexto está en ${base(h)} y el emisor en ${base(hostEmisor)}`;
        } catch {}
        filas.push(fila);
        continue;
      }
      const notas = [`${resp?.estado ?? 200}`, `Content-Type: ${resp?.tipo ?? "ausente"}`, `Cache-Control: ${resp?.cache ?? "ausente"}`];
      let e = OK;
      if (!tipoJson(resp?.tipo)) { e = AVISO; notas.push("debería ser application/ld+json o application/json"); }
      if (!AJENOS.test(url)) {
        const cc = (resp?.cache ?? "").toLowerCase();
        if (!cc) { e = AVISO; notas.push("sin Cache-Control: cada cliente decide cuánto guarda su copia; recomendamos no-cache"); }
        else if (cc.includes("no-store")) { e = AVISO; notas.push("no-store obliga a descargarlo en cada verificación; basta no-cache"); }
        else if (!cc.includes("no-cache")) { e = AVISO; notas.push("sin no-cache, los teléfonos pueden seguir con una copia vieja; recomendamos no-cache"); }
      }
      estados.push(e);
      filas.push(`${url}: ${notas.join(" · ")}`);
    }
    if (enLinea) filas.push("Hay contextos en línea (objetos) en la metadata: se usan tal cual.");
    const primeros = [...new Set(confs.map((c) => c.contextos[0]))];
    if (primeros.some((p) => p !== V1 && p !== V2))
      filas.push("En la metadata el contexto W3C no va primero. Certify puede mostrarlos en otro orden que la credencial: compruébelo con una muestra.");
    if (confs.some((c) => c.contextos.length && !c.contextos.includes(V1) && !c.contextos.includes(V2))) {
      estados.push(FALLA); filas.push("Alguna credencial no incluye el contexto W3C (credentials/v1 o credentials/v2).");
    }
    const rotos = [...contextosRotos];
    cs.contextos = !urls.length && !enLinea
      ? resultado("contextos", FALLA, "Ninguna credencial declara @context.", "Declare en credential_definition los contextos de la credencial.")
      : resultado("contextos", peor(estados),
          rotos.length ? `No se puede descargar: ${rotos.map((u) => vistos.get(u)?.error ?? u).join("; ")}.`
            : peor(estados) === OK ? `${plural(urls.length, "contexto")}, todos descargables y con caché correcta.`
            : `${plural(urls.length, "contexto")} descargables, con advertencias de caché o tipo.`,
          rotos.length ? "Publique el contexto en una URL que resuelva, con HTTPS, y no lo cambie nunca en esa misma URL."
            : peor(estados) === OK ? null : "Sirva sus contextos con Content-Type application/ld+json y Cache-Control: no-cache.",
          filas);
  }

  // 8 y 9. Cobertura y nombres ----------------------------------------------------------
  {
    const filas8 = [], est8 = [], filas9 = [], est9 = [];
    for (const c of confs) {
      const attrs = [...new Set([...c.order, ...c.deCs])];
      // 9a. order contra credentialSubject: no necesita contexto.
      const soloOrder = c.order.filter((x) => !c.deCs.includes(x));
      const soloCs = c.order.length ? c.deCs.filter((x) => !c.order.includes(x)) : [];
      if (soloOrder.length) { est9.push(FALLA); filas9.push(`${c.nombre}: «order» nombra ${soloOrder.join(", ")}, que no está en credentialSubject`); }
      if (soloCs.length) { est9.push(AVISO); filas9.push(`${c.nombre}: ${soloCs.join(", ")} está en credentialSubject pero no en «order» (puede no mostrarse)`); }
      if (!attrs.length) { est8.push(AVISO); filas8.push(`${c.nombre}: la metadata no declara atributos`); continue; }
      const rotos = c.contextos.filter((x) => typeof x === "string" && contextosRotos.has(x));
      if (rotos.length) {
        est8.push(PENDIENTE); est9.push(PENDIENTE);
        filas8.push(`${c.nombre}: ${plural(attrs.length, "atributo")} sin evaluar; no baja ${rotos.join(", ")}`);
        continue;
      }
      // El documento sintético: el contexto W3C primero, como irá en la credencial,
      // y el de la suite si firma con Ed25519.
      const base = c.contextos.includes(V1) ? V1 : V2;
      const ctx = [base, ...c.contextos.filter((x) => x !== base)];
      if (c.algoritmos.some((a) => /eddsa|ed25519/i.test(a)) && !ctx.includes(ED2020)) ctx.push(ED2020);
      const marca = (i) => `__valor_${i}__`;
      const doc = { "@context": ctx, type: ["VerifiableCredential", ...c.tipos], issuer: "did:web:emisor.example",
        ...(base === V1 ? { issuanceDate: "2026-01-01T00:00:00Z" } : { validFrom: "2026-01-01T00:00:00Z" }),
        credentialSubject: { id: "did:example:sujeto", ...Object.fromEntries(attrs.map((a, i) => [a, marca(i)])) } };
      let cuads;
      try { cuads = aRdf(await expandir(doc, { cargar })); }
      catch (e) { est8.push(FALLA); filas8.push(`${c.nombre}: la expansión falla — ${e.message}`); est9.push(PENDIENTE); continue; }
      const { terminos, vocabs } = terminosDe(c.contextos.filter((x) => typeof x === "string").map((u) => vistos.get(u)?.doc?.["@context"]).concat(c.contextos.filter((x) => typeof x === "object")));
      const definidos = [], porVocab = [], fuera = [];
      attrs.forEach((a, i) => {
        const q = cuads.find((x) => x.o.tipo === "literal" && x.o.valor === marca(i));
        if (!q) fuera.push(a);
        else if ([...vocabs].some((v) => q.p.valor === v + a) && !terminos.has(a)) porVocab.push(a);
        else definidos.push(a);
      });
      const tiposFuera = c.tipos.filter((t) => !cuads.some((x) => x.p.valor.endsWith("#type") && x.o.valor.endsWith(t)));
      const e = fuera.length ? FALLA : porVocab.length || tiposFuera.length ? AVISO : OK;
      est8.push(e);
      filas8.push(`${c.nombre}: ${definidos.length + porVocab.length} de ${attrs.length} atributos definidos` +
        (fuera.length ? ` · NO firmados: ${fuera.join(", ")}` : "") +
        (porVocab.length ? ` · solo por @vocab: ${porVocab.join(", ")}` : "") +
        (tiposFuera.length ? ` · el tipo ${tiposFuera.join(", ")} no está definido en el contexto` : ""));
      // 9b. nombres parecidos en el contexto para los que se caen.
      for (const a of fuera) {
        const parecido = [...terminos].find((t) => t !== a && normal(t) === normal(a));
        if (parecido) { est9.push(FALLA); filas9.push(`${c.nombre}: la metadata usa «${a}» y el contexto define «${parecido}»`); }
      }
      if (!soloOrder.length && !soloCs.length && !fuera.length) est9.push(OK);
      else if (fuera.length && !filas9.some((f) => f.startsWith(c.nombre + ": la metadata usa"))) {
        est9.push(FALLA); filas9.push(`${c.nombre}: el contexto no define ${fuera.join(", ")} con ningún nombre parecido`);
      }
    }
    const e8 = est8.length ? peor(est8) : AVISO;
    const todos = filas8.map((f) => f.match(/: (\d+) de (\d+) atributos/)).filter(Boolean);
    const resumen8 = e8 === PENDIENTE ? "Depende de la comprobación 7: sin el @context no se puede medir qué queda firmado."
      : todos.length === 1 ? `${todos[0][1]} de ${todos[0][2]} atributos definidos.`
      : `${todos.reduce((n, m) => n + Number(m[1]), 0)} de ${todos.reduce((n, m) => n + Number(m[2]), 0)} atributos definidos en ${plural(todos.length, "credencial", "credenciales")}.`;
    cs.cobertura = resultado("cobertura", e8, resumen8,
      e8 === FALLA ? "Defina en su @context cada atributo, con el mismo nombre exacto que en la metadata, y publíquelo en una URL nueva."
        : e8 === AVISO ? "Defina explícitamente cada atributo y el tipo de la credencial en el @context." : null, filas8);
    const e9 = est9.length ? peor(est9) : OK;
    cs.nombres = resultado("nombres", e9,
      e9 === PENDIENTE ? "credentialSubject y order coinciden; falta el @context (comprobación 7) para compararlos con él."
        : e9 === OK ? "credentialSubject, order y @context usan los mismos nombres."
        : "Hay nombres que no coinciden.",
      e9 === FALLA ? "Use exactamente el mismo nombre (mayúsculas, guiones) en credentialSubject, order y el @context." : null,
      filas9);
    if (e9 === PENDIENTE && filas9.length === 0) cs.nombres.detalles = [];
  }

  // 10. DID --------------------------------------------------------------------------
  if (!didWebDe(wk.credential_issuer).raiz) {
    // credential_issuer no es una URL: la comprobación 2 ya lo dice; aquí no hay DID.
    cs.did = pendienteDe("did", 2, "el identificador del emisor no es una URL, así que no hay DID que resolver");
  } else {
    const { raiz, conRuta } = didWebDe(wk.credential_issuer);
    const host = new URL(wk.credential_issuer).hostname;
    const det = [];
    // El JWKS se mira aparte: puede estar en la pasarela aunque el host del emisor
    // no exista, y una clave privada publicada es grave se resuelva o no el DID.
    const baseMeta = metadata_url.replace(/\/+$/, "").endsWith(WK) ? metadata_url.replace(/\/+$/, "").slice(0, -WK.length) : null;
    const jwksUrls = [...new Set([baseMeta && baseMeta + "/.well-known/jwks.json",
      !hostEmisorRoto && new URL(wk.credential_issuer).origin + "/.well-known/jwks.json"].filter(Boolean))];
    let jwks = null, jwksPrivado = false;
    for (const u of jwksUrls) {
      try {
        const r = await red.traer(u);
        const d = r.estado === 200 ? json(r.cuerpo) : null;
        if (Array.isArray(d?.keys)) {
          jwks = { url: u, claves: d.keys };
          const tipos = d.keys.map((k) => k.crv ? `${k.kty}/${k.crv}` : k.kty);
          jwksPrivado = d.keys.some((k) => PRIVADOS_JWK.some((p) => p in k));
          det.push(`JWKS en ${u}: ${d.keys.length ? plural(d.keys.length, "clave") + " (" + tipos.join(", ") + ")" : "publicado vacío"}` +
            (jwksPrivado ? " · ¡INCLUYE PARTES PRIVADAS!" : d.keys.length ? ", solo públicas" : ""));
          break;
        }
        // Un JWKS es opcional (el verificador usa el DID), pero si responde algo
        // raro se dice: el nuestro dio 503 con {"keys":[]} el 29-sep.
        if (r.estado !== 404) det.push(`JWKS en ${u} → ${r.estado}${r.estado === 200 ? " (no es un JWKS)" : ""}; es opcional, el verificador usa el DID`);
      } catch {}
    }
    const falloJwks = jwksPrivado ? resultado("did", FALLA, "El JWKS publicado incluye material de clave PRIVADA.",
      "Retírelo ya, genere claves nuevas y publique solo la parte pública (kty, crv, x, n, e).", det) : null;

    if (hostEmisorRoto) cs.did = falloJwks ?? resultado("did", PENDIENTE,
      `Depende de la comprobación 2: ${raiz} se resolvería en ${host}, que no resuelve.`,
      `Cuando ${host} exista, publique ahí /.well-known/did.json.`, det);
    else {
      const candidatos = [[raiz, urlDidWeb(raiz)], ...(conRuta ? [[conRuta, urlDidWeb(conRuta)]] : [])];
      let doc = null, did = null;
      for (const [d, u] of candidatos) {
        try {
          const r = await red.traer(u);
          const x = r.estado === 200 ? json(r.cuerpo) : null;
          det.push(`${u} → ${r.estado}${r.estado === 200 && !x ? " (no es JSON)" : ""}`);
          if (x) { doc = x; did = d; break; }
        } catch (e) { det.push(`${u} → ${e.message}`); }
      }
      if (!doc) cs.did = falloJwks ?? resultado("did", FALLA, `${raiz} no resuelve: no hay did.json en ${urlDidWeb(raiz)}.`,
        `Publique el documento DID en ${urlDidWeb(raiz)}.`, det);
      else {
        datos.did = did;
        const problemas = [], avisos = [];
        if (doc.id !== did) problemas.push(`el documento dice id «${doc.id}» y se esperaba «${did}»`);
        const vms = comoLista(doc.verificationMethod);
        const abs = (x) => (typeof x === "string" && x.startsWith("#") ? did + x : x);
        const ids = vms.map((m) => abs(m?.id)).filter(Boolean);
        if (!vms.length) problemas.push("no tiene verificationMethod");
        for (const m of vms) if (!m?.publicKeyMultibase && !m?.publicKeyJwk && !m?.publicKeyPem && !m?.publicKeyBase58)
          problemas.push(`el método ${m?.id ?? "sin id"} no publica clave`);
        const am = comoLista(doc.assertionMethod);
        if (!am.length) problemas.push("no tiene assertionMethod: ninguna clave está autorizada a firmar credenciales");
        for (const a of am) {
          if (typeof a === "string") {
            if (abs(a) === doc.id || abs(a) === did) problemas.push(`assertionMethod contiene el DID pelado («${a}») en lugar del id de una clave`);
            else if (!ids.includes(abs(a))) problemas.push(`assertionMethod apunta a «${a}», que no es ningún verificationMethod`);
          } else if (!a?.id) problemas.push("assertionMethod contiene un método sin id");
        }
        const tiposVm = vms.map((m) => m?.type).filter(Boolean);
        det.push(`${did}: ${plural(vms.length, "método")} (${tiposVm.join(", ") || "sin tipo"}), assertionMethod con ${am.length}`);
        const firmaEd = confs.some((c) => c.algoritmos.some((a) => /eddsa|ed25519/i.test(a)));
        if (firmaEd && !vms.some((m) => claveEd25519(m))) avisos.push("firma con EdDSA pero el DID no publica ninguna clave Ed25519");
        if (jwks?.claves.length) {
          const enDid = new Set(vms.map(huellaClave).filter(Boolean));
          const coinciden = jwks.claves.filter((k) => enDid.has(huellaClave(k)));
          if (!coinciden.length) avisos.push("ninguna clave del JWKS coincide con las del DID");
          else det.push(`${plural(coinciden.length, "clave")} del JWKS coincide${coinciden.length === 1 ? "" : "n"} con el DID`);
        }
        det.push(...problemas.map((p) => "✗ " + p), ...avisos.map((p) => "⚠ " + p));
        cs.did = falloJwks ?? (problemas.length
          ? resultado("did", FALLA, `${did} resuelve, pero ${problemas[0]}.`,
              problemas.some((p) => p.includes("DID pelado")) ? "Ponga en assertionMethod el id completo de la clave (did:web:…#clave), no el DID." : "Corrija el documento DID.", det)
          : avisos.length ? resultado("did", AVISO, `${did} resuelve y autoriza su clave, con una advertencia: ${avisos[0]}.`,
              "Publique la misma clave en el DID y en el JWKS.", det)
          : resultado("did", OK, `${did} resuelve y autoriza su clave en assertionMethod.`, null, det));
      }
    }
  }

  // 11. Orden de tipos y contextos ------------------------------------------------------
  // Pasó de verdad con MAP el 29-sep-2026: 10 de 10 aquí, token y datos bien, y la
  // descarga moría con «CredentialConfig not found» porque guardó los contextos con
  // el de W3C primero. Se ve en la metadata sin necesidad de ningún login.
  // Solo aplica a ldp_vc, que es donde Certify busca por tipos y contextos. El sort
  // por defecto de JS compara unidades UTF-16, igual que String.compareTo de Java.
  {
    const filas = [], sql = [];
    let alguna = false;
    for (const c of confs) {
      if (c.formato !== "ldp_vc") continue;
      alguna = true;
      const tipos = comoLista(c.cd.type), ctx = c.contextos;
      const malTipos = tipos.join(",") !== [...tipos].sort().join(",");
      const malCtx = ctx.join(",") !== [...ctx].sort().join(",");
      if (malTipos) filas.push(`${c.nombre}: tipos guardados como «${tipos.join(",")}»; Certify busca «${[...tipos].sort().join(",")}»`);
      if (malCtx) filas.push(`${c.nombre}: contextos guardados como «${ctx.join(",")}»; Certify busca «${[...ctx].sort().join(",")}»`);
      if (malTipos || malCtx) sql.push(`UPDATE certify.credential_config SET ${[
        malTipos && `credential_type = '${[...tipos].sort().join(",")}'`,
        malCtx && `context = '${[...ctx].sort().join(",")}'`].filter(Boolean).join(", ")} WHERE credential_config_key_id = '${c.nombre}';`);
    }
    cs.orden = !alguna ? resultado("orden", OK, "No hay credenciales ldp_vc: no aplica.")
      : !filas.length ? resultado("orden", OK, "Tipos y contextos están guardados en orden alfabético.")
      : resultado("orden", FALLA,
          "Tipos o contextos no están en orden alfabético: la descarga fallará con «CredentialConfig not found» después del login.",
          "Guarde credential_type y context en orden alfabético (la plantilla vc_template no se toca: ahí W3C sigue primero) y reinicie Certify, que guarda las plantillas en caché.",
          [...filas, ...sql.map((s) => `SQL sugerido: ${s}`)]);
  }
  return cerrar(cs, { metadata_url, inicio, datos });
}

function cerrar(cs, { metadata_url, inicio, datos }) {
  const comprobaciones = Object.keys(CATALOGO).map((id) => cs[id]);
  return { metadata_url, momento: Date.now(), duracion: Date.now() - inicio, veredicto: veredicto(comprobaciones), comprobaciones, datos };
}

export function veredicto(lista) {
  const n = (e) => lista.filter((c) => c.estado === e).length;
  const f = n(FALLA), a = n(AVISO), o = n(OK), p = n(PENDIENTE);
  const partes = [plural(f, "bloqueante"), plural(a, "advertencia"), plural(o, "resuelto")].concat(p ? [plural(p, "no evaluable", "no evaluables")] : []);
  const cabeza = f ? "No integrable todavía" : a ? "Integrable, con advertencias" : "Todo en orden";
  return { texto: `${cabeza}: ${partes.join(", ")}`, falla: f, aviso: a, ok: o, pendiente: p, integrable: f === 0 && p === 0 };
}

// =============================================================================
// La credencial de muestra (comprobación 11)
// =============================================================================
// Se procesa en memoria y se olvida. Quien llama no debe guardarla ni registrarla;
// aquí no se copia ningún VALOR del sujeto a la salida, solo nombres y recuentos.
export const MAX_MUESTRA = 64 * 1024;

export async function evaluarMuestra(texto, { red, base }) {
  const out = [];
  const pon = (id, estado, resumen, accion = null, detalles = []) => out.push(resultado(id, estado, resumen, accion, detalles));
  if (Buffer.byteLength(texto ?? "", "utf8") > MAX_MUESTRA) return { error: `La muestra supera ${MAX_MUESTRA / 1024} KB.` };
  let vc;
  try { vc = JSON.parse(texto); }
  catch (e) {
    // El mensaje de JSON.parse incluye un trozo del texto: no se reproduce.
    const pos = String(e.message).match(/position (\d+)/)?.[1];
    return { error: `No es JSON válido${pos ? ` (posición ${pos})` : ""}.` };
  }
  if (vc?.credential && typeof vc.credential === "object") vc = vc.credential;
  if (!vc || typeof vc !== "object" || Array.isArray(vc) || !vc["@context"] || !vc.proof)
    return { error: "No parece una credencial ldp_vc: le falta @context o proof." };

  const ctx = comoLista(vc["@context"]);
  const { cargar, vistos } = crearCargador(red);

  // a. El primer contexto.
  pon("m_contexto", ctx[0] === V1 || ctx[0] === V2 ? OK : FALLA,
    ctx[0] === V1 || ctx[0] === V2 ? `El primero es ${ctx[0]}.` : `El primero es «${typeof ctx[0] === "string" ? ctx[0] : "un objeto"}».`,
    ctx[0] === V1 || ctx[0] === V2 ? null : "Ponga https://www.w3.org/2018/credentials/v1 (o credentials/v2) el primero de la lista en la plantilla.",
    [`Contextos: ${ctx.map((c) => (typeof c === "string" ? c : "{en línea}")).join(", ")}`]);

  // b. El contexto de la suite.
  const proofs = comoLista(vc.proof);
  const p0 = proofs[0] ?? {};
  const suite = p0.type === "DataIntegrityProof" ? `DataIntegrityProof/${p0.cryptosuite ?? "?"}` : p0.type;
  if (p0.type === "Ed25519Signature2020") pon("m_suite", ctx.includes(ED2020) ? OK : FALLA,
    ctx.includes(ED2020) ? "Incluye el contexto de Ed25519Signature2020." : "Firma con Ed25519Signature2020 y no incluye su contexto.",
    ctx.includes(ED2020) ? null : `Añada ${ED2020} a los contextos de la plantilla.`);
  else if (p0.type === "DataIntegrityProof") pon("m_suite", ctx.includes(V2) ? OK : FALLA,
    ctx.includes(V2) ? "DataIntegrityProof está definido en credentials/v2." : "DataIntegrityProof necesita el contexto credentials/v2.",
    ctx.includes(V2) ? null : `Añada ${V2}.`);
  else pon("m_suite", PENDIENTE, `Suite ${suite ?? "desconocida"}: esta comprobación solo conoce Ed25519Signature2020 y DataIntegrityProof.`);

  // c y d. Cobertura real y cuádruplas de la prueba.
  const { proof, ...sinProof } = vc;
  let canonDoc = null, errorCanon = null;
  try {
    canonDoc = await canonizarDocumento(sinProof, { cargar });
    const sujetos = comoLista(vc.credentialSubject);
    const nombres = [...new Set(sujetos.flatMap((s) => Object.keys(s ?? {})).filter((k) => k !== "id" && k !== "type"))];
    const caidos = [...new Set(canonDoc.descartados.filter((d) => d.en === "credentialSubject" || nombres.includes(d.termino)).map((d) => d.termino))];
    const otros = [...new Set(canonDoc.descartados.map((d) => d.termino).filter((t) => !caidos.includes(t)))];
    pon("m_cobertura", caidos.length ? FALLA : OK,
      `${nombres.length - caidos.length} de ${nombres.length} atributos de credentialSubject firmados.`,
      caidos.length ? "Defina esos atributos en el @context, con el mismo nombre, en una URL nueva." : null,
      [caidos.length ? `No firmados: ${caidos.join(", ")}` : null,
       otros.length ? `Fuera de credentialSubject también se descartan: ${otros.join(", ")}` : null,
       `El documento sin la prueba da ${plural(canonDoc.cuads.length, "cuádrupla")} RDF.`]);
  } catch (e) {
    errorCanon = e;
    pon("m_cobertura", FALLA, `No se pudo expandir la credencial: ${e.message}.`,
      "Revise que todos sus contextos se puedan descargar y sean compatibles entre sí.");
  }
  let canonProof = null;
  const opciones = { ...p0 }; delete opciones.proofValue; delete opciones.jws;
  try {
    const r = await canonizarDocumento({ "@context": vc["@context"], ...opciones }, { cargar });
    canonProof = r.nquads;
    // Cuádruplas del grafo de la prueba dentro de la credencial completa.
    const todo = await canonizarDocumento(vc, { cargar });
    const enGrafo = todo.cuads.filter((q) => q.g).length;
    const minimas = 4;
    pon("m_prueba", r.cuads.length >= minimas ? OK : FALLA,
      `Las opciones de la prueba dan ${plural(r.cuads.length, "cuádrupla")} firmable${r.cuads.length === 1 ? "" : "s"}; ${enGrafo} en el grafo de la prueba de la credencial.`,
      r.cuads.length >= minimas ? null : "Incluya el contexto de la suite: sin él el tipo de prueba y sus campos no se definen.",
      [r.descartados.length ? `Campos de la prueba sin definir: ${[...new Set(r.descartados.map((d) => d.termino))].join(", ")}` : null]);
  } catch (e) { pon("m_prueba", FALLA, `No se pudo expandir la prueba: ${e.message}.`); }

  // e. El emisor.
  const issuer = typeof vc.issuer === "string" ? vc.issuer : vc.issuer?.id;
  const esperado = base?.datos?.did ?? (base?.datos?.credential_issuer ? didWebDe(base.datos.credential_issuer).raiz : null);
  pon("m_emisor", !esperado ? PENDIENTE : issuer === esperado ? OK : AVISO,
    !esperado ? `issuer: ${issuer ?? "ausente"}; no hay DID del emisor registrado con el que compararlo.`
      : issuer === esperado ? `issuer es ${esperado}.` : `issuer es «${issuer ?? "ausente"}» y el emisor registrado es ${esperado}.`,
    issuer === esperado || !esperado ? null : "Emita con el DID del emisor, el que resuelve en su host.");

  // f. La firma.
  const vmId = p0.verificationMethod;
  const soportada = p0.type === "Ed25519Signature2020" || (p0.type === "DataIntegrityProof" && p0.cryptosuite === "eddsa-rdfc-2022");
  if (!soportada) pon("m_firma", PENDIENTE, `La verificación de ${suite ?? "esta suite"} no está implementada aquí (solo Ed25519Signature2020 y eddsa-rdfc-2022).`);
  else if (proofs.length > 1) pon("m_firma", PENDIENTE, "La credencial trae varias pruebas; solo se verifica una sola.");
  else if (errorCanon || !canonDoc || canonProof === null) pon("m_firma", PENDIENTE, "No se puede verificar sin expandir la credencial (ver arriba).");
  else {
    try {
      const didVm = String(vmId ?? "").split("#")[0];
      let docDid = null;
      if (didVm.startsWith("did:key:")) {
        const clave = didVm.slice(8);
        docDid = { id: didVm, verificationMethod: [{ id: `${didVm}#${clave}`, publicKeyMultibase: clave }], assertionMethod: [`${didVm}#${clave}`] };
      } else if (urlDidWeb(didVm)) {
        const r = await red.traer(urlDidWeb(didVm));
        docDid = r.estado === 200 ? json(r.cuerpo) : null;
        if (!docDid) throw new Error(`${urlDidWeb(didVm)} responde ${r.estado}`);
      } else throw new Error(`método DID no soportado: ${didVm.split(":").slice(0, 2).join(":") || "ausente"}`);
      const abs = (x) => (typeof x === "string" && x.startsWith("#") ? didVm + x : x);
      const vm = comoLista(docDid.verificationMethod).find((m) => abs(m?.id) === vmId)
        ?? comoLista(docDid.assertionMethod).find((m) => typeof m === "object" && abs(m?.id) === vmId);
      if (!vm) throw new Error(`la clave ${vmId} no está en el documento DID`);
      const pub = claveEd25519(vm);
      if (!pub) throw new Error("la clave no es Ed25519");
      const autorizada = p0.proofPurpose === "assertionMethod" &&
        comoLista(docDid.assertionMethod).some((a) => abs(typeof a === "string" ? a : a?.id) === vmId);
      const sha = (s) => createHash("sha256").update(s, "utf8").digest();
      const datosFirma = Buffer.concat([sha(canonProof), sha(canonDoc.nquads)]);
      const firma = multibase(p0.proofValue);
      const clave = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub.toString("base64url") }, format: "jwk" });
      const valida = firma.length === 64 && verificarFirma(null, datosFirma, clave, firma);
      pon("m_firma", valida && autorizada ? OK : FALLA,
        valida && autorizada ? "Firma válida, con una clave autorizada en assertionMethod."
          : !valida ? "La firma NO verifica." : "La firma verifica, pero la clave no está autorizada en assertionMethod.",
        valida && autorizada ? null : !valida
          ? "Si la credencial se editó después de emitirla, la firma no puede verificar: envíe una tal como sale del emisor."
          : "Ponga el id de la clave en assertionMethod del DID.",
        [`Clave: ${vmId}`, `Propósito: ${p0.proofPurpose ?? "ausente"}`,
         // Una firma válida solo protege lo que quedó en el RDF. Si se descartaron
         // atributos, se podrían cambiar sin que la firma se entere.
         valida && canonDoc.descartados.length
           ? `Ojo: la firma es válida pero NO cubre ${[...new Set(canonDoc.descartados.map((d) => d.termino))].join(", ")}: se pueden cambiar sin romperla` : null]);
    } catch (e) { pon("m_firma", FALLA, `No se pudo verificar: ${e.message}.`); }
  }
  return { comprobaciones: out, veredicto: veredicto(out), bytes: Buffer.byteLength(texto, "utf8") };
}
