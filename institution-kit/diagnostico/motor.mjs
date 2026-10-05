// El motor del diagnóstico: once comprobaciones sobre la metadata de un emisor,
// más la evaluación opcional de una credencial de muestra (11a-f) y, a partir de
// ella, la comprobación 12 (la lista de estado). Lo usan el servidor
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
import { gunzipSync, inflateSync, inflateRawSync, brotliDecompressSync } from "node:zlib";
import { expandir, aRdf, canonizar, canonizarDocumento, ErrorJsonLd } from "./jsonld.mjs";

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
  bsl: ["Bitstring Status List v1.0", "https://www.w3.org/TR/vc-bitstring-status-list/"],
  bslTam: ["Bitstring Status List — codificación del bitstring y tamaño mínimo (privacidad de grupo)", "https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-encoding"],
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
  // La 12 no sale de la metadata: parte de la credencial de muestra, porque la dirección
  // de la lista solo se conoce desde su `credentialStatus`. `deMuestra` la deja fuera de
  // diagnosticar() (que sigue devolviendo las once) y la evalúa evaluarMuestra().
  estado: { n: 12, deMuestra: true, titulo: "La lista de estado (revocación) es conforme a lo que exige la app",
    porque: "Cuando la credencial declara `credentialStatus`, la app descarga la lista de estado del emisor para saber si fue anulada, y si la lista no cumple lo que su verificador exige (la firma el mismo emisor con Ed25519Signature2020, está vigente, se sirve por https sin redirecciones y tiene el formato correcto) muestra la credencial como «no comprobada». Se evalúa con la credencial de muestra, porque solo ahí se conoce la dirección de la lista. Lo que W3C recomienda y la app tolera (declarar el type BitstringStatusListCredential, al menos 131 072 bits) sale como advertencia, no como fallo.",
    refs: refs("bsl", "bslTam", "vc20", "rfc9111") },
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
// Las once comprobaciones de la metadata (la 12 sale de la muestra: ver más abajo)
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
    for (const [id, c] of Object.entries(CATALOGO)) if (id !== "metadata" && !c.deMuestra) cs[id] = pendienteDe(id, 1, "sin metadata no se puede evaluar");
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
  const comprobaciones = Object.keys(CATALOGO).filter((id) => !CATALOGO[id].deMuestra).map((id) => cs[id]);
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

// Verifica la prueba Ed25519 de un documento ya canonicalizado: resuelve el DID del
// método de verificación, busca la clave, comprueba que esté en assertionMethod y
// verifica la firma (SHA-256 de las opciones + SHA-256 del documento, Ed25519).
// La usan la comprobación de firma de la muestra (11f) y la de la lista de estado
// (12): una sola implementación. Lanza con el motivo si no se puede verificar.
async function verificarPruebaEd25519(p0, canonProof, canonNquads, red) {
  const vmId = p0.verificationMethod;
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
  const datosFirma = Buffer.concat([sha(canonProof), sha(canonNquads)]);
  const firma = multibase(p0.proofValue);
  const clave = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub.toString("base64url") }, format: "jwk" });
  const valida = firma.length === 64 && verificarFirma(null, datosFirma, clave, firma);
  return { valida, autorizada };
}

export async function evaluarMuestra(texto, { red, base, ahora }) {
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
      const { valida, autorizada } = await verificarPruebaEd25519(p0, canonProof, canonDoc.nquads, red);
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
  // g. La lista de estado (comprobación 12). Va APARTE de `comprobaciones` y de su
  // veredicto: las seis de arriba (11a-f) no cambian, y una muestra sin credentialStatus
  // (R1) no las vuelve «no evaluables». Quien enseña el resultado suma las dos
  // (veredictoMuestra). Nada del sujeto de la muestra entra en este resultado.
  const estado = await comprobarListaDeEstado(vc, red, { cargar, ...(ahora === undefined ? {} : { ahora }) });
  return { comprobaciones: out, veredicto: veredicto(out), estado, bytes: Buffer.byteLength(texto, "utf8") };
}

// =============================================================================
// Comprobación 12: la lista de estado (revocación) es conforme a lo que exige la app
// =============================================================================
// PROCEDENCIA. Las reglas están copiadas de la app (no las inventa este fichero), de DOS sitios:
//   1. carpeta-ciudadana-mobile/src/vc/js/statusListChecker.ts (PR #395, MOB-40; repositorio en
//      f2a092e3, último commit del fichero 05a22d10; copiadas el 2026-10-04): lo que decide si
//      la lista vale (tipo de entrada, URL, descarga, issuer, vigencia, encodedList, índice) y cómo
//      se combinan varias entradas.
//   2. carpeta-ciudadana-mobile/src/vc/js/verifyCredential.ts y `_checkCredential` de
//      `@digitalcredentials/vc` (lib/index.js y lib/helpers.js), más la suite
//      (`lib/suites/ed255192020/Ed25519Signature2020.ts`, `Ed25519VerificationKey2020.ts`) y el propósito de la
//      prueba (`lib/purposes/ControllerProofPurpose.ts`): lo que el VERIFICADOR de la app exige de la lista
//      y de la clave que la firma ANTES de darla por firmada. El primero llama al segundo (`verifySignature`),
//      así que una lista que el verificador rechaza es «no comprobado» aunque cumpla el primero. La evaluación
//      adversarial (C1-C5, C11, 2026-10-04) encontró que la 12 solo copiaba el primero. Desde entonces
//      `test/paridad-app.test.mjs` corre los ficheros REALES de la app contra la 12 en cada caso.
//   Si la app cambia sus reglas y esto no, una institución recibiría un aviso falso (o dejaría de
//   recibir uno verdadero): al tocar el comprobador o el verificador de la app hay que revisar este
//   bloque, y la prueba de paridad lo dirá si se olvida.
// Qué se copia y qué NO:
//   - Se copia lo que la app RECHAZA (FALLA): tipo de la entrada; URL https de dominio público;
//     descarga sin redirecciones, con tope de 2 MiB (ya descomprimido) y 5 s; la prueba de la lista como
//     OBJETO, de una suite que la app verifica, con `verificationMethod` que la app encuentra (un
//     `did:key` pelado, sin fragmento, no), `created` que sea una fecha, `proofValue` en base58 y un
//     `proofPurpose` que la app entienda; la clave en el documento DID tal como la lee la app (solo
//     `publicKeyMultibase`, sin `revoked`, con `controller`, autorizada en `assertionMethod` por su id o
//     por el DID a secas); primer @context de W3C, `type` con VerifiableCredential,
//     `credentialSubject.id` URI, `credentialStatus`/`evidence`/`termsOfUse` con `type`, `issuanceDate`
//     en VC 1.1, fechas con hora; la firma; issuer y verificationMethod del mismo emisor; vigencia de
//     la raíz y del sujeto; tipo y propósito; `statusSize`; `encodedList`; índice dentro de rango.
//   - Lo que la app TOLERA y W3C recomienda es AVISO, no FALLA: `type` raíz sin
//     BitstringStatusListCredential y menos de 131 072 bits (la app solo lo anota en su log).
//   - Lo que depende del teléfono es AVISO: una fecha-hora sin zona en un campo que la librería de la app
//     lee en hora LOCAL (statusListChecker la lee como UTC; la librería, no).
//   - Lo que el diagnóstico no puede decidir es PENDIENTE, y solo si todo lo demás está bien: firmas
//     Ed25519Signature2018 o RsaSignature2018 (la app las verifica, el diagnóstico no) y JSON-LD que el
//     canonicalizador del diagnóstico no cubre (@nest, @reverse…; la app usa jsonld.js completo), una clave
//     cuyo `controller` es otro DID (la app resolvería ese documento, el diagnóstico no lo sigue), un
//     documento DID sin el contexto de DID v1 (la app lo reinterpreta con JSON-LD) y `proofPurpose: publicKey`.
//
// ORDEN dentro de la comprobación, y por qué. El primer fallo manda:
//   entrada y URL -> descarga y cuerpo -> prueba (objeto, suite, verificationMethod, proofPurpose, proofValue,
//   created) -> reglas del verificador sobre la lista -> tipo, propósito y statusSize -> issuer y
//   verificationMethod del emisor -> firma (documento DID, clave, controller) -> vigencia y fechas ->
//   encodedList -> índice y bit.
//   Lo barato y que no necesita criptografía va antes de canonicalizar; el issuer va ANTES de la firma
//   porque verificar la firma de una lista ajena puede significar resolver el did:web que ella misma
//   declara (C14: eso es una petición hacia donde diga el documento de otro); y de la firma en adelante
//   el orden es el de la app, para que el primer motivo que se enseña sea el que la app daría.
// COSTE. Todo lo que sube la institución tiene tope: como mucho 5 entradas (las demás, AVISO), una
//   descarga y una canonicalización por lista distinta, y un plazo global de 15 s para toda la 12
//   (también dentro de la canonicalización, que no cede el hilo).
// PRIVACIDAD. Aquí no se copia NADA del credentialSubject de la muestra: solo el `issuer`, los campos
//   de `credentialStatus` (tipo, propósito, URL de la lista e índice) y lo que dice la propia lista.
//   Todo texto ajeno que se cita pasa por `citar`.
export const ESTADO_MAX_RESPUESTA = 2 * 1024 * 1024;
export const ESTADO_MAX_DECODIFICADA = 8 * 1024 * 1024;
export const ESTADO_ESPERA_MS = 5000;
export const ESTADO_MIN_BITS = 131072;
export const ESTADO_MAX_ENTRADAS = 5;
export const ESTADO_PLAZO_MS = 15_000;
// Lo que puede tardar CADA canonicalización de la lista. Una lista de estado de verdad canonicaliza en
// milisegundos; la canonicalización no cede el hilo, así que lo que pase de aquí es un documento hecho para
// colgar el proceso (nodos en blanco indistinguibles: factorial; una cadena de 500: 7 s) y todas las
// instituciones comparten ese proceso. Más corto que el plazo global a propósito.
export const ESTADO_CANON_MS = 2000;
const DIA_MS = 86_400_000;
const TREINTA_DIAS_MS = 30 * DIA_MS;
export const TOTAL_COMPROBACIONES = Object.keys(CATALOGO).length;

const citar = (v, n = 80) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);
const bits = (n) => String(n).replace(/\B(?=(\d{3})+(?!\d))/g, " ");
const identificador = (v) => (typeof v === "string" && v ? v : typeof v?.id === "string" && v.id ? v.id : null);
const propositoDe = (e) => (e && typeof e === "object" && !Array.isArray(e) && typeof e.statusPurpose === "string" && e.statusPurpose !== "" ? e.statusPurpose.toLowerCase() : null);
const MIB = (n) => `${n / 1024 / 1024} MiB`;
const esObjeto = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const segundos = (ms) => { const s = ms / 1000; return `${Number.isInteger(s) ? s : String(s).replace(".", ",")} s`; };
// Un URI como lo entiende `_validateUriId` de la librería de la app: lo que `new URL` acepta.
const esUri = (v) => { try { new URL(v); return true; } catch { return false; } };

// --- la URL de la lista (statusListChecker.ts: parseHttpsUrl, isPublicHostname) -----
const URL_HTTPS = /^https:\/\/([^/?#@]+)(?:[/?#]|$)/i;
const URL_PROHIBIDOS = /[\u0000- \u007f\\]/;
const ETIQUETA_NUMERICA = /^(\d+|0x[0-9a-f]*)$/i;
// Devuelve el motivo por el que la app NO pediría esa URL, o null si la pide.
export function motivoUrlDeLista(valor) {
  if (typeof valor !== "string" || !valor) return "la entrada no trae statusListCredential";
  if (URL_PROHIBIDOS.test(valor)) return "la URL tiene espacios, caracteres de control o barras invertidas";
  const autoridad = URL_HTTPS.exec(valor)?.[1];
  if (!autoridad) return /^https:\/\//i.test(valor) ? "la URL no es válida (¿lleva usuario o clave?)" : "la URL no es https";
  const partes = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(autoridad);
  if (!partes) return "la URL no es válida";
  const host = partes[1].toLowerCase().replace(/\.$/, "");
  const puerto = (partes[2] ?? "") === "" ? 443 : Number(partes[2]);
  if (!Number.isInteger(puerto) || puerto > 65535) return "el puerto no es válido";
  if (host.startsWith("[")) return "el host es una dirección IP (IPv6), no un nombre de dominio";
  if (!/^[a-z0-9.-]+$/.test(host)) return `el host «${citar(host, 60)}» no es un nombre de dominio ASCII`;
  const etiquetas = host.split(".");
  if (etiquetas.length === 1 && ETIQUETA_NUMERICA.test(host)) return "el host es una dirección IP, no un nombre de dominio";
  if (etiquetas.length < 2 || etiquetas.some((e) => e === "")) return `el host «${citar(host, 60)}» no es un nombre de dominio público (localhost o nombre de red interna)`;
  const sufijo = etiquetas[etiquetas.length - 1];
  if (ETIQUETA_NUMERICA.test(sufijo)) return "el host es una dirección IP, no un nombre de dominio";
  if (["local", "internal", "localhost"].includes(sufijo)) return `el host «${citar(host, 60)}» es de una red interna (.${sufijo})`;
  return null;
}

// --- fechas (statusListChecker.ts: parseListDate, assertWithinValidity; helpers.js: dateRegex) -----
// Una fecha-hora sin zona la lee statusListChecker como UTC; Date.parse la leería en hora local. La
// librería de la app (`new Date(...)` en `_checkCredential`) SÍ la lee en hora local: por eso es AVISO.
const FECHA_SIN_ZONA = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/;
const fechaDeLista = (v) => { const t = String(v); return Date.parse(FECHA_SIN_ZONA.test(t) ? `${t}Z` : t); };
// El `dateRegex` de @digitalcredentials/vc (lib/helpers.js), igual de laxo que el original: SIN anclar y con `.` donde
// él escribe «\.» dentro de una cadena JS (que es un punto cualquiera). Exige la hora completa; la zona es opcional.
const FECHA_COMPLETA = /-?([1-9][0-9]{3,}|0[0-9]{3})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T(([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](.[0-9]+)?|(24:00:00(.0+)?))(Z|(\+|-)((0[0-9]|1[0-3]):[0-5][0-9]|14:00))?/;
const SOLO_DIA = /^\d{4}-\d{2}-\d{2}$/;
// Motivo por el que `fuente` no cubre `ahora`, o null.
function motivoDeVigencia(fuente, desde, hasta, ahora, donde) {
  for (const campo of desde) {
    const v = fuente[campo];
    if (v === undefined || v === null || v === "") continue;
    const t = fechaDeLista(v);
    if (Number.isNaN(t)) return `${donde}.${campo} no es una fecha válida («${citar(v, 40)}»)`;
    if (ahora < t) return `${donde}.${campo} es ${citar(v, 40)}: todavía no es vigente`;
  }
  for (const campo of hasta) {
    const v = fuente[campo];
    if (v === undefined || v === null || v === "") continue;
    const t = fechaDeLista(v);
    if (Number.isNaN(t)) return `${donde}.${campo} no es una fecha válida («${citar(v, 40)}»)`;
    if (ahora > t) return `${donde}.${campo} es ${citar(v, 40)}: ya venció`;
  }
  return null;
}
// Las fechas que la librería de la app comprueba de la raíz de la lista, según su versión del modelo
// (primer @context): VC 1.1, `issuanceDate` (obligatoria) y `expirationDate` si la lista trae la clave;
// VC 2.0, `validUntil` y `validFrom` si tienen valor. El resto (p. ej. `validFrom` en una lista 1.1) solo
// lo mira statusListChecker, que acepta cualquier fecha que `Date.parse` entienda.
function fechasDeLaLibreria(lista, v1) {
  if (v1) return ["issuanceDate", ...("expirationDate" in lista ? ["expirationDate"] : [])];
  return ["validUntil", "validFrom"].filter((c) => lista[c]);
}

// --- encodedList (statusListChecker.ts: decodeEncodedList, gunzipBounded) -------------
// base64url (con o sin el prefijo multibase `u`) y gzip. El tope de salida de
// zlib hace de freno contra una bomba de descompresión.
function decodificarLista(encodedList) {
  const sinPrefijo = encodedList.startsWith("u") ? encodedList.slice(1) : encodedList;
  if (!/^[A-Za-z0-9_-]*$/.test(sinPrefijo)) return { error: "no es base64url" };
  let bytes;
  try { bytes = gunzipSync(Buffer.from(sinPrefijo, "base64url"), { maxOutputLength: ESTADO_MAX_DECODIFICADA }); }
  catch (e) {
    if (e?.code === "ERR_BUFFER_TOO_LARGE") return { error: `descomprimida pasa de ${MIB(ESTADO_MAX_DECODIFICADA)}` };
    return { error: "no es un gzip válido" };
  }
  if (!bytes.length) return { error: "no es un gzip válido (sin contenido)" };
  return { bytes };
}

function parsearIndice(raw) {
  if (typeof raw === "number") { if (Number.isSafeInteger(raw) && raw >= 0) return { indice: raw }; }
  else if (typeof raw === "string" && /^\d+$/.test(raw)) {
    const n = Number(raw);
    return Number.isSafeInteger(n) ? { indice: n } : { fuera: true };
  }
  return { invalido: true };
}

const duracion = (ms) => ms % DIA_MS === 0 ? `${ms / DIA_MS} d` : ms % 3_600_000 === 0 ? `${ms / 3_600_000} h` : ms >= 1000 && ms % 1000 === 0 ? `${ms / 1000} s` : `${ms} ms`;

// --- el cuerpo de la respuesta (lo que hace `fetch` en la app) ---------------------------
// `fetch` descomprime `Content-Encoding` (gzip, deflate, br) aunque el cliente no lo pida, y la app lo lee con
// `TextDecoder`, que quita un BOM UTF-8 inicial. Un servidor con gzip estático, o un S3 con el metadato de
// compresión, responde así (C8, C9). red.mjs entrega los bytes tal cual; aquí se deshacen con el mismo tope
// que la app aplica al cuerpo ya descomprimido.
const CODIFICACIONES = { gzip: gunzipSync, "x-gzip": gunzipSync, deflate: (b, o) => { try { return inflateSync(b, o); } catch { return inflateRawSync(b, o); } }, br: brotliDecompressSync };
function descomprimirCuerpo(cuerpo, codificacion) {
  const tokens = String(codificacion ?? "").toLowerCase().split(",").map((t) => t.trim()).filter((t) => t && t !== "identity");
  let bytes = cuerpo;
  for (const t of tokens.reverse()) {
    const f = CODIFICACIONES[t];
    if (!f) return { bytes, sinEntender: t }; // una codificación que fetch tampoco entiende: se deja tal cual
    try { bytes = f(bytes, { maxOutputLength: ESTADO_MAX_RESPUESTA + 1 }); }
    catch (e) { return { error: e?.code === "ERR_BUFFER_TOO_LARGE" ? "grande" : "ilegible", codificacion: t }; }
  }
  return { bytes };
}
function jsonDeCuerpo(bytes) {
  let t = bytes.toString("utf8");
  if (t.charCodeAt(0) === 0xfeff) t = t.slice(1);
  try { return JSON.parse(t); } catch { return null; }
}

// --- la clave y el documento DID, como los lee la app ------------------------------------
// Copia de la lógica de la app, no de la 11f (que tiene la suya y no cambia): `buscarClave` y `getVerificationMethod`
// de Ed25519Signature2020.ts, `Ed25519VerificationKey2020.decodificarClave` y `ControllerProofPurpose.validate`
// (con `isAuthorizedVerificationMethodEntry`). Lo encontró la prueba de paridad, no la evaluación adversarial: la
// versión anterior comprobaba la firma con la lógica de la 11f, que acepta cosas que la app no (una clave en
// publicKeyJwk, una clave `revoked`, un `controller` ausente o de otro DID, ids relativos que no casan) y rechaza
// una que la app sí admite (`assertionMethod` con solo el DID).
const DID_V1 = "https://www.w3.org/ns/did/v1";
function buscarClaveDeLaApp(documento, vmId) {
  if (!esObjeto(documento)) return null;
  const fragmento = vmId.includes("#") ? `#${vmId.split("#")[1]}` : null;
  const candidatos = [...(Array.isArray(documento.verificationMethod) ? documento.verificationMethod : []),
    ...(Array.isArray(documento.assertionMethod) ? documento.assertionMethod : [])].filter((e) => e && typeof e === "object");
  return candidatos.find((e) => e.id === vmId)
    ?? (fragmento ? candidatos.find((e) => typeof e.id === "string" && e.id.endsWith(fragmento)) : undefined) ?? null;
}
// `publicKeyMultibase` en base58-btc con el multicodec de Ed25519 (0xed01) y 32 bytes; lanza si no.
function claveDeLaApp(publicKeyMultibase) {
  if (typeof publicKeyMultibase !== "string" || !publicKeyMultibase || publicKeyMultibase[0] !== "z") throw new Error("no es multibase base58-btc");
  const bytes = b58(publicKeyMultibase.slice(1));
  if (bytes[0] !== 0xed || bytes[1] !== 0x01 || bytes.length - 2 !== 32) throw new Error("no es una clave Ed25519");
  return bytes.subarray(2);
}
const idListado = (e) => (typeof e === "string" ? e : esObjeto(e) && typeof e.id === "string" ? e.id : null);
// `isAuthorizedVerificationMethodEntry`: la entrada es el id de la clave, o un DID a secas del que la clave cuelga.
const autorizaLaApp = (entrada, idClave) => { const l = idListado(entrada); return l !== null && (l === idClave || (!l.includes("#") && String(idClave).startsWith(`${l}#`))); };

// Devuelve { ok: true }, o { fin: { estado: FALLA | PENDIENTE, resumen, accion } }.
async function verificarPruebaComoLaApp({ p0, vmId, canonPrueba, canonLista, red }) {
  const ACCION_DID = "Publique el DID del emisor con la clave que firma la lista (publicKeyMultibase, controller y assertionMethod).";
  const falla = (resumen, accion = ACCION_DID) => ({ fin: { estado: FALLA, resumen, accion } });
  const noSigue = (resumen) => ({ fin: { estado: PENDIENTE, resumen, accion: null } });
  const didVm = vmId.split("#")[0];
  let doc;
  if (didVm.startsWith("did:key:")) {                    // como buildDidKeyDocument de DidResolver.ts
    const huella = didVm.slice(8), idClave = `${didVm}#${huella}`;
    doc = { "@context": DID_V1, id: didVm, verificationMethod: [{ id: idClave, type: "Ed25519VerificationKey2020", controller: didVm, publicKeyMultibase: huella }],
      assertionMethod: [idClave], authentication: [idClave] };
  } else if (didVm.startsWith("did:web:")) {
    let url;
    try { url = urlDidWeb(didVm); } catch { url = null; }
    if (!url) return falla(`No se pudo verificar la firma de la lista: el did:web ${citar(didVm, 100)} no es válido.`);
    const r = await red.traer(url);
    if (r.estado < 200 || r.estado >= 300) return falla(`No se pudo verificar la firma de la lista: ${citar(url, 160)} responde ${r.estado}.`);
    const des = descomprimirCuerpo(r.cuerpo, cabecera(r, "content-encoding"));
    doc = des.error ? null : jsonDeCuerpo(des.bytes);
    if (!esObjeto(doc)) return falla(`No se pudo verificar la firma de la lista: ${citar(url, 160)} no sirve un documento JSON.`);
  } else return falla(`No se pudo verificar la firma de la lista: método DID no soportado: ${citar(didVm.split(":").slice(0, 2).join(":") || "ausente", 40)}.`);

  const clave = buscarClaveDeLaApp(doc, vmId);
  if (!clave) return falla(`No se pudo verificar la firma de la lista: la clave ${citar(vmId, 140)} no está en el documento DID.`);
  if (clave.revoked !== undefined) return falla(`La clave que firma la lista figura como revocada en el documento DID (revoked): la app no la usa ${NO_COMPROBADO}.`,
    "Firme la lista con una clave vigente del DID del emisor, o quite «revoked» si la clave no está revocada.");
  let pub;
  try { pub = claveDeLaApp(clave.publicKeyMultibase); }
  catch { return falla(`La clave ${citar(vmId, 140)} del documento DID no trae un publicKeyMultibase en base58 (z…) con el prefijo de Ed25519: la app solo lee ese formato (no publicKeyJwk) ${NO_COMPROBADO}.`,
    "Publique la clave como publicKeyMultibase (z6Mk…), de tipo Ed25519VerificationKey2020."); }

  // La firma: SHA-256 de las opciones de la prueba + SHA-256 de la lista, Ed25519 (la misma de la 11f).
  let firma = null;
  try { firma = b58(p0.proofValue.slice(1)); } catch { /* base58 mal escrito: no verifica */ }
  const sha = (t) => createHash("sha256").update(t, "utf8").digest();
  const clavePublica = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: pub.toString("base64url") }, format: "jwk" });
  const valida = firma !== null && firma.length === 64 && verificarFirma(null, Buffer.concat([sha(canonPrueba), sha(canonLista)]), clavePublica, firma);
  if (!valida) return falla("La firma de la lista no verifica: la app mostrará «no comprobado».",
    "Si la lista se editó después de firmarla, la firma no puede verificar: vuelva a firmarla tal como la publica el emisor.");

  // Quién autoriza la clave (ControllerProofPurpose.validate): el documento de su `controller`.
  const c = clave.controller;
  const controllerId = typeof c === "string" ? c : esObjeto(c) && typeof c.id === "string" ? c.id : null;
  if (!controllerId) return falla(`La clave del documento DID no declara controller: la app lo necesita para comprobar que está autorizada ${NO_COMPROBADO}.`,
    "Añada controller (el DID del emisor) a la clave en el documento DID.");
  if (controllerId !== didVm) return noSigue(`La clave declara como controller a «${citar(controllerId, 100)}», que no es su propio DID: la app resolvería ese documento y el diagnóstico no lo sigue, así que no puede decir si la acepta.`);
  const ctxDid = doc["@context"];
  if (!(ctxDid === DID_V1 || (Array.isArray(ctxDid) && ctxDid[0] === DID_V1))) {
    // La app, si el documento no empieza por el contexto de DID v1, lo reinterpreta con JSON-LD (frame) y lee de ahí la lista de claves.
    if (ctxDid === undefined || ctxDid === null) return falla(`El documento DID del emisor no declara @context (${DID_V1}): la app no puede leer sus claves ${NO_COMPROBADO}.`,
      `Ponga ${DID_V1} como primer @context del documento DID.`);
    if (!comoLista(ctxDid).includes(DID_V1)) return noSigue("El documento DID del emisor declara un @context sin el de DID v1: la app lo reinterpreta con JSON-LD y el diagnóstico no, así que no puede decir si la acepta.");
  }
  if (!comoLista(doc.assertionMethod).some((e) => autorizaLaApp(e, clave.id))) return falla(
    "La firma de la lista verifica, pero la clave no está autorizada en assertionMethod del DID.",
    "Ponga el id de la clave que firma la lista en assertionMethod del documento DID.");
  return { ok: true };
}

// --- lo que el verificador de la app exige de la lista antes de mirar la firma ----------
// (`_checkCredential` de @digitalcredentials/vc, lib/index.js). Devuelve { resumen, accion } o null.
const NO_COMPROBADO = "y mostrará «no comprobado»";
function reglasDelVerificador(lista) {
  const sujeto = lista.credentialSubject;
  const ctx = lista["@context"];
  if (!Array.isArray(ctx)) return { resumen: `El @context de la lista no es una lista: la app necesita una lista cuyo primer elemento sea el de W3C ${NO_COMPROBADO}.`,
    accion: `Escriba el @context como lista y ponga ${V2} (o ${V1}) el primero.` };
  if (ctx[0] !== V1 && ctx[0] !== V2) return { resumen: `El primer @context de la lista es «${typeof ctx[0] === "string" ? citar(ctx[0], 100) : "un objeto"}», no el de W3C (${V2} o ${V1}): la app lo exige ${NO_COMPROBADO}.`,
    accion: `Ponga ${V2} el primero de la lista de @context.` };
  if (!lista.type) return { resumen: `La lista no declara type: la app lo exige ${NO_COMPROBADO}.`,
    accion: "Declare type: [\"VerifiableCredential\", \"BitstringStatusListCredential\"] en la lista." };
  if (!comoLista(lista.type).includes("VerifiableCredential")) return { resumen: `El type de la lista no incluye VerifiableCredential: la app lo exige ${NO_COMPROBADO}.`,
    accion: "Declare type: [\"VerifiableCredential\", \"BitstringStatusListCredential\"] en la lista." };
  if (!esObjeto(sujeto)) return { resumen: "La lista no tiene credentialSubject: la app no puede leerla.", accion: "Publique la lista con credentialSubject de tipo BitstringStatusList.", sinSujeto: true };
  if (!Object.keys(sujeto).length) return { resumen: `credentialSubject de la lista está vacío: la app lo rechaza ${NO_COMPROBADO}.`, accion: "Publique la lista con credentialSubject de tipo BitstringStatusList y su encodedList." };
  if (sujeto.id && !esUri(sujeto.id)) return { resumen: `credentialSubject.id de la lista («${citar(sujeto.id, 60)}») no es un URI: la app lo rechaza ${NO_COMPROBADO}.`,
    accion: "Quite credentialSubject.id o escríbalo como URI (p. ej. https://… o urn:uuid:…)." };
  if (ctx[0] === V1) {
    if (!lista.issuanceDate) return { resumen: `La lista es VC 1.1 (credentials/v1) y no trae issuanceDate: la app lo exige ${NO_COMPROBADO}.`,
      accion: "Añada issuanceDate (AAAA-MM-DDThh:mm:ssZ) a la lista, o publíquela como VC 2.0 con credentials/v2." };
    if (Array.isArray(lista.issuanceDate) && lista.issuanceDate.length > 1) return { resumen: `issuanceDate de la lista tiene más de un valor: la app lo rechaza ${NO_COMPROBADO}.`, accion: "Deje una sola fecha en issuanceDate." };
  }
  if ("credentialStatus" in lista) for (const cs of comoLista(lista.credentialStatus)) {
    if (!esObjeto(cs) || !cs.type) return { resumen: `La lista declara un credentialStatus sin type: la app lo rechaza ${NO_COMPROBADO}.`, accion: "Quite el credentialStatus de la lista o declare su type." };
    if ("id" in cs && !esUri(cs.id)) return { resumen: `credentialStatus.id de la lista («${citar(cs.id, 60)}») no es un URI: la app lo rechaza ${NO_COMPROBADO}.`, accion: "Escriba credentialStatus.id como URI, o quítelo." };
  }
  for (const prop of ["evidence", "termsOfUse"]) {
    if (!(prop in lista)) continue;
    for (const v of comoLista(lista[prop])) {
      if (!esObjeto(v) || !Object.keys(v).length || !("type" in v)) return { resumen: `«${prop}» de la lista no es un objeto no vacío con type: la app lo rechaza ${NO_COMPROBADO}.`, accion: `Quite «${prop}» de la lista, o declare un objeto con su type.` };
      if (prop === "evidence" && "id" in v && !esUri(v.id)) return { resumen: `evidence.id de la lista («${citar(v.id, 60)}») no es un URI: la app lo rechaza ${NO_COMPROBADO}.`, accion: "Escriba evidence.id como URI, o quítelo." };
    }
  }
  return null;
}

// Lo que se enseña cuando no hay muestra con la que evaluar la 12.
export function estadoSinMuestra() {
  return resultado("estado", PENDIENTE, "Sin credencial de muestra no se puede evaluar: la dirección de la lista solo se conoce desde su credentialStatus.",
    "Pegue una credencial de muestra (con datos de prueba) o use --muestra en la línea de comandos.");
}

class PlazoAgotado extends Error {}

// `vc` es la muestra ya parseada; `red` la de red.mjs (o una que cumpla `traer`). Devuelve
// un resultado de la comprobación 12. Nunca lanza: lo inesperado es «no evaluable». `plazoMs` es el
// tiempo máximo de TODA la comprobación (por defecto 15 s).
export async function comprobarListaDeEstado(vc, red, { cargar, ahora = Date.now(), plazoMs = ESTADO_PLAZO_MS, canonMs = ESTADO_CANON_MS } = {}) {
  const nuevo = (estado, resumen, accion = null, detalles = []) => resultado("estado", estado, resumen, accion, detalles);
  const limite = Date.now() + plazoMs;
  const sinTiempo = () => nuevo(PENDIENTE, `La comprobación no terminó en ${segundos(plazoMs)} (el diagnóstico limita lo que tarda): no se puede decir si la app aceptaría la lista.`,
    "Una lista de estado pequeña, sin estructuras anidadas raras y en un servidor que responda en menos de 5 segundos se comprueba en menos de un segundo.");
  let reloj;
  const agotado = new Promise((resolver) => { reloj = setTimeout(() => resolver(sinTiempo()), plazoMs); });
  try { return await Promise.race([evaluarEstado(vc, red, { cargar, ahora, nuevo, limite, sinTiempo, canonMs }), agotado]); }
  finally { clearTimeout(reloj); }
}

async function evaluarEstado(vc, red, { cargar, ahora, nuevo, limite, sinTiempo, canonMs }) {
  try {
    const campo = vc?.credentialStatus;
    const sinRevocacion = (nota) => nuevo(PENDIENTE,
      "Sin credentialStatus: el emisor no publica revocación: la app mostrará la credencial como válida sin poder saber si fue anulada.",
      "Si necesitan poder anular credenciales, publiquen una lista de estado (Bitstring Status List) y declaren credentialStatus en la plantilla de la credencial.",
      [nota]);
    if (campo === undefined || campo === null) return sinRevocacion("La credencial de muestra no declara credentialStatus.");
    const entradas = comoLista(campo);
    if (!entradas.length) return nuevo(FALLA, "credentialStatus está vacío ([]): la app no lo entiende y mostrará «no comprobado».",
      "Declare una entrada BitstringStatusListEntry, o quite credentialStatus si no publican revocación.");
    const relevantes = entradas.filter((e) => { const p = propositoDe(e); return p === "revocation" || p === null; });
    if (!relevantes.length) return sinRevocacion(`credentialStatus solo declara otros propósitos (${[...new Set(entradas.map(propositoDe))].map((p) => citar(p, 30)).join(", ")}), no revocation.`);

    const ctx = { red, cargar: cargar ?? crearCargador(red).cargar, ahora, nuevo, limite, canonMs,
      vigilar: () => { if (Date.now() > limite) throw new PlazoAgotado(); }, restante: () => limite - Date.now(), listas: new Map(), vc };
    // Como mucho ESTADO_MAX_ENTRADAS: cada una cuesta una lista que descargar y canonicalizar. Las demás, AVISO.
    const evaluadas = relevantes.slice(0, ESTADO_MAX_ENTRADAS), omitidas = relevantes.length - evaluadas.length;
    const avisoDeTope = omitidas > 0 ? [`la credencial declara ${relevantes.length} entradas de revocación y el diagnóstico evalúa como mucho ${ESTADO_MAX_ENTRADAS}: las otras ${omitidas} no se comprobaron`,
      "Declare una sola entrada de revocación por credencial: es lo habitual y lo que el diagnóstico puede comprobar entera."] : null;
    const salidas = [];
    for (const e of evaluadas) salidas.push(await comprobarEntradaDeEstado(e, ctx, avisoDeTope));
    return combinarEntradas(salidas, { omitidas });
  } catch (e) {
    if (e instanceof PlazoAgotado) return sinTiempo();
    return nuevo(PENDIENTE, `No se pudo evaluar la lista de estado: ${citar(e?.message, 120)}.`);
  }
}

// Varias entradas de revocación, como la app (`combineOutcomes` de statusListChecker.ts): si alguna dice
// «revocada», revocada; si ninguna y alguna da error, error; si no, vigente. Entre errores, el FALLA (seguro) antes que el
// PENDIENTE (no se pudo decidir). Lo que la 12 sabe de las otras entradas va al detalle.
function combinarEntradas(salidas, { omitidas }) {
  const revocadas = salidas.filter((s) => s.revocada);
  const errores = salidas.filter((s) => s.r.estado === FALLA || s.r.estado === PENDIENTE);
  if (!revocadas.length && errores.length) return (errores.find((s) => s.r.estado === FALLA) ?? errores[0]).r;
  const elegida = (revocadas.length ? revocadas : salidas.filter((s) => !errores.includes(s))).find((s) => s.r.estado === AVISO) ?? (revocadas[0] ?? salidas.find((s) => !errores.includes(s)));
  const r = elegida.r;
  for (const resumen of [...new Set(errores.map((s) => s.r.resumen))].slice(0, 3)) r.detalles.push(`Otra entrada de revocación no cumple lo que exige la app: ${resumen}`);
  if (salidas.length > 1 && !errores.length && !omitidas) r.detalles.push(`La credencial declara ${salidas.length} entradas de revocación; todas cumplen.`);
  return r;
}

// Una entrada: su tipo y su URL; la lista (compartida por todas las entradas que apunten a la misma:
// una descarga, una canonicalización); y su índice y su bit. Devuelve { r, revocada }.
async function comprobarEntradaDeEstado(entrada, ctx, avisoDeTope) {
  const { nuevo } = ctx;
  const proposito = propositoDe(entrada);
  const fin = (r) => ({ r, revocada: false });
  if (proposito === null) return fin(nuevo(FALLA, "Una entrada de credentialStatus no declara statusPurpose: la app no sabe a qué sirve y mostrará «no comprobado».",
    "Declare statusPurpose: \"revocation\" en la entrada."));

  // 1. La entrada y la URL (R2) ---------------------------------------------------
  if (entrada.type !== "BitstringStatusListEntry") return fin(nuevo(FALLA,
    `La entrada de estado es de tipo «${citar(entrada.type, 60)}»: la app solo entiende BitstringStatusListEntry y mostrará «no comprobado».`,
    "Use el tipo BitstringStatusListEntry (W3C Bitstring Status List)."));
  const url = entrada.statusListCredential;
  const motivoUrl = motivoUrlDeLista(url);
  if (motivoUrl) return fin(nuevo(FALLA, `La dirección de la lista no sirve para la app: ${motivoUrl}.`,
    "Publique la lista en una URL https con nombre de dominio público (sin IP, localhost, .local ni .internal, sin usuario ni clave)."));

  // 2. La lista, una vez por URL ------------------------------------------------------
  const clave = `${url}\n${proposito}`;
  if (!ctx.listas.has(clave)) ctx.listas.set(clave, evaluarLista(url, proposito, ctx));
  const lista = await ctx.listas.get(clave);
  if (lista.fin) return fin(lista.fin);
  return resultadoDeEntrada(entrada, lista, ctx, avisoDeTope);
}

// La lista y todo lo que depende solo de ella. Devuelve { fin: resultado } si ya se sabe que falla o que no se
// puede decidir, o { datos } con lo que hace falta para leer el bit de cada entrada.
async function evaluarLista(url, proposito, ctx) {
  const { nuevo, red, cargar, ahora } = ctx;
  const deLaLista = [`Lista: ${citar(url, 200)}`];
  const falla = (resumen, accion, detalles = deLaLista) => ({ fin: nuevo(FALLA, resumen, accion, detalles) });
  const avisos = [];
  let sinVerificar = null; // por qué no se pudo verificar la firma: PENDIENTE si todo lo demás está bien

  // 3. La descarga: como la app (sin redirecciones, 2 MiB, 5 s), por red.mjs ----------------
  ctx.vigilar();
  let r;
  try { r = await red.traer(url, { limite: ESTADO_MAX_RESPUESTA + 1, sinRedirecciones: true, espera: Math.min(ESTADO_ESPERA_MS, Math.max(1, Math.floor(ctx.restante()))) }); }
  catch (e) {
    ctx.vigilar();
    return falla(`No se pudo descargar la lista de estado: ${citar(e?.message, 160)}.`,
      "Compruebe que la dirección de la lista responde por HTTPS, con un certificado válido y en menos de 5 segundos.");
  }
  ctx.vigilar();
  const origen = (u) => { try { return new URL(u).origin; } catch { return null; } };
  if ((r.estado >= 300 && r.estado < 400) || (typeof r.url === "string" && r.url && origen(r.url) !== origen(url)))
    return falla(`La dirección de la lista redirige${r.estado >= 300 && r.estado < 400 ? ` (${r.estado})` : ""}: la app no sigue redirecciones y mostrará «no comprobado».`,
      "Sirva la lista directamente en la URL que declara statusListCredential, sin redirigir.");
  if (r.estado < 200 || r.estado >= 300) return falla(`La dirección de la lista responde ${r.estado}.`,
    "Publique la lista en la URL que declara statusListCredential.");
  const pesa = (cuando) => falla(`La lista pesa más de ${MIB(ESTADO_MAX_RESPUESTA)}${cuando}: la app la rechaza.`,
    `Una lista de ${bits(ESTADO_MIN_BITS)} bits ocupa unos 16 KiB comprimida; no hacen falta ${MIB(ESTADO_MAX_RESPUESTA)}.`);
  if (r.truncado || Buffer.byteLength(r.cuerpo) > ESTADO_MAX_RESPUESTA) return pesa("");
  const codificacion = cabecera(r, "content-encoding");
  const des = descomprimirCuerpo(r.cuerpo, codificacion);
  if (des.error === "grande") return pesa(" una vez descomprimida");
  if (des.error) return falla(`La lista llega con Content-Encoding «${citar(des.codificacion, 20)}» pero no se puede descomprimir: la app no podrá leerla.`,
    "Sirva la lista sin Content-Encoding, o con un cuerpo que de verdad esté comprimido con esa codificación.", [...deLaLista, `Content-Encoding: ${citar(codificacion, 40)}`]);
  if (Buffer.byteLength(des.bytes) > ESTADO_MAX_RESPUESTA) return pesa(des.bytes === r.cuerpo ? "" : " una vez descomprimida");
  const lista = jsonDeCuerpo(des.bytes);
  if (!lista || typeof lista !== "object" || Array.isArray(lista)) return falla("La dirección de la lista no sirve un documento JSON.",
    "Sirva la BitstringStatusListCredential como JSON.", [...deLaLista, `Content-Type: ${citar(cabecera(r, "content-type") ?? "ausente", 80)}`]);

  // 4. La prueba: objeto, suite que la app verifica y verificationMethod que la app encuentra -----
  const { proof, ...sinProof } = lista;
  if (proof === undefined || proof === null || (Array.isArray(proof) && !proof.length)) return falla("La lista no está firmada (no tiene proof): la app rechaza una lista sin firma.",
    "Firme la lista con la clave del emisor (Ed25519Signature2020).");
  if (Array.isArray(proof)) return proof.length === 1
    ? falla(`La prueba (proof) de la lista va dentro de una lista ([…]): la app solo lee la prueba como objeto ${NO_COMPROBADO}.`,
      "Publique la lista con una sola prueba, como objeto («proof»: {…}), no entre corchetes.")
    : falla(`La lista trae varias pruebas: la app rechaza listas con varias pruebas ${NO_COMPROBADO}.`,
      "Firme la lista con una sola prueba y publíquela como objeto.");
  if (!esObjeto(proof)) return falla(`La prueba (proof) de la lista no es un objeto: la app la rechaza ${NO_COMPROBADO}.`,
    "Firme la lista con la clave del emisor (Ed25519Signature2020) y publique la prueba como objeto.");
  const p0 = proof;
  const tipoProof = typeof p0.type === "string" ? p0.type : null;
  const suite = tipoProof === "DataIntegrityProof" ? `DataIntegrityProof/${citar(p0.cryptosuite ?? "?", 30)}` : tipoProof ? citar(tipoProof, 40) : "una suite sin type";
  if (tipoProof === "Ed25519Signature2018" || tipoProof === "RsaSignature2018") {
    sinVerificar = `La lista se firma con ${tipoProof}: la app sí la verifica, pero el diagnóstico solo verifica Ed25519Signature2020; no puede decir si la app la acepta.`;
  } else if (tipoProof !== "Ed25519Signature2020") return falla(
    `La lista se firma con ${suite}: la app no verifica esa suite (solo Ed25519Signature2020, Ed25519Signature2018 y RsaSignature2018) ${NO_COMPROBADO}.`,
    "Firme la lista con Ed25519Signature2020: es la suite que la app verifica.");
  const vmId = identificador(p0.verificationMethod);
  if (!vmId) return falla(`La prueba de la lista no declara verificationMethod (ni como texto ni como objeto con id): la app no encuentra la clave ${NO_COMPROBADO}.`,
    "Declare en la prueba el verificationMethod completo: el DID del emisor, «#» y el identificador de la clave.");
  // Un did:key a secas es el DID y la clave a la vez, y `deEmisor` (más abajo) lo admite; pero el verificador de la
  // app busca el método de verificación por su id completo y no lo encuentra («No se encontró el método de
  // verificación»). El comentario que había aquí decía lo contrario; la evaluación adversarial (C3) lo midió.
  if (vmId.startsWith("did:key:") && !vmId.includes("#")) return falla(
    `El verificationMethod de la prueba de la lista es el did:key a secas, sin fragmento («#…»): la app no encuentra la clave ${NO_COMPROBADO}.`,
    "Escriba el verificationMethod completo: el did:key, «#» y el identificador de la clave (did:key:z6Mk…#z6Mk…).");

  // El propósito decide qué lista del DID autoriza la clave; la app solo entiende dos y falla antes de mirar la firma.
  // `publicKey` (obsoleto) lo valida la app con JSON-LD sobre el documento DID: el diagnóstico solo valida assertionMethod.
  if (p0.proofPurpose === "publicKey") sinVerificar ??= "La prueba de la lista declara proofPurpose publicKey: la app lo valida con JSON-LD sobre el documento DID y el diagnóstico solo valida assertionMethod, así que no puede decir si la app la acepta.";
  else if (p0.proofPurpose !== "assertionMethod") return falla(
    `La prueba de la lista declara proofPurpose «${citar(p0.proofPurpose ?? "ausente", 30)}»: la app solo admite assertionMethod y publicKey ${NO_COMPROBADO}.`,
    "Firme la lista con proofPurpose: \"assertionMethod\".");
  // Con Ed25519Signature2020 la firma va en `proofValue` y la app solo lee base58-btc («z…»).
  if (tipoProof === "Ed25519Signature2020") {
    if (typeof p0.proofValue !== "string" || !p0.proofValue) return falla(`La prueba de la lista no trae proofValue: la app lo necesita para verificar la firma ${NO_COMPROBADO}.`,
      "Firme la lista: la firma de Ed25519Signature2020 va en proofValue.");
    if (p0.proofValue[0] !== "z") return falla(`La prueba de la lista trae un proofValue que no es multibase base58 (tiene que empezar por «z»): la app solo lee ese formato ${NO_COMPROBADO}.`,
      "Escriba proofValue en multibase base58-btc («z…»), como hace Ed25519Signature2020.");
  }
  // `created` lo lee la suite de la app con `new Date(created)` y su constructor rechaza una fecha inválida
  // («"date" … is not a valid date»); sin `created` no pasa nada. Hallazgo propio, de la prueba de paridad.
  if (p0.created !== undefined && Number.isNaN(new Date(p0.created).getTime())) return falla(
    `La prueba de la lista trae un created («${citar(p0.created, 40)}») que no es una fecha: la app lo rechaza ${NO_COMPROBADO}.`,
    "Escriba created como fecha y hora (AAAA-MM-DDThh:mm:ssZ), o quítelo de la prueba.");

  // 5. Lo que el verificador de la app exige de la lista antes de mirar la firma -----------------
  const regla = reglasDelVerificador(lista);
  if (regla) return falla(regla.resumen, regla.accion);
  const sujeto = lista.credentialSubject;

  // 6. Tipo, propósito y statusSize ---------------------------------------------------
  const tipos = comoLista(lista.type);
  if (!tipos.includes("BitstringStatusListCredential")) avisos.push([
    `el type de la lista es «${tipos.map((t) => citar(t, 40)).join(", ")}» y no incluye BitstringStatusListCredential: la app lo acepta; la especificación recomienda declararlo`,
    "Declare type: [\"VerifiableCredential\", \"BitstringStatusListCredential\"] en la lista, como pide W3C."]);
  if (sujeto.type !== "BitstringStatusList") return falla(
    `El sujeto de la lista es de tipo «${citar(sujeto.type ?? "ausente", 60)}» y debe ser BitstringStatusList.`,
    "Ponga credentialSubject.type: \"BitstringStatusList\".");
  if (String(sujeto.statusPurpose ?? "").toLowerCase() !== proposito) return falla(
    `La lista es para «${citar(sujeto.statusPurpose ?? "ausente", 40)}» y la credencial pide «${citar(proposito, 40)}»: la app las rechaza.`,
    `Publique una lista con statusPurpose: "${citar(proposito, 40)}", o corrija el de la entrada.`);
  let tamano = 1;
  if (sujeto.statusSize !== undefined && sujeto.statusSize !== null) {
    const p = parseInt(String(sujeto.statusSize), 10);
    tamano = Number.isNaN(p) ? 1 : p;
  }
  if (tamano <= 0) return falla(`statusSize ${citar(sujeto.statusSize, 20)} no es válido: tiene que ser mayor que 0.`, "Use statusSize 1 (o quítelo) en una lista de revocación.");
  if (tamano > 1 && proposito === "revocation") return falla(
    `statusSize es ${tamano}: en una lista de revocación tiene que ser 1, y la app rechaza otro valor.`,
    "Use statusSize 1 (o quítelo): los tamaños mayores son para statusMessage, no para revocación.");

  // 7. issuer y verificationMethod: la lista tiene que ser del mismo emisor. ANTES de la firma: verificarla puede
  //    pedir el did:web que declara la propia lista, y eso no se hace para la lista de otro (C14). ----------
  const vc = ctx.vc;
  const emisorCredencial = identificador(vc.issuer);
  const emisorLista = identificador(lista.issuer);
  if (!emisorCredencial || !emisorLista || emisorLista !== emisorCredencial) return falla(
    `La lista la firma otro emisor: su issuer es «${citar(emisorLista ?? "ausente", 120)}» y el de la credencial es «${citar(emisorCredencial ?? "ausente", 120)}».`,
    "Publique la lista con el mismo issuer (el mismo DID) que las credenciales que emite.");
  if (!esUri(emisorLista)) return falla(`El issuer de la lista («${citar(emisorLista, 100)}») no es un URI (por ejemplo un DID): la app lo rechaza ${NO_COMPROBADO}.`,
    "Use como issuer el DID del emisor (did:web:… o did:key:…).");
  const deEmisor = (id) => id.startsWith(`${emisorCredencial}#`) || (id === emisorCredencial && emisorCredencial.startsWith("did:key:"));
  if (!deEmisor(vmId)) return falla(
    `La lista está firmada con una clave que no es del emisor: su verificationMethod es «${citar(vmId, 140)}» y debería empezar por «${citar(emisorCredencial, 100)}#».`,
    "Firme la lista con una clave del DID del emisor de las credenciales.");

  // 8. La firma ---------------------------------------------------------------------------
  ctx.vigilar();
  if (!sinVerificar) {
    let canonLista, canonPrueba;
    const limiteCanon = Math.min(ctx.limite, Date.now() + ctx.canonMs);
    try {
      canonLista = await canonizarDocumento(sinProof, { cargar, limite: limiteCanon });
      const opciones = { ...p0 }; delete opciones.proofValue; delete opciones.jws;
      canonPrueba = await canonizarDocumento({ "@context": lista["@context"], ...opciones }, { cargar, limite: limiteCanon });
    } catch (e) {
      ctx.vigilar(); // si lo que se acabó es el plazo GLOBAL, la comprobación entera termina aquí (PlazoAgotado)
      if (e?.codigo === "plazo")
        // Solo se acabó el de la canonicalización: no tira la 12, porque el resto de las reglas son baratas y pueden
        // decir que la lista ya falla por otra cosa.
        sinVerificar = `La lista tarda demasiado en canonicalizarse para verificar su firma (más de ${segundos(ctx.canonMs)}; una lista normal tarda milisegundos): el diagnóstico no puede decir si la app la aceptaría.`;
      else if (e instanceof ErrorJsonLd && e.codigo === "no soportado")
        sinVerificar = `No se pudo verificar la firma de la lista con el canonicalizador del diagnóstico (${citar(e.message, 100)}); la app sí la verifica con una biblioteca completa, así que el diagnóstico no puede decir si la acepta.`;
      else return falla(`No se pudo expandir la lista para verificar su firma: ${citar(e?.message, 160)}.`,
        "Revise que todos los @context de la lista se puedan descargar y sean compatibles entre sí.");
    }
    if (!sinVerificar) {
      let v;
      try { v = await verificarPruebaComoLaApp({ p0, vmId, canonPrueba: canonPrueba.nquads, canonLista: canonLista.nquads, red }); }
      catch (e) { ctx.vigilar(); return falla(`No se pudo verificar la firma de la lista: ${citar(e?.message, 160)}.`, "Publique el DID del emisor con la clave que firma la lista."); }
      ctx.vigilar();
      if (v.fin?.estado === FALLA) return falla(v.fin.resumen, v.fin.accion);
      if (v.fin) sinVerificar = v.fin.resumen;           // PENDIENTE: lo demás se sigue evaluando
    }
  }

  // 9. Vigencia: la de la raíz (va firmada); la del sujeto también la mira la app -----------------
  const motivoVigencia = motivoDeVigencia(lista, ["validFrom", "issuanceDate"], ["validUntil", "expirationDate"], ahora, "la lista")
    ?? motivoDeVigencia(sujeto, ["validFrom"], ["validUntil"], ahora, "credentialSubject");
  if (motivoVigencia) return falla(`La lista no está vigente: ${motivoVigencia}.`,
    "Vuelva a firmar y publicar la lista con una vigencia que cubra el momento actual (y renuévela antes de que venza).");
  // Y las fechas como las exige la librería de la app: con hora, y la zona mejor explícita (C5).
  const v1 = lista["@context"][0] === V1;
  for (const campo of fechasDeLaLibreria(lista, v1)) {
    const valor = lista[campo];
    if (!FECHA_COMPLETA.test(valor)) return falla(SOLO_DIA.test(String(valor))
      ? `La lista no lleva hora en ${campo} («${citar(valor, 40)}»): la app exige fecha y hora completas (AAAA-MM-DDThh:mm:ssZ) ${NO_COMPROBADO}.`
      : `${campo} de la lista («${citar(valor, 40)}») no es una fecha y hora completa (AAAA-MM-DDThh:mm:ssZ): la app la rechaza ${NO_COMPROBADO}.`,
      `Escriba ${campo} con fecha, hora y zona, p. ej. 2099-01-01T00:00:00Z.`);
  }
  for (const campo of fechasDeLaLibreria(lista, v1)) {
    if (FECHA_SIN_ZONA.test(String(lista[campo]))) avisos.push([
      `${campo} de la lista («${citar(lista[campo], 40)}») no lleva zona horaria: la app la interpreta en la hora local del teléfono y puede rechazarla según la zona`,
      `Escriba ${campo} con zona (Z o +hh:mm), p. ej. ${citar(lista[campo], 40).replace(/\.\d+$/, "")}Z.`]);
  }

  // 10. encodedList ---------------------------------------------------------------------------
  if (typeof sujeto.encodedList !== "string") return falla("La lista no trae encodedList (o no es un texto).", "Publique el bitstring comprimido en credentialSubject.encodedList.");
  const dec = decodificarLista(sujeto.encodedList);
  if (dec.error) return falla(`encodedList no es válido: ${dec.error}.`, "encodedList es un bitstring comprimido con GZIP y codificado en base64url, con el prefijo «u».");
  const totalBits = dec.bytes.length * 8;
  if (totalBits < ESTADO_MIN_BITS * tamano) avisos.push([
    `la lista tiene ${bits(totalBits)} bits: la app lo acepta; la especificación recomienda al menos ${bits(ESTADO_MIN_BITS * tamano)} para que una consulta no delate a qué credencial se refiere`,
    `W3C recomienda al menos ${bits(ESTADO_MIN_BITS)} entradas (privacidad de grupo). Rellene la lista hasta ese tamaño; la app no lo exige.`]);

  // 11. Los avisos que dependen de la lista ---------------------------------------------------------
  const detalles = [];
  const ttlCrudo = sujeto.ttl;
  const detallesTtl = [];
  if (ttlCrudo !== undefined && ttlCrudo !== null && ttlCrudo !== "" && typeof ttlCrudo !== "boolean") {
    const ttl = Number(ttlCrudo);
    if (!Number.isFinite(ttl) || ttl < 0) { detallesTtl.push(`ttl: «${citar(ttlCrudo, 30)}»`); avisos.push(["ttl no es un número mayor o igual que 0: la app lo ignora", "Declare ttl en milisegundos (p. ej. 86400000 para 24 h), o quítelo."]); }
    else {
      detallesTtl.push(`ttl: ${ttl} ms (${duracion(ttl)})`);
      if (ttl < DIA_MS) avisos.push([`ttl es ${duracion(ttl)}, menos de 24 h: la app volverá a pedir la lista con esa frecuencia`, "Un ttl de 24 h (86400000) basta: la app nunca guarda la lista más de 24 h."]);
      else if (ttl > TREINTA_DIAS_MS) avisos.push([`ttl es ${duracion(ttl)}, más de 30 días: la app no lo respeta, usa 24 h como máximo`, "Declare un ttl de 24 h o menos, que es el que la app aplica."]);
    }
  } else detallesTtl.push("ttl: no declarado");
  const cc = cabecera(r, "cache-control");
  const detalleCache = `Cache-Control: ${citar(cc ?? "ausente", 120)}`;
  if (cc && !/no-store|no-cache/i.test(cc)) {
    const edades = [...cc.matchAll(/(?:^|[\s,])(?:s-maxage|max-age)\s*=\s*"?(\d+)/gi)].map((m) => Number(m[1]));
    if (edades.some((e) => e * 1000 > DIA_MS)) avisos.push([`Cache-Control permite guardar la lista más de 24 h (${citar(cc, 60)}): una revocación puede tardar ese tiempo en verse`, "Sirva la lista con Cache-Control: no-cache, o con un max-age de 24 h (86400) como máximo."]);
  }
  detalles.push(...detallesTtl, detalleCache, `issuer (el de la credencial y el de la lista): ${citar(emisorCredencial, 140)}`);
  return { datos: { url, dec, tamano, totalBits, avisos, detalles, sinVerificar, deLaLista } };
}

// El bit de la entrada en una lista que ya se sabe conforme, y el resultado final de esa entrada.
function resultadoDeEntrada(entrada, { datos }, ctx, avisoDeTope) {
  const { nuevo } = ctx;
  const { url, dec, tamano, totalBits, deLaLista } = datos;
  const falla = (resumen, accion) => ({ r: nuevo(FALLA, resumen, accion, deLaLista), revocada: false });
  const ix = parsearIndice(entrada.statusListIndex);
  if (ix.invalido) return falla(`statusListIndex «${citar(entrada.statusListIndex ?? "ausente", 40)}» no es un entero mayor o igual que 0.`,
    "statusListIndex es la posición de la credencial en la lista: un entero (o un texto de dígitos) sin signo.");
  const posicion = ix.fuera ? Infinity : ix.indice * tamano;
  if (posicion >= totalBits) return falla(
    `El statusListIndex ${citar(entrada.statusListIndex, 40)} está fuera de la lista, que tiene ${bits(totalBits / tamano)} posiciones.`,
    "Asigne a cada credencial una posición dentro del tamaño de la lista, o publique una lista más grande.");
  // La firma no se pudo verificar con el canonicalizador del diagnóstico (C10, 2018/RSA): todo lo demás está bien.
  if (datos.sinVerificar) return { r: nuevo(PENDIENTE, datos.sinVerificar, null, deLaLista), revocada: false };
  const bit = (dec.bytes[posicion >> 3] >> (7 - (posicion & 7))) & 1;

  const avisos = [...datos.avisos, ...(avisoDeTope ? [avisoDeTope] : [])];
  const detalles = [`Lista: ${citar(url, 200)}`, `Tamaño: ${bits(totalBits)} bits`, `Bit de la muestra (posición ${ix.indice}): ${bit} → ${bit ? "revocada" : "vigente"}`,
    ...datos.detalles, ...avisos.map(([a]) => `⚠ ${a}`)];
  const dicho = bit ? "revocada" : "vigente";
  const r = avisos.length
    ? nuevo(AVISO, `La lista de estado cumple lo que exige la app, con ${plural(avisos.length, "advertencia")}: ${avisos[0][0]}.${bit ? " La credencial de muestra figura como revocada." : ""}`, avisos[0][1], detalles)
    : nuevo(OK, `La lista de estado cumple lo que exige la app: ${bits(totalBits)} bits, y la credencial de muestra figura como ${dicho}.`, null, detalles);
  return { r, revocada: !!bit };
}

// =============================================================================
// Totales con la 12
// =============================================================================
// El veredicto de la muestra (11a-f) no cambia; con la 12 se calcula aparte, para que
// una lista que falla se vea en el titular y en el código de salida de la CLI.
export function veredictoMuestra(m) {
  return veredicto([...(m?.comprobaciones ?? []), ...(m?.estado ? [m.estado] : [])]);
}
// «N/12»: las resueltas (OK) de las once de la metadata más la 12 si se evaluó y está OK.
export function resumenGeneral(r, m) {
  const resueltas = (r?.veredicto?.ok ?? 0) + (m?.estado?.estado === OK ? 1 : 0);
  const evaluada = !!m?.estado && m.estado.estado !== PENDIENTE;
  return { resueltas, total: TOTAL_COMPROBACIONES, doce_evaluada: evaluada, texto: `${resueltas}/${TOTAL_COMPROBACIONES}` };
}
