// Genera, de forma DETERMINISTA, las fixtures sintéticas de las pruebas:
//
//   credenciales/contexto-propio.json        un @context propio que define 4 atributos
//   credenciales/did.json                    el documento DID de prueba (did:web)
//   credenciales/valida.json                 ldp_vc Ed25519Signature2020, firmada con did:key
//   credenciales/valida-did-web.json         la misma, pero firmada con la clave del did:web
//   credenciales/alterada.json               un atributo cambiado DESPUÉS de firmar
//   credenciales/contexto-propio-primero.json el @context propio antes que el de W3C
//   credenciales/sin-suite.json              sin el @context de la suite de firma
//   credenciales/atributo-no-definido.json   un atributo que el @context no define
//
// NO HAY NINGÚN DATO REAL: la clave sale de una semilla fija escrita aquí (es
// de pruebas y no protege nada), los dominios son `*.test` (reservados por la
// RFC 2606, no resuelven) y los valores dicen «PRUEBA».
//
// La firma se calcula con la implementación de diagnostico/jsonld.mjs para
// canonicalizar y node:crypto para firmar. Eso significa que ESTE script no es
// independiente del código que prueba; la independencia la pone
// test/jsonld.test.mjs, que compara cada fixture contra jsonld.js (la biblioteca
// de referencia) byte a byte.
//
// Uso:  node test/fixtures/generar.mjs          (reescribe los ficheros)
//       node test/fixtures/generar.mjs --comprobar   (sale con 1 si hay deriva)
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { canonizarDocumento } from "../../diagnostico/jsonld.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
export const DIR_CREDENCIALES = join(AQUI, "credenciales");
export const DIR_CONTEXTOS = join(AQUI, "contextos");

export const V1 = "https://www.w3.org/2018/credentials/v1";
export const V2 = "https://www.w3.org/ns/credentials/v2";
export const ED2020 = "https://w3id.org/security/suites/ed25519-2020/v1";
export const DID_V1 = "https://www.w3.org/ns/did/v1";
export const URL_CONTEXTO = "https://emisor.prueba.test/contextos/prueba.json";
export const DID_WEB = "did:web:emisor.prueba.test";
export const TIPO = "CredencialPrueba";
export const ATRIBUTOS = ["nombre_completo", "numero_documento", "categoria", "fecha_vencimiento"];
export const FECHA = "2026-01-01T00:00:00Z";

// --- la clave fija -----------------------------------------------------------
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
export function b58codificar(buf) {
  let n = BigInt("0x" + (buf.toString("hex") || "0"));
  let s = "";
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = "1" + s; else break; }
  return s;
}
const SEMILLA = createHash("sha256").update("soyyord/inji-vc/pruebas/semilla-ed25519-solo-para-pruebas").digest();
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");
const clavePrivada = createPrivateKey({ key: Buffer.concat([PKCS8, SEMILLA]), format: "der", type: "pkcs8" });
export const CLAVE_PUBLICA_CRUDA = Buffer.from(createPublicKey(clavePrivada).export({ format: "jwk" }).x, "base64url");
// multicodec ed25519-pub (0xed 0x01) + 32 bytes, en multibase base58btc.
export const CLAVE_MULTIBASE = "z" + b58codificar(Buffer.concat([Buffer.from([0xed, 0x01]), CLAVE_PUBLICA_CRUDA]));
export const DID_KEY = `did:key:${CLAVE_MULTIBASE}`;
export const VM_DID_KEY = `${DID_KEY}#${CLAVE_MULTIBASE}`;
export const VM_DID_WEB = `${DID_WEB}#key-1`;

// --- los documentos ------------------------------------------------------------
// Con la misma forma que genera bin/sembrar-credenciales.sh.
export function contextoPropio(url = URL_CONTEXTO, atributos = ATRIBUTOS, tipo = TIPO) {
  const ctx = { "@version": 1.1, "@protected": true, id: "@id", type: "@type",
    v: url + "#", xsd: "http://www.w3.org/2001/XMLSchema#", [tipo]: "v:" + tipo };
  for (const a of atributos) ctx[a] = { "@id": "v:" + a, "@type": "xsd:string" };
  return { "@context": ctx };
}

// El documento DID de un did:web cualquiera con la clave de prueba.
export function didJson(did = DID_WEB) {
  const vm = `${did}#key-1`;
  return {
    "@context": [DID_V1, ED2020],
    id: did,
    verificationMethod: [{ id: vm, type: "Ed25519VerificationKey2020", controller: did, publicKeyMultibase: CLAVE_MULTIBASE }],
    authentication: [vm],
    assertionMethod: [vm],
  };
}

export const SUJETO = {
  id: "did:example:titular-de-prueba",
  nombre_completo: "PRUEBA - Titular Sintetico",
  numero_documento: "00000000000",
  categoria: "02 PRUEBA",
  fecha_vencimiento: "2031-01-01",
};

// Los contextos que resuelven sin red: el propio y los tres públicos copiados.
export function contextosLocales() {
  const leer = (f) => JSON.parse(readFileSync(join(DIR_CONTEXTOS, f), "utf8"));
  return new Map([
    [URL_CONTEXTO, contextoPropio()],
    [V1, leer("w3-credentials-v1.json")],
    [V2, leer("w3-credentials-v2.json")],
    [ED2020, leer("w3id-ed25519-2020-v1.json")],
    [DID_V1, { "@context": "https://www.w3.org/ns/did/v1" }],
  ]);
}
export const cargadorLocal = (mapa = contextosLocales()) => async (url) => {
  if (!mapa.has(url)) throw new Error(`fixture sin contexto para ${url}`);
  return structuredClone(mapa.get(url));
};

const sha = (s) => createHash("sha256").update(s, "utf8").digest();

// Firma como lo hace Ed25519Signature2020 y como lo verifica el motor: SHA-256 de
// las opciones de la prueba canonicalizadas, SHA-256 del documento sin prueba
// canonicalizado, y Ed25519 sobre los dos hashes concatenados.
export async function firmar(sinProof, { vm }) {
  const cargar = cargadorLocal();
  const opciones = { type: "Ed25519Signature2020", created: FECHA, verificationMethod: vm, proofPurpose: "assertionMethod" };
  const canonOpciones = (await canonizarDocumento({ "@context": sinProof["@context"], ...opciones }, { cargar })).nquads;
  const canonDoc = (await canonizarDocumento(sinProof, { cargar })).nquads;
  const firma = sign(null, Buffer.concat([sha(canonOpciones), sha(canonDoc)]), clavePrivada);
  return { ...sinProof, proof: { ...opciones, proofValue: "z" + b58codificar(firma) } };
}

const sinFirmar = ({ contextos = [V2, URL_CONTEXTO, ED2020], issuer, sujeto = SUJETO } = {}) => ({
  "@context": contextos,
  type: ["VerifiableCredential", TIPO],
  issuer,
  validFrom: FECHA,
  credentialSubject: sujeto,
});

// Todas las fixtures, como { nombre de fichero: objeto }. Determinista.
export async function construir() {
  const valida = await firmar(sinFirmar({ issuer: DID_KEY }), { vm: VM_DID_KEY });
  const alterada = structuredClone(valida);
  alterada.credentialSubject.nombre_completo = "PRUEBA - Titular ALTERADO";
  return {
    "contexto-propio.json": contextoPropio(),
    "did.json": didJson(),
    "valida.json": valida,
    "valida-did-web.json": await firmar(sinFirmar({ issuer: DID_WEB }), { vm: VM_DID_WEB }),
    "alterada.json": alterada,
    "contexto-propio-primero.json": await firmar(
      sinFirmar({ contextos: [URL_CONTEXTO, V2, ED2020], issuer: DID_KEY }), { vm: VM_DID_KEY }),
    "sin-suite.json": await firmar(sinFirmar({ contextos: [V2, URL_CONTEXTO], issuer: DID_KEY }), { vm: VM_DID_KEY }),
    "atributo-no-definido.json": await firmar(
      sinFirmar({ issuer: DID_KEY, sujeto: { ...SUJETO, apodo: "PRUEBA - Apodo no definido" } }), { vm: VM_DID_KEY }),
  };
}
export const serializar = (o) => JSON.stringify(o, null, 2) + "\n";

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const todo = await construir();
  if (process.argv.includes("--comprobar")) {
    const deriva = Object.entries(todo).filter(([f, o]) => {
      try { return readFileSync(join(DIR_CREDENCIALES, f), "utf8") !== serializar(o); } catch { return true; }
    }).map(([f]) => f);
    if (deriva.length) { console.error(`fixtures distintas de lo que genera generar.mjs: ${deriva.join(", ")}`); process.exit(1); }
    console.log("fixtures al día");
  } else {
    mkdirSync(DIR_CREDENCIALES, { recursive: true });
    for (const [f, o] of Object.entries(todo)) writeFileSync(join(DIR_CREDENCIALES, f), serializar(o));
    console.log(`escritas ${Object.keys(todo).length} fixtures en ${DIR_CREDENCIALES}`);
  }
}
