// Un «emisor simulado»: un servidor https local que sirve lo que serviría una
// institución (metadata, did.json, JWKS, contextos, logo, endpoint de emisión y
// el descubrimiento de su servidor de autorización) y que se puede torcer pieza
// por pieza para provocar cada fallo del diagnóstico.
//
// Por defecto TODO está bien: diagnosticar() contra él da 11 ✅.
//
//   const e = await emisorSimulado({
//     metadata: (m, base) => { m.credential_endpoint = base + "/otro"; },   // retocar la metadata
//     rutas: { "/credential": null },                                      // null = 404
//     rutas: { "/logos/prueba.png": { cuerpo: "<svg/>", tipo: "image/svg+xml" } },
//   });
//   await e.cerrar();
//
// Los contextos y servidores de W3C (www.w3.org, w3id.org) NO se piden a internet:
// la red de la prueba (redDeEmisor) los redirige a /ajenos/<host>/<ruta> de este
// mismo servidor, que los sirve de test/fixtures/contextos/.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { crearRed } from "../../diagnostico/red.mjs";
import { servidorHttps } from "./aislamiento.mjs";
import { DIR_CONTEXTOS, V1, V2, ED2020, ATRIBUTOS, TIPO, FECHA, CLAVE_PUBLICA_CRUDA, contextoPropio, didJson } from "../fixtures/generar.mjs";

export const PNG = Buffer.concat([Buffer.from("89504e470d0a1a0a", "hex"), Buffer.alloc(200, 1)]);
export const ETIQUETAS = { nombre_completo: "Nombre completo", numero_documento: "Documento", categoria: "Categoría", fecha_vencimiento: "Vence" };

const AJENOS = {
  "www.w3.org/2018/credentials/v1": "w3-credentials-v1.json",
  "www.w3.org/ns/credentials/v2": "w3-credentials-v2.json",
  "w3id.org/security/suites/ed25519-2020/v1": "w3id-ed25519-2020-v1.json",
};

// La metadata por defecto. Tipos y contextos ya en el orden alfabético que Certify busca.
export function metadataBase(base) {
  const contextos = [`${base}/contextos/prueba.json`, ED2020, V2];
  return {
    credential_issuer: base,
    credential_endpoint: `${base}/credential`,
    authorization_servers: [base],
    display: [{ name: "Emisor de pruebas", locale: "es" }],
    credential_configurations_supported: {
      CredencialPrueba: {
        format: "ldp_vc",
        scope: "credencial_prueba",
        credential_signing_alg_values_supported: ["Ed25519Signature2020"],
        cryptographic_binding_methods_supported: ["did:jwk"],
        credential_definition: {
          "@context": contextos,
          type: ["CredencialPrueba", "VerifiableCredential"],
          credentialSubject: Object.fromEntries(ATRIBUTOS.map((a) => [a, { display: [{ name: ETIQUETAS[a], locale: "es" }] }])),
        },
        display: [{ name: "Credencial de prueba", locale: "es", background_color: "#0E3B5C", text_color: "#FFFFFF",
          logo: { url: `${base}/logos/prueba.png`, alt_text: "Logo de prueba" } }],
        order: [...ATRIBUTOS],
      },
    },
  };
}

const json = (cuerpo, extra = {}) => ({ estado: 200, tipo: "application/json", cuerpo: JSON.stringify(cuerpo), ...extra });

export async function emisorSimulado({ metadata, rutas = {}, did, jwks } = {}) {
  let base = "";
  const porDefecto = () => {
    const m = metadataBase(base);
    metadata?.(m, base);
    const d = didJson(`did:web:localhost%3A${new URL(base).port}`);
    did?.(d, base);
    const k = { keys: [{ kty: "OKP", crv: "Ed25519", x: CLAVE_PUBLICA_CRUDA.toString("base64url") }] };
    jwks?.(k, base);
    const r = {
      "/.well-known/openid-credential-issuer": json(m),
      "/.well-known/openid-configuration": json({ issuer: base, authorization_endpoint: `${base}/authorize`, token_endpoint: `${base}/token` }),
      "/credential": { metodos: ["POST"], estado: 401, tipo: "application/json", cuerpo: JSON.stringify({ error: "invalid_token" }) },
      "/contextos/prueba.json": json(contextoPropio(`${base}/contextos/prueba.json`), { tipo: "application/ld+json", cache: "no-cache" }),
      "/logos/prueba.png": { estado: 200, tipo: "image/png", cuerpo: PNG },
      "/.well-known/did.json": json(d, { tipo: "application/did+ld+json" }),
      "/.well-known/jwks.json": json(k),
    };
    for (const [ruta, f] of Object.entries(AJENOS))
      r["/ajenos/" + ruta] = json(JSON.parse(readFileSync(join(DIR_CONTEXTOS, f), "utf8")), { tipo: "application/ld+json" });
    return r;
  };

  const srv = await servidorHttps((req, res) => {
    const ruta = new URL(req.url, "https://x").pathname;
    const tabla = { ...porDefecto(), ...rutas };
    let r = tabla[ruta];
    if (typeof r === "function") r = r(req, base);
    if (!r || (r.metodos && !r.metodos.includes(req.method))) { res.writeHead(r ? 405 : 404, { "content-type": "text/plain" }); return res.end("no"); }
    const cabeceras = { "content-type": r.tipo ?? "application/json" };
    if (r.cache) cabeceras["cache-control"] = r.cache;
    res.writeHead(r.estado ?? 200, { ...cabeceras, ...(r.cabeceras ?? {}) });
    res.end(r.cuerpo);
  });
  base = srv.base;
  return { ...srv, metadataUrl: `${base}/.well-known/openid-credential-issuer`, did: `did:web:localhost%3A${srv.puerto}` };
}

// La red con la que se diagnostica a un emisor simulado. Es la red de verdad
// (crearRed) con una sola trampa: lo de W3C se redirige a ESTE servidor. Cualquier
// otro host que no sea el servidor local o un nombre `.invalid` es un error de la prueba.
export function redDeEmisor(emisor, opciones = {}) {
  const real = crearRed({ espera: 3000, permitirPrivadas: true, ...opciones });
  const mapa = (url) => {
    let u;
    try { u = new URL(url); } catch { return url; }
    if (u.hostname === "www.w3.org" || u.hostname === "w3id.org") return `${emisor.base}/ajenos/${u.hostname}${u.pathname}`;
    return url;
  };
  return {
    traer: async (url, o) => {
      const real_url = mapa(url);
      const r = await real.traer(real_url, o);
      return { ...r, url }; // el motor ve la URL pública, no la de la trampa
    },
  };
}
