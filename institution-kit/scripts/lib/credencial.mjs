// Lógica de la credencial del kit: validación de entradas, contexto propio, plantilla,
// credencial de muestra y SQL. Node 22, sin dependencias (en el servidor se ejecuta dentro
// de `node:22-alpine`, ver `run_node` en common.sh).
//
// PROCEDENCIA. Es la traducción a un módulo de lo que hace
// `inji-vc/stack/bin/sembrar-credenciales.sh` (emisor propio de OGTIC, en producción con el
// diagnóstico 11/11), tomado el 4-oct-2026. Se copia: la forma del contexto (términos planos
// con `@type: xsd:string`, `@protected`), la plantilla VC 2.0 (`validFrom`/`validUntil`,
// `issuer: ${_issuer}`, `credentialSubject.id: ${_holderId}`), el orden de tipos y contextos
// y el UPSERT que conserva `status`. Se cambia: sin manifiesto (la entrada son variables de
// entorno del `.env`), sin `id`/`type` en el contexto (los define credentials/v2), sin
// `terminos_heredados`, y `ON CONFLICT` en lugar de `DELETE` + `INSERT`.
//
// POR QUÉ NO SE USA el contexto con alcance de tipo (`"<tipo>": {"@context": {attrs…}}`):
// ese contexto solo vale para el nodo que lleva el tipo (la credencial), no se propaga a
// `credentialSubject`, y la canonicalización descarta los tres atributos (medido en T2, ver
// el registro). Los atributos tienen que ser términos del nivel superior.

export const CTX_V2 = "https://www.w3.org/ns/credentials/v2";
export const CTX_ED2020 = "https://w3id.org/security/suites/ed25519-2020/v1";
export const CTX_V1 = "https://www.w3.org/2018/credentials/v1";

export class ErrorEntrada extends Error {}
const falla = (mensaje) => { throw new ErrorEntrada(mensaje); };

const NOMBRE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const CLAVE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

// Términos que un atributo (o un tipo) no puede usar porque ya los define otro contexto de la
// credencial: credentials/v2 y ed25519-2020/v1 (nivel superior y los del alcance de
// VerifiableCredential: issuer, validFrom…), las variables que Certify inyecta en la
// plantilla (`_issuer`, `_holderId`) y los prefijos que usa el contexto propio (`v`, `xsd`).
// Redefinir uno de los protegidos hace que la expansión falle en el verificador, no en el
// emisor, así que se rechaza aquí. La prueba `reservados cubren los contextos W3C` lo compara
// con las copias de los contextos en test/fixtures/contextos/.
export const RESERVADOS = new Set([
  "id", "type", "description", "digestMultibase", "digestSRI", "mediaType", "name",
  "VerifiableCredential", "EnvelopedVerifiableCredential", "VerifiablePresentation",
  "EnvelopedVerifiablePresentation", "JsonSchemaCredential", "JsonSchema",
  "BitstringStatusListCredential", "BitstringStatusList", "BitstringStatusListEntry",
  "DataIntegrityProof", "_sd", "_sd_alg", "aud", "cnf", "exp", "iat", "iss", "jku", "kid", "nbf",
  "sub", "x5u", "proof", "Ed25519VerificationKey2020", "Ed25519Signature2020",
  // del alcance de VerifiableCredential / VerifiablePresentation / DataIntegrityProof (v2)
  "credentialSubject", "issuer", "validFrom", "validUntil", "credentialStatus", "credentialSchema",
  "evidence", "termsOfUse", "refreshService", "relatedResource", "holder", "verifiableCredential",
  "cryptosuite", "challenge", "created", "domain", "expires", "nonce", "previousProof",
  "proofPurpose", "proofValue", "verificationMethod", "statusPurpose", "statusListCredential",
  "statusListIndex", "statusSize", "statusMessage", "encodedList", "ttl", "authentication",
  "assertionMethod", "confidenceMethod", "renderMethod", "jsonSchema", "statusReference", "jwk",
  "message", "status", "capabilityDelegation", "capabilityInvocation", "keyAgreement", "controller",
  "revoked", "publicKeyMultibase",
  // ligados a la plantilla y al contexto propio
  "_issuer", "_holderId", "v", "xsd",
]);

// `Collections.sort` de Java ordena Strings por unidades UTF-16, con mayúsculas antes que
// minúsculas; `Array.prototype.sort()` sin comparador hace exactamente eso. Es lo que usa
// `CredentialUtils.getTemplateName` en Certify para formar la clave de búsqueda. Un orden por
// idioma (`localeCompare`, `sort` de bash con otro LC_ALL) daría otro y Certify respondería
// «CredentialConfig not found» al emitir.
export const ordenarComoJava = (lista) => [...lista].sort();

function lista(texto, nombreVar) {
  const partes = String(texto).split(",").map((s) => s.trim());
  if (partes.some((p) => p === "")) falla(`${nombreVar} tiene un elemento vacío (¿una coma de más?): «${texto}».`);
  return partes;
}

function sinControl(valor, nombreVar) {
  if (CONTROL.test(valor)) falla(`${nombreVar} contiene caracteres de control (saltos de línea, tabuladores…).`);
  return valor;
}

function validarNombre(n, cual, nombreVar) {
  if (!NOMBRE.test(n)) {
    falla(`${cual} «${n}» no es válido en ${nombreVar}: solo letras sin acento, dígitos y «_», sin empezar por dígito `
      + `(nada de espacios, «:», «|» ni acentos). Ejemplo: numero_licencia. La etiqueta que se ve en la app va en CREDENTIAL_LABELS_JSON.`);
  }
  if (RESERVADOS.has(n)) {
    falla(`${cual} «${n}» en ${nombreVar} choca con un término que ya definen credentials/v2, la suite de firma o la plantilla `
      + `(p. ej. name, description, issuer, validFrom). Use otro nombre, como «${n}_institucion».`);
  }
}

// Lee y valida las variables del `.env`. `env` es process.env (o un objeto igual).
// `paraSql`: además exige CREDENTIAL_SCOPE (el contexto propio solo necesita clave, atributos y URL).
export function leerEntrada(env, { paraSql = false } = {}) {
  const pide = (v) => {
    const x = env[v];
    if (x === undefined || String(x).trim() === "") falla(`Falta la variable obligatoria ${v}.`);
    return String(x).trim();
  };

  const clave = pide("CREDENTIAL_CONFIG_KEY_ID");
  if (!CLAVE.test(clave)) {
    falla(`CREDENTIAL_CONFIG_KEY_ID «${clave}» no es válido: letras, dígitos, «_» y «-», sin espacios ni «/» `
      + `(es el nombre del fichero del contexto y parte de su URL).`);
  }

  let urlPublica = pide("CERTIFY_PUBLIC_URL").replace(/\/+$/, "");
  let u;
  try { u = new URL(urlPublica); } catch { falla(`CERTIFY_PUBLIC_URL «${urlPublica}» no es una URL.`); }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (!(u.protocol === "https:" || (u.protocol === "http:" && local)) || u.pathname !== "/" || u.search || u.hash || u.username) {
    falla(`CERTIFY_PUBLIC_URL «${urlPublica}» debe ser https://<dominio> sin ruta (http solo con localhost).`);
  }
  urlPublica = u.origin;

  const atributos = lista(pide("CREDENTIAL_ATTRIBUTES"), "CREDENTIAL_ATTRIBUTES");
  atributos.forEach((a) => validarNombre(a, "El atributo", "CREDENTIAL_ATTRIBUTES"));
  const dup = atributos.find((a, i) => atributos.indexOf(a) !== i);
  if (dup) falla(`El atributo «${dup}» está repetido en CREDENTIAL_ATTRIBUTES.`);

  // Tipos: siempre VerifiableCredential (sin él, credentials/v2 no activa issuer/validFrom…)
  // más al menos un tipo propio, que es por el que la app y Certify resuelven la credencial.
  const institucion = String(env.INSTITUTION_ID ?? "").trim();
  const tipoPorDefecto = `VerifiableCredential,${institucion}Credential`;
  const tiposEntrada = lista(env.CREDENTIAL_TYPE && String(env.CREDENTIAL_TYPE).trim() ? env.CREDENTIAL_TYPE : tipoPorDefecto, "CREDENTIAL_TYPE");
  const propios = [...new Set(tiposEntrada.filter((t) => t !== "VerifiableCredential"))];
  if (propios.length === 0) falla("CREDENTIAL_TYPE necesita al menos un tipo propio además de VerifiableCredential (o INSTITUTION_ID para el de por defecto).");
  propios.forEach((t) => validarNombre(t, "El tipo", "CREDENTIAL_TYPE"));
  const choque = propios.find((t) => atributos.includes(t));
  if (choque) falla(`«${choque}» es a la vez tipo y atributo.`);
  const tipos = ordenarComoJava(["VerifiableCredential", ...propios]);

  if (env.CREDENTIAL_ATTRIBUTE_LABELS && String(env.CREDENTIAL_ATTRIBUTE_LABELS).trim()) {
    falla("CREDENTIAL_ATTRIBUTE_LABELS (formato «attr:Etiqueta», que truncaba las etiquetas con «:») ya no se admite. "
      + "Use CREDENTIAL_LABELS_JSON='{\"attr\":\"Etiqueta\"}'.");
  }
  let etiquetas = {};
  if (env.CREDENTIAL_LABELS_JSON && String(env.CREDENTIAL_LABELS_JSON).trim()) {
    let j;
    try { j = JSON.parse(env.CREDENTIAL_LABELS_JSON); } catch (e) { falla(`CREDENTIAL_LABELS_JSON no es JSON válido: ${e.message}.`); }
    if (j === null || typeof j !== "object" || Array.isArray(j)) falla('CREDENTIAL_LABELS_JSON debe ser un objeto {"atributo":"Etiqueta"}.');
    for (const [k, v] of Object.entries(j)) {
      if (!atributos.includes(k)) falla(`CREDENTIAL_LABELS_JSON habla de «${k}», que no está en CREDENTIAL_ATTRIBUTES (¿errata?).`);
      if (typeof v !== "string" || v.trim() === "") falla(`CREDENTIAL_LABELS_JSON: la etiqueta de «${k}» debe ser un texto no vacío.`);
      sinControl(v, "CREDENTIAL_LABELS_JSON");
    }
    etiquetas = j;
  }

  const formato = String(env.CREDENTIAL_FORMAT ?? "").trim() || "ldp_vc";
  if (formato !== "ldp_vc") falla(`CREDENTIAL_FORMAT «${formato}» no es compatible con este kit: solo ldp_vc (firma Ed25519Signature2020).`);

  const host = u.host;
  const texto = (v, defecto) => sinControl(String(env[v] ?? "").trim() || defecto, v);
  return {
    clave, urlPublica, atributos, tipos, tiposPropios: ordenarComoJava(propios), etiquetas, formato,
    urlContexto: `${urlPublica}/contextos/${clave}.json`,
    didUrl: texto("DID_URL", `did:web:${host}`),
    nombreVisible: texto("CREDENTIAL_DISPLAY_NAME", texto("INSTITUTION_DISPLAY_NAME", clave)),
    // R10: el logo lo sirve el propio kit (scripts/generate-logo.sh copia LOGO_PATH a esa ruta).
    logoUrl: `${urlPublica}/logos/${clave}.png`,
    colorFondo: texto("CREDENTIAL_BG_COLOR", "#12107c"),
    colorTexto: texto("CREDENTIAL_TEXT_COLOR", "#FFFFFF"),
    scope: paraSql ? sinControl(pide("CREDENTIAL_SCOPE"), "CREDENTIAL_SCOPE") : "",
  };
}

// Los tres contextos (D3). Dos órdenes, a propósito (es lo que hace sembrar-credenciales.sh):
//  - COLUMNA `credential_config.context`: ordenados como Java, porque Certify ordena antes de
//    buscar la configuración (`CredentialUtils.getTemplateName`). Con host «emisor…» queda
//    [propio, suite, v2]; el orden depende del dominio.
//  - PLANTILLA (el `@context` de la credencial emitida): credentials/v2 PRIMERO, como exige VCDM 2.0
//    y comprueba el diagnóstico de OGTIC («m_contexto») y los verificadores de las apps: un
//    @context propio o de suite antes del de W3C hace fallar al verificador aunque la firma sea
//    válida. Después el propio y, al final, la suite.
export const contextosOrdenados = (e) => ordenarComoJava([CTX_ED2020, CTX_V2, e.urlContexto]);
export const contextosPlantilla = (e) => [CTX_V2, e.urlContexto, CTX_ED2020];

// Contexto propio: un término por atributo, en el nivel superior y con @protected.
export function construirContexto(e) {
  const ctx = {
    "@version": 1.1,
    "@protected": true,
    v: `${e.urlContexto}#`,
    xsd: "http://www.w3.org/2001/XMLSchema#",
  };
  for (const t of e.tiposPropios) ctx[t] = `v:${t}`;
  for (const a of e.atributos) ctx[a] = { "@id": `v:${a}`, "@type": "xsd:string" };
  return { "@context": ctx };
}

// Plantilla Velocity (VC 2.0). El orden del @context es el de contextosPlantilla; `type` lleva
// VerifiableCredential primero y los propios después (igual que el emisor propio; el orden de
// `type` no afecta a la firma y la búsqueda de Certify usa la columna, ya ordenada).
export function construirPlantilla(e) {
  return {
    "@context": contextosPlantilla(e),
    issuer: "${_issuer}",
    type: ["VerifiableCredential", ...e.tiposPropios],
    validFrom: "${validFrom}",
    validUntil: "${validUntil}",
    credentialSubject: { id: "${_holderId}", ...Object.fromEntries(e.atributos.map((a) => [a, "${" + a + "}"])) },
  };
}

// Valor ficticio por atributo (ningún dato personal real). Distinto para cada atributo, para
// que la prueba de cobertura pueda buscar cada valor entre las cuádruplas.
export function valorDeMuestra(atributo) {
  const a = atributo.toLowerCase();
  if (/(cedula|national_?id|identificacion|documento)/.test(a)) return "000-0000000-0";
  if (/(apellido|surname|last_?name)/.test(a)) return "Apellido de Prueba";
  if (/(nombre|name)/.test(a)) return "Nombre de Prueba";
  if (/(fecha|date|nacimiento|birth|emision|issue|expir|vence)/.test(a)) return "2000-01-01";
  return `Valor de prueba de ${atributo}`;
}

export function construirMuestra(e) {
  const vistos = new Set();
  const sujeto = { id: "did:example:titular-de-prueba" };
  for (const a of e.atributos) {
    let v = valorDeMuestra(a);
    if (vistos.has(v)) v = `${v} (${a})`; // dos atributos con el mismo valor ficticio no se distinguirían
    vistos.add(v);
    sujeto[a] = v;
  }
  return {
    "@context": contextosPlantilla(e),
    issuer: e.didUrl,
    type: ["VerifiableCredential", ...e.tiposPropios],
    validFrom: "2026-01-01T00:00:00Z",
    validUntil: "2027-01-01T00:00:00Z",
    credentialSubject: sujeto,
  };
}

const q = (s) => `'${String(s).replaceAll("'", "''")}'`;
const arr = (xs) => `ARRAY[${xs.map(q).join(",")}]`;
const json = (o) => `${q(JSON.stringify(o))}::JSONB`;

// Columnas de credential_config en el orden del INSERT. `valores` las trae ya como literal SQL.
export function construirSql(e) {
  const plantilla = Buffer.from(JSON.stringify(construirPlantilla(e)), "utf8").toString("base64");
  const display = [{
    name: e.nombreVisible, locale: "es",
    logo: { url: e.logoUrl, alt_text: e.nombreVisible },
    background_color: e.colorFondo, text_color: e.colorTexto,
  }];
  const sujeto = Object.fromEntries(e.atributos.map((a) => [a, { display: [{ name: e.etiquetas[a] ?? a, locale: "es" }] }]));
  const columnas = [
    ["credential_config_key_id", q(e.clave)],
    ["config_id", q(e.clave)],
    ["status", q("active")],
    ["vc_template", q(plantilla)],
    ["doctype", "NULL"],
    ["sd_jwt_vct", "NULL"],
    ["context", q(contextosOrdenados(e).join(","))],
    ["credential_type", q(e.tipos.join(","))],
    ["credential_format", q(e.formato)],
    ["did_url", q(e.didUrl)],
    ["key_manager_app_id", q("CERTIFY_VC_SIGN_ED25519")],
    ["key_manager_ref_id", q("ED25519_SIGN")],
    ["signature_algo", q("EdDSA")],
    ["signature_crypto_suite", q("Ed25519Signature2020")],
    ["sd_claim", "NULL"],
    ["display", json(display)],
    ["display_order", arr(e.atributos)],
    ["scope", q(e.scope)],
    ["cryptographic_binding_methods_supported", "ARRAY['did:jwk']"],
    ["credential_signing_alg_values_supported", "ARRAY['Ed25519Signature2020']"],
    ["proof_types_supported", `'{"jwt": {"proof_signing_alg_values_supported": ["RS256", "ES256"]}}'::JSONB`],
    ["credential_subject", json(sujeto)],
    ["sd_jwt_claims", "NULL"],
    ["mso_mdoc_claims", "NULL"],
    ["plugin_configurations", "NULL"],
    ["credential_status_purpose", "ARRAY['revocation']"],
    ["qr_settings", "NULL"],
    ["qr_signature_algo", "NULL"],
    ["cr_dtimes", "NOW()"],
    ["upd_dtimes", "NULL"],
  ];
  // En el UPSERT se actualiza todo salvo la clave, `cr_dtimes` (fecha de creación) y `status`
  // (si la institución puso la credencial en `inactive`, re-aplicar no la reactiva); `config_id`
  // sí, para que una fila creada por el kit anterior (UUID aleatorio) pase a ser determinista.
  const actualizar = columnas
    .map(([c]) => c)
    .filter((c) => !["credential_config_key_id", "cr_dtimes", "status", "upd_dtimes"].includes(c))
    .map((c) => `    ${c} = EXCLUDED.${c}`);
  actualizar.push("    status = certify.credential_config.status");
  actualizar.push("    upd_dtimes = NOW()");
  return [
    `-- Generado por scripts/generate-credential-sql.sh: no editar a mano. Credencial ${e.clave}.`,
    "-- Idempotente: se puede aplicar las veces que haga falta (scripts/apply-credential.sh).",
    "INSERT INTO certify.credential_config (",
    columnas.map(([c]) => `    ${c}`).join(",\n"),
    ") VALUES (",
    columnas.map(([, v]) => `    ${v}`).join(",\n"),
    ")",
    "ON CONFLICT (credential_config_key_id) DO UPDATE SET",
    actualizar.join(",\n") + ";",
    "",
  ].join("\n");
}
