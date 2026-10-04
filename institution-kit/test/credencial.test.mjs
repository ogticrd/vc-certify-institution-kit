// T2 · La credencial que genera el kit: orden (R2), contexto propio (R1), plantilla VC 2.0 (R3),
// SQL idempotente (R7) y, sobre todo, COBERTURA DE FIRMA: con el @context generado, cada atributo
// aparece en las cuádruplas RDF (100 %); con el @context viejo del kit (solo credentials/v1), ninguno (0 %).
// La canonicalización es la del diagnóstico de OGTIC (diagnostico/jsonld.mjs), con los contextos
// leídos DESDE DISCO (test/fixtures/contextos/ y el contexto que el propio kit generó): sin red.
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, mkdirSync, writeFileSync, chmodSync, realpathSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { prepararEntorno, valoresSql, literal, plantillaDesdeSql, KIT_ORIGEN } from "./helpers/entorno.mjs";
import { canonizarDocumento } from "../diagnostico/jsonld.mjs";
import { RESERVADOS, ordenarComoJava, CTX_V1, CTX_V2, CTX_ED2020 } from "../scripts/lib/credencial.mjs";

const AQUI = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(AQUI, "fixtures", "contextos");
const leerJson = (r) => JSON.parse(readFileSync(r, "utf8"));
const V1_DOC = leerJson(join(FIXTURES, "w3-credentials-v1.json"));
const V2_DOC = leerJson(join(FIXTURES, "w3-credentials-v2.json"));
const ED_DOC = leerJson(join(FIXTURES, "w3id-ed25519-2020-v1.json"));

// Genera con el kit y devuelve el entorno (con .limpiar()).
const generar = (extra = {}, modo = "domain") => {
  const e = prepararEntorno({ modo, extra, runtime: false });
  assert.equal(e.salida.status, 0, e.salida.stderr);
  return e;
};
const conEntorno = (extra, fn) => { const e = generar(extra); try { return fn(e); } finally { e.limpiar(); } };

// documentLoader «desde disco»: los dos contextos W3C vienen de test/fixtures y el propio del
// fichero que generó el kit. Pedir cualquier otra URL falla: nada sale a la red.
const cargadorDeDisco = (urlPropia, ficheroPropio, w3 = new Map([[CTX_V1, V1_DOC], [CTX_V2, V2_DOC], [CTX_ED2020, ED_DOC]])) => async (url) => {
  if (url === urlPropia) return leerJson(ficheroPropio);
  if (w3.has(url)) return structuredClone(w3.get(url));
  throw new Error(`contexto inesperado (no hay copia local): ${url}`);
};

const esIri = (t, valor) => t.tipo === "iri" && t.valor === valor;
// Cuántos atributos aparecen como predicado de alguna cuádrupla con su valor de muestra.
function cobertura(cuads, muestra, urlContexto) {
  const attrs = Object.keys(muestra.credentialSubject).filter((k) => k !== "id");
  const cubiertos = attrs.filter((a) =>
    cuads.some((q) => esIri(q.p, `${urlContexto}#${a}`) && q.o.valor === muestra.credentialSubject[a]));
  return { attrs, cubiertos };
}

describe("R2 · orden de tipos y contextos (Collections.sort de Java)", () => {
  test("CREDENTIAL_TYPE=zetaCredential,VerifiableCredential se guarda como VerifiableCredential,zetaCredential", () => {
    conEntorno({ CREDENTIAL_TYPE: "zetaCredential,VerifiableCredential" }, (e) => {
      assert.equal(literal(valoresSql(e.leer("sql")).credential_type), "VerifiableCredential,zetaCredential");
    });
  });

  test("el orden es por unidades UTF-16 (mayúsculas antes que minúsculas), no el de ningún idioma", () => {
    // 'A' < 'V' < 'z': con un orden por idioma (localeCompare) «pruebaCredential» iría antes que «VerifiableCredential».
    conEntorno({ CREDENTIAL_TYPE: "zetaCredential,AlfaCredential,VerifiableCredential" }, (e) => {
      assert.equal(literal(valoresSql(e.leer("sql")).credential_type), "AlfaCredential,VerifiableCredential,zetaCredential");
    });
    assert.deepEqual(["VerifiableCredential", "pruebaCredential"].sort(), ["VerifiableCredential", "pruebaCredential"]);
    assert.deepEqual(["VerifiableCredential", "pruebaCredential"].sort((a, b) => a.localeCompare(b, "es")), ["pruebaCredential", "VerifiableCredential"]);
    assert.deepEqual(ordenarComoJava(["b", "B", "a", "A", "_x"]), ["A", "B", "_x", "a", "b"]);
  });

  test("VerifiableCredential se añade si falta y los duplicados se quitan", () => {
    conEntorno({ CREDENTIAL_TYPE: "zetaCredential,zetaCredential" }, (e) => {
      assert.equal(literal(valoresSql(e.leer("sql")).credential_type), "VerifiableCredential,zetaCredential");
    });
  });

  test("sin CREDENTIAL_TYPE, el tipo por defecto es VerifiableCredential,<INSTITUTION_ID>Credential", () => {
    conEntorno({}, (e) => {
      assert.equal(literal(valoresSql(e.leer("sql")).credential_type), "VerifiableCredential,pruebaCredential");
    });
  });

  test("la columna context son los tres contextos de D3 ordenados, y el orden depende del dominio", () => {
    for (const host of ["emisor.prueba.invalid", "zeta.prueba.invalid", "www.prueba.invalid"]) {
      conEntorno({ CERTIFY_PUBLIC_HOST: host }, (e) => {
        const propio = `https://${host}/contextos/PruebaLicencia.json`;
        const esperado = [CTX_ED2020, CTX_V2, propio].sort();
        assert.equal(literal(valoresSql(e.leer("sql")).context), esperado.join(","), host);
        assert.equal(esperado.length, 3);
      });
    }
    // con «emisor…» el propio queda ANTES que la suite y que v2; con «zeta…», después: no hay un orden fijo.
    assert.notDeepEqual(
      [CTX_ED2020, CTX_V2, "https://emisor.x/contextos/k.json"].sort().indexOf("https://emisor.x/contextos/k.json"),
      [CTX_ED2020, CTX_V2, "https://zeta.x/contextos/k.json"].sort().indexOf("https://zeta.x/contextos/k.json"));
  });

  test("tipos y contexto de la columna coinciden con lo que Certify busca (misma ordenación sobre los valores guardados)", () => {
    conEntorno({ CREDENTIAL_TYPE: "ZetaCredential,VerifiableCredential" }, (e) => {
      const v = valoresSql(e.leer("sql"));
      for (const col of ["credential_type", "context"]) {
        const partes = literal(v[col]).split(",");
        assert.deepEqual(partes, [...partes].sort(), `${col} no está ordenada`);
      }
    });
  });
});

describe("R1 · contexto propio generado", () => {
  test("define un término por atributo (nivel superior), con @protected y @version 1.1; no declara id ni type", () => {
    conEntorno({}, (e) => {
      const { "@context": c } = leerJson(e.rutas.contexto);
      assert.equal(c["@version"], 1.1);
      assert.equal(c["@protected"], true);
      assert.equal(c.v, "https://emisor.prueba.invalid/contextos/PruebaLicencia.json#");
      assert.equal(c.pruebaCredential, "v:pruebaCredential");
      for (const a of ["nombre", "apellido", "numeroLicencia"]) {
        assert.deepEqual(c[a], { "@id": `v:${a}`, "@type": "xsd:string" }, a);
      }
      assert.deepEqual(Object.keys(c).sort(), ["@protected", "@version", "apellido", "nombre", "numeroLicencia", "pruebaCredential", "v", "xsd"]);
      assert.equal("id" in c, false);
      assert.equal("type" in c, false);
    });
  });

  test("la forma con alcance de tipo NO se usa: ningún atributo vive dentro de un @context anidado", () => {
    conEntorno({}, (e) => {
      const { "@context": c } = leerJson(e.rutas.contexto);
      for (const valor of Object.values(c)) {
        if (valor && typeof valor === "object") assert.equal("@context" in valor, false);
      }
    });
  });

  test("determinista: generar dos veces da el mismo fichero", () => {
    conEntorno({}, (e) => {
      const antes = readFileSync(e.rutas.contexto, "utf8");
      const r = e.ejecutar('bash "$PWD/scripts/generate-context.sh"');
      assert.equal(r.status, 0, r.stderr);
      assert.equal(readFileSync(e.rutas.contexto, "utf8"), antes);
    });
  });

  test("generate-context.mjs solo necesita clave, atributos y URL pública (entrada mínima de la spec)", () => {
    const e = prepararEntorno({ runtime: false, generar: false });
    try {
      const r = e.ejecutar(
        'CREDENTIAL_CONFIG_KEY_ID=K1 CREDENTIAL_ATTRIBUTES=a_1,b2 CERTIFY_PUBLIC_URL=https://x.prueba.invalid/ INSTITUTION_ID=prueba '
        + 'node scripts/generate-context.mjs salida');
      assert.equal(r.status, 0, r.stderr);
      const { "@context": c } = leerJson(join(e.kit, "salida", "contextos", "K1.json"));
      assert.equal(c.v, "https://x.prueba.invalid/contextos/K1.json#"); // la barra final sobra y se quita
      assert.deepEqual(Object.keys(c).filter((k) => !k.startsWith("@")), ["v", "xsd", "pruebaCredential", "a_1", "b2"]);
    } finally { e.limpiar(); }
  });

  test("la URL del contexto sale de CERTIFY_PUBLIC_URL (modo ip)", () => {
    const e = prepararEntorno({ modo: "ip", runtime: false });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      const { "@context": c } = leerJson(e.rutas.contexto);
      assert.equal(c.v, "https://203-0-113-10.sslip.io/contextos/PruebaLicencia.json#");
      assert.match(literal(valoresSql(e.leer("sql")).context), /https:\/\/203-0-113-10\.sslip\.io\/contextos\/PruebaLicencia\.json/);
    } finally { e.limpiar(); }
  });

  test("los términos reservados cubren los contextos W3C (v2 y suite): ningún atributo puede pisarlos", () => {
    const nombres = new Set();
    const recoger = (ctx) => {
      for (const [k, v] of Object.entries(ctx)) {
        if (k.startsWith("@") || k === "...") continue;
        nombres.add(k);
        if (v && typeof v === "object" && v["@context"] && typeof v["@context"] === "object") recoger(v["@context"]);
      }
    };
    recoger(V2_DOC["@context"]); recoger(ED_DOC["@context"]);
    const sinCubrir = [...nombres].filter((n) => !RESERVADOS.has(n));
    assert.deepEqual(sinCubrir, [], `faltan en RESERVADOS: ${sinCubrir.join(", ")}`);
  });
});

describe("R1 · atributos y nombres inválidos: error en español, salida distinta de cero, nada generado", () => {
  const casos = [
    ["numero licencia", /«numero licencia».*no es válido.*nada de espacios/s],
    ["a:b", /«a:b».*no es válido/s],
    ["a|b", /«a\|b».*no es válido/s],
    ["número", /«número».*no es válido/s],
    ["1abc", /«1abc».*no es válido/s],
    ["nombre,name", /«name».*choca con un término/s],
    ["nombre,validFrom", /«validFrom».*choca con un término/s],
    ["nombre,_holderId", /«_holderId».*choca con un término/s],
    ["nombre,nombre", /«nombre» está repetido/],
    ["nombre,,apellido", /elemento vacío/],
    ["nombre,", /elemento vacío/],
  ];
  for (const [attrs, mensaje] of casos) {
    test(`CREDENTIAL_ATTRIBUTES=${JSON.stringify(attrs)}`, () => {
      const e = prepararEntorno({ extra: { CREDENTIAL_ATTRIBUTES: attrs }, runtime: false });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /^ERROR: /m);
        assert.match(e.salida.stderr, mensaje);
        assert.equal(e.existe("contexto"), false);
        assert.equal(e.existe("sql"), false);
        assert.equal(e.existe("muestra"), false);
      } finally { e.limpiar(); }
    });
  }

  test("generate-context.sh por sí solo también falla con atributo inválido (no deja contexto)", () => {
    const e = prepararEntorno({ extra: { CREDENTIAL_ATTRIBUTES: "a:b" }, runtime: false, generar: false });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/generate-context.sh"');
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /«a:b»/);
      assert.equal(e.existe("contexto"), false);
    } finally { e.limpiar(); }
  });

  test("clave de credencial con «/» o espacios, CERTIFY_PUBLIC_URL con ruta y formato distinto de ldp_vc se rechazan", () => {
    const rechazos = [
      [{ CREDENTIAL_CONFIG_KEY_ID: "../x" }, /CREDENTIAL_CONFIG_KEY_ID/],
      [{ CREDENTIAL_CONFIG_KEY_ID: "mi clave" }, /CREDENTIAL_CONFIG_KEY_ID/],
      [{ CREDENTIAL_FORMAT: "vc+sd-jwt" }, /CREDENTIAL_FORMAT/],
      [{ CREDENTIAL_TYPE: "VerifiableCredential" }, /al menos un tipo propio/],
      [{ CREDENTIAL_TYPE: "Mi Tipo,VerifiableCredential" }, /«Mi Tipo»/],
      [{ CREDENTIAL_SCOPE: "openid\nprofile" }, /caracteres de control/],
    ];
    for (const [extra, mensaje] of rechazos) {
      const e = prepararEntorno({ extra, runtime: false });
      try {
        assert.notEqual(e.salida.status, 0, JSON.stringify(extra));
        assert.match(e.salida.stderr, mensaje, JSON.stringify(extra));
      } finally { e.limpiar(); }
    }
  });

  test("CREDENTIAL_ATTRIBUTE_LABELS (formato antiguo con «:») se rechaza explicando el cambio", () => {
    const e = prepararEntorno({ extra: { CREDENTIAL_ATTRIBUTE_LABELS: "nombre:Nombre" }, runtime: false });
    try {
      assert.notEqual(e.salida.status, 0);
      assert.match(e.salida.stderr, /CREDENTIAL_LABELS_JSON/);
    } finally { e.limpiar(); }
  });

  test("CREDENTIAL_LABELS_JSON inválido, con atributo desconocido o con etiqueta vacía se rechaza", () => {
    for (const [json, mensaje] of [
      ["{no es json", /no es JSON válido/],
      ['["a"]', /debe ser un objeto/],
      ['{"nombre_mal":"X"}', /«nombre_mal».*no está en CREDENTIAL_ATTRIBUTES/],
      ['{"nombre":""}', /etiqueta de «nombre»/],
      ['{"nombre":3}', /etiqueta de «nombre»/],
    ]) {
      const e = prepararEntorno({ extra: { CREDENTIAL_LABELS_JSON: json }, runtime: false });
      try {
        assert.notEqual(e.salida.status, 0, json);
        assert.match(e.salida.stderr, mensaje, json);
      } finally { e.limpiar(); }
    }
  });
});

describe("R7 · SQL idempotente (UPSERT por la clave única de credential_config)", () => {
  test("config_id = CREDENTIAL_CONFIG_KEY_ID, ON CONFLICT sobre credential_config_key_id y status conservado", () => {
    conEntorno({}, (e) => {
      const sql = e.leer("sql");
      const v = valoresSql(sql);
      assert.equal(literal(v.credential_config_key_id), "PruebaLicencia");
      assert.equal(literal(v.config_id), "PruebaLicencia");
      assert.doesNotMatch(sql, /gen_random_uuid/);
      assert.match(sql, /\nON CONFLICT \(credential_config_key_id\) DO UPDATE SET\n/);
      const set = sql.split("DO UPDATE SET\n")[1];
      assert.match(set, /^ {4}status = certify\.credential_config\.status,$/m);
      assert.doesNotMatch(set, /status = EXCLUDED/);
      assert.match(set, /^ {4}upd_dtimes = NOW\(\);$/m);
      assert.doesNotMatch(set, /cr_dtimes/); // la fecha de creación no cambia al re-aplicar
      assert.doesNotMatch(set, /credential_config_key_id/);
    });
  });

  test("la clave única real de la tabla es credential_config_key_id (y la PK, config_id)", () => {
    const esquema = readFileSync(join(KIT_ORIGEN, "sql", "00-schema.sql"), "utf8");
    const tabla = esquema.match(/CREATE TABLE IF NOT EXISTS certify\.credential_config \(([\s\S]*?)\n\);/)[1];
    assert.match(tabla, /credential_config_key_id VARCHAR\(2048\) NOT NULL UNIQUE,/);
    assert.match(tabla, /CONSTRAINT pk_config_id PRIMARY KEY \(config_id\)/);
  });

  test("el INSERT cubre todas las columnas del esquema y el SET actualiza todas menos clave, status y cr_dtimes", () => {
    const esquema = readFileSync(join(KIT_ORIGEN, "sql", "00-schema.sql"), "utf8");
    const tabla = esquema.match(/CREATE TABLE IF NOT EXISTS certify\.credential_config \(([\s\S]*?)\n\);/)[1];
    const delEsquema = tabla.split("\n").map((l) => l.trim()).filter((l) => /^[a-z_]+ [A-Z]/.test(l) && !l.startsWith("CONSTRAINT"))
      .map((l) => l.split(" ")[0]);
    conEntorno({}, (e) => {
      const sql = e.leer("sql");
      const delInsert = sql.match(/INSERT INTO certify\.credential_config \(([\s\S]*?)\) VALUES/)[1].split(",").map((c) => c.trim());
      assert.deepEqual(delInsert, delEsquema);
      const set = [...sql.split("DO UPDATE SET\n")[1].matchAll(/^ {4}([a-z_]+) = /gm)].map((m) => m[1]);
      assert.deepEqual(set.sort(), delEsquema.filter((c) => !["credential_config_key_id", "cr_dtimes"].includes(c)).sort());
    });
  });

  test("las comillas y metacaracteres de las etiquetas y del nombre no rompen el SQL ni se interpretan", () => {
    const sucio = "O'Brien'); DROP TABLE certify.credential_config;-- \\n $$";
    conEntorno({ CREDENTIAL_LABELS_JSON: JSON.stringify({ nombre: sucio }), CREDENTIAL_DISPLAY_NAME: sucio }, (e) => {
      const sql = e.leer("sql");
      const v = valoresSql(sql);
      assert.equal(JSON.parse(literal(v.credential_subject)).nombre.display[0].name, sucio);
      assert.equal(JSON.parse(literal(v.display))[0].name, sucio);
      // Todas las comillas simples del texto sucio van duplicadas: no queda ninguna que cierre el literal.
      assert.ok(sql.includes("O''Brien''); DROP TABLE"));
      assert.doesNotMatch(sql.replaceAll("''", ""), /[^'\\]'\);\s*DROP/);
      // el texto aparece en subject, display.name y logo.alt_text, siempre dentro de un literal JSON entero en su línea
      const lineas = sql.split("\n").filter((l) => l.includes("DROP TABLE"));
      assert.equal(lineas.length, 2);
      for (const l of lineas) assert.match(l, /^ {4}'[[{].*[\]}]'::JSONB,$/);
    });
  });

  test("display_order y credential_subject siguen el orden de CREDENTIAL_ATTRIBUTES; etiqueta por defecto = nombre", () => {
    conEntorno({ CREDENTIAL_LABELS_JSON: '{"numeroLicencia":"Número: de licencia"}' }, (e) => {
      const v = valoresSql(e.leer("sql"));
      assert.equal(v.display_order, "ARRAY['nombre','apellido','numeroLicencia']");
      const s = JSON.parse(literal(v.credential_subject));
      assert.deepEqual(Object.keys(s), ["nombre", "apellido", "numeroLicencia"]);
      assert.equal(s.nombre.display[0].name, "nombre");
      assert.equal(s.numeroLicencia.display[0].name, "Número: de licencia");
    });
  });
});

describe("R3 · plantilla VC 2.0", () => {
  test("validFrom/validUntil, issuer y titular como variables Velocity, un $!{_esc.java($atributo)} por atributo (K9), sin issuanceDate", () => {
    conEntorno({}, (e) => {
      const t = plantillaDesdeSql(e.leer("sql"));
      assert.deepEqual(Object.keys(t), ["@context", "issuer", "type", "validFrom", "validUntil", "credentialSubject"]);
      assert.equal(t.issuer, "${_issuer}");
      assert.equal(t.validFrom, "${validFrom}");
      assert.equal(t.validUntil, "${validUntil}");
      assert.deepEqual(t.credentialSubject, {
        id: "${_holderId}", nombre: "$!{_esc.java($nombre)}", apellido: "$!{_esc.java($apellido)}", numeroLicencia: "$!{_esc.java($numeroLicencia)}",
      });
      assert.deepEqual(t.type, ["VerifiableCredential", "pruebaCredential"]);
    });
  });

  test("el @context de la plantilla lleva credentials/v2 PRIMERO (VCDM 2.0; el diagnóstico exige el W3C el primero)", () => {
    conEntorno({ CERTIFY_PUBLIC_HOST: "emisor.prueba.invalid" }, (e) => {
      const ctx = plantillaDesdeSql(e.leer("sql"))["@context"];
      assert.deepEqual(ctx, [CTX_V2, "https://emisor.prueba.invalid/contextos/PruebaLicencia.json", CTX_ED2020]);
      // En la columna, con este dominio, el orden de Java pone el contexto propio primero: por eso plantilla y columna difieren a propósito.
      assert.notDeepEqual(literal(valoresSql(e.leer("sql")).context).split(","), ctx);
    });
  });
});

describe("cobertura de firma: con el @context generado, 100 %; con el viejo del kit, 0 %", () => {
  // Una credencial con el @context VIEJO del kit (solo credentials/v1), tal como la emitía la plantilla anterior.
  const credencialVieja = (muestra) => ({
    "@context": [CTX_V1],
    issuer: muestra.issuer,
    type: [...muestra.type].sort(),
    issuanceDate: muestra.validFrom,
    expirationDate: muestra.validUntil,
    credentialSubject: muestra.credentialSubject,
  });

  for (const [modo, host] of [["domain", "emisor.prueba.invalid"], ["domain", "zeta.prueba.invalid"], ["ip", "203-0-113-10.sslip.io"]]) {
    test(`${modo} · ${host}: 3 de 3 atributos en las cuádruplas con el contexto nuevo; 0 de 3 con el viejo`, async (t) => {
      const e = generar(modo === "domain" ? { CERTIFY_PUBLIC_HOST: host } : {}, modo);
      try {
        const muestra = leerJson(e.rutas.muestra);
        const urlPropia = `https://${host}/contextos/PruebaLicencia.json`;
        assert.deepEqual(muestra["@context"], [CTX_V2, urlPropia, CTX_ED2020]);
        const cargar = cargadorDeDisco(urlPropia, e.rutas.contexto);

        // NUEVO
        const nuevo = await canonizarDocumento(muestra, { cargar });
        const cNuevo = cobertura(nuevo.cuads, muestra, urlPropia);
        assert.deepEqual(nuevo.descartados, [], "ningún término descartado");
        assert.equal(cNuevo.attrs.length, 3);
        assert.deepEqual(cNuevo.cubiertos, cNuevo.attrs, "cobertura 100 %");
        // Además del atributo, el tipo propio y las fechas están en el RDF.
        assert.ok(nuevo.cuads.some((q) => esIri(q.o, `${urlPropia}#pruebaCredential`)), "el tipo propio está definido");
        assert.ok(nuevo.cuads.some((q) => esIri(q.p, "https://www.w3.org/2018/credentials#validFrom")));

        // El orden de la COLUMNA tampoco rompe la cobertura (un verificador lo vería así si alguien lo usara).
        const reordenada = { ...muestra, "@context": ordenarComoJava(muestra["@context"]) };
        const ord = await canonizarDocumento(reordenada, { cargar });
        assert.deepEqual(cobertura(ord.cuads, muestra, urlPropia).cubiertos, cNuevo.attrs, "cobertura 100 % con el orden de la columna");
        assert.deepEqual(ord.descartados, []);

        // VIEJO (la prueba negativa: demuestra el defecto que se corrige)
        const vieja = credencialVieja(muestra);
        const viejo = await canonizarDocumento(vieja, { cargar });
        const cViejo = cobertura(viejo.cuads, muestra, urlPropia);
        assert.deepEqual(cViejo.cubiertos, [], "cobertura 0 %");
        const valores = Object.values(muestra.credentialSubject);
        assert.equal(viejo.cuads.filter((q) => valores.includes(q.o.valor) && q.o.valor !== muestra.credentialSubject.id).length, 0,
          "ningún valor de atributo aparece en las cuádruplas");
        assert.deepEqual(viejo.descartados.map((d) => d.termino).sort(), ["apellido", "nombre", "numeroLicencia"]);
        assert.ok(viejo.cuads.length < nuevo.cuads.length);

        t.diagnostic(`cuádruplas con el contexto generado: ${nuevo.cuads.length} (${cNuevo.cubiertos.length}/${cNuevo.attrs.length} atributos); `
          + `con el viejo (credentials/v1): ${viejo.cuads.length} (${cViejo.cubiertos.length}/${cViejo.attrs.length} atributos)`);
      } finally { e.limpiar(); }
    });
  }

  test("también con más atributos y nombres con guion bajo, dígitos y mayúsculas, y etiquetas con acentos", async (t) => {
    const attrs = "national_id,full_name,fechaNacimiento,Estado_Civil2,_interno,lugar_de_nacimiento";
    const e = generar({ CREDENTIAL_ATTRIBUTES: attrs, CREDENTIAL_LABELS_JSON: '{"national_id":"Cédula","full_name":"Nombre: completo"}' });
    try {
      const muestra = leerJson(e.rutas.muestra);
      const urlPropia = "https://emisor.prueba.invalid/contextos/PruebaLicencia.json";
      const r = await canonizarDocumento(muestra, { cargar: cargadorDeDisco(urlPropia, e.rutas.contexto) });
      const c = cobertura(r.cuads, muestra, urlPropia);
      assert.equal(c.attrs.length, 6);
      assert.deepEqual(c.cubiertos, c.attrs);
      assert.deepEqual(r.descartados, []);
      // valores de muestra ficticios, sin datos personales y distintos entre sí
      assert.equal(new Set(Object.values(muestra.credentialSubject)).size, 7);
      assert.equal(muestra.credentialSubject.national_id, "000-0000000-0");
      t.diagnostic(`6 atributos: ${r.cuads.length} cuádruplas, ${c.cubiertos.length}/${c.attrs.length} cubiertos`);
    } finally { e.limpiar(); }
  });

  test("la credencial de muestra es la de la plantilla: mismos atributos, mismos tipos y mismo @context", () => {
    conEntorno({}, (e) => {
      const muestra = leerJson(e.rutas.muestra);
      const plantilla = plantillaDesdeSql(e.leer("sql"));
      assert.deepEqual(muestra["@context"], plantilla["@context"]);
      assert.deepEqual(muestra.type, plantilla.type);
      assert.deepEqual(Object.keys(muestra.credentialSubject), Object.keys(plantilla.credentialSubject));
      assert.equal(muestra.issuer, "did:web:emisor.prueba.invalid");
      assert.equal("proof" in muestra, false);
    });
  });
});

describe("scripts: sintaxis y modo de prueba sin ejecutar nada", () => {
  const scripts = ["generate-config.sh", "generate-context.sh", "generate-credential-sql.sh", "apply-credential.sh", "lib/common.sh"];
  for (const s of scripts) {
    test(`bash -n ${s}`, () => {
      const r = spawnSync("bash", ["-n", join(KIT_ORIGEN, "scripts", s)], { encoding: "utf8" });
      assert.equal(r.status, 0, r.stderr);
    });
  }

  test("apply-credential.sh con DRY_RUN=1 imprime el comando de psql y no llama a docker", () => {
    const e = prepararEntorno({ runtime: false, generar: false });
    try {
      // `docker` falso al principio del PATH: si el script lo ejecutara, dejaría una marca.
      const bin = join(e.raiz, "bin"); mkdirSync(bin);
      const marca = join(e.raiz, "docker-llamado");
      writeFileSync(join(bin, "docker"), `#!/bin/sh\necho "$@" >> "${marca}"\n`); chmodSync(join(bin, "docker"), 0o755);
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1", PATH: `${bin}:${process.env.PATH}` });
      assert.equal(r.status, 0, r.stderr);
      const linea = r.stdout.split("\n").find((l) => l.startsWith("docker compose "));
      assert.ok(linea, r.stdout);
      assert.equal(linea.trim(),
        `docker compose -f docker-compose.yml -f docker-compose.tls.yml --env-file generated/.env.runtime exec -T database psql -v ON_ERROR_STOP=1 -U postgres -d inji_certify < ${join(realpathSync(e.generated), "credential_config.sql")}`);
      assert.equal(existsSync(marca), false, "no se llamó a docker");
      assert.ok(e.existe("sql"), "regeneró el SQL antes de imprimir");
    } finally { e.limpiar(); }
  });

  test("apply-credential.sh respeta POSTGRES_USER y POSTGRES_DB del .env", () => {
    const e = prepararEntorno({ runtime: false, generar: false, extra: { POSTGRES_USER: "certify", POSTGRES_DB: "otra_bd" } });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.equal(r.status, 0, r.stderr);
      assert.match(r.stdout, /psql -v ON_ERROR_STOP=1 -U certify -d otra_bd < /);
    } finally { e.limpiar(); }
  });

  test("apply-credential.sh con atributo inválido falla antes de tocar nada", () => {
    const e = prepararEntorno({ runtime: false, generar: false, extra: { CREDENTIAL_ATTRIBUTES: "a b" } });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/apply-credential.sh"', { DRY_RUN: "1" });
      assert.notEqual(r.status, 0);
      assert.doesNotMatch(r.stdout, /docker compose exec/);
    } finally { e.limpiar(); }
  });

  test("sin Node local (KIT_FORCE_DOCKER=1) el generador se ejecuta con docker run node:22-alpine y el kit montado", () => {
    const e = prepararEntorno({ runtime: false, generar: false });
    try {
      const r = e.ejecutar('bash "$PWD/scripts/generate-context.sh"', { KIT_FORCE_DOCKER: "1", KIT_DRY_RUN: "1" });
      assert.equal(r.status, 0, r.stderr);
      const linea = r.stdout.split("\n").find((l) => l.startsWith("docker run"));
      assert.ok(linea, r.stdout);
      assert.match(linea, new RegExp(`^docker run --rm --user [0-9]+:[0-9]+ -v ${realpathSync(e.kit).replace(/[.*+?^${}()|[\]\\]/g, "\\\\$&")}:/kit -w /kit `));
      for (const v of ["CREDENTIAL_CONFIG_KEY_ID", "CREDENTIAL_ATTRIBUTES", "CERTIFY_PUBLIC_URL", "CREDENTIAL_LABELS_JSON"]) {
        assert.match(linea, new RegExp(`-e ${v}\\b`));
      }
      assert.match(linea, / node:22-alpine node \/kit\/scripts\/generate-context\.mjs generated$/);
      assert.equal(e.existe("contexto"), false, "en modo prueba no ejecuta nada");
    } finally { e.limpiar(); }
  });

  test("sin node ni docker, el error lo dice en español", () => {
    const e = prepararEntorno({ runtime: false, generar: false });
    try {
      const vacio = join(e.raiz, "vacio"); mkdirSync(vacio);
      const r = e.ejecutar(`source "$PWD/scripts/lib/common.sh"; PATH="${vacio}" run_node generate-context.mjs`);
      assert.notEqual(r.status, 0);
      assert.match(r.stderr, /hace falta Node 18\+ o Docker/);
    } finally { e.limpiar(); }
  });
});
