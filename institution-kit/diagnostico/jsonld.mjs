// JSON-LD sin dependencias: expansión, paso a RDF y canonicalización URDNA2015.
//
// POR QUE EXISTE. El auditor del panel responde «qué campos sobreviven a la
// expansión» resolviendo términos a mano, y deja escrito que la canonicalización
// URDNA2015 «necesitaría una biblioteca JSON-LD». Aquí hace falta más que eso:
// contar las cuádruplas del proof de una credencial de muestra y verificar su
// firma, y las dos cosas exigen el RDF de verdad. La regla del proyecto sigue
// siendo cero dependencias npm, así que se implementa el subconjunto de JSON-LD
// 1.1 que usan los contextos del ecosistema.
//
// QUÉ CUBRE, y es lo que usan los contextos W3C (VC 1.1, VC 2.0), el de la suite
// Ed25519Signature2020 y los contextos propios de los emisores:
//   - @context remotos, en línea y en lista; @version, @vocab, @protected,
//     @propagate, @language
//   - términos simples y expandidos, IRIs compactas con prefijo, @type en
//     términos (@id, @vocab, @json, IRIs de tipo de dato)
//   - contextos con alcance de tipo (no se propagan) y de propiedad (sí)
//   - contenedores @set, @list, @graph y @language
//   - nodos en blanco, listas y grafos con nombre al pasar a RDF
// Lo que NO cubre (@index/@id/@type como mapas, @nest, @reverse, @import,
// @included) LANZA un error que dice cuál es, en vez de dar un resultado
// silenciosamente distinto del de una biblioteca completa: una firma que se
// declara inválida por una carencia nuestra sería peor que no verificar.
//
// CÓMO SE VALIDÓ: contra jsonld.js 8 (la biblioteca que usan bin/prueba-*.mjs),
// comparando el N-Quads canónico byte a byte sobre credenciales VC 1.1 y 2.0,
// con y sin contexto de suite, y con términos sin definir. Ver el README.
import { createHash } from "node:crypto";

const RDF = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const XSD = "http://www.w3.org/2001/XMLSchema#";
const RDF_TYPE = RDF + "type", RDF_FIRST = RDF + "first", RDF_REST = RDF + "rest", RDF_NIL = RDF + "nil";
const RDF_LANGSTRING = RDF + "langString", RDF_JSON = RDF + "JSON";
const XSD_STRING = XSD + "string", XSD_BOOLEAN = XSD + "boolean", XSD_INTEGER = XSD + "integer", XSD_DOUBLE = XSD + "double";

const PALABRAS = new Set(["@base", "@container", "@context", "@default", "@direction", "@embed", "@explicit",
  "@graph", "@id", "@import", "@included", "@index", "@json", "@language", "@list", "@nest", "@none",
  "@omitDefault", "@prefix", "@preserve", "@propagate", "@protected", "@requireAll", "@reverse", "@set",
  "@type", "@value", "@version", "@vocab"]);
const esPalabra = (v) => typeof v === "string" && PALABRAS.has(v);
const pareceClave = (v) => typeof v === "string" && /^@[a-zA-Z]+$/.test(v);
const esAbsoluta = (v) => typeof v === "string" && /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(v);
const esBlanco = (v) => typeof v === "string" && v.startsWith("_:");
const comoLista = (v) => (Array.isArray(v) ? v : [v]);
const esObjeto = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const GEN_DELIM = /[:/?#\[\]@]$/;

export class ErrorJsonLd extends Error {
  constructor(codigo, mensaje) { super(`${codigo}: ${mensaje}`); this.codigo = codigo; }
}
const fallar = (codigo, mensaje) => { throw new ErrorJsonLd(codigo, mensaje); };

// --- procesado de contextos (JSON-LD 1.1 API §4.1) ---------------------------

function contextoVacio() {
  return { terminos: new Map(), vocab: null, idioma: null, previo: null };
}
function clonar(ctx) {
  return { terminos: new Map(ctx.terminos), vocab: ctx.vocab, idioma: ctx.idioma, previo: ctx.previo };
}

// `cargar(url)` devuelve el documento remoto ya parseado. Lo pone quien llama:
// así este módulo no sale a la red y no decide qué URLs se pueden pedir.
async function procesarContexto(activo, local, op, pila = [], propagar = true, pisarProtegidos = false) {
  let resultado = clonar(activo);
  if (esObjeto(local) && "@propagate" in local) propagar = local["@propagate"] === true;
  if (!propagar && !resultado.previo) resultado.previo = activo;
  for (const c of comoLista(local)) {
    if (c === null) {
      if (!pisarProtegidos && [...resultado.terminos.values()].some((d) => d.protegido))
        fallar("invalid context nullification", "no se puede anular un contexto con términos protegidos");
      const nuevo = contextoVacio();
      if (!propagar) nuevo.previo = resultado;
      resultado = nuevo;
      continue;
    }
    if (typeof c === "string") {
      if (pila.includes(c)) fallar("recursive context inclusion", c);
      if (pila.length > 16) fallar("context overflow", c);
      const doc = await op.cargar(c);
      if (!esObjeto(doc) || !("@context" in doc)) fallar("invalid remote context", `${c} no tiene @context`);
      resultado = await procesarContexto(resultado, doc["@context"], op, [...pila, c]);
      continue;
    }
    if (!esObjeto(c)) fallar("invalid local context", typeof c);
    if ("@import" in c) fallar("no soportado", "@import");
    if ("@version" in c && c["@version"] !== 1.1) fallar("invalid @version value", String(c["@version"]));
    if ("@vocab" in c) {
      const v = c["@vocab"];
      if (v === null) resultado.vocab = null;
      else if (typeof v !== "string") fallar("invalid vocab mapping", String(v));
      else resultado.vocab = expandirIri(resultado, v, { vocab: true, doc: true });
    }
    if ("@language" in c) resultado.idioma = c["@language"] === null ? null : String(c["@language"]).toLowerCase();
    const definidos = new Map();
    const protegido = c["@protected"] === true;
    for (const termino of Object.keys(c)) {
      if (["@base", "@direction", "@import", "@language", "@propagate", "@protected", "@version", "@vocab"].includes(termino)) continue;
      crearTermino(resultado, c, termino, definidos, { protegido, pisarProtegidos });
    }
    if ("@base" in c) resultado.base = c["@base"];
  }
  return resultado;
}

// Crear una definición de término (JSON-LD 1.1 API §4.2).
function crearTermino(activo, local, termino, definidos, op) {
  if (definidos.get(termino) === true) return;
  if (definidos.get(termino) === false) fallar("cyclic IRI mapping", termino);
  definidos.set(termino, false);
  let valor = local[termino];
  if (termino === "@type" && esObjeto(valor)) { definidos.set(termino, true); return; } // @type: {@container: @set}
  if (esPalabra(termino)) fallar("keyword redefinition", termino);
  if (pareceClave(termino)) { definidos.set(termino, true); return; }
  const previa = activo.terminos.get(termino);
  activo.terminos.delete(termino);
  let simple = false;
  if (valor === null) valor = { "@id": null };
  else if (typeof valor === "string") { valor = { "@id": valor }; simple = true; }
  else if (!esObjeto(valor)) fallar("invalid term definition", termino);
  for (const k of ["@reverse", "@nest", "@index"]) if (k in valor) fallar("no soportado", `${k} en «${termino}»`);

  const def = { iri: null, prefijo: false, protegido: "@protected" in valor ? valor["@protected"] === true : op.protegido };
  if ("@type" in valor) {
    const t = valor["@type"];
    if (typeof t !== "string") fallar("invalid type mapping", termino);
    const e = expandirIri(activo, t, { vocab: true, local, definidos });
    if (!["@id", "@json", "@none", "@vocab"].includes(e) && !esAbsoluta(e)) fallar("invalid type mapping", `${termino}: ${t}`);
    def.tipo = e;
  }
  if ("@id" in valor && valor["@id"] !== termino) {
    const id = valor["@id"];
    if (id === null) def.iri = null;
    else {
      if (typeof id !== "string") fallar("invalid IRI mapping", termino);
      if (!esPalabra(id) && pareceClave(id)) { definidos.set(termino, true); return; }
      def.iri = expandirIri(activo, id, { vocab: true, local, definidos });
      if (!esPalabra(def.iri) && !esAbsoluta(def.iri) && !esBlanco(def.iri)) fallar("invalid IRI mapping", `${termino}: ${id}`);
      if (def.iri === "@context") fallar("invalid keyword alias", termino);
      if (!/[:/]/.test(termino) && simple && (GEN_DELIM.test(def.iri) || esBlanco(def.iri))) def.prefijo = true;
    }
  } else if (termino.indexOf(":", 1) > 0) {
    const i = termino.indexOf(":");
    const pre = termino.slice(0, i), suf = termino.slice(i + 1);
    if (!suf.startsWith("//") && pre !== "_" && pre in local) crearTermino(activo, local, pre, definidos, op);
    const dp = activo.terminos.get(pre);
    def.iri = dp?.iri && !suf.startsWith("//") ? dp.iri + suf : termino;
  } else if (termino.includes("/")) {
    def.iri = expandirIri(activo, termino, { vocab: true });
    if (!esAbsoluta(def.iri)) fallar("invalid IRI mapping", termino);
  } else if (termino === "@type") def.iri = "@type";
  else if (activo.vocab) def.iri = activo.vocab + termino;
  else fallar("invalid IRI mapping", `«${termino}» sin @id y sin @vocab`);

  if ("@container" in valor) {
    const cont = comoLista(valor["@container"]);
    for (const x of cont) if (!["@list", "@set", "@graph", "@language", "@index", "@id", "@type"].includes(x))
      fallar("invalid container mapping", `${termino}: ${x}`);
    def.contenedor = [...cont].sort();
  }
  if ("@context" in valor) def.contexto = valor["@context"];
  if ("@language" in valor) def.idioma = valor["@language"] === null ? null : String(valor["@language"]).toLowerCase();
  if ("@prefix" in valor) def.prefijo = valor["@prefix"] === true;

  if (previa?.protegido && !op.pisarProtegidos) {
    // Redefinir un término protegido sólo se admite si la definición es idéntica.
    if (!mismaDefinicion(previa, def)) fallar("protected term redefinition", termino);
    activo.terminos.set(termino, previa);
  } else activo.terminos.set(termino, def);
  definidos.set(termino, true);
}

function mismaDefinicion(a, b) {
  const f = (d) => JSON.stringify([d.iri, d.tipo ?? null, d.contenedor ?? null, d.idioma, d.prefijo,
    d.contexto === undefined ? null : d.contexto]);
  return f(a) === f(b);
}

// Expansión de IRI (JSON-LD 1.1 API §5.2).
function expandirIri(activo, valor, { vocab = false, doc = false, local = null, definidos = null } = {}) {
  if (valor === null || esPalabra(valor)) return valor;
  if (pareceClave(valor)) return null;
  if (local && valor in local && definidos?.get(valor) !== true) crearTermino(activo, local, valor, definidos, { protegido: local["@protected"] === true });
  if (vocab && activo.terminos.has(valor)) return activo.terminos.get(valor).iri;
  const i = valor.indexOf(":", 1);
  if (i > 0) {
    const pre = valor.slice(0, i), suf = valor.slice(i + 1);
    if (pre === "_" || suf.startsWith("//")) return valor;
    if (local && pre in local && definidos?.get(pre) !== true) crearTermino(activo, local, pre, definidos, { protegido: local["@protected"] === true });
    const dp = activo.terminos.get(pre);
    if (dp?.iri && dp.prefijo) return dp.iri + suf;
    if (esAbsoluta(valor)) return valor;
  }
  if (vocab && activo.vocab) return activo.vocab + valor;
  // Sin @base: una IRI relativa se deja tal cual y el paso a RDF la descarta,
  // que es lo que hace jsonld.js sin base.
  return valor;
}

// --- expansión (JSON-LD 1.1 API §5.1) ----------------------------------------

async function expandirElemento(activo, prop, elem, op, desdeMapa = false) {
  if (elem === null || elem === undefined) return null;
  const defProp = prop ? activo.terminos.get(prop) : null;
  const ctxProp = defProp?.contexto;
  if (!Array.isArray(elem) && !esObjeto(elem)) {
    if (prop === null || prop === "@graph") return null;
    if (ctxProp !== undefined) activo = await procesarContexto(activo, ctxProp, op, [], true, true);
    return expandirValor(activo, prop, elem);
  }
  if (Array.isArray(elem)) {
    const r = [];
    const esLista = defProp?.contenedor?.includes("@list");
    for (const x of elem) {
      let e = await expandirElemento(activo, prop, x, op);
      if (esLista && Array.isArray(e)) e = { "@list": e };
      if (Array.isArray(e)) r.push(...e); else if (e !== null) r.push(e);
    }
    return r;
  }
  // Un nodo nuevo no hereda un contexto de tipo: se vuelve al anterior, salvo
  // que el objeto sea un valor o una simple referencia {@id}.
  if (activo.previo && !desdeMapa) {
    const claves = Object.keys(elem).map((k) => expandirIri(activo, k, { vocab: true }));
    const esValor = claves.includes("@value");
    const soloId = claves.length === 1 && claves[0] === "@id";
    if (!esValor && !soloId) activo = activo.previo;
  }
  if (ctxProp !== undefined) activo = await procesarContexto(activo, ctxProp, op, [], true, true);
  if ("@context" in elem) activo = await procesarContexto(activo, elem["@context"], op);
  const ctxTipo = activo;
  for (const k of Object.keys(elem).sort()) {
    if (expandirIri(activo, k, { vocab: true }) !== "@type") continue;
    for (const t of comoLista(elem[k]).filter((x) => typeof x === "string").sort()) {
      const d = ctxTipo.terminos.get(t);
      if (d?.contexto !== undefined) activo = await procesarContexto(activo, d.contexto, op, [], false);
    }
  }
  const r = {};
  for (const clave of Object.keys(elem).sort()) {
    if (clave === "@context") continue;
    const valor = elem[clave];
    const ep = expandirIri(activo, clave, { vocab: true });
    if (ep === null || (!ep.includes(":") && !esPalabra(ep))) {
      // Término sin definir: la expansión lo DESCARTA, y con él su valor sale de
      // lo firmado. Se avisa a quien lo quiera saber.
      op.descartado?.(clave, prop);
      continue;
    }
    if (esPalabra(ep)) {
      if (prop === "@reverse") fallar("invalid reverse property map", clave);
      if (ep in r && ep !== "@type") fallar("colliding keywords", ep);
      switch (ep) {
        case "@id":
          if (typeof valor !== "string") fallar("invalid @id value", typeof valor);
          r["@id"] = expandirIri(activo, valor, { doc: true });
          break;
        case "@type": {
          if (!comoLista(valor).every((x) => typeof x === "string")) fallar("invalid type value", JSON.stringify(valor));
          const tipos = comoLista(valor).map((x) => expandirIri(ctxTipo, x, { vocab: true, doc: true }));
          r["@type"] = [...(r["@type"] ?? []), ...tipos];
          break;
        }
        case "@graph": r["@graph"] = comoLista(await expandirElemento(activo, "@graph", valor, op)); break;
        case "@value":
          if (valor !== null && typeof valor === "object" && defProp?.tipo !== "@json") fallar("invalid value object value", clave);
          r["@value"] = valor; break;
        case "@language":
          if (typeof valor !== "string") fallar("invalid language-tagged string", clave);
          r["@language"] = valor.toLowerCase(); break;
        case "@list": {
          if (prop === null || prop === "@graph") break;
          let e = await expandirElemento(activo, prop, valor, op);
          r["@list"] = comoLista(e ?? []);
          break;
        }
        case "@set": r["@set"] = await expandirElemento(activo, prop, valor, op); break;
        case "@index": if (typeof valor !== "string") fallar("invalid @index value", clave); r["@index"] = valor; break;
        default: fallar("no soportado", ep);
      }
      continue;
    }
    const def = activo.terminos.get(clave);
    const cont = def?.contenedor ?? [];
    let ev;
    if (def?.tipo === "@json") ev = { "@value": valor, "@type": "@json" };
    else if (cont.includes("@language") && esObjeto(valor)) {
      ev = [];
      for (const idioma of Object.keys(valor).sort()) for (const t of comoLista(valor[idioma])) {
        if (t === null) continue;
        if (typeof t !== "string") fallar("invalid language map value", clave);
        const v = { "@value": t };
        if (expandirIri(activo, idioma, { vocab: true }) !== "@none") v["@language"] = idioma.toLowerCase();
        ev.push(v);
      }
    } else if ((cont.includes("@index") || cont.includes("@id") || cont.includes("@type")) && esObjeto(valor))
      fallar("no soportado", `contenedor ${cont.join(",")} en «${clave}»`);
    else ev = await expandirElemento(activo, clave, valor, op);
    if (ev === null || ev === undefined) continue;
    if (cont.includes("@list") && !(esObjeto(ev) && "@list" in ev)) ev = { "@list": comoLista(ev) };
    if (cont.includes("@graph") && !cont.includes("@id") && !cont.includes("@index"))
      ev = comoLista(ev).map((x) => ({ "@graph": comoLista(x) }));
    r[ep] = [...(r[ep] ?? []), ...comoLista(ev)];
  }
  if ("@value" in r) {
    if (r["@value"] === null) return null;
    if (r["@type"]) {
      if (r["@type"].length !== 1) fallar("invalid typed value", JSON.stringify(r["@type"]));
      r["@type"] = r["@type"][0];
    }
    if (r["@type"] !== "@json" && typeof r["@value"] !== "string" && "@language" in r) fallar("invalid language-tagged value", "");
  } else if ("@set" in r) return r["@set"];
  if (Object.keys(r).length === 1 && "@language" in r) return null;
  if (prop === null || prop === "@graph") {
    const k = Object.keys(r);
    if (!k.length || "@value" in r || "@list" in r) return null;
    if (k.length === 1 && k[0] === "@id") return null;
  }
  return r;
}

function expandirValor(activo, prop, valor) {
  const def = activo.terminos.get(prop);
  if (def?.tipo === "@id" && typeof valor === "string") return { "@id": expandirIri(activo, valor, { doc: true }) };
  if (def?.tipo === "@vocab" && typeof valor === "string") return { "@id": expandirIri(activo, valor, { vocab: true, doc: true }) };
  const r = { "@value": valor };
  if (def?.tipo && !["@id", "@vocab", "@none"].includes(def.tipo)) r["@type"] = def.tipo;
  else if (typeof valor === "string") {
    const idioma = def && "idioma" in def ? def.idioma : activo.idioma;
    if (idioma) r["@language"] = idioma;
  }
  return r;
}

// Expande un documento. `op.cargar(url)` trae contextos remotos; `op.descartado`
// se llama con cada término que la expansión tira.
export async function expandir(doc, op) {
  let r = await expandirElemento(contextoVacio(), null, doc, op);
  if (r === null) return [];
  if (esObjeto(r) && Object.keys(r).length === 1 && "@graph" in r) r = r["@graph"];
  return comoLista(r);
}

// --- de JSON-LD expandido a RDF (JSON-LD 1.1 API §7.2 y §8.1) ----------------

class Emisor {
  constructor(prefijo) { this.prefijo = prefijo; this.n = 0; this.mapa = new Map(); }
  id(viejo) {
    if (viejo && this.mapa.has(viejo)) return this.mapa.get(viejo);
    const nuevo = this.prefijo + this.n++;
    if (viejo) this.mapa.set(viejo, nuevo);
    return nuevo;
  }
  tiene(viejo) { return this.mapa.has(viejo); }
  clon() { const c = new Emisor(this.prefijo); c.n = this.n; c.mapa = new Map(this.mapa); return c; }
}

function mapaNodos(elem, mapa, emisor, grafo = "@default", sujeto = null, prop = null, lista = null) {
  if (Array.isArray(elem)) { for (const x of elem) mapaNodos(x, mapa, emisor, grafo, sujeto, prop, lista); return; }
  const g = (mapa[grafo] ??= {});
  const nodoSujeto = sujeto ? g[sujeto] : null;
  const anadir = (arr, v) => { if (!arr.some((x) => JSON.stringify(x) === JSON.stringify(v))) arr.push(v); };
  if ("@value" in elem) {
    if (lista) lista["@list"].push(elem); else anadir(nodoSujeto[prop], elem);
    return;
  }
  if ("@list" in elem) {
    const res = { "@list": [] };
    mapaNodos(elem["@list"], mapa, emisor, grafo, sujeto, prop, res);
    if (lista) lista["@list"].push(res); else nodoSujeto[prop].push(res);
    return;
  }
  let id = elem["@id"];
  id = id === undefined ? emisor.id(null) : esBlanco(id) ? emisor.id(id) : id;
  const nodo = (g[id] ??= { "@id": id });
  if (prop) {
    const ref = { "@id": id };
    if (lista) lista["@list"].push(ref); else anadir(nodoSujeto[prop], ref);
  }
  if (elem["@type"]) {
    nodo["@type"] ??= [];
    for (const t of comoLista(elem["@type"])) { const tt = esBlanco(t) ? emisor.id(t) : t; if (!nodo["@type"].includes(tt)) nodo["@type"].push(tt); }
  }
  if ("@graph" in elem) mapaNodos(elem["@graph"], mapa, emisor, id);
  for (const p of Object.keys(elem).sort()) {
    if (["@id", "@type", "@graph", "@index", "@reverse", "@included"].includes(p)) continue;
    const pp = esBlanco(p) ? emisor.id(p) : p;
    nodo[pp] ??= [];
    mapaNodos(elem[p], mapa, emisor, grafo, id, pp);
  }
}

const iri = (v) => ({ tipo: esBlanco(v) ? "blanco" : "iri", valor: v });

// JCS (RFC 8785) para los literales @json.
function jsonCanonico(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(jsonCanonico).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jsonCanonico(v[k])).join(",") + "}";
}

function objetoRdf(item, triples, emisor) {
  if ("@id" in item && !("@value" in item)) {
    const id = item["@id"];
    return esAbsoluta(id) || esBlanco(id) ? iri(id) : null;
  }
  if ("@list" in item) return listaRdf(item["@list"], triples, emisor);
  let v = item["@value"], dt = item["@type"] ?? null;
  if (dt !== null && dt !== "@json" && !esAbsoluta(dt)) return null;
  if (dt === "@json") { v = jsonCanonico(v); dt = RDF_JSON; }
  else if (typeof v === "boolean") { v = String(v); dt ??= XSD_BOOLEAN; }
  else if (typeof v === "number" && (!Number.isInteger(v) || dt === XSD_DOUBLE || Math.abs(v) >= 1e21)) {
    v = v.toExponential(15).replace(/(\d)0*e\+?/, "$1E"); dt ??= XSD_DOUBLE;
  } else if (typeof v === "number") { v = v.toFixed(0); dt ??= XSD_INTEGER; }
  else if ("@language" in item) dt = RDF_LANGSTRING;
  else dt ??= XSD_STRING;
  return { tipo: "literal", valor: String(v), dt, idioma: item["@language"] ?? null };
}

function listaRdf(lista, triples, emisor) {
  if (!lista.length) return iri(RDF_NIL);
  const nodos = lista.map(() => emisor.id(null));
  lista.forEach((x, i) => {
    const s = iri(nodos[i]);
    const o = objetoRdf(x, triples, emisor);
    if (o) triples.push({ s, p: iri(RDF_FIRST), o });
    triples.push({ s, p: iri(RDF_REST), o: i + 1 < nodos.length ? iri(nodos[i + 1]) : iri(RDF_NIL) });
  });
  return iri(nodos[0]);
}

// Del JSON-LD expandido a una lista de cuádruplas {s, p, o, g}.
export function aRdf(expandido) {
  const mapa = { "@default": {} }, emisor = new Emisor("_:b");
  mapaNodos(expandido, mapa, emisor);
  const cuads = [];
  for (const nombre of Object.keys(mapa).sort()) {
    if (nombre !== "@default" && !esAbsoluta(nombre) && !esBlanco(nombre)) continue;
    const g = nombre === "@default" ? null : iri(nombre);
    const grafo = mapa[nombre];
    for (const sid of Object.keys(grafo).sort()) {
      if (!esAbsoluta(sid) && !esBlanco(sid)) continue;
      const nodo = grafo[sid], s = iri(sid);
      for (const p of Object.keys(nodo).sort()) {
        if (p === "@type") {
          for (const t of nodo[p]) if (esAbsoluta(t) || esBlanco(t)) cuads.push({ s, p: iri(RDF_TYPE), o: iri(t), g });
          continue;
        }
        if (pareceClave(p) || esBlanco(p) || !esAbsoluta(p)) continue;
        for (const item of nodo[p]) {
          const extra = [];
          const o = objetoRdf(item, extra, emisor);
          if (o) cuads.push({ s, p: iri(p), o, g });
          for (const t of extra) cuads.push({ ...t, g });
        }
      }
    }
  }
  return cuads;
}

// --- N-Quads y URDNA2015 (RDF Dataset Canonicalization, RDFC-1.0) ------------

const escapar = (s) => s.replace(/["\\\n\r]/g, (c) => ({ '"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r" })[c]);
function termino(t) {
  if (t.tipo === "iri") return `<${t.valor}>`;
  if (t.tipo === "blanco") return t.valor;
  let s = `"${escapar(t.valor)}"`;
  if (t.idioma) s += "@" + t.idioma; else if (t.dt !== XSD_STRING) s += `^^<${t.dt}>`;
  return s;
}
export const nquad = (q) => `${termino(q.s)} ${termino(q.p)} ${termino(q.o)} ${q.g ? termino(q.g) + " " : ""}.\n`;
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");

export function canonizar(cuads) {
  const porBlanco = new Map();
  for (const q of cuads) for (const k of ["s", "o", "g"]) {
    const t = q[k];
    if (t?.tipo === "blanco") { if (!porBlanco.has(t.valor)) porBlanco.set(t.valor, []); const l = porBlanco.get(t.valor); if (l.at(-1) !== q) l.push(q); }
  }
  const canonico = new Emisor("_:c14n");
  const cambiar = (q, f) => {
    const r = { ...q };
    for (const k of ["s", "o", "g"]) if (q[k]?.tipo === "blanco") r[k] = { tipo: "blanco", valor: f(q[k].valor) };
    return r;
  };
  const cachePrimero = new Map();
  const hashPrimero = (id) => {
    if (cachePrimero.has(id)) return cachePrimero.get(id);
    const lineas = porBlanco.get(id).map((q) => nquad(cambiar(q, (b) => (b === id ? "_:a" : "_:z")))).sort();
    const h = sha256(lineas.join(""));
    cachePrimero.set(id, h);
    return h;
  };
  const hashRelacionado = (rel, q, emisor, pos) => {
    const id = canonico.tiene(rel) ? canonico.id(rel) : emisor.tiene(rel) ? emisor.id(rel) : hashPrimero(rel);
    return sha256(pos + (pos !== "g" ? `<${q.p.valor}>` : "") + id);
  };
  function* permutaciones(l) {
    if (l.length <= 1) { yield l; return; }
    for (let i = 0; i < l.length; i++) for (const r of permutaciones([...l.slice(0, i), ...l.slice(i + 1)])) yield [l[i], ...r];
  }
  const hashN = (id, emisor) => {
    const relacionados = new Map();
    for (const q of porBlanco.get(id)) for (const [k, pos] of [["s", "s"], ["o", "o"], ["g", "g"]]) {
      const t = q[k];
      if (t?.tipo === "blanco" && t.valor !== id) {
        const h = hashRelacionado(t.valor, q, emisor, pos);
        if (!relacionados.has(h)) relacionados.set(h, []);
        relacionados.get(h).push(t.valor);
      }
    }
    let datos = "";
    for (const h of [...relacionados.keys()].sort()) {
      datos += h;
      let elegido = "", emisorElegido = null;
      for (const perm of permutaciones(relacionados.get(h))) {
        let copia = emisor.clon(), camino = "", recursion = [], descartar = false;
        for (const rel of perm) {
          if (canonico.tiene(rel)) camino += canonico.id(rel);
          else { if (!copia.tiene(rel)) recursion.push(rel); camino += copia.id(rel); }
          if (elegido && camino.length >= elegido.length && camino > elegido) { descartar = true; break; }
        }
        if (descartar) continue;
        for (const rel of recursion) {
          const res = hashN(rel, copia);
          camino += copia.id(rel) + `<${res.hash}>`;
          copia = res.emisor;
          if (elegido && camino.length >= elegido.length && camino > elegido) { descartar = true; break; }
        }
        if (descartar) continue;
        if (!elegido || camino < elegido) { elegido = camino; emisorElegido = copia; }
      }
      datos += elegido;
      emisor = emisorElegido;
    }
    return { hash: sha256(datos), emisor };
  };

  const porHash = new Map();
  for (const id of porBlanco.keys()) {
    const h = hashPrimero(id);
    if (!porHash.has(h)) porHash.set(h, []);
    porHash.get(h).push(id);
  }
  const hashes = [...porHash.keys()].sort();
  for (const h of hashes) if (porHash.get(h).length === 1) canonico.id(porHash.get(h)[0]);
  for (const h of hashes) {
    const ids = porHash.get(h);
    if (ids.length === 1) continue;
    const resultados = [];
    for (const id of ids) {
      if (canonico.tiene(id)) continue;
      const temp = new Emisor("_:b");
      temp.id(id);
      resultados.push(hashN(id, temp));
    }
    resultados.sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
    for (const r of resultados) for (const viejo of r.emisor.mapa.keys()) canonico.id(viejo);
  }
  return cuads.map((q) => nquad(cambiar(q, (b) => canonico.id(b)))).sort().join("");
}

// Atajo: documento JSON-LD -> N-Quads canónico, más lo que la expansión descartó.
export async function canonizarDocumento(doc, op) {
  const descartados = [];
  const exp = await expandir(doc, { ...op, descartado: (t, p) => descartados.push({ termino: t, en: p }) });
  const cuads = aRdf(exp);
  return { nquads: canonizar(cuads), cuads, expandido: exp, descartados };
}
