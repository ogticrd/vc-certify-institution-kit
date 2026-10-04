// Simulador MÍNIMO del enrutado del fragmento `certify_comun` del Caddyfile generado (sin binario
// `caddy`): lee los `handle <ruta> { … }` de primer nivel, los ordena como lo hace el adaptador de
// Caddyfile (misma directiva: ruta más larga primero; sin matcher, al final) y devuelve a dónde iría una
// petición. Solo entiende lo que el fragmento usa: rutas exactas o con `*` final, `method`, `respond`,
// `reverse_proxy`, `file_server` y `handle` anidado. NO sustituye a `caddy validate` (eso lo hace el CI);
// sirve para que una regla de lista blanca se pruebe con peticiones y no solo con cadenas.
//
// Resultado: "certify" (reverse_proxy a Certify), "404", "fichero" (file_server), "salud" (health, solo
// red privada: aquí se trata como «certify» si `interno` es true) o "sin-regla".

// Texto entre llaves (con cabecera en `ini`), devuelve [cuerpo, índice del cierre].
function cuerpoDe(texto, iniLlave) {
  let prof = 0;
  for (let j = iniLlave; j < texto.length; j++) {
    if (texto[j] === "{") prof++;
    else if (texto[j] === "}" && --prof === 0) return [texto.slice(iniLlave + 1, j), j];
  }
  throw new Error("bloque sin cerrar");
}

// Todos los `handle`/`handle_path` directos de `texto` (no los anidados), con su ruta (o null).
export function manejadores(texto) {
  const sinComentarios = texto.split("\n").map((l) => l.replace(/^\s*#.*$/, "")).join("\n");
  const salida = [];
  const re = /(^|\n)[ \t]*(handle_path|handle|route)((?:[ \t]+[^\s{]+)?)[ \t]*\{/g;
  let m;
  let desde = 0;
  while ((m = re.exec(sinComentarios)) && m.index >= desde) {
    const ini = sinComentarios.indexOf("{", m.index + m[1].length);
    const [cuerpo, fin] = cuerpoDe(sinComentarios, ini);
    const ruta = m[3].trim() || null;
    salida.push({ directiva: m[2], ruta: ruta && !ruta.startsWith("@") ? ruta : null, matcher: ruta && ruta.startsWith("@") ? ruta : null, cuerpo });
    desde = fin + 1;
    re.lastIndex = desde;
  }
  return salida;
}

const casa = (patron, ruta) => {
  const p = patron.toLowerCase();
  const r = ruta.toLowerCase();
  return p.endsWith("*") ? r.startsWith(p.slice(0, -1)) : r === p;
};

// Orden de Caddy: por directiva (handle antes que handle_path antes que route), y dentro de la misma,
// la ruta más larga primero; sin ruta, al final. (Es lo que hace `sortRoutes` del adaptador.)
const POS = { handle: 0, handle_path: 1, route: 2 };
export function ordenar(hs) {
  return [...hs].map((h, i) => ({ ...h, i })).sort((a, b) => {
    if (a.directiva !== b.directiva) return POS[a.directiva] - POS[b.directiva];
    const la = a.ruta ? a.ruta.length : -1;
    const lb = b.ruta ? b.ruta.length : -1;
    return lb - la || a.i - b.i;
  });
}

function resolverCuerpo(cuerpo, peticion) {
  // Matchers con nombre: `@x method POST`, `@x client_ip …`
  const nombrados = {};
  for (const m of cuerpo.matchAll(/^[ \t]*(@\w+)[ \t]+(method|client_ip|file)[ \t]*([^\n{]*)/gm)) nombrados[m[1]] = { tipo: m[2], valor: m[3].trim() };
  const hijos = manejadores(cuerpo);
  if (hijos.length) {
    for (const h of ordenar(hijos)) {
      if (h.matcher) {
        const n = nombrados[h.matcher];
        if (!n) continue;
        if (n.tipo === "method" && !n.valor.split(/\s+/).includes(peticion.metodo)) continue;
        if (n.tipo === "client_ip" && !peticion.interno) continue;
        if (n.tipo === "file") continue; // did.json corregido: se evalúa aparte
      }
      return resolverCuerpo(h.cuerpo, peticion);
    }
    return "sin-regla";
  }
  if (/\brespond\s+404\b/.test(cuerpo)) return "404";
  if (/\breverse_proxy\b/.test(cuerpo)) return "certify";
  if (/\bfile_server\b/.test(cuerpo)) return "fichero";
  return "sin-regla";
}

// A dónde va `metodo ruta` según el fragmento (texto de Caddyfile.comun.inc o el generado). `interno`:
// la petición viene de un rango privado (para el health).
export function enrutar(caddyfile, metodo, ruta, { interno = false } = {}) {
  const i = caddyfile.indexOf("(certify_comun) {");
  const fragmento = i === -1 ? caddyfile : (() => {
    const [cuerpo] = cuerpoDe(caddyfile, caddyfile.indexOf("{", i));
    return cuerpo;
  })();
  for (const h of ordenar(manejadores(fragmento))) {
    if (h.ruta && !casa(h.ruta, ruta)) continue;
    return resolverCuerpo(h.cuerpo, { metodo, interno });
  }
  return "sin-regla";
}
