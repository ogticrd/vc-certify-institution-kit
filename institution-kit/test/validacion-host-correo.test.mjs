// T8 · K7 (media): en domain e ip el nombre público no se validaba (barra final, puerto, mayúsculas, IDN, saltos de línea)
// y llegaba al Caddyfile y a las properties; en proxy se aceptaban mayúsculas. CADDY_ACME_EMAIL con saltos de línea
// metía un sitio entero en el Caddyfile. Ahora se valida antes de escribir nada.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { prepararEntorno } from "./helpers/entorno.mjs";

const nadaGenerado = (e) => { for (const f of ["propiedadesDefault", "caddyfile", "sql", "composeArgs", "runtime", "contexto"]) assert.equal(e.existe(f), false, `se generó ${f}`); };

describe("K7 · CERTIFY_PUBLIC_HOST (TLS_MODE=domain)", () => {
  for (const [nombre, host] of [
    ["barra final", "emisor.prueba.invalid/"],
    ["mayúsculas", "Emisor.Prueba.INVALID"],
    ["IDN (no ASCII)", "emisión.gob.do"],
    ["puerto", "emisor.prueba.invalid:8443"],
    ["esquema", "https://emisor.prueba.invalid"],
    ["usuario@", "usuario:clave@emisor.prueba.invalid"],
    ["una @", "a@emisor.prueba.invalid"],
    ["espacios", "emisor prueba.invalid"],
    ["una ruta", "emisor.prueba.invalid/v1"],
    ["guion bajo", "emisor_x.prueba.invalid"],
    ["etiqueta que empieza por guion", "-emisor.prueba.invalid"],
    ["etiqueta vacía (dos puntos seguidos)", "emisor..prueba.invalid"],
    ["punto final", "emisor.prueba.invalid."],
    ["una sola etiqueta (no es un dominio completo)", "emisor"],
    ["inyección de Caddyfile (llaves y respond)", "x { respond 200 } evil"],
    ["inyección con salto de línea", "emisor.prueba.invalid\nevil.invalid {\nrespond 200"],
    ["llave de cierre", "emisor.prueba.invalid}"],
  ]) {
    test(`se rechaza ${nombre}, nombrando la variable, y no se genera NADA`, () => {
      const e = prepararEntorno({ extra: { CERTIFY_PUBLIC_HOST: host } });
      try {
        assert.notEqual(e.salida.status, 0, "debía rechazarse");
        assert.match(e.salida.stderr, /ERROR: CERTIFY_PUBLIC_HOST/);
        nadaGenerado(e);
      } finally { e.limpiar(); }
    });
  }

  for (const host of ["emisor.prueba.invalid", "a-b.c-d.gob.do", "xn--emisin-fxa.gob.do", "certify.intrant.gob.do", "1emisor.prueba.invalid"]) {
    test(`se acepta ${host}`, () => {
      const e = prepararEntorno({ extra: { CERTIFY_PUBLIC_HOST: host } });
      try {
        assert.equal(e.salida.status, 0, e.salida.stderr);
        assert.match(e.leer("caddyfile"), new RegExp(`^${host.replaceAll(".", "\\.")} \\{$`, "m"));
        assert.match(e.leer("propiedadesDefault"), new RegExp(`^mosip\\.certify\\.domain\\.url=https://${host.replaceAll(".", "\\.")}$`, "m"));
        assert.match(e.leer("propiedadesDefault"), new RegExp(`^mosip\\.certify\\.data-provider-plugin\\.did-url=did:web:${host.replaceAll(".", "\\.")}$`, "m"));
      } finally { e.limpiar(); }
    });
  }

  test("el mensaje explica cómo usar otro puerto (proxy) y el punycode para nombres con acentos", () => {
    const a = prepararEntorno({ extra: { CERTIFY_PUBLIC_HOST: "emisor.prueba.invalid:8443" } });
    const b = prepararEntorno({ extra: { CERTIFY_PUBLIC_HOST: "emisión.gob.do" } });
    try {
      assert.match(a.salida.stderr, /TLS_MODE=proxy/);
      assert.match(b.salida.stderr, /xn--|punycode/);
    } finally { a.limpiar(); b.limpiar(); }
  });
});

describe("K7 · SERVER_PUBLIC_IP e IP_DNS_PROVIDER (TLS_MODE=ip)", () => {
  for (const [nombre, ip] of [
    ["octeto fuera de rango", "999.1.1.1"],
    ["tres octetos", "1.2.3"],
    ["cinco octetos", "1.2.3.4.5"],
    ["ceros a la izquierda", "01.2.3.4"],
    ["máscara", "1.2.3.4/24"],
    ["texto", "abc"],
    ["espacio", "1.2.3.4 "],
    ["IPv6", "2001:db8::1"],
    ["inyección", "1.2.3.4 { respond 200 }"],
  ]) {
    test(`SERVER_PUBLIC_IP: se rechaza ${nombre} y no se genera nada`, () => {
      const e = prepararEntorno({ modo: "ip", extra: { SERVER_PUBLIC_IP: ip } });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /ERROR: SERVER_PUBLIC_IP/);
        nadaGenerado(e);
      } finally { e.limpiar(); }
    });
  }

  test("SERVER_PUBLIC_IP válida: hostname sslip.io", () => {
    const e = prepararEntorno({ modo: "ip", extra: { SERVER_PUBLIC_IP: "203.0.113.10" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("caddyfile"), /^203-0-113-10\.sslip\.io \{$/m);
    } finally { e.limpiar(); }
  });

  for (const prov of ["Sslip.io", "x{y", "a b", "sslip.io/x", "-x.io", "sslip"]) {
    test(`IP_DNS_PROVIDER «${prov}» se rechaza`, () => {
      const e = prepararEntorno({ modo: "ip", extra: { IP_DNS_PROVIDER: prov } });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.match(e.salida.stderr, /ERROR: IP_DNS_PROVIDER/);
        nadaGenerado(e);
      } finally { e.limpiar(); }
    });
  }

  test("IP_DNS_PROVIDER nip.io se acepta", () => {
    const e = prepararEntorno({ modo: "ip", extra: { IP_DNS_PROVIDER: "nip.io" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("caddyfile"), /^203-0-113-10\.nip\.io \{$/m);
    } finally { e.limpiar(); }
  });
});

describe("K7 · CADDY_ACME_EMAIL (domain e ip)", () => {
  for (const [nombre, correo] of [
    ["inyección con saltos de línea (sitio nuevo en el Caddyfile)", "a@b.c\n}\nevil.invalid {\nrespond 200"],
    ["espacios", "a b@c.d"],
    ["sin arroba", "sin-arroba"],
    ["sin dominio con punto", "a@b"],
    ["llave de cierre", "a@b.c}"],
    ["entre ángulos", "<a@b.c>"],
    ["dos direcciones", "a@b.c,d@e.f"],
    ["con retorno de carro", "a@b.c\r"],
    ["dos arrobas", "a@@b.c"],
  ]) {
    for (const modo of ["domain", "ip"]) {
      test(`${modo}: se rechaza ${nombre} y no se genera nada`, () => {
        const e = prepararEntorno({ modo, extra: { CADDY_ACME_EMAIL: correo } });
        try {
          assert.notEqual(e.salida.status, 0);
          assert.match(e.salida.stderr, /ERROR: CADDY_ACME_EMAIL/);
          nadaGenerado(e);
        } finally { e.limpiar(); }
      });
    }
  }

  test("un correo normal pasa y es lo único que lleva el bloque global", () => {
    const e = prepararEntorno({ extra: { CADDY_ACME_EMAIL: "a.b+c@x-y.gob.do" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("caddyfile"), /^\{\n\temail a\.b\+c@x-y\.gob\.do\n\}/);
    } finally { e.limpiar(); }
  });
});

describe("K7 · proxy: CERTIFY_PUBLIC_URL en minúsculas", () => {
  const proxy = (url) => prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: url, CADDY_ACME_EMAIL: undefined } });
  test("mayúsculas en el host: rechazado (el DID y la URL tendrían identidades distintas)", () => {
    const e = proxy("https://Certify.Prueba.INVALID");
    try {
      assert.notEqual(e.salida.status, 0);
      assert.match(e.salida.stderr, /CERTIFY_PUBLIC_URL.*minúsculas/);
      nadaGenerado(e);
    } finally { e.limpiar(); }
  });
  test("host en minúsculas con puerto: aceptado", () => {
    const e = proxy("https://certify.prueba.invalid:8443");
    try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
  });
  test("en proxy CADDY_ACME_EMAIL no se exige ni se valida (no hay ACME)", () => {
    const e = prepararEntorno({ modo: "proxy", extra: { CERTIFY_PUBLIC_URL: "https://certify.prueba.invalid", CADDY_ACME_EMAIL: "no es un correo" } });
    try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
  });
});

describe("K7 · defensa en profundidad: nada con «{», «}» ni saltos de línea entra al Caddyfile", () => {
  test("caddy_valor_seguro rechaza llaves y saltos de línea y acepta un nombre normal", () => {
    const e = prepararEntorno({ generar: false });
    try {
      const prueba = (valor) => e.ejecutar('source scripts/lib/common.sh; caddy_valor_seguro NOMBRE "$VALOR"', { VALOR: valor });
      for (const malo of ["x} evil {", "x{y", "a\nb", "a\rb", "}"]) {
        const r = prueba(malo);
        assert.notEqual(r.status, 0, JSON.stringify(malo));
        assert.match(r.stderr, /NOMBRE.*rompería el Caddyfile/);
      }
      assert.equal(prueba("emisor.prueba.invalid").status, 0);
      assert.equal(prueba("a@b.c").status, 0);
    } finally { e.limpiar(); }
  });

  test("el Caddyfile generado nunca contiene lo inyectado (todas las cargas útiles de esta prueba fallan antes de escribirlo)", () => {
    for (const [v, malo] of [["CERTIFY_PUBLIC_HOST", "x { respond 200 } evil.invalid"], ["CADDY_ACME_EMAIL", "a@b.c\n}\nevil.invalid {\nrespond 200"]]) {
      const e = prepararEntorno({ extra: { [v]: malo } });
      try {
        assert.notEqual(e.salida.status, 0);
        assert.equal(e.existe("caddyfile"), false);
      } finally { e.limpiar(); }
    }
  });
});
