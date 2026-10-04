// T8 · K6 (media): una contraseña explícita con `$nombre`, `${…}` o `\` no era la misma en compose (--env-file), en
// Spring y en la base (medido con docker compose config real y el cargador de Spring Boot): Postgres se
// inicializaba con una y Certify se conectaba con otra. validate_env rechaza los caracteres que cada destino
// interpreta, antes de generar nada y sin imprimir la contraseña.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { prepararEntorno } from "./helpers/entorno.mjs";

const VARIABLES = ["POSTGRES_PASSWORD", "KEYSTORE_PASSWORD", "OAUTH_CLIENT_SECRET"];
const MALAS = [
  ["un «$» y un nombre (compose lo expande: «ab$cd»)", "ab$cd"],
  ["«${HOME}» (compose lo sustituye por una variable del servidor)", "a${HOME}b"],
  ["una barra invertida (Spring la pierde)", "ab\\cd"],
  ["una comilla invertida", "ab`cd"],
  ["una comilla doble", 'ab"cd'],
  ["una comilla simple", "ab'cd"],
  ["un espacio", "ab cd"],
  ["un salto de línea", "ab\ncd"],
  ["un retorno de carro", "ab\rcd"],
  ["un tabulador", "ab\tcd"],
];

describe("K6 · caracteres no permitidos en las contraseñas y el secreto OAuth", () => {
  for (const variable of VARIABLES) {
    for (const [nombre, valor] of MALAS) {
      test(`${variable} con ${nombre}: error claro, sin eco del valor y sin generar nada`, () => {
        const e = prepararEntorno({ extra: { [variable]: valor } });
        try {
          assert.notEqual(e.salida.status, 0, "debía rechazarse");
          assert.match(e.salida.stderr, new RegExp(`ERROR: ${variable} contiene`));
          assert.match(e.salida.stderr, /openssl rand -hex 32/);
          const salida = e.salida.stdout + e.salida.stderr;
          assert.ok(!salida.includes(valor.trim()), "no repite el valor");
          for (const f of ["propiedadesDefault", "caddyfile", "sql", "composeArgs", "runtime"]) assert.equal(e.existe(f), false, f);
        } finally { e.limpiar(); }
      });
    }
  }

  test("el mensaje dice qué caracteres no se admiten", () => {
    const e = prepararEntorno({ extra: { POSTGRES_PASSWORD: "ab$cd" } });
    try {
      assert.match(e.salida.stderr, /«\$»/);
      assert.match(e.salida.stderr, /«\\»/);
      assert.match(e.salida.stderr, /comillas/);
      assert.match(e.salida.stderr, /espacios/);
    } finally { e.limpiar(); }
  });

  test("lo que sí se admite: letras, dígitos y . _ @ % + = - # : / ~ (misma contraseña en compose, Spring y la base)", () => {
    const e = prepararEntorno({ extra: { POSTGRES_PASSWORD: "aZ09._@%+=-#:/~x", KEYSTORE_PASSWORD: "k.e-y_s@t%o+r=e", OAUTH_CLIENT_SECRET: "oauth.S3cret-_~" } });
    try {
      assert.equal(e.salida.status, 0, e.salida.stderr);
      assert.match(e.leer("runtime"), /^POSTGRES_PASSWORD=aZ09\._@%\+=-#:\/~x$/m);
    } finally { e.limpiar(); }
  });

  test("las contraseñas generadas (64 hex) siempre pasan", () => {
    const e = prepararEntorno({ extra: { POSTGRES_PASSWORD: undefined, KEYSTORE_PASSWORD: undefined } });
    try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
  });

  test("los valores por defecto (postgres, local) y el marcador de ejemplo no se confunden con un error de caracteres", () => {
    const e = prepararEntorno({ extra: { POSTGRES_PASSWORD: "postgres", KEYSTORE_PASSWORD: "local" } });
    try { assert.equal(e.salida.status, 0, e.salida.stderr); } finally { e.limpiar(); }
  });
});
