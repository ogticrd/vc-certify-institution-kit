// T9 · I2 (integración real, 4-oct-2026): Caddy salía `unhealthy` siempre. El healthcheck pedía
// `http://localhost:2019/config/` con el `wget` de busybox, que resuelve `localhost` a `::1` primero y NO prueba
// `127.0.0.1`; la API de administración de Caddy escucha solo en 127.0.0.1:2019 -> «Connection refused» en cada intento
// (`docker inspect` mostraba FailingStreak creciente y `docker compose ps`, `(unhealthy)`).
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { KIT_ORIGEN } from "./helpers/entorno.mjs";

describe("I2 · el healthcheck de Caddy alcanza su API de administración", () => {
  const yml = readFileSync(join(KIT_ORIGEN, "docker-compose.yml"), "utf8");
  const caddy = yml.match(/^  caddy:\n((?:    .*\n|\n)*)/m)[1];
  const test_ = caddy.match(/healthcheck:\n(?:      .*\n)*?      test: (.*)\n/)[1];
  test("usa 127.0.0.1:2019 y no `localhost` (busybox wget prueba ::1 y no cae a IPv4)", () => {
    assert.match(test_, /127\.0\.0\.1:2019/);
    assert.doesNotMatch(test_, /localhost/);
  });
});
