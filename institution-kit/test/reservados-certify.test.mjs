// T8 · K14 (media) y los nombres de propiedades de objeto de K15: la lista de nombres reservados no incluía las variables
// que Certify mete en el MISMO mapa que los datos de la plantilla (credentialId, didUrl, templateName, rootContext…):
// un atributo con ese nombre pisaba o era pisado (`credentialId` del dato acababa como `id` de primer nivel de la
// credencial), y `__proto__`/`constructor`/`toString` pasaban la validación y rompían el contexto o la muestra.
// La prueba EXTRAE las claves del fuente de Certify (el kit vive dentro del fork), así que si Certify añade una variable
// nueva a la plantilla, esta prueba falla hasta que se reserve.
// Ejecutar: fnm exec --using 22.14.0 node --test "institution-kit/test/*.test.mjs"
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { KIT_ORIGEN } from "./helpers/entorno.mjs";
import { RESERVADOS, leerEntrada, ErrorEntrada } from "../scripts/lib/credencial.mjs";

const RAIZ = join(KIT_ORIGEN, "..");
const FUENTES = {
  constantes: join(RAIZ, "certify-core/src/main/java/io/mosip/certify/core/constants"),
  emision: join(RAIZ, "certify-service/src/main/java/io/mosip/certify/services/CertifyIssuanceServiceImpl.java"),
  motor: join(RAIZ, "certify-service/src/main/java/io/mosip/certify/vcformatters/VelocityTemplatingEngineImpl.java"),
};
const HAY_FUENTE = Object.values(FUENTES).every((r) => existsSync(r));

function constantes() {
  const mapa = {};
  for (const f of readdirSync(FUENTES.constantes)) {
    const t = readFileSync(join(FUENTES.constantes, f), "utf8");
    const clase = f.replace(/\.java$/, "");
    for (const m of t.matchAll(/static\s+final\s+String\s+(\w+)\s*=\s*"([^"]*)"/g)) mapa[`${clase}.${m[1]}`] = m[2];
  }
  return mapa;
}

// Claves que Certify inserta en el mapa de la plantilla: `<mapa>.put(<"literal" | Clase.CONSTANTE>, …)`.
function clavesDePlantilla() {
  const consts = constantes();
  const claves = new Set();
  for (const ruta of [FUENTES.emision, FUENTES.motor]) {
    const t = readFileSync(ruta, "utf8");
    for (const m of t.matchAll(/\b(?:templateParams|updatedTemplateParams)\.put\(\s*(?:"([^"]+)"|(\w+\.\w+))/g)) {
      if (m[1]) claves.add(m[1]);
      else {
        const v = consts[m[2]];
        assert.ok(v !== undefined, `constante sin resolver: ${m[2]}`);
        claves.add(v);
      }
    }
  }
  return claves;
}

describe("K14 · variables que Certify inyecta en la plantilla", () => {
  test("el fuente de Certify está al lado del kit (si no, esta prueba no puede comprobar nada)", { skip: !HAY_FUENTE && "no hay fuente de Certify junto al kit" }, () => {
    assert.ok(clavesDePlantilla().size >= 10);
  });

  test("TODAS las claves que Certify mete en el mapa de la plantilla están reservadas", { skip: !HAY_FUENTE && "no hay fuente de Certify" }, () => {
    const faltan = [...clavesDePlantilla()].filter((c) => !RESERVADOS.has(c));
    assert.deepEqual(faltan, [], `Certify inyecta estas claves y el kit las deja usar como atributo: ${faltan.join(", ")}`);
  });

  test("las que la evaluación adversarial demostró (credentialId, didUrl, templateName, renderingTemplateId, vct, rootContext, envConfigs, _esc, _dateTool, claim_169_values)", () => {
    for (const n of ["credentialId", "didUrl", "templateName", "renderingTemplateId", "vct", "rootContext", "envConfigs", "_esc", "_dateTool", "claim_169_values", "cnf", "_doctype", "_renderMethodSVGdigest", "credentialStatus", "validFrom", "validUntil", "_issuer", "_holderId"]) {
      assert.ok(RESERVADOS.has(n), n);
    }
  });

  for (const nombre of ["credentialId", "didUrl", "templateName", "rootContext", "envConfigs", "_esc", "_dateTool", "claim_169_values", "renderingTemplateId", "vct"]) {
    test(`un atributo llamado «${nombre}» se rechaza con un mensaje que lo explica`, () => {
      assert.throws(
        () => leerEntrada({ CREDENTIAL_CONFIG_KEY_ID: "K", CREDENTIAL_ATTRIBUTES: `ok,${nombre}`, CERTIFY_PUBLIC_URL: "https://x.prueba.invalid", INSTITUTION_ID: "i" }),
        (e) => e instanceof ErrorEntrada && e.message.includes(`«${nombre}»`) && /choca con un término/.test(e.message),
      );
    });
  }

  test("el tipo con ese nombre también se rechaza (los tipos usan la misma regla)", () => {
    assert.throws(() => leerEntrada({ CREDENTIAL_CONFIG_KEY_ID: "K", CREDENTIAL_ATTRIBUTES: "ok", CREDENTIAL_TYPE: "VerifiableCredential,credentialId", CERTIFY_PUBLIC_URL: "https://x.prueba.invalid", INSTITUTION_ID: "i" }), ErrorEntrada);
  });
});

describe("K15 · nombres que son propiedades de Object (__proto__, constructor, toString…)", () => {
  for (const nombre of ["__proto__", "constructor", "prototype", "toString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__"]) {
    test(`«${nombre}» como atributo se rechaza`, () => {
      assert.throws(
        () => leerEntrada({ CREDENTIAL_CONFIG_KEY_ID: "K", CREDENTIAL_ATTRIBUTES: `ok,${nombre}`, CERTIFY_PUBLIC_URL: "https://x.prueba.invalid", INSTITUTION_ID: "i" }),
        (e) => e instanceof ErrorEntrada && e.message.includes(`«${nombre}»`),
      );
    });
  }

  test("el lookup de etiquetas y de reservados no depende del prototipo: «toString» sin etiqueta no pierde su nombre", () => {
    // Defensa en profundidad si alguien quitara la reserva: la etiqueta por defecto es el propio nombre.
    const e = leerEntrada({ CREDENTIAL_CONFIG_KEY_ID: "K", CREDENTIAL_ATTRIBUTES: "nombre", CERTIFY_PUBLIC_URL: "https://x.prueba.invalid", INSTITUTION_ID: "i" });
    assert.equal(Object.getPrototypeOf(e.etiquetas), null, "etiquetas sin prototipo");
    assert.equal(e.etiquetas.toString, undefined);
  });
});
